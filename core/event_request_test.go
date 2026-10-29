package core_test

import (
	"crypto/tls"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestEventRequestRealIP(t *testing.T) {
	t.Parallel()

	headers := map[string][]string{
		"CF-Connecting-IP": {"1.2.3.4", "1.1.1.1"},
		"Fly-Client-IP":    {"1.2.3.4", "1.1.1.2"},
		"X-Real-IP":        {"1.2.3.4", "1.1.1.3,1.1.1.4"},
		"X-Forwarded-For":  {"1.2.3.4", "invalid,1.1.1.5,1.1.1.6,invalid"},
	}

	scenarios := []struct {
		name           string
		headers        map[string][]string
		trustedHeaders []string
		useLeftmostIP  bool
		expected       string
	}{
		{
			"no trusted headers",
			headers,
			nil,
			false,
			"127.0.0.1",
		},
		{
			"non-matching trusted header",
			headers,
			[]string{"header1", "header2"},
			false,
			"127.0.0.1",
		},
		{
			"trusted X-Real-IP (rightmost)",
			headers,
			[]string{"header1", "x-real-ip", "x-forwarded-for"},
			false,
			"1.1.1.4",
		},
		{
			"trusted X-Real-IP (leftmost)",
			headers,
			[]string{"header1", "x-real-ip", "x-forwarded-for"},
			true,
			"1.1.1.3",
		},
		{
			"trusted X-Forwarded-For (rightmost)",
			headers,
			[]string{"header1", "x-forwarded-for"},
			false,
			"1.1.1.6",
		},
		{
			"trusted X-Forwarded-For (leftmost)",
			headers,
			[]string{"header1", "x-forwarded-for"},
			true,
			"1.1.1.5",
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app, err := tests.NewTestApp()
			if err != nil {
				t.Fatal(err)
			}
			defer app.Cleanup()

			app.Settings().TrustedProxy.Headers = s.trustedHeaders
			app.Settings().TrustedProxy.UseLeftmostIP = s.useLeftmostIP

			event := core.RequestEvent{}
			event.App = app

			event.Request, err = http.NewRequest(http.MethodGet, "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			event.Request.RemoteAddr = "127.0.0.1:80" // fallback

			for k, values := range s.headers {
				for _, v := range values {
					event.Request.Header.Add(k, v)
				}
			}

			result := event.RealIP()

			if result != s.expected {
				t.Fatalf("Expected ip %q, got %q", s.expected, result)
			}
		})
	}
}

func TestEventRequestRequestSchemeAndOrigin(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name           string
		tls            bool
		headers        map[string][]string
		trustedHeaders []string
		expectedScheme string
	}{
		{"plain http", false, nil, nil, "http"},
		{"tls", true, nil, nil, "https"},
		{"tls with forwarded http (TLS wins)", true, map[string][]string{"X-Forwarded-Proto": {"http"}}, []string{"X-Forwarded-For"}, "https"},
		{"forwarded proto without trusted proxy (ignored)", false, map[string][]string{"X-Forwarded-Proto": {"https"}}, nil, "http"},
		{"forwarded proto with trusted proxy", false, map[string][]string{"X-Forwarded-Proto": {"https"}}, []string{"X-Forwarded-For"}, "https"},
		{"forwarded proto last value is used", false, map[string][]string{"X-Forwarded-Proto": {"http", "https"}}, []string{"X-Forwarded-For"}, "https"},
		{"forwarded proto last list item is used", false, map[string][]string{"X-Forwarded-Proto": {"https, http"}}, []string{"X-Forwarded-For"}, "http"},
		{"invalid forwarded proto", false, map[string][]string{"X-Forwarded-Proto": {"javascript"}}, []string{"X-Forwarded-For"}, "http"},
		{"rfc 7239 Forwarded with trusted proxy", false, map[string][]string{"Forwarded": {`for=1.2.3.4;proto="https";host=example.com`}}, []string{"X-Forwarded-For"}, "https"},
		{"rfc 7239 Forwarded without trusted proxy (ignored)", false, map[string][]string{"Forwarded": {"proto=https"}}, nil, "http"},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app, err := tests.NewTestApp()
			if err != nil {
				t.Fatal(err)
			}
			defer app.Cleanup()

			app.Settings().TrustedProxy.Headers = s.trustedHeaders

			event := core.RequestEvent{}
			event.App = app

			event.Request, err = http.NewRequest(http.MethodGet, "http://Example.com:8090/", nil)
			if err != nil {
				t.Fatal(err)
			}
			if s.tls {
				event.Request.TLS = &tls.ConnectionState{}
			}

			for k, values := range s.headers {
				for _, v := range values {
					event.Request.Header.Add(k, v)
				}
			}

			if scheme := event.RequestScheme(); scheme != s.expectedScheme {
				t.Fatalf("Expected scheme %q, got %q", s.expectedScheme, scheme)
			}

			if origin := event.RequestOrigin(); origin != s.expectedScheme+"://example.com:8090" {
				t.Fatalf("Expected origin %q, got %q", s.expectedScheme+"://example.com:8090", origin)
			}
		})
	}
}

func TestEventRequestIsStaffAndIsOwner(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	owner, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	staff, err := tests.CreateStaff(app, "staff_none@example.com")
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name          string
		record        *core.Record
		expectedStaff bool
		expectedOwner bool
	}{
		{"nil record", nil, false, false},
		{"regular user record", user, false, false},
		{"Owner superuser record", owner, true, true},
		{"superuser record without roles", staff, true, false},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			e := core.RequestEvent{App: app}
			e.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
			e.Auth = s.record

			if v := e.IsStaff(); v != s.expectedStaff {
				t.Fatalf("Expected IsStaff %v, got %v", s.expectedStaff, v)
			}

			if v := e.IsOwner(); v != s.expectedOwner {
				t.Fatalf("Expected IsOwner %v, got %v", s.expectedOwner, v)
			}
		})
	}
}

func TestRequestEventRequestInfo(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	userCol, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	user1 := core.NewRecord(userCol)
	user1.Id = "user1"
	user1.SetEmail("test1@example.com")

	user2 := core.NewRecord(userCol)
	user2.Id = "user2"
	user2.SetEmail("test2@example.com")

	testBody := `{"a":123,"b":"test"}`

	event := core.RequestEvent{}
	event.Request, err = http.NewRequest("POST", "/test?q1=123&q2=456", strings.NewReader(testBody))
	if err != nil {
		t.Fatal(err)
	}
	event.Request.Header.Add("content-type", "application/json")
	event.Request.Header.Add("x-test", "test")
	event.Set(core.RequestEventKeyInfoContext, "test")
	event.Auth = user1

	t.Run("init", func(t *testing.T) {
		info, err := event.RequestInfo()
		if err != nil {
			t.Fatalf("Failed to resolve request info: %v", err)
		}

		raw, err := json.Marshal(info, json.Deterministic(true))
		if err != nil {
			t.Fatalf("Failed to serialize request info: %v", err)
		}
		rawStr := string(raw)

		expected := `{"query":{"q1":"123","q2":"456"},"headers":{"content_type":"application/json","x_test":"test"},"body":{"a":123,"b":"test"},"auth":{"avatar":"","collectionId":"_pb_users_auth_","collectionName":"users","created":"","emailVisibility":false,"file":[],"id":"user1","name":"","rel":"","updated":"","username":"","verified":false},"method":"POST","context":"test","oauth2":{"clientId":"","scopes":[],"firstParty":false},"apiKey":null}`

		if expected != rawStr {
			t.Fatalf("Expected\n%v\ngot\n%v", expected, rawStr)
		}
	})

	t.Run("change user and context", func(t *testing.T) {
		event.Set(core.RequestEventKeyInfoContext, "test2")
		event.Auth = user2

		info, err := event.RequestInfo()
		if err != nil {
			t.Fatalf("Failed to resolve request info: %v", err)
		}

		raw, err := json.Marshal(info, json.Deterministic(true))
		if err != nil {
			t.Fatalf("Failed to serialize request info: %v", err)
		}
		rawStr := string(raw)

		expected := `{"query":{"q1":"123","q2":"456"},"headers":{"content_type":"application/json","x_test":"test"},"body":{"a":123,"b":"test"},"auth":{"avatar":"","collectionId":"_pb_users_auth_","collectionName":"users","created":"","emailVisibility":false,"file":[],"id":"user2","name":"","rel":"","updated":"","username":"","verified":false},"method":"POST","context":"test2","oauth2":{"clientId":"","scopes":[],"firstParty":false},"apiKey":null}`

		if expected != rawStr {
			t.Fatalf("Expected\n%v\ngot\n%v", expected, rawStr)
		}
	})
}

func TestRequestInfoIsStaffAndIsOwner(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	superuser, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	event := core.RequestEvent{App: app}
	event.Request, err = http.NewRequest("POST", "/test?q1=123&q2=456", strings.NewReader(`{"a":123,"b":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	event.Request.Header.Add("content-type", "application/json")

	scenarios := []struct {
		name     string
		record   *core.Record
		expected bool
	}{
		{"nil record", nil, false},
		{"regular user record", user, false},
		{"Owner superuser record", superuser, true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			event.Auth = s.record

			info, err := event.RequestInfo()
			if err != nil {
				t.Fatalf("Failed to resolve request info: %v", err)
			}

			if v := info.IsStaff(); v != s.expected {
				t.Fatalf("Expected IsStaff %v, got %v", s.expected, v)
			}

			if v := info.IsOwner(app); v != s.expected {
				t.Fatalf("Expected IsOwner %v, got %v", s.expected, v)
			}
		})
	}
}

func TestRequestInfoClone(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	userCol, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	user := core.NewRecord(userCol)
	user.Id = "user1"
	user.SetEmail("test1@example.com")

	event := core.RequestEvent{}
	event.Request, err = http.NewRequest("POST", "/test?q1=123&q2=456", strings.NewReader(`{"a":123,"b":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	event.Request.Header.Add("content-type", "application/json")
	event.Auth = user

	info, err := event.RequestInfo()
	if err != nil {
		t.Fatalf("Failed to resolve request info: %v", err)
	}

	clone := info.Clone()

	// modify the clone fields to ensure that it is a shallow copy
	clone.Headers["new_header"] = "test"
	clone.Query["new_query"] = "test"
	clone.Body["new_body"] = "test"
	clone.Auth.Id = "user2" // should be a Fresh copy of the record

	// check the original data
	// ---
	originalRaw, err := json.Marshal(info, json.Deterministic(true))
	if err != nil {
		t.Fatalf("Failed to serialize original request info: %v", err)
	}
	originalRawStr := string(originalRaw)

	expectedRawStr := `{"query":{"q1":"123","q2":"456"},"headers":{"content_type":"application/json"},"body":{"a":123,"b":"test"},"auth":{"avatar":"","collectionId":"_pb_users_auth_","collectionName":"users","created":"","emailVisibility":false,"file":[],"id":"user1","name":"","rel":"","updated":"","username":"","verified":false},"method":"POST","context":"default","oauth2":{"clientId":"","scopes":[],"firstParty":false},"apiKey":null}`
	if expectedRawStr != originalRawStr {
		t.Fatalf("Expected original info\n%v\ngot\n%v", expectedRawStr, originalRawStr)
	}

	// check the clone data
	// ---
	cloneRaw, err := json.Marshal(clone, json.Deterministic(true))
	if err != nil {
		t.Fatalf("Failed to serialize clone request info: %v", err)
	}
	cloneRawStr := string(cloneRaw)

	expectedCloneStr := `{"query":{"new_query":"test","q1":"123","q2":"456"},"headers":{"content_type":"application/json","new_header":"test"},"body":{"a":123,"b":"test","new_body":"test"},"auth":{"avatar":"","collectionId":"_pb_users_auth_","collectionName":"users","created":"","emailVisibility":false,"file":[],"id":"user2","name":"","rel":"","updated":"","username":"","verified":false},"method":"POST","context":"default","oauth2":{"clientId":"","scopes":[],"firstParty":false},"apiKey":null}`
	if expectedCloneStr != cloneRawStr {
		t.Fatalf("Expected clone info\n%v\ngot\n%v", expectedCloneStr, cloneRawStr)
	}
}

func TestNewRequestInfoOAuth2(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client := stubOAuth2Client(t, app, "users", "test_client")
	session := stubAuthSession(t, app, client, user, []string{"openid", "posts:read"})

	oauth2Token, err := session.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}

	// a token without cid (e.g. a non auth record token)
	regularToken, err := user.NewFileToken()
	if err != nil {
		t.Fatal(err)
	}

	if v := core.NewRequestInfoOAuth2(nil, oauth2Token); v != nil {
		t.Fatalf("Expected nil for nil auth record, got %v", v)
	}

	if v := core.NewRequestInfoOAuth2(user, "invalid"); v != nil {
		t.Fatalf("Expected nil for invalid token, got %v", v)
	}

	if v := core.NewRequestInfoOAuth2(user, regularToken); v != nil {
		t.Fatalf("Expected nil for token without cid, got %v", v)
	}

	info := core.NewRequestInfoOAuth2(user, oauth2Token)
	if info == nil {
		t.Fatal("Expected non-nil OAuth2 info")
	}

	if info.ClientId != "test_client" {
		t.Fatalf("Expected clientId %q, got %q", "test_client", info.ClientId)
	}

	if strings.Join(info.Scopes, " ") != "openid posts:read" {
		t.Fatalf("Expected scopes %q, got %v", "openid posts:read", info.Scopes)
	}

	if !info.HasScope("posts:read") || info.HasScope("posts:write") {
		t.Fatal("Unexpected HasScope result")
	}
}

func TestRequestEventRequestInfoOAuth2(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user1, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	user2, err := app.FindAuthRecordByEmail("users", "test2@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client := stubOAuth2Client(t, app, "users", "test_client")
	session := stubAuthSession(t, app, client, user1, []string{"openid", "posts:read"})

	token, err := session.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}

	event := new(core.RequestEvent)
	event.App = app
	event.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	event.Response = httptest.NewRecorder()
	event.Auth = user1
	event.Set(core.RequestEventKeyOAuth2, core.NewRequestInfoOAuth2(user1, token))

	info, err := event.RequestInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.OAuth2.ClientId != "test_client" || strings.Join(info.OAuth2.Scopes, " ") != "openid posts:read" {
		t.Fatalf("Unexpected OAuth2 info %#v", info.OAuth2)
	}

	clone := info.Clone()
	if clone.OAuth2.ClientId != "test_client" || len(clone.OAuth2.Scopes) != 2 {
		t.Fatalf("Expected cloned OAuth2 info, got %#v", clone.OAuth2)
	}
	clone.OAuth2.Scopes[0] = "changed"
	if info.OAuth2.Scopes[0] != "openid" {
		t.Fatal("Expected the OAuth2 scopes slice to be cloned")
	}

	// change the auth record -> the OAuth2 data is no longer relevant
	event.Auth = user2
	info, err = event.RequestInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.OAuth2.ClientId != "" || len(info.OAuth2.Scopes) != 0 {
		t.Fatalf("Expected empty OAuth2 info after auth change, got %#v", info.OAuth2)
	}

	// clear auth
	event.Auth = nil
	info, err = event.RequestInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.OAuth2.ClientId != "" {
		t.Fatalf("Expected empty OAuth2 info for guest, got %#v", info.OAuth2)
	}
}
