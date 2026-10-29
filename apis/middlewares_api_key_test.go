package apis_test

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/subscriptions"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

// apiKeyMux is a single router test helper for the API key scenarios
// (the scenarios share the same test app to keep the test setup cheap).
type apiKeyMux struct {
	*oauth2TestMux
}

func newAPIKeyMux(t testing.TB, app core.App) *apiKeyMux {
	t.Helper()

	return &apiKeyMux{oauth2Mux(t, app)}
}

// req sends the request and returns its status and raw body.
func (m *apiKeyMux) req(method string, url string, body string, headers map[string]string) (int, string) {
	m.t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
		if headers == nil {
			headers = map[string]string{}
		}
		if headers["Content-Type"] == "" {
			headers["Content-Type"] = "application/json"
		}
	}

	res := m.do(method, url, reader, headers)
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)

	return res.StatusCode, string(raw)
}

// expect sends the request and fails if the response status doesn't match
// (and the body doesn't contain the optional expected content).
func (m *apiKeyMux) expect(name string, status int, method string, url string, body string, headers map[string]string, contains ...string) string {
	m.t.Helper()

	resStatus, resBody := m.req(method, url, body, headers)
	if resStatus != status {
		m.t.Fatalf("[%s] Expected status %d, got %d (%s)", name, status, resStatus, resBody)
	}

	for _, c := range contains {
		if !strings.Contains(resBody, c) {
			m.t.Fatalf("[%s] Expected %q in the response body, got %s", name, c, resBody)
		}
	}

	return resBody
}

func apiKeyTestDemo2Permissions(t testing.TB, app core.App, actions ...string) core.Permissions {
	t.Helper()

	demo2, err := app.FindCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}

	return core.Permissions{Collections: map[string][]string{demo2.Id: actions}}
}

func TestAPIKeyDenyByDefault(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2PrepareIssuer(t, app, "users")

	mux := newAPIKeyMux(t, app)

	_, publicToken, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}
	withKey := map[string]string{apis.APIKeyPublicHeader: publicToken}

	protected := []struct {
		name   string
		method string
		url    string
		body   string
		status int // with a public key (guest governed by the rules)
	}{
		{"list", http.MethodGet, "/api/collections/demo2/records", "", 200},
		{"view", http.MethodGet, "/api/collections/demo2/records/0yxhwia2amd8gec", "", 200},
		{"create", http.MethodPost, "/api/collections/demo2/records", `{"title":"deny"}`, 200},
		{"update", http.MethodPatch, "/api/collections/demo2/records/achvryl401bhse3", `{"title":"deny_update"}`, 200},
		{"delete", http.MethodDelete, "/api/collections/demo2/records/llvuca81nly1qls", "", 204},
		{"batch", http.MethodPost, "/api/batch", `{"requests":[{"method":"POST","url":"/api/collections/demo2/records","body":{"title":"deny_batch"}}]}`, 200},
		{"missing collection", http.MethodGet, "/api/collections/missing/records", "", 404},
		{"auth collection", http.MethodGet, "/api/collections/users/records/4q1xlclmfloku33", "", 404},
		{"system collection", http.MethodGet, "/api/collections/_superusers/records", "", 403},
	}

	for _, s := range protected {
		mux.expect(s.name+" without credentials", 401, s.method, s.url, s.body, nil, `"missing_client_credentials"`)
		mux.expect(s.name+" with a public key", s.status, s.method, s.url, s.body, withKey)
	}

	// the bearer token alone is a client credential too
	mux.expect("list with an auth token", 200, http.MethodGet, "/api/collections/demo2/records", "", map[string]string{
		"Authorization": tests.AuthToken("users", "test@example.com"),
	})

	// exempt routes (anonymous access still works and it is governed by the routes/rules)
	exempt := []struct {
		name   string
		method string
		url    string
		status int
	}{
		{"health", http.MethodGet, "/api/health", 200},
		{"file", http.MethodGet, "/api/files/_pb_users_auth_/4q1xlclmfloku33/300_1SEi6Q6U72.png", 200},
		{"well-known (no default issuer)", http.MethodGet, "/.well-known/oauth-protected-resource", 404},
		{"jwks", http.MethodGet, "/oauth2/users/jwks.json", 200},
		{"oauth2 discovery", http.MethodGet, "/oauth2/users/.well-known/openid-configuration", 200},
		{"oauth2 hosted login page", http.MethodGet, "/oauth2/users/login", 400},
		{"installer", http.MethodPost, "/api/installer", 401},
	}

	for _, s := range exempt {
		body := mux.expect(s.name+" without credentials", s.status, s.method, s.url, "", nil)
		if strings.Contains(body, "missing_client_credentials") {
			t.Fatalf("[%s] Expected the route to be exempt, got %s", s.name, body)
		}
	}
}

func TestAPIKeyResolution(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	mux := newAPIKeyMux(t, app)

	newKey := func(kind string, modify func(k *core.APIKey)) (*core.APIKey, string) {
		key, token, err := tests.NewAPIKey(app, "users", kind, tests.AllCollectionsActions)
		if err != nil {
			t.Fatal(err)
		}
		if modify != nil {
			modify(key)
			if err := app.Save(key); err != nil {
				t.Fatal(err)
			}
		}
		return key, token
	}

	_, public := newKey(core.APIKeyKindPublic, nil)
	_, privateNone := newKey(core.APIKeyKindPrivate, nil)
	_, privateBuyer := newKey(core.APIKeyKindPrivate, func(k *core.APIKey) { k.SetBuyerContext(core.APIKeyBuyerContextRequired) })
	_, disabled := newKey(core.APIKeyKindPublic, func(k *core.APIKey) { k.SetDisabled(true) })
	_, expired := newKey(core.APIKeyKindPublic, func(k *core.APIKey) { k.SetExpiresAt(types.NowDateTime().Add(-time.Minute)) })
	_, future := newKey(core.APIKeyKindPublic, func(k *core.APIKey) { k.SetExpiresAt(types.NowDateTime().Add(time.Hour)) })
	_, origins := newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
		k.SetAllowedOrigins([]string{"https://shop.example.com", "http://localhost:3000"})
	})

	rotatedKey, rotatedOld := newKey(core.APIKeyKindPrivate, nil)
	rotatedNew := rotatedKey.GenerateToken()
	if err := app.Save(rotatedKey); err != nil {
		t.Fatal(err)
	}

	// a key of a client that was disabled later
	oauth2PrepareIssuer(t, app, "users")
	disabledClient := oauth2StubClient(t, app, "users", "disabled_storefront")
	_, disabledClientKey, err := tests.NewClientAPIKey(app, disabledClient, core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}
	disabledClient.SetDisabled(true)
	if err := app.Save(disabledClient); err != nil {
		t.Fatal(err)
	}

	url := "/api/collections/demo2/records"

	scenarios := []struct {
		name    string
		url     string
		headers map[string]string
		status  int
	}{
		{"public header", url, map[string]string{apis.APIKeyPublicHeader: public}, 200},
		{"public query (pk)", url + "?pk=" + public, nil, 200},
		{"public header from a browser", url, map[string]string{apis.APIKeyPublicHeader: public, "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "empty"}, 200},
		{"public not expired", url, map[string]string{apis.APIKeyPublicHeader: future}, 200},
		{"private without buyer context", url, map[string]string{apis.APIKeyPrivateHeader: privateNone}, 200},
		{"private without buyer context + buyer IP", url, map[string]string{apis.APIKeyPrivateHeader: privateNone, apis.APIKeyBuyerIPHeader: "203.0.113.5"}, 200},
		{"private with buyer IP", url, map[string]string{apis.APIKeyPrivateHeader: privateBuyer, apis.APIKeyBuyerIPHeader: "203.0.113.5"}, 200},
		{"private with buyer IPv6", url, map[string]string{apis.APIKeyPrivateHeader: privateBuyer, apis.APIKeyBuyerIPHeader: "2001:db8::1"}, 200},
		{"private missing buyer IP", url, map[string]string{apis.APIKeyPrivateHeader: privateBuyer}, 401},
		{"private invalid buyer IP", url, map[string]string{apis.APIKeyPrivateHeader: privateBuyer, apis.APIKeyBuyerIPHeader: "203.0.113.500"}, 401},
		{"private invalid buyer IP (list)", url, map[string]string{apis.APIKeyPrivateHeader: privateBuyer, apis.APIKeyBuyerIPHeader: "203.0.113.5, 10.0.0.1"}, 401},
		{"private via query", url + "?pk=" + privateNone, nil, 401},
		{"private via public header", url, map[string]string{apis.APIKeyPublicHeader: privateNone}, 401},
		{"private from a browser", url, map[string]string{apis.APIKeyPrivateHeader: privateNone, "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "empty"}, 401},
		{"private from a browser (same-origin no-cors)", url, map[string]string{apis.APIKeyPrivateHeader: privateNone, "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "script"}, 401},
		{"private with Sec-Fetch-Site", url, map[string]string{apis.APIKeyPrivateHeader: privateNone, "Sec-Fetch-Site": "none"}, 401},
		{"private with Sec-Fetch-Dest", url, map[string]string{apis.APIKeyPrivateHeader: privateNone, "Sec-Fetch-Dest": "document"}, 401},
		{"private from Node.js fetch (undici sends only sec-fetch-mode)", url, map[string]string{apis.APIKeyPrivateHeader: privateNone, "Sec-Fetch-Mode": "cors"}, 200},
		{"public via private header", url, map[string]string{apis.APIKeyPrivateHeader: public}, 401},
		{"both keys", url, map[string]string{apis.APIKeyPublicHeader: public, apis.APIKeyPrivateHeader: privateNone}, 401},
		{"unknown public", url, map[string]string{apis.APIKeyPublicHeader: "pb_pk_unknown"}, 401},
		{"unknown private", url, map[string]string{apis.APIKeyPrivateHeader: "pb_sk_unknown"}, 401},
		{"garbage", url, map[string]string{apis.APIKeyPublicHeader: "garbage"}, 401},
		{"unknown public query", url + "?pk=pb_pk_unknown", nil, 401},
		{"disabled", url, map[string]string{apis.APIKeyPublicHeader: disabled}, 401},
		{"expired", url, map[string]string{apis.APIKeyPublicHeader: expired}, 401},
		{"rotated (old token)", url, map[string]string{apis.APIKeyPrivateHeader: rotatedOld}, 401},
		{"rotated (new token)", url, map[string]string{apis.APIKeyPrivateHeader: rotatedNew}, 200},
		{"disabled client", url, map[string]string{apis.APIKeyPublicHeader: disabledClientKey}, 401},
		{"origins: no Origin (server usage)", url, map[string]string{apis.APIKeyPublicHeader: origins}, 200},
		{"origins: allowed Origin", url, map[string]string{apis.APIKeyPublicHeader: origins, "Origin": "https://shop.example.com"}, 200},
		{"origins: allowed Origin (localhost port)", url, map[string]string{apis.APIKeyPublicHeader: origins, "Origin": "http://localhost:3000"}, 200},
		{"origins: other scheme", url, map[string]string{apis.APIKeyPublicHeader: origins, "Origin": "http://shop.example.com"}, 401},
		{"origins: other port", url, map[string]string{apis.APIKeyPublicHeader: origins, "Origin": "http://localhost:3001"}, 401},
		{"origins: other host", url, map[string]string{apis.APIKeyPublicHeader: origins, "Origin": "https://evil.example.com"}, 401},
		{"origins: null Origin", url, map[string]string{apis.APIKeyPublicHeader: origins, "Origin": "null"}, 401},
		{"origins: allowed Origin via query", url + "?pk=" + origins, map[string]string{"Origin": "https://shop.example.com"}, 200},
		{"origins: other Origin via query", url + "?pk=" + origins, map[string]string{"Origin": "https://evil.example.com"}, 401},
		{"invalid key on an exempt route (never anonymous)", "/api/health", map[string]string{apis.APIKeyPublicHeader: disabled}, 401},
	}

	for _, s := range scenarios {
		body := mux.expect(s.name, s.status, http.MethodGet, s.url, "", s.headers)
		if s.status == 401 && strings.Contains(body, `"items"`) {
			t.Fatalf("[%s] Expected no records, got %s", s.name, body)
		}
	}
}

func TestAPIKeyBearerClient(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	mux := newAPIKeyMux(t, app)

	customer, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// the customer token client is pb_test_users (see tests.NewSessionAuthToken)
	customerToken, err := tests.NewSessionAuthToken(app, customer)
	if err != nil {
		t.Fatal(err)
	}

	_, sameClientKey, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, apiKeyTestDemo2Permissions(t, app, "list", "view"))
	if err != nil {
		t.Fatal(err)
	}

	oauth2PrepareIssuer(t, app, "users")
	other := oauth2StubClient(t, app, "users", "other_storefront")
	_, otherClientKey, err := tests.NewClientAPIKey(app, other, core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}

	owner, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	ownerToken, err := tests.NewSessionAuthToken(app, owner)
	if err != nil {
		t.Fatal(err)
	}

	mux.expect("customer + same client key", 200, http.MethodGet, "/api/collections/demo2/records", "", map[string]string{
		"Authorization":         customerToken,
		apis.APIKeyPublicHeader: sameClientKey,
	})

	mux.expect("customer + same client key outside the ceiling", 403, http.MethodPost, "/api/collections/demo2/records", `{"title":"x"}`, map[string]string{
		"Authorization":         customerToken,
		apis.APIKeyPublicHeader: sameClientKey,
	})

	mux.expect("customer + other client key", 401, http.MethodGet, "/api/collections/demo2/records", "", map[string]string{
		"Authorization":         customerToken,
		apis.APIKeyPublicHeader: otherClientKey,
	})

	mux.expect("customer + other client key on an exempt route", 401, http.MethodGet, "/api/health", "", map[string]string{
		"Authorization":         customerToken,
		apis.APIKeyPublicHeader: otherClientKey,
	})

	// the dashboard (pb_dashboard first-party token) never uses API keys
	mux.expect("dashboard token + key", 401, http.MethodGet, "/api/collections/demo2/records", "", map[string]string{
		"Authorization":         ownerToken,
		apis.APIKeyPublicHeader: sameClientKey,
	})
	mux.expect("dashboard token alone", 200, http.MethodGet, "/api/collections/demo1/records", "", map[string]string{
		"Authorization": ownerToken,
	})
}

func TestAPIKeyCeiling(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	mux := newAPIKeyMux(t, app)

	_, readKey, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, apiKeyTestDemo2Permissions(t, app, "list", "view"))
	if err != nil {
		t.Fatal(err)
	}

	_, allKey, err := tests.NewAPIKey(app, "users", core.APIKeyKindPrivate, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}

	_, emptyKey, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, core.Permissions{})
	if err != nil {
		t.Fatal(err)
	}

	read := map[string]string{apis.APIKeyPublicHeader: readKey}
	all := map[string]string{apis.APIKeyPrivateHeader: allKey}
	empty := map[string]string{apis.APIKeyPublicHeader: emptyKey}

	// the demo2 rules allow everything for guests
	mux.expect("read key list", 200, http.MethodGet, "/api/collections/demo2/records", "", read, `"totalItems":3`)
	mux.expect("read key create (rules allow, key doesn't)", 403, http.MethodPost, "/api/collections/demo2/records", `{"title":"x"}`, read)
	mux.expect("read key delete (rules allow, key doesn't)", 403, http.MethodDelete, "/api/collections/demo2/records/0yxhwia2amd8gec", "", read)
	mux.expect("read key batch create", 400, http.MethodPost, "/api/batch", `{"requests":[{"method":"POST","url":"/api/collections/demo2/records","body":{"title":"x"}}]}`, read)
	mux.expect("read key other collection", 403, http.MethodGet, "/api/collections/demo3/records", "", read)
	mux.expect("empty key list", 403, http.MethodGet, "/api/collections/demo2/records", "", empty)

	// the expand of a not allowed collection is skipped (demo3 has public rules)
	mux.expect("all key expand", 200, http.MethodGet, "/api/collections/demo4/records?expand=rel_one_no_cascade", "", all)

	// the collection rules always still apply (demo1 has nil rules)
	mux.expect("all key create (key allows, rules don't)", 403, http.MethodPost, "/api/collections/demo1/records", `{"text":"x"}`, all)
	mux.expect("all key list (key allows, rules don't)", 403, http.MethodGet, "/api/collections/demo1/records", "", all)
	mux.expect("all key auth collection view (rule)", 404, http.MethodGet, "/api/collections/users/records/4q1xlclmfloku33", "", all)

	// a key never grants system access
	mux.expect("all key system collection", 403, http.MethodGet, "/api/collections/_superusers/records", "", all)
	mux.expect("all key api keys collection", 403, http.MethodGet, "/api/collections/_apiKeys/records", "", all)
	mux.expect("all key logs", 401, http.MethodGet, "/api/logs", "", all)
	mux.expect("all key settings", 401, http.MethodGet, "/api/settings", "", all)
	mux.expect("all key collections", 401, http.MethodGet, "/api/collections", "", all)
	mux.expect("all key api keys", 401, http.MethodGet, "/api/oauth2/clients/missing/api-keys", "", all)
}

func TestAPIKeyLastUsed(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	mux := newAPIKeyMux(t, app)

	key, token, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}
	if !key.LastUsedAt().IsZero() {
		t.Fatalf("Expected empty lastUsedAt, got %v", key.LastUsedAt())
	}
	initialUpdated := key.Updated()

	headers := map[string]string{apis.APIKeyPublicHeader: token}

	// concurrent first use (race-safe; a single write)
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := mux.do(http.MethodGet, "/api/collections/demo2/records", nil, headers)
			res.Body.Close()
		}()
	}
	wg.Wait()

	key, err = app.FindAPIKeyById(key.Id)
	if err != nil {
		t.Fatal(err)
	}
	if key.LastUsedAt().IsZero() {
		t.Fatal("Expected lastUsedAt to be set")
	}

	// mark the stored value so that a new write could be detected
	marker := "2000-01-01 00:00:00.000Z"
	if _, err := app.NonconcurrentDB().Update(core.CollectionNameAPIKeys, dbx.Params{"lastUsedAt": marker}, dbx.HashExp{"id": key.Id}).Execute(); err != nil {
		t.Fatal(err)
	}

	mux.expect("throttled use", 200, http.MethodGet, "/api/collections/demo2/records", "", headers)

	key, err = app.FindAPIKeyById(key.Id)
	if err != nil {
		t.Fatal(err)
	}
	if key.LastUsedAt().String() != marker {
		t.Fatalf("Expected the lastUsedAt write to be throttled, got %v", key.LastUsedAt())
	}

	// the lastUsedAt write is not a key change (no record hooks, the "updated" date is unchanged)
	if key.Updated().String() != initialUpdated.String() {
		t.Fatalf("Expected unchanged updated date %v, got %v", initialUpdated, key.Updated())
	}
}

func TestAPIKeyRateLimitBuckets(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	app.Settings().RateLimits.Enabled = true
	app.Settings().RateLimits.Rules = []core.RateLimitRule{
		{Label: "/api/collections/demo2/records", MaxRequests: 1, Duration: 60},
	}

	mux := newAPIKeyMux(t, app)

	newKey := func(kind string, buyerContext string) string {
		key, token, err := tests.NewAPIKey(app, "users", kind, tests.AllCollectionsActions)
		if err != nil {
			t.Fatal(err)
		}
		if buyerContext != "" {
			key.SetBuyerContext(buyerContext)
			if err := app.Save(key); err != nil {
				t.Fatal(err)
			}
		}
		return token
	}

	publicA := newKey(core.APIKeyKindPublic, "")
	publicB := newKey(core.APIKeyKindPublic, "")
	privateBuyer := newKey(core.APIKeyKindPrivate, core.APIKeyBuyerContextRequired)
	privateNone := newKey(core.APIKeyKindPrivate, core.APIKeyBuyerContextNone)

	url := "/api/collections/demo2/records"

	steps := []struct {
		name    string
		headers map[string]string
		status  int
	}{
		// public: key id + client IP (the test requests have the same remote IP)
		{"public A first", map[string]string{apis.APIKeyPublicHeader: publicA}, 200},
		{"public A second", map[string]string{apis.APIKeyPublicHeader: publicA}, 429},
		{"public B first (own bucket)", map[string]string{apis.APIKeyPublicHeader: publicB}, 200},
		{"public B second", map[string]string{apis.APIKeyPublicHeader: publicB}, 429},

		// private with buyer context: key id + buyer IP
		{"private buyer 1 first", map[string]string{apis.APIKeyPrivateHeader: privateBuyer, apis.APIKeyBuyerIPHeader: "203.0.113.1"}, 200},
		{"private buyer 1 second", map[string]string{apis.APIKeyPrivateHeader: privateBuyer, apis.APIKeyBuyerIPHeader: "203.0.113.1"}, 429},
		{"private buyer 2 first (own bucket)", map[string]string{apis.APIKeyPrivateHeader: privateBuyer, apis.APIKeyBuyerIPHeader: "203.0.113.2"}, 200},

		// private without buyer context: key id
		{"private none first", map[string]string{apis.APIKeyPrivateHeader: privateNone}, 200},
		{"private none second", map[string]string{apis.APIKeyPrivateHeader: privateNone}, 429},

		// the guests (no key) bucket is still the client IP (the 401 is before the rate limit counting of the route)
		{"guest", nil, 401},
	}

	for _, s := range steps {
		mux.expect(s.name, s.status, http.MethodGet, url, "", s.headers)
	}
}

func TestAPIKeyCORS(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	key, _, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}
	key.SetAllowedOrigins([]string{"https://shop.example.com"})
	if err := app.Save(key); err != nil {
		t.Fatal(err)
	}

	disabledKey, _, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}
	disabledKey.SetAllowedOrigins([]string{"https://disabled.example.com"})
	disabledKey.SetDisabled(true)
	if err := app.Save(disabledKey); err != nil {
		t.Fatal(err)
	}

	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	// restricted CORS (the default "*" would allow every origin)
	r.Bind(apis.CORS(apis.CORSConfig{AllowOrigins: []string{"https://admin.example.com"}, AllowMethods: []string{http.MethodGet}}))
	handler, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	mux := &oauth2TestMux{t: t, app: app, handler: handler}

	scenarios := []struct {
		origin   string
		expected string
	}{
		{"https://admin.example.com", "https://admin.example.com"},
		{"https://shop.example.com", "https://shop.example.com"},
		{"https://disabled.example.com", ""},
		{"https://evil.example.com", ""},
	}

	for _, s := range scenarios {
		res := mux.do(http.MethodOptions, "/api/collections/demo2/records", nil, map[string]string{
			"Origin":                         s.origin,
			"Access-Control-Request-Method":  http.MethodGet,
			"Access-Control-Request-Headers": apis.APIKeyPublicHeader,
		})
		res.Body.Close()

		if v := res.Header.Get("Access-Control-Allow-Origin"); v != s.expected {
			t.Fatalf("[%s] Expected Access-Control-Allow-Origin %q, got %q", s.origin, s.expected, v)
		}
	}
}

func TestAPIKeyRealtimeSubscribe(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	mux := newAPIKeyMux(t, app)

	key, public, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}

	oauth2PrepareIssuer(t, app, "users")
	other := oauth2StubClient(t, app, "users", "other_storefront")
	_, otherPublic, err := tests.NewClientAPIKey(app, other, core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}

	customer, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	customerToken, err := tests.NewSessionAuthToken(app, customer) // pb_test_users client
	if err != nil {
		t.Fatal(err)
	}

	newClient := func(storedKey bool) subscriptions.Client {
		c := subscriptions.NewDefaultClient()
		if storedKey {
			// aka. connected with "?pk="
			c.Set(apis.RealtimeClientAPIKeyKey, &core.RequestInfoAPIKey{ClientId: tests.ClientIdForCollection("users"), KeyId: key.Id, KeyKind: key.Kind()})
		}
		app.SubscriptionsBroker().Register(c)
		return c
	}

	subscribe := func(c subscriptions.Client, topic string) string {
		return `{"clientId":"` + c.Id() + `","subscriptions":["` + topic + `"]}`
	}

	c := newClient(false)
	mux.expect("collection topic without credentials", 401, http.MethodPost, "/api/realtime", subscribe(c, "demo2/*"), nil, `"missing_client_credentials"`)
	mux.expect("record topic without credentials", 401, http.MethodPost, "/api/realtime", subscribe(c, "demo2/0yxhwia2amd8gec"), nil, `"missing_client_credentials"`)
	mux.expect("custom topic without credentials", 204, http.MethodPost, "/api/realtime", subscribe(c, "custom_topic"), nil)

	c = newClient(false)
	mux.expect("collection topic with public key header", 204, http.MethodPost, "/api/realtime", subscribe(c, "demo2/*"), map[string]string{apis.APIKeyPublicHeader: public})
	if stored, _ := c.Get(apis.RealtimeClientAPIKeyKey).(*core.RequestInfoAPIKey); stored == nil || stored.KeyId != key.Id {
		t.Fatalf("Expected the subscribe key to be stored, got %v", stored)
	}

	c = newClient(false)
	mux.expect("collection topic with ?pk=", 204, http.MethodPost, "/api/realtime?pk="+public, subscribe(c, "demo2/*"), nil)

	c = newClient(false)
	mux.expect("collection topic with an invalid ?pk=", 401, http.MethodPost, "/api/realtime?pk=pb_pk_invalid", subscribe(c, "demo2/*"), nil)

	c = newClient(true)
	mux.expect("collection topic with the connect key", 204, http.MethodPost, "/api/realtime", subscribe(c, "demo2/*"), nil)

	c = newClient(true)
	mux.expect("connect key + same client token", 204, http.MethodPost, "/api/realtime", subscribe(c, "demo2/*"), map[string]string{"Authorization": customerToken})

	c = newClient(true)
	mux.expect("connect key + other client key", 403, http.MethodPost, "/api/realtime", subscribe(c, "demo2/*"), map[string]string{apis.APIKeyPublicHeader: otherPublic})

	c = newClient(true)
	c.Set(apis.RealtimeClientAPIKeyKey, &core.RequestInfoAPIKey{ClientId: other.ClientId(), KeyId: "x", KeyKind: core.APIKeyKindPublic})
	mux.expect("connect key of another client + token", 401, http.MethodPost, "/api/realtime", subscribe(c, "demo2/*"), map[string]string{"Authorization": customerToken})
}

func TestAPIKeyRealtimeConnect(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:           "connect with ?pk=",
			Method:         http.MethodGet,
			URL:            "/api/realtime?pk=" + tests.PublicAPIKey(),
			Timeout:        100 * time.Millisecond,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`event:PB_CONNECT`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRealtimeConnectRequest": 1,
				"OnRealtimeMessageSend":    1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnRealtimeConnectRequest().BindFunc(func(e *core.RealtimeConnectRequestEvent) error {
					stored, _ := e.Client.Get(apis.RealtimeClientAPIKeyKey).(*core.RequestInfoAPIKey)
					if stored == nil || stored.ClientId != tests.ClientIdForCollection("users") || stored.KeyKind != core.APIKeyKindPublic {
						t.Errorf("Expected the connect key to be stored, got %v", stored)
					}

					return e.Next()
				})
			},
		},
		{
			Name:            "connect with an invalid ?pk=",
			Method:          http.MethodGet,
			URL:             "/api/realtime?pk=pb_pk_invalid",
			Timeout:         100 * time.Millisecond,
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "connect with a private key in the query",
			Method:          http.MethodGet,
			URL:             "/api/realtime?pk=pb_sk_whatever",
			Timeout:         100 * time.Millisecond,
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			// connecting without credentials is allowed (custom topics), the collection topics are checked on subscribe
			Name:            "connect without credentials",
			Method:          http.MethodGet,
			URL:             "/api/realtime",
			Timeout:         100 * time.Millisecond,
			ExpectedStatus:  200,
			ExpectedContent: []string{`event:PB_CONNECT`},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRealtimeConnectRequest": 1,
				"OnRealtimeMessageSend":    1,
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestAPIKeyRealtimeBroadcast(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// init realtime handlers
	if _, err := apis.NewRouter(app); err != nil {
		t.Fatal(err)
	}

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	demo3, _ := app.FindCollectionByNameOrId("demo3")

	newKey := func(permissions core.Permissions) (*core.APIKey, *core.RequestInfoAPIKey) {
		key, _, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, permissions)
		if err != nil {
			t.Fatal(err)
		}
		client, err := app.FindOAuth2ClientById(key.ClientRef())
		if err != nil {
			t.Fatal(err)
		}
		return key, core.NewRequestInfoAPIKey(client, key, "")
	}

	_, allKey := newKey(tests.AllCollectionsActions)
	_, viewKey := newKey(core.Permissions{Collections: map[string][]string{demo2.Id: {"view"}}})
	_, listKey := newKey(core.Permissions{Collections: map[string][]string{demo2.Id: {"list"}}})
	_, otherKey := newKey(core.Permissions{Collections: map[string][]string{demo3.Id: {"list", "view"}}})
	disabledKey, disabledInfo := newKey(tests.AllCollectionsActions)
	rotatedKey, rotatedInfo := newKey(tests.AllCollectionsActions)
	deletedKey, deletedInfo := newKey(tests.AllCollectionsActions)

	subs := []struct {
		name          string
		key           *core.RequestInfoAPIKey
		expectMessage bool
	}{
		{"all actions key", allKey, true},
		{"view key", viewKey, true},
		{"list only key", listKey, false},
		{"other collection key", otherKey, false},
		{"disabled after subscribe", disabledInfo, false},
		{"rotated after subscribe", rotatedInfo, false},
		{"deleted after subscribe", deletedInfo, false},
	}

	clients := make([]subscriptions.Client, len(subs))
	for i, s := range subs {
		c := subscriptions.NewDefaultClient()
		c.Set(apis.RealtimeClientAPIKeyKey, s.key)
		c.Subscribe(demo2.Name + "/*")
		app.SubscriptionsBroker().Register(c)
		clients[i] = c
	}

	disabledKey.SetDisabled(true)
	if err := app.Save(disabledKey); err != nil {
		t.Fatal(err)
	}
	rotatedKey.GenerateToken()
	if err := app.Save(rotatedKey); err != nil {
		t.Fatal(err)
	}
	if err := app.Delete(deletedKey); err != nil {
		t.Fatal(err)
	}

	messages := make([]string, len(subs))
	wg := sync.WaitGroup{}
	for i, c := range clients {
		wg.Go(func() {
			select {
			case msg := <-c.Channel():
				messages[i] = string(msg.Data)
			case <-time.After(1500 * time.Millisecond):
			}
		})
	}

	record := core.NewRecord(demo2)
	record.Set("title", "realtime_key")
	if err := app.Save(record); err != nil {
		t.Fatal(err)
	}

	wg.Wait()

	for i, s := range subs {
		if got := messages[i] != ""; got != s.expectMessage {
			t.Errorf("[%s] Expected message %v, got %q", s.name, s.expectMessage, messages[i])
		}
	}
}
