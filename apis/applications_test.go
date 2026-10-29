package apis_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/tools/subscriptions"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

const appTokenURL = "/oauth2/" + core.CollectionNameApplicationInstallations + "/token"

// appInstall imports a minimal custom application manifest and installs it with the provided grant
// (trusted core services; the API endpoints are covered by TestApplicationsApi).
func appInstall(t testing.TB, app core.App, handle string, grant core.Permissions) *core.ApplicationInstallResult {
	t.Helper()

	manifest, err := core.ParseApplicationManifest([]byte(`{"handle":"`+handle+`","name":"App `+handle+`","version":"1.0.0"}`), core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}

	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}

	result, err := app.InstallApplication(imported.Application, grant, "")
	if err != nil {
		t.Fatal(err)
	}

	return result
}

// appTokenRequest sends a raw form request to the installations issuer token endpoint.
func appTokenRequest(t testing.TB, app core.App, rawURL string, form url.Values, headers map[string]string) (int, map[string]any) {
	t.Helper()

	res := oauth2Mux(t, app).do(http.MethodPost, rawURL, strings.NewReader(form.Encode()), oauth2FormHeaders(headers))
	defer res.Body.Close()

	data := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&data)

	return res.StatusCode, data
}

// appToken exchanges the managed client credentials at the real token endpoint
// (client_credentials grant; the only way to obtain an application access token).
func appToken(t testing.TB, app core.App, clientId string, secret string, scope string) string {
	t.Helper()

	form := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		form.Set("scope", scope)
	}

	status, data := appTokenRequest(t, app, appTokenURL, form, map[string]string{"Authorization": basicAuth(clientId, secret)})
	if status != http.StatusOK {
		t.Fatalf("Expected client_credentials 200, got %d %v", status, data)
	}

	token, _ := data["access_token"].(string)
	if token == "" {
		t.Fatalf("Missing access_token in %v", data)
	}

	return token
}

// appApi sends an API request with the provided auth token and returns the status and raw body.
func appApi(t testing.TB, app core.App, method string, rawURL string, token string, body string) (int, string) {
	t.Helper()

	headers := map[string]string{"Content-Type": "application/json"}
	if token != "" {
		headers["Authorization"] = token
	}

	res := oauth2Mux(t, app).do(method, rawURL, strings.NewReader(body), headers)
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)

	return res.StatusCode, string(raw)
}

// -------------------------------------------------------------------
// Application actor × every API endpoint
// -------------------------------------------------------------------

const (
	appActorFull   = "app full grant"
	appActorScoped = "app full grant + read_demo2 scope token"
	appActorRead   = "app demo2 read grant"
	appActorNone   = "app empty grant"
)

var appActors = []string{appActorFull, appActorScoped, appActorRead, appActorNone}

// appMatrixSetup installs the matrix application of the provided actor and returns its access token
// (only the actor application is installed to keep the setup cheap):
//   - full: demo2 all actions, demo1 list + settings, collections, logs, crons and llm read, webhooks write
//   - scoped: the full installation with a token narrowed to "read_demo2"
//   - read: demo2 list/view
//   - none: empty grant
func appMatrixSetup(t testing.TB, app *tests.TestApp, actor string) string {
	t.Helper()

	demo1, err := app.FindCollectionByNameOrId("demo1")
	if err != nil {
		t.Fatal(err)
	}

	demo2, err := app.FindCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}

	switch actor {
	case appActorFull, appActorScoped:
		full := appInstall(t, app, "matrix-full", core.Permissions{
			Collections: map[string][]string{
				demo1.Id: {core.PermissionActionList},
				demo2.Id: core.PermissionCollectionActions,
			},
			System: map[string]string{
				core.PermissionResourceSettings:    core.PermissionLevelRead,
				core.PermissionResourceCollections: core.PermissionLevelRead,
				core.PermissionResourceLogs:        core.PermissionLevelRead,
				core.PermissionResourceCrons:       core.PermissionLevelRead,
				core.PermissionResourceLLM:         core.PermissionLevelRead,
				core.PermissionResourceWebhooks:    core.PermissionLevelWrite,
			},
		})

		scope := ""
		if actor == appActorScoped {
			scope = "read_demo2"
		}

		return appToken(t, app, full.Client.ClientId(), full.ClientSecret, scope)
	case appActorRead:
		read := appInstall(t, app, "matrix-read", core.Permissions{
			Collections: map[string][]string{demo2.Id: {core.PermissionActionList, core.PermissionActionView}},
		})

		return appToken(t, app, read.Client.ClientId(), read.ClientSecret, "")
	case appActorNone:
		none := appInstall(t, app, "matrix-none", core.Permissions{})

		return appToken(t, app, none.Client.ClientId(), none.ClientSecret, "")
	}

	t.Fatalf("unknown application matrix actor %q", actor)

	return ""
}

func appAll(status int, overrides map[string]int) map[string]int {
	result := make(map[string]int, len(appActors))
	for _, a := range appActors {
		result[a] = status
	}
	for k, v := range overrides {
		result[k] = v
	}
	return result
}

func TestApplicationsRBACMatrix(t *testing.T) {
	t.Parallel()

	rows := []rbacMatrixRow{
		// regular collection with public rules (demo2) - the apps bypass the rules only with the grant ∩ scopes
		{
			name:     "list demo2 records",
			method:   http.MethodGet,
			url:      "/api/collections/demo2/records",
			expected: appAll(403, map[string]int{appActorFull: 200, appActorScoped: 200, appActorRead: 200}),
		},
		{
			name:     "view demo2 record",
			method:   http.MethodGet,
			url:      "/api/collections/demo2/records/0yxhwia2amd8gec",
			expected: appAll(403, map[string]int{appActorFull: 200, appActorScoped: 200, appActorRead: 200}),
		},
		{
			name:     "create demo2 record",
			method:   http.MethodPost,
			url:      "/api/collections/demo2/records",
			body:     `{"title":"app"}`,
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "update demo2 record",
			method:   http.MethodPatch,
			url:      "/api/collections/demo2/records/0yxhwia2amd8gec",
			body:     `{"title":"app"}`,
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "delete demo2 record",
			method:   http.MethodDelete,
			url:      "/api/collections/demo2/records/0yxhwia2amd8gec",
			expected: appAll(403, map[string]int{appActorFull: 204}),
		},
		// regular collection with nil (staff only) rules (demo1)
		{
			name:     "list demo1 records (list grant => bypass)",
			method:   http.MethodGet,
			url:      "/api/collections/demo1/records",
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "view demo1 record (only list granted)",
			method:   http.MethodGet,
			url:      "/api/collections/demo1/records/84nmscqy84lsi1t",
			expected: appAll(403, nil),
		},
		// auth collection (no grant, no own-record fallback)
		{
			name:     "list users",
			method:   http.MethodGet,
			url:      "/api/collections/users/records",
			expected: appAll(403, nil),
		},
		{
			name:     "view users record",
			method:   http.MethodGet,
			url:      "/api/collections/users/records/4q1xlclmfloku33",
			expected: appAll(403, nil),
		},
		// system collections (only the mapped application grantable resources)
		{
			name:     "list _superusers",
			method:   http.MethodGet,
			url:      "/api/collections/_superusers/records",
			expected: appAll(403, nil),
		},
		{
			name:     "list _externalAuths (no own-record fallback)",
			method:   http.MethodGet,
			url:      "/api/collections/_externalAuths/records",
			expected: appAll(403, nil),
		},
		{
			name:     "list _authSessions",
			method:   http.MethodGet,
			url:      "/api/collections/_authSessions/records",
			expected: appAll(403, nil),
		},
		{
			name:     "list _roles",
			method:   http.MethodGet,
			url:      "/api/collections/_roles/records",
			expected: appAll(403, nil),
		},
		{
			name:     "list _roleAssignments",
			method:   http.MethodGet,
			url:      "/api/collections/_roleAssignments/records",
			expected: appAll(403, nil),
		},
		{
			name:     "list _oauth2Clients",
			method:   http.MethodGet,
			url:      "/api/collections/_oauth2Clients/records",
			expected: appAll(403, nil),
		},
		{
			name:     "list _applications",
			method:   http.MethodGet,
			url:      "/api/collections/_applications/records",
			expected: appAll(403, nil),
		},
		{
			name:     "list _applicationVersions",
			method:   http.MethodGet,
			url:      "/api/collections/_applicationVersions/records",
			expected: appAll(403, nil),
		},
		{
			name:     "list _applicationInstallations",
			method:   http.MethodGet,
			url:      "/api/collections/_applicationInstallations/records",
			expected: appAll(403, nil),
		},
		{
			name:     "list _webhooks (webhooks grant)",
			method:   http.MethodGet,
			url:      "/api/collections/_webhooks/records",
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		// webhooks (W1: only the topics of the granted viewable collections; never wildcards)
		{
			name:     "subscribe to a viewable collection topic",
			method:   http.MethodPost,
			url:      "/api/collections/_webhooks/records",
			body:     `{"name":"w","uri":"https://example.com/hook","topics":["demo2.create"]}`,
			expected: appAll(403, map[string]int{appActorFull: 200}),
			content:  map[string][]string{appActorFull: {`"actorRef":"`}},
		},
		{
			name:     "subscribe to a not viewable collection topic (list only)",
			method:   http.MethodPost,
			url:      "/api/collections/_webhooks/records",
			body:     `{"name":"w","uri":"https://example.com/hook","topics":["demo1.create"]}`,
			expected: appAll(403, map[string]int{appActorFull: 400}),
		},
		{
			name:     "subscribe to a wildcard topic",
			method:   http.MethodPost,
			url:      "/api/collections/_webhooks/records",
			body:     `{"name":"w","uri":"https://example.com/hook","topics":["*.create"]}`,
			expected: appAll(403, map[string]int{appActorFull: 400}),
		},
		// W2: the subscription filter can reference only the granted fields and collections
		{
			name:     "subscribe with a filter of the own fields",
			method:   http.MethodPost,
			url:      "/api/collections/_webhooks/records",
			body:     `{"name":"w","uri":"https://example.com/hook","topics":["demo2.create"],"filter":"title != ''"}`,
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "subscribe with a filter of a not viewable @collection (list only)",
			method:   http.MethodPost,
			url:      "/api/collections/_webhooks/records",
			body:     `{"name":"w","uri":"https://example.com/hook","topics":["demo2.create"],"filter":"@collection.demo1.id != ''"}`,
			expected: appAll(403, map[string]int{appActorFull: 400}),
			content:  map[string][]string{appActorFull: {`"validation_webhook_filter_forbidden"`}},
		},
		{
			name:     "subscribe to a custom topic",
			method:   http.MethodPost,
			url:      "/api/collections/_webhooks/records",
			body:     `{"name":"w","uri":"https://example.com/hook","topics":["orders.paid"]}`,
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "webhook deliveries list",
			method:   http.MethodGet,
			url:      "/api/webhooks/deliveries",
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "webhook deliveries stats",
			method:   http.MethodGet,
			url:      "/api/webhooks/deliveries/stats",
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		// batch
		{
			name:     "batch create demo2 record",
			method:   http.MethodPost,
			url:      "/api/batch",
			body:     `{"requests":[{"method":"POST","url":"/api/collections/demo2/records","body":{"title":"app"}}]}`,
			expected: appAll(400, map[string]int{appActorFull: 200}),
		},
		// system APIs
		{
			// note: without collections read only the accessible (granted ∩ scopes) collections are listed (same as staff)
			name:     "collections list",
			method:   http.MethodGet,
			url:      "/api/collections",
			expected: appAll(403, map[string]int{appActorFull: 200, appActorScoped: 200, appActorRead: 200}),
			content: map[string][]string{
				appActorFull:   {`"totalItems":25`},
				appActorScoped: {`"totalItems":1`, `"name":"demo2"`},
				appActorRead:   {`"totalItems":1`, `"name":"demo2"`},
			},
		},
		{
			name:     "collection view",
			method:   http.MethodGet,
			url:      "/api/collections/demo3",
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "collection create",
			method:   http.MethodPost,
			url:      "/api/collections",
			body:     `{"name":"app_new","type":"base"}`,
			expected: appAll(403, nil),
		},
		{
			name:     "settings read",
			method:   http.MethodGet,
			url:      "/api/settings",
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "settings write (Owner only)",
			method:   http.MethodPatch,
			url:      "/api/settings",
			body:     `{"meta":{"appName":"app"}}`,
			expected: appAll(403, nil),
		},
		{
			name:     "logs list",
			method:   http.MethodGet,
			url:      "/api/logs",
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "logs truncate (read only grant)",
			method:   http.MethodDelete,
			url:      "/api/logs",
			expected: appAll(403, nil),
		},
		{
			name:     "backups",
			method:   http.MethodGet,
			url:      "/api/backups",
			expected: appAll(403, nil),
		},
		{
			name:     "crons",
			method:   http.MethodGet,
			url:      "/api/crons",
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "webhooks topics",
			method:   http.MethodGet,
			url:      "/api/webhooks/topics",
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "llm providers",
			method:   http.MethodGet,
			url:      "/api/llm/providers",
			expected: appAll(403, map[string]int{appActorFull: 200}),
		},
		{
			name:     "oauth2 clients secret",
			method:   http.MethodPost,
			url:      "/api/oauth2/clients/missing/rotate-secret",
			expected: appAll(403, nil),
		},
		{
			name:     "roles list",
			method:   http.MethodGet,
			url:      "/api/roles",
			expected: appAll(403, nil),
		},
		{
			name:     "roles assignments",
			method:   http.MethodPut,
			url:      "/api/roles/assignments",
			body:     `{"collection":"users","record":"4q1xlclmfloku33","roles":[]}`,
			expected: appAll(403, nil),
		},
		{
			name:     "sql",
			method:   http.MethodPost,
			url:      "/api/sql",
			body:     `{"query":"select 1 as a"}`,
			expected: appAll(403, nil),
		},
		{
			name:     "file token (restricted route)",
			method:   http.MethodPost,
			url:      "/api/files/token",
			expected: appAll(403, nil),
		},
		{
			name:     "applications list",
			method:   http.MethodGet,
			url:      "/api/applications",
			expected: appAll(403, nil),
		},
		{
			name:     "applications manifest import",
			method:   http.MethodPost,
			url:      "/api/applications/manifests",
			body:     `{"handle":"app-made","name":"x","version":"1.0.0"}`,
			expected: appAll(403, nil),
		},
		{
			name:     "applications create",
			method:   http.MethodPost,
			url:      "/api/applications",
			body:     `{"handle":"app-made","name":"x"}`,
			expected: appAll(403, nil),
		},
		{
			name:     "permissions me",
			method:   http.MethodGet,
			url:      "/api/permissions/me",
			expected: appAll(200, nil),
			content: map[string][]string{
				appActorFull:   {`"kind":"application"`, `"owner":false`, `"roles":[]`, `"application":{`, `"handle":"matrix-full"`, `"system:write_webhooks"`, `"webhooks":"write"`},
				appActorScoped: {`"kind":"application"`, `"scopes":["read_demo2"]`, `"handle":"matrix-full"`},
				appActorRead:   {`"kind":"application"`, `"handle":"matrix-read"`, `"scopes":["read_demo2"]`},
				appActorNone:   {`"kind":"application"`, `"handle":"matrix-none"`, `"scopes":[]`},
			},
		},
		// impersonation (token exchange; the app token is the actor token)
		{
			name:            "impersonate",
			method:          http.MethodPost,
			url:             "/oauth2/users/token",
			contentType:     "application/x-www-form-urlencoded",
			body:            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=pb_dashboard&subject_token=oap640cot4yru2s&subject_token_type=urn%3Apocketbase%3Aparams%3Aoauth%3Atoken-type%3Arecord_id&actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
			actorTokenField: "actor_token",
			expected:        appAll(400, nil),
		},
	}

	for _, row := range rows {
		for _, actor := range appActors {
			expectedStatus, ok := row.expected[actor]
			if !ok {
				t.Fatalf("[%s] missing expected status for %q", row.name, actor)
			}

			headers := map[string]string{}
			if row.contentType != "" {
				headers["Content-Type"] = row.contentType
			}

			body := &strings.Builder{}

			scenario := tests.ApiScenario{
				Name:            row.name + " / " + actor,
				Method:          row.method,
				URL:             row.url,
				Headers:         headers,
				ExpectedStatus:  expectedStatus,
				ExpectedContent: row.content[actor],
				BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
					oauth2PrepareIssuer(t, app, "users")

					token := appMatrixSetup(t, app, actor)

					body.WriteString(row.body)
					if row.actorTokenField != "" {
						body.WriteString("&" + row.actorTokenField + "=" + url.QueryEscape(token))
					} else {
						headers["Authorization"] = token
					}
				},
			}

			if row.body != "" || row.actorTokenField != "" {
				scenario.Body = &lazyReader{builder: body}
			}

			if len(row.content[actor]) == 0 {
				switch {
				case expectedStatus == 204:
					// empty body
				case expectedStatus >= 400 && row.actorTokenField != "":
					scenario.ExpectedContent = []string{`"error"`}
				case expectedStatus >= 400:
					scenario.ExpectedContent = []string{`"status"`}
				default:
					scenario.NotExpectedContent = []string{`"status":4`, `"status":5`}
				}
			}

			scenario.Test(t)
		}
	}
}

// -------------------------------------------------------------------
// Token endpoint (client_credentials)
// -------------------------------------------------------------------

func TestApplicationsClientCredentials(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")

	installed := appInstall(t, app, "cc-app", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
		System:      map[string]string{core.PermissionResourceLogs: core.PermissionLevelRead},
	})
	clientId := installed.Client.ClientId()
	secret := installed.ClientSecret

	tokenHookCalls := 0
	app.OnOAuth2TokenRequest().BindFunc(func(e *core.OAuth2TokenRequestEvent) error {
		tokenHookCalls++
		if e.GrantType != "client_credentials" || e.Record.Id != installed.Installation.Id || e.Client.Id != installed.Client.Id {
			t.Errorf("Unexpected OnOAuth2TokenRequest event data %q %q", e.GrantType, e.Record.Id)
		}
		return e.Next()
	})

	t.Run("basic auth, default scopes = full grant", func(t *testing.T) {
		status, data := appTokenRequest(t, app, appTokenURL, url.Values{"grant_type": {"client_credentials"}}, map[string]string{"Authorization": basicAuth(clientId, secret)})
		if status != 200 {
			t.Fatalf("Expected 200, got %d %v", status, data)
		}

		if data["scope"] != "read_demo2 system:read_logs" || data["token_type"] != "Bearer" || data["expires_in"] != float64(core.ApplicationInstallationTokenDuration) {
			t.Fatalf("Unexpected token response %v", data)
		}
		if _, ok := data["refresh_token"]; ok {
			t.Fatal("Unexpected refresh_token")
		}
		if _, ok := data["id_token"]; ok {
			t.Fatal("Unexpected id_token")
		}

		// a root-less active client_credentials session without refresh token
		claims := decodeTestJWT(t, data["access_token"].(string))
		session, err := app.FindAuthSessionById(claims["sid"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if session.Parent() != "" || session.HasRefreshToken() || !session.HasAuthMethod(core.AuthSessionMethodClientCredentials) || !session.IsActive() {
			t.Fatalf("Unexpected session %v", session.PublicExport())
		}
		if claims["cid"] != clientId || claims["id"] != installed.Installation.Id {
			t.Fatalf("Unexpected claims %v", claims)
		}
	})

	t.Run("body auth with narrowed scope", func(t *testing.T) {
		status, data := appTokenRequest(t, app, appTokenURL, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {clientId},
			"client_secret": {secret},
			"scope":         {"read_demo2"},
		}, nil)
		if status != 200 || data["scope"] != "read_demo2" {
			t.Fatalf("Expected 200 read_demo2, got %d %v", status, data)
		}
	})

	failures := []struct {
		name     string
		rawURL   string
		form     url.Values
		headers  map[string]string
		status   int
		expected string
	}{
		{
			"credentials in the URL query are ignored",
			appTokenURL + "?client_id=" + clientId + "&client_secret=" + secret,
			url.Values{"grant_type": {"client_credentials"}},
			nil,
			401, "invalid_client",
		},
		{
			"grant_type in the URL query is ignored",
			appTokenURL + "?grant_type=client_credentials",
			url.Values{"client_id": {clientId}, "client_secret": {secret}},
			nil,
			400, "invalid_request",
		},
		{
			"invalid secret",
			appTokenURL,
			url.Values{"grant_type": {"client_credentials"}},
			map[string]string{"Authorization": basicAuth(clientId, "invalid")},
			401, "invalid_client",
		},
		{
			"missing secret",
			appTokenURL,
			url.Values{"grant_type": {"client_credentials"}, "client_id": {clientId}},
			nil,
			401, "invalid_client",
		},
		{
			"scope outside of the grant",
			appTokenURL,
			url.Values{"grant_type": {"client_credentials"}, "scope": {"read_demo2 write_demo2"}},
			map[string]string{"Authorization": basicAuth(clientId, secret)},
			400, "invalid_scope",
		},
		{
			"openid scope",
			appTokenURL,
			url.Values{"grant_type": {"client_credentials"}, "scope": {"openid"}},
			map[string]string{"Authorization": basicAuth(clientId, secret)},
			400, "invalid_scope",
		},
		{
			"not granted system scope",
			appTokenURL,
			url.Values{"grant_type": {"client_credentials"}, "scope": {"system:write_logs"}},
			map[string]string{"Authorization": basicAuth(clientId, secret)},
			400, "invalid_scope",
		},
		{
			"refresh_token grant with the managed client",
			appTokenURL,
			url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"abc"}},
			map[string]string{"Authorization": basicAuth(clientId, secret)},
			400, "unauthorized_client",
		},
		{
			"authorization_code grant with the managed client",
			appTokenURL,
			url.Values{"grant_type": {"authorization_code"}, "code": {"abc"}, "redirect_uri": {"https://example.com"}},
			map[string]string{"Authorization": basicAuth(clientId, secret)},
			400, "unauthorized_client",
		},
		{
			// note: the managed clients exchange only the extension launch tokens (A3)
			"impersonation token exchange with the managed client",
			appTokenURL,
			url.Values{
				"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
				"subject_token":      {"x"},
				"subject_token_type": {"urn:pocketbase:params:oauth:token-type:record_id"},
			},
			map[string]string{"Authorization": basicAuth(clientId, secret)},
			400, "unauthorized_client",
		},
		{
			"managed client on another issuer",
			"/oauth2/users/token",
			url.Values{"grant_type": {"client_credentials"}},
			map[string]string{"Authorization": basicAuth(clientId, secret)},
			401, "invalid_client",
		},
	}

	for _, s := range failures {
		t.Run(s.name, func(t *testing.T) {
			status, data := appTokenRequest(t, app, s.rawURL, s.form, s.headers)
			if status != s.status || data["error"] != s.expected {
				t.Fatalf("Expected %d %s, got %d %v", s.status, s.expected, status, data)
			}
		})
	}

	if tokenHookCalls != 2 {
		t.Fatalf("Expected 2 OnOAuth2TokenRequest calls, got %d", tokenHookCalls)
	}
}

func decodeTestJWT(t testing.TB, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("Invalid JWT %q", token)
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]any{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}

	return claims
}

// appStaffSetup creates staff members with applications write and a partial grant:
//   - installer@example.com: applications write + demo2 list/view
//   - appreader@example.com: applications read + demo2 list/view
func appStaffSetup(t testing.TB, app core.App) {
	t.Helper()

	demo2, err := app.FindCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}

	installer, err := tests.CreateRole(app, "installer", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
		System:      map[string]string{core.PermissionResourceApplications: core.PermissionLevelWrite},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tests.CreateStaff(app, "installer@example.com", installer.Id); err != nil {
		t.Fatal(err)
	}

	reader, err := tests.CreateRole(app, "app reader", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
		System:      map[string]string{core.PermissionResourceApplications: core.PermissionLevelRead},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tests.CreateStaff(app, "appreader@example.com", reader.Id); err != nil {
		t.Fatal(err)
	}
}

func appFindInstallation(t testing.TB, app core.App, handle string) *core.ApplicationInstallation {
	t.Helper()

	application, err := app.FindApplicationByHandle(handle)
	if err != nil {
		t.Fatal(err)
	}

	installation, err := app.FindApplicationInstallationByApplication(application.Id)
	if err != nil {
		t.Fatal(err)
	}

	return installation
}

func TestApplicationsApi(t *testing.T) {
	t.Parallel()

	owner := tests.AuthToken(core.CollectionNameSuperusers, "test@example.com")
	installer := tests.AuthToken(core.CollectionNameSuperusers, "installer@example.com")
	reader := tests.AuthToken(core.CollectionNameSuperusers, "appreader@example.com")
	customer := tests.AuthToken("users", "test@example.com")

	demo2Grant := func(app core.App, actions ...string) core.Permissions {
		demo2, _ := app.FindCollectionByNameOrId("demo2")
		return core.Permissions{Collections: map[string][]string{demo2.Id: actions}}
	}

	setup := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		appStaffSetup(t, app)
	}

	installedSetup := func(grant func(app core.App) core.Permissions) func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		return func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			appStaffSetup(t, app)
			appInstall(t, app, "api-app", grant(app))
		}
	}

	notInstalledSetup := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		appStaffSetup(t, app)
		manifest, _ := core.ParseApplicationManifest([]byte(`{"handle":"api-app","name":"API app","version":"1.0.0"}`), core.ApplicationManifestFormatJSON)
		if _, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, ""); err != nil {
			t.Fatal(err)
		}
	}

	scenarios := []tests.ApiScenario{
		// list
		{
			Name:            "list as guest",
			Method:          http.MethodGet,
			URL:             "/api/applications",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"status":401`},
		},
		{
			Name:            "list as customer",
			Method:          http.MethodGet,
			URL:             "/api/applications",
			Headers:         map[string]string{"Authorization": customer},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
		},
		{
			Name:           "list as staff with applications read",
			Method:         http.MethodGet,
			URL:            "/api/applications",
			Headers:        map[string]string{"Authorization": reader},
			BeforeTestFunc: installedSetup(func(app core.App) core.Permissions { return demo2Grant(app, "list") }),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"handle":"api-app"`,
				`"installation":{`,
				`"clientId":"pbapp_`,
				`"scopes":["read_demo2"]`,
				`"tokenURL":"`,
				`"applicationGrantable":true`,
				`"latestVersion":{`,
			},
			NotExpectedContent: []string{`"clientSecret"`, `clientSecretHash`, `tokenKey`, `"password"`},
		},
		// create custom application (form)
		{
			Name:            "create as staff with applications read",
			Method:          http.MethodPost,
			URL:             "/api/applications",
			Body:            strings.NewReader(`{"handle":"new-app","name":"New app"}`),
			Headers:         map[string]string{"Authorization": reader},
			BeforeTestFunc:  setup,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
		},
		{
			Name:           "create with invalid data",
			Method:         http.MethodPost,
			URL:            "/api/applications",
			Body:           strings.NewReader(`{"handle":"New App","name":"","applicationURL":"javascript:x"}`),
			Headers:        map[string]string{"Authorization": installer},
			BeforeTestFunc: setup,
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"handle":{`,
				`"name":{`,
				`"applicationURL":{`,
			},
		},
		{
			Name:            "create with existing handle",
			Method:          http.MethodPost,
			URL:             "/api/applications",
			Body:            strings.NewReader(`{"handle":"api-app","name":"Dup"}`),
			Headers:         map[string]string{"Authorization": installer},
			BeforeTestFunc:  notInstalledSetup,
			ExpectedStatus:  400,
			ExpectedContent: []string{`"handle":{"code":"validation_handle_exists"`},
		},
		{
			Name:           "create as installer",
			Method:         http.MethodPost,
			URL:            "/api/applications",
			Body:           strings.NewReader(`{"handle":"new-app","name":"New app","description":"d","applicationURL":"https://new.example.com","developerName":"ACME"}`),
			Headers:        map[string]string{"Authorization": installer},
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"created":true`,
				`"handle":"new-app"`,
				`"version":"1.0.0"`,
				`"sourceFormat":"json"`,
				`"installation":null`,
			},
			ExpectedEvents: map[string]int{
				"OnApplicationManifestImportRequest": 1,
				"OnModelCreate":                      2,
				"OnModelUpdate":                      1,
			},
		},
		// manifests
		{
			Name:            "manifest import with unsupported content type",
			Method:          http.MethodPost,
			URL:             "/api/applications/manifests",
			Body:            strings.NewReader(`handle: x`),
			Headers:         map[string]string{"Authorization": owner, "Content-Type": "application/yaml"},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"status":400`},
		},
		{
			Name:   "manifest import (toml)",
			Method: http.MethodPost,
			URL:    "/api/applications/manifests",
			Body: strings.NewReader(`
				handle = "toml-app"
				name = "TOML app"
				version = "0.1.0"
				[access]
				scopes = ["read_demo2"]
			`),
			Headers:        map[string]string{"Authorization": owner, "Content-Type": "application/toml"},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"created":true`,
				`"handle":"toml-app"`,
				`"sourceFormat":"toml"`,
				`"scopes":["read_demo2"]`,
				`"manifestDigest":"`,
			},
			ExpectedEvents: map[string]int{"OnApplicationManifestImportRequest": 1},
		},
		{
			Name:            "manifest import (json) with unknown keys",
			Method:          http.MethodPost,
			URL:             "/api/applications/manifests",
			Body:            strings.NewReader(`{"handle":"json-app","name":"x","version":"1.0.0","launch_url":"https://x.com","developer":{"email":"x"}}`),
			Headers:         map[string]string{"Authorization": owner, "Content-Type": "application/json"},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"launch_url":{"code":"validation_unknown_manifest_key"`, `"developer.email":{`, `Unknown manifest key developer.email`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "manifest import with invalid handle",
			Method:          http.MethodPost,
			URL:             "/api/applications/manifests",
			Body:            strings.NewReader(`{"handle":"Bad_Handle","name":"x","version":"1.0.0"}`),
			Headers:         map[string]string{"Authorization": owner, "Content-Type": "application/json"},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"handle":{`},
		},
		{
			Name:            "manifest import of an existing version with a different manifest (immutable)",
			Method:          http.MethodPost,
			URL:             "/api/applications/manifests",
			Body:            strings.NewReader(`{"handle":"api-app","name":"API app changed","version":"1.0.0"}`),
			Headers:         map[string]string{"Authorization": owner, "Content-Type": "application/json"},
			BeforeTestFunc:  notInstalledSetup,
			ExpectedStatus:  400,
			ExpectedContent: []string{`"version":{"code":"validation_application_version_exists"`},
		},
		{
			Name:            "manifest import of an existing version with the same manifest (idempotent)",
			Method:          http.MethodPost,
			URL:             "/api/applications/manifests",
			Body:            strings.NewReader(`{"handle":"api-app","name":"API app","version":"1.0.0"}`),
			Headers:         map[string]string{"Authorization": owner, "Content-Type": "application/json"},
			BeforeTestFunc:  notInstalledSetup,
			ExpectedStatus:  200,
			ExpectedContent: []string{`"unchanged":true`, `"created":false`},
		},
		{
			Name:            "manifest import of a new version",
			Method:          http.MethodPost,
			URL:             "/api/applications/manifests",
			Body:            strings.NewReader(`{"handle":"api-app","name":"API app v2","version":"2.0.0"}`),
			Headers:         map[string]string{"Authorization": owner, "Content-Type": "application/json; charset=utf-8"},
			BeforeTestFunc:  notInstalledSetup,
			ExpectedStatus:  200,
			ExpectedContent: []string{`"created":false`, `"unchanged":false`, `"name":"API app v2"`, `"latestVersion":{"id":`, `"version":"2.0.0"`},
		},
		// install
		{
			Name:            "install as staff with applications read",
			Method:          http.MethodPost,
			URL:             "/api/applications/{id}/install",
			Headers:         map[string]string{"Authorization": reader},
			Body:            strings.NewReader(`{"permissions":{}}`),
			BeforeTestFunc:  notInstalledSetup,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
		},
		{
			Name:            "install with a grant the installer doesn't hold",
			Method:          http.MethodPost,
			URL:             "/api/applications/{id}/install",
			Headers:         map[string]string{"Authorization": installer},
			Body:            strings.NewReader(`{"permissions":{"collections":{"*":["list"]}}}`),
			BeforeTestFunc:  notInstalledSetup,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
			ExpectedEvents:  map[string]int{"OnApplicationInstallRequest": 1, "OnModelCreate": 0},
		},
		{
			Name:            "install with an Owner only level",
			Method:          http.MethodPost,
			URL:             "/api/applications/{id}/install",
			Headers:         map[string]string{"Authorization": owner},
			Body:            strings.NewReader(`{"permissions":{"system":{"settings":"write"}}}`),
			BeforeTestFunc:  notInstalledSetup,
			ExpectedStatus:  400,
			ExpectedContent: []string{`"permissions":{`},
		},
		{
			Name:            "install with a not application grantable resource",
			Method:          http.MethodPost,
			URL:             "/api/applications/{id}/install",
			Headers:         map[string]string{"Authorization": owner},
			Body:            strings.NewReader(`{"permissions":{"system":{"staff":"read"}}}`),
			BeforeTestFunc:  notInstalledSetup,
			ExpectedStatus:  400,
			ExpectedContent: []string{`"permissions":{`, `validation_not_application_grantable`},
		},
		{
			Name:            "install of an already installed application",
			Method:          http.MethodPost,
			URL:             "/api/applications/{id}/install",
			Headers:         map[string]string{"Authorization": owner},
			Body:            strings.NewReader(`{"permissions":{}}`),
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return core.Permissions{} }),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"status":400`},
		},
		{
			Name:           "install with a covered grant",
			Method:         http.MethodPost,
			URL:            "/api/applications/{id}/install",
			Headers:        map[string]string{"Authorization": installer},
			BeforeTestFunc: notInstalledSetup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"clientId":"pbapp_`,
				`"clientSecret":"`,
				`"tokenURL":"`,
				`/oauth2/_applicationInstallations/token"`,
				`"scopes":["read_demo2"]`,
			},
			ExpectedEvents: map[string]int{"OnApplicationInstallRequest": 1},
		},
		// installation update
		{
			Name:            "narrow the grant of a not covered installation",
			Method:          http.MethodPatch,
			URL:             "/api/applications/installations/{installation}",
			Headers:         map[string]string{"Authorization": installer},
			Body:            strings.NewReader(`{"permissions":{}}`),
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return demo2Grant(app, "list", "delete") }),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
		},
		{
			Name:            "change the installation to a version of another application",
			Method:          http.MethodPatch,
			URL:             "/api/applications/installations/{installation}",
			Headers:         map[string]string{"Authorization": owner},
			Body:            strings.NewReader(`{"versionRef":"missing"}`),
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return core.Permissions{} }),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"versionRef":{`},
		},
		{
			Name:            "narrow a covered grant",
			Method:          http.MethodPatch,
			URL:             "/api/applications/installations/{installation}",
			Headers:         map[string]string{"Authorization": installer},
			Body:            strings.NewReader(`{"permissions":{"collections":{}}}`),
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return demo2Grant(app, "list", "view") }),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"scopes":[]`},
		},
		// rotate
		{
			Name:            "rotate the secret of a not covered installation",
			Method:          http.MethodPost,
			URL:             "/api/applications/installations/{installation}/rotate-secret",
			Headers:         map[string]string{"Authorization": installer},
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return demo2Grant(app, "create") }),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
		},
		{
			Name:            "rotate the secret",
			Method:          http.MethodPost,
			URL:             "/api/applications/installations/{installation}/rotate-secret",
			Headers:         map[string]string{"Authorization": installer},
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return demo2Grant(app, "list") }),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"clientSecret":"`, `"secretRotatedAt":"20`},
		},
		// uninstall
		{
			Name:            "uninstall a not covered installation",
			Method:          http.MethodDelete,
			URL:             "/api/applications/installations/{installation}",
			Headers:         map[string]string{"Authorization": installer},
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return demo2Grant(app, "update") }),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
			ExpectedEvents:  map[string]int{"OnApplicationUninstallRequest": 0},
		},
		{
			Name:           "uninstall",
			Method:         http.MethodDelete,
			URL:            "/api/applications/installations/{installation}",
			Headers:        map[string]string{"Authorization": installer},
			BeforeTestFunc: installedSetup(func(app core.App) core.Permissions { return demo2Grant(app, "list") }),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{"OnApplicationUninstallRequest": 1},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				application, _ := app.FindApplicationByHandle("api-app")
				if _, err := app.FindApplicationInstallationByApplication(application.Id); err == nil {
					t.Fatal("Expected the installation to be deleted")
				}
				clients, _ := app.FindAllRecords(core.CollectionNameOAuth2Clients)
				for _, c := range clients {
					if c.GetString("applicationInstallationRef") != "" {
						t.Fatal("Expected the managed client to be deleted")
					}
				}
			},
		},
		// delete application
		{
			Name:            "delete an installed application",
			Method:          http.MethodDelete,
			URL:             "/api/applications/{id}",
			Headers:         map[string]string{"Authorization": owner},
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return core.Permissions{} }),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"status":400`},
		},
		{
			Name:           "delete a not installed application",
			Method:         http.MethodDelete,
			URL:            "/api/applications/{id}",
			Headers:        map[string]string{"Authorization": installer},
			BeforeTestFunc: notInstalledSetup,
			ExpectedStatus: 204,
		},
		// records API of the applications collections
		{
			Name:            "records API create _applications as non-Owner (dedicated endpoints only)",
			Method:          http.MethodPost,
			URL:             "/api/collections/_applications/records",
			Headers:         map[string]string{"Authorization": installer},
			Body:            strings.NewReader(`{"handle":"raw-app","name":"x","source":"custom"}`),
			BeforeTestFunc:  setup,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
		},
		{
			Name:            "records API update _applicationInstallations as non-Owner",
			Method:          http.MethodPatch,
			URL:             "/api/collections/_applicationInstallations/records/{installation}",
			Headers:         map[string]string{"Authorization": installer},
			Body:            strings.NewReader(`{"permissions":{"collections":{"*":["list"]}}}`),
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return core.Permissions{} }),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
		},
		{
			Name:            "records API delete of a not covered installation",
			Method:          http.MethodDelete,
			URL:             "/api/collections/_applicationInstallations/records/{installation}",
			Headers:         map[string]string{"Authorization": installer},
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return demo2Grant(app, "delete") }),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
		},
		{
			Name:            "records API delete of an installed application with a not covered grant",
			Method:          http.MethodDelete,
			URL:             "/api/collections/_applications/records/{id}",
			Headers:         map[string]string{"Authorization": installer},
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return demo2Grant(app, "delete") }),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
		},
		{
			Name:               "records API list installations hides the secret fields",
			Method:             http.MethodGet,
			URL:                "/api/collections/_applicationInstallations/records",
			Headers:            map[string]string{"Authorization": reader},
			BeforeTestFunc:     installedSetup(func(app core.App) core.Permissions { return core.Permissions{} }),
			ExpectedStatus:     200,
			ExpectedContent:    []string{`"totalItems":1`, `"permissions":{`},
			NotExpectedContent: []string{`"tokenKey"`, `"password"`},
		},
		{
			Name:            "records API update of a managed client (even by an Owner)",
			Method:          http.MethodPatch,
			URL:             "/api/collections/_oauth2Clients/records/{client}",
			Headers:         map[string]string{"Authorization": owner},
			Body:            strings.NewReader(`{"redirectURIs":["https://evil.example.com"],"grantTypes":["authorization_code"]}`),
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return core.Permissions{} }),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"status":400`},
		},
		{
			Name:            "records API delete of a managed client (even by an Owner)",
			Method:          http.MethodDelete,
			URL:             "/api/collections/_oauth2Clients/records/{client}",
			Headers:         map[string]string{"Authorization": owner},
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return core.Permissions{} }),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"status":400`},
		},
		{
			Name:            "role assignment to an installation (even by an Owner)",
			Method:          http.MethodPut,
			URL:             "/api/roles/assignments",
			Headers:         map[string]string{"Authorization": owner},
			Body:            strings.NewReader(`{"collection":"_applicationInstallations","record":"{installation}","roles":["pbrolecustomer0"]}`),
			BeforeTestFunc:  installedSetup(func(app core.App) core.Permissions { return core.Permissions{} }),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"status":400`},
		},
	}

	for i := range scenarios {
		s := &scenarios[i]

		// resolve the dynamic {id}, {installation} and {client} placeholders after the setup
		// (the scenario URL is read after the BeforeTestFunc)
		originalBefore := s.BeforeTestFunc
		originalURL := s.URL
		originalBody := s.Body
		bodyBuilder := &strings.Builder{}
		s.BeforeTestFunc = func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			if originalBefore != nil {
				originalBefore(t, app, e)
			}

			pairs := []string{}
			if a, err := app.FindApplicationByHandle("api-app"); err == nil {
				pairs = append(pairs, "{id}", a.Id)
				if i, err := app.FindApplicationInstallationByApplication(a.Id); err == nil {
					pairs = append(pairs, "{installation}", i.Id)
					if c, err := app.FindApplicationInstallationClient(i.Id); err == nil {
						pairs = append(pairs, "{client}", c.Id)
					}
				}
			}
			replacer := strings.NewReplacer(pairs...)

			s.URL = replacer.Replace(originalURL)

			if originalBody != nil {
				raw, _ := io.ReadAll(originalBody)
				bodyBuilder.WriteString(replacer.Replace(string(raw)))
			}
		}
		if originalBody != nil {
			s.Body = &lazyReader{builder: bodyBuilder}
		}

		// the install grant references the demo2 collection id
		if s.Name == "install with a covered grant" {
			s.Body = &lazyReader{builder: bodyBuilder}
			before := s.BeforeTestFunc
			s.BeforeTestFunc = func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				before(t, app, e)
				demo2, _ := app.FindCollectionByNameOrId("demo2")
				bodyBuilder.WriteString(`{"permissions":{"collections":{"` + demo2.Id + `":["list","view"]}}}`)
			}
		}

		s.Test(t)
	}
}

func TestApplicationsAttacks(t *testing.T) {
	t.Parallel()

	newApp := func(t testing.TB) *tests.TestApp {
		app, err := tests.NewTestApp()
		if err != nil {
			t.Fatal(err)
		}
		return app
	}

	demo2Grant := func(app core.App, actions ...string) core.Permissions {
		demo2, _ := app.FindCollectionByNameOrId("demo2")
		return core.Permissions{Collections: map[string][]string{demo2.Id: actions}}
	}

	t.Run("grant narrowing applies live to the already issued tokens", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		installed := appInstall(t, app, "live-app", demo2Grant(app, "list", "view", "create"))
		token := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

		if status, body := appApi(t, app, http.MethodPost, "/api/collections/demo1/records", token, `{}`); status != 403 {
			t.Fatalf("Expected demo1 403, got %d %s", status, body)
		}
		if status, body := appApi(t, app, http.MethodPost, "/api/collections/demo2/records", token, `{"title":"ab"}`); status != 200 {
			t.Fatalf("Expected create 200, got %d %s", status, body)
		}

		installation, _ := app.FindApplicationInstallationById(installed.Installation.Id)
		installation.SetPermissions(demo2Grant(app, "list"))
		if err := app.Save(installation); err != nil {
			t.Fatal(err)
		}

		if status, body := appApi(t, app, http.MethodPost, "/api/collections/demo2/records", token, `{"title":"bc"}`); status != 403 {
			t.Fatalf("Expected create 403 after narrowing, got %d %s", status, body)
		}
		if status, body := appApi(t, app, http.MethodGet, "/api/collections/demo2/records", token, ""); status != 200 {
			t.Fatalf("Expected list 200, got %d %s", status, body)
		}

		// widening doesn't extend the already issued token scopes
		installation.SetPermissions(demo2Grant(app, "list", "view", "create", "delete"))
		if err := app.Save(installation); err != nil {
			t.Fatal(err)
		}
		if status, _ := appApi(t, app, http.MethodDelete, "/api/collections/demo2/records/0yxhwia2amd8gec", token, ""); status != 204 {
			// write_demo2 was part of the original token scopes => delete is allowed with the new grant
			t.Fatalf("Expected delete 204 (write_demo2 scope + new grant), got %d", status)
		}
	})

	t.Run("rotate secret invalidates the old token and secret", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		installed := appInstall(t, app, "rotate-app", demo2Grant(app, "list"))
		token := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

		if status, _ := appApi(t, app, http.MethodGet, "/api/permissions/me", token, ""); status != 200 {
			t.Fatalf("Expected 200, got %d", status)
		}

		installation, _ := app.FindApplicationInstallationById(installed.Installation.Id)
		_, newSecret, err := app.RotateApplicationInstallationSecret(installation)
		if err != nil {
			t.Fatal(err)
		}

		if status, _ := appApi(t, app, http.MethodGet, "/api/permissions/me", token, ""); status != 401 {
			t.Fatalf("Expected the old token to be rejected, got %d", status)
		}

		status, data := appTokenRequest(t, app, appTokenURL, url.Values{"grant_type": {"client_credentials"}}, map[string]string{"Authorization": basicAuth(installed.Client.ClientId(), installed.ClientSecret)})
		if status != 401 || data["error"] != "invalid_client" {
			t.Fatalf("Expected the old secret to be rejected, got %d %v", status, data)
		}

		newToken := appToken(t, app, installed.Client.ClientId(), newSecret, "")
		if status, _ := appApi(t, app, http.MethodGet, "/api/permissions/me", newToken, ""); status != 200 {
			t.Fatalf("Expected the new token to work, got %d", status)
		}
	})

	t.Run("uninstall invalidates the token and the credentials", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		installed := appInstall(t, app, "uninstall-app", demo2Grant(app, "list"))
		token := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

		status, body := appApi(t, app, http.MethodDelete, "/api/applications/installations/"+installed.Installation.Id, mustOwnerToken(t, app), "")
		if status != 204 {
			t.Fatalf("Expected uninstall 204, got %d %s", status, body)
		}

		if status, _ := appApi(t, app, http.MethodGet, "/api/permissions/me", token, ""); status != 401 {
			t.Fatalf("Expected the token to be rejected, got %d", status)
		}

		status, data := appTokenRequest(t, app, appTokenURL, url.Values{"grant_type": {"client_credentials"}}, map[string]string{"Authorization": basicAuth(installed.Client.ClientId(), installed.ClientSecret)})
		if status != 401 || data["error"] != "invalid_client" {
			t.Fatalf("Expected invalid_client, got %d %v", status, data)
		}
	})

	t.Run("disabled managed client rejects the tokens and the credentials", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		installed := appInstall(t, app, "disabled-app", demo2Grant(app, "list"))
		token := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

		// note: the managed clients are read-only so this simulates a raw db change
		if _, err := app.DB().NewQuery("UPDATE {{_oauth2Clients}} SET [[disabled]] = TRUE WHERE id = {:id}").
			Bind(map[string]any{"id": installed.Client.Id}).Execute(); err != nil {
			t.Fatal(err)
		}

		if status, _ := appApi(t, app, http.MethodGet, "/api/permissions/me", token, ""); status != 401 {
			t.Fatalf("Expected the token to be rejected, got %d", status)
		}

		status, _ := appTokenRequest(t, app, appTokenURL, url.Values{"grant_type": {"client_credentials"}}, map[string]string{"Authorization": basicAuth(installed.Client.ClientId(), installed.ClientSecret)})
		if status != 401 {
			t.Fatalf("Expected invalid_client, got %d", status)
		}
	})

	t.Run("non-managed client client_credentials", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		oauth2PrepareIssuer(t, app, "users")
		oauth2StubClient(t, app, "users", "conf_cc", oauth2Confidential)

		status, data := appTokenRequest(t, app, "/oauth2/users/token", url.Values{"grant_type": {"client_credentials"}}, map[string]string{"Authorization": basicAuth("conf_cc", "secret_conf_cc")})
		if status != 400 || data["error"] != "unauthorized_client" {
			t.Fatalf("Expected unauthorized_client, got %d %v", status, data)
		}

		// a regular client can't get the client_credentials grant
		client := oauth2FindClient(t, app, "conf_cc")
		client.SetGrantTypes([]string{core.OAuth2GrantTypeClientCredentials})
		if err := app.Save(client); err == nil {
			t.Fatal("Expected the client_credentials grant to be rejected for a regular client")
		}
	})

	t.Run("installations issuer interactive endpoints are not available", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		appInstall(t, app, "issuer-app", core.Permissions{})

		base := "/oauth2/" + core.CollectionNameApplicationInstallations
		for _, path := range []string{
			"/authorize?response_type=code&client_id=x",
			"/login",
			"/login/mfa",
			"/signup",
			"/consent",
			"/password-reset",
			"/verify-email",
			"/email-change/confirm",
			"/userinfo",
			"/logout",
		} {
			status, body := appApi(t, app, http.MethodGet, base+path, "", "")
			if status != 404 {
				t.Fatalf("[%s] Expected 404, got %d %s", path, status, body)
			}
		}

		status, body := appApi(t, app, http.MethodGet, base+"/.well-known/openid-configuration", "", "")
		if status != 200 || !strings.Contains(body, `"grant_types_supported":["client_credentials","urn:ietf:params:oauth:grant-type:token-exchange"]`) {
			t.Fatalf("Expected the client_credentials and token exchange (launch tokens) only discovery document, got %d %s", status, body)
		}
	})

	t.Run("secret fields and account takeover fields", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		users, _ := app.FindCollectionByNameOrId("users")
		installed := appInstall(t, app, "secrets-app", core.Permissions{
			Collections: map[string][]string{users.Id: core.PermissionCollectionActions},
		})
		token := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

		status, body := appApi(t, app, http.MethodGet, "/api/collections/users/records", token, "")
		if status != 200 || strings.Contains(body, `"tokenKey"`) || strings.Contains(body, `"password"`) || !strings.Contains(body, `"email":"test@example.com"`) {
			t.Fatalf("Expected the users list without secret fields, got %d %s", status, body)
		}

		if status, _ := appApi(t, app, http.MethodGet, "/api/collections/users/records?filter="+url.QueryEscape("tokenKey!=''"), token, ""); status != 400 {
			t.Fatalf("Expected the tokenKey filter to be rejected, got %d", status)
		}

		for _, body := range []string{
			`{"password":"1234567890abc","passwordConfirm":"1234567890abc"}`,
			`{"email":"taken@example.com"}`,
			`{"verified":true}`,
		} {
			if status, res := appApi(t, app, http.MethodPatch, "/api/collections/users/records/4q1xlclmfloku33", token, body); status != 403 {
				t.Fatalf("Expected %s to be rejected, got %d %s", body, status, res)
			}
		}

		if status, _ := appApi(t, app, http.MethodPatch, "/api/collections/users/records/4q1xlclmfloku33", token, `{"name":"by app"}`); status != 200 {
			t.Fatalf("Expected the regular field update to be allowed, got %d", status)
		}
	})

	t.Run("system collection webhook topics are Owner only", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		installed := appInstall(t, app, "webhooks-app", core.Permissions{
			System: map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
		})
		token := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

		status, body := appApi(t, app, http.MethodPost, "/api/collections/_webhooks/records", token,
			`{"name":"x","url":"https://example.com/hook","topics":["_superusers.create"],"active":true}`)
		if status != 403 {
			t.Fatalf("Expected the system topic subscription to be rejected, got %d %s", status, body)
		}
	})

	t.Run("realtime uses the same authorization", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		if _, err := apis.NewRouter(app); err != nil {
			t.Fatal(err)
		}

		readApp := appInstall(t, app, "rt-read", demo2Grant(app, "list", "view"))
		noneApp := appInstall(t, app, "rt-none", core.Permissions{})

		readRecord, _ := app.FindRecordById(core.CollectionNameApplicationInstallations, readApp.Installation.Id)
		noneRecord, _ := app.FindRecordById(core.CollectionNameApplicationInstallations, noneApp.Installation.Id)

		type sub struct {
			name          string
			auth          *core.Record
			oauth2        core.RequestInfoOAuth2
			topic         string
			expectMessage bool
		}

		subs := []*sub{
			{"granted app", readRecord, core.RequestInfoOAuth2{ClientId: readApp.Client.ClientId(), Scopes: []string{"read_demo2"}}, "demo2/*", true},
			{"granted app without scope", readRecord, core.RequestInfoOAuth2{ClientId: readApp.Client.ClientId(), Scopes: []string{}}, "demo2/*", false},
			{"not granted app", noneRecord, core.RequestInfoOAuth2{ClientId: noneApp.Client.ClientId(), Scopes: []string{}}, "demo2/*", false},
			{"system collection topic", readRecord, core.RequestInfoOAuth2{ClientId: readApp.Client.ClientId(), Scopes: []string{"read_demo2"}}, core.CollectionNameSuperusers + "/*", false},
		}

		clients := make([]subscriptions.Client, len(subs))
		for i, s := range subs {
			c := subscriptions.NewDefaultClient()
			c.Set(apis.RealtimeClientAuthKey, s.auth)
			c.Set(apis.RealtimeClientOAuth2Key, s.oauth2)
			c.Subscribe(s.topic)
			app.SubscriptionsBroker().Register(c)
			clients[i] = c
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

		demo2, _ := app.FindCollectionByNameOrId("demo2")
		record := core.NewRecord(demo2)
		record.Set("title", "rt")
		if err := app.Save(record); err != nil {
			t.Fatal(err)
		}

		superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
		su := core.NewRecord(superusers)
		su.SetEmail("rt@example.com")
		su.SetPassword("1234567890")
		if err := app.Save(su); err != nil {
			t.Fatal(err)
		}

		wg.Wait()

		for i, s := range subs {
			if got := messages[i] != ""; got != s.expectMessage {
				t.Errorf("[%s] Expected message %v, got %q", s.name, s.expectMessage, messages[i])
			}
		}
	})

	t.Run("concurrent install via the API", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		manifest, _ := core.ParseApplicationManifest([]byte(`{"handle":"race-api","name":"x","version":"1.0.0"}`), core.ApplicationManifestFormatJSON)
		imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
		if err != nil {
			t.Fatal(err)
		}

		token := mustOwnerToken(t, app)

		var wg sync.WaitGroup
		var mu sync.Mutex
		statuses := map[int]int{}
		for range 5 {
			wg.Go(func() {
				status, _ := appApi(t, app, http.MethodPost, "/api/applications/"+imported.Application.Id+"/install", token, `{"permissions":{}}`)
				mu.Lock()
				statuses[status]++
				mu.Unlock()
			})
		}
		wg.Wait()

		if statuses[200] != 1 || statuses[400] != 4 {
			t.Fatalf("Expected exactly one successful install, got %v", statuses)
		}
	})

	t.Run("introspection and revocation by the managed client", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		installed := appInstall(t, app, "revoke-app", demo2Grant(app, "list"))
		token := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")
		auth := map[string]string{"Authorization": basicAuth(installed.Client.ClientId(), installed.ClientSecret)}
		base := "/oauth2/" + core.CollectionNameApplicationInstallations

		status, data := appTokenRequest(t, app, base+"/introspect", url.Values{"token": {token}}, auth)
		if status != 200 || data["active"] != true || data["client_id"] != installed.Client.ClientId() {
			t.Fatalf("Expected an active introspection result, got %d %v", status, data)
		}

		if status, _ := appTokenRequest(t, app, base+"/revoke", url.Values{"token": {token}}, auth); status != 200 {
			t.Fatalf("Expected revoke 200, got %d", status)
		}

		if status, _ := appApi(t, app, http.MethodGet, "/api/permissions/me", token, ""); status != 401 {
			t.Fatalf("Expected the revoked token to be rejected, got %d", status)
		}
	})

	t.Run("application token on the users issuer endpoints", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		oauth2PrepareIssuer(t, app, "users")
		installed := appInstall(t, app, "cross-app", core.Permissions{})
		token := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

		if status, _ := appApi(t, app, http.MethodGet, "/oauth2/users/userinfo", "Bearer "+token, ""); status != 401 {
			t.Fatalf("Expected the users userinfo to reject the app token, got %d", status)
		}
	})

	t.Run("application token + API key of another client", func(t *testing.T) {
		app := newApp(t)
		defer app.Cleanup()

		installed := appInstall(t, app, "key-app", demo2Grant(app, "list", "view"))
		token := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

		// the managed clients can't have API keys and therefore any key is of another client
		_, key, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
		if err != nil {
			t.Fatal(err)
		}

		mux := oauth2Mux(t, app)

		res := mux.do(http.MethodGet, "/api/collections/demo2/records", nil, map[string]string{"Authorization": token})
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("Expected the application token alone to be allowed, got %d", res.StatusCode)
		}

		for name, headers := range map[string]map[string]string{
			"public key header": {"Authorization": token, apis.APIKeyPublicHeader: key},
			"public key query":  {"Authorization": token},
		} {
			url := "/api/collections/demo2/records"
			if name == "public key query" {
				url += "?pk=" + key
			}

			res := mux.do(http.MethodGet, url, nil, headers)
			res.Body.Close()
			if res.StatusCode != 401 {
				t.Fatalf("[%s] Expected 401, got %d", name, res.StatusCode)
			}
		}

		if _, _, err := tests.NewClientAPIKey(app, installed.Client, core.APIKeyKindPrivate, core.Permissions{}); err == nil {
			t.Fatal("Expected the managed client API key create to fail")
		}
	})
}

// mustOwnerToken returns a session-backed token of the fixtures Owner.
func mustOwnerToken(t testing.TB, app core.App) string {
	t.Helper()

	owner, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	token, err := tests.NewSessionAuthToken(app, owner)
	if err != nil {
		t.Fatal(err)
	}

	return token
}
