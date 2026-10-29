package apis_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
)

// newDevTestApp returns a test app in dev mode (the http loopback urls of the
// test vendors are allowed only in dev mode).
func newDevTestApp(t testing.TB) *tests.TestApp {
	t.Helper()

	app, err := tests.NewTestAppWithConfig(core.BaseAppConfig{IsDev: true, EncryptionEnv: "pb_test_env"})
	if err != nil {
		t.Fatal(err)
	}

	return app
}

func appCatalogManifest(v *tests.ApplicationVendor, handle string, version string, scopes []string, webhookTopics []string) string {
	manifest := map[string]any{
		"handle":          handle,
		"name":            "Vendor " + handle,
		"version":         version,
		"application_url": v.URL(),
		"install_url":     v.URL() + "/install",
		"uninstall_url":   v.URL() + "/uninstall",
		"access":          map[string]any{"scopes": scopes},
	}

	if len(webhookTopics) > 0 {
		manifest["webhooks"] = map[string]any{
			"subscriptions": []any{map[string]any{"topics": webhookTopics, "uri": v.URL() + "/webhooks"}},
		}
	}

	raw, _ := json.Marshal(manifest)

	return string(raw)
}

func appCatalogSources(t testing.TB, app core.App, sources ...core.ApplicationCatalogSource) {
	t.Helper()

	app.Settings().Applications.Catalogs = sources
	if err := app.Save(app.Settings()); err != nil {
		t.Fatal(err)
	}
}

// mustFetch returns the body of a GET request to the provided url.
func mustFetch(t testing.TB, rawURL string) []byte {
	t.Helper()

	res, err := http.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)

	return body
}

func TestApplicationsCatalogApi(t *testing.T) {
	t.Parallel()

	owner := tests.AuthToken(core.CollectionNameSuperusers, "test@example.com")
	installer := tests.AuthToken(core.CollectionNameSuperusers, "installer@example.com")
	reader := tests.AuthToken(core.CollectionNameSuperusers, "appreader@example.com")
	customer := tests.AuthToken("users", "test@example.com")

	vendor := tests.NewApplicationVendor()
	defer vendor.Close()
	vendor.Publish(true,
		appCatalogManifest(vendor, "vendor-app", "1.0.0", []string{"read_demo2"}, []string{"demo2.create"}),
		appCatalogManifest(vendor, "vendor-wide", "1.0.0", []string{"write_demo2", "read_demo3"}, nil),
	)

	failing := tests.NewApplicationVendor()
	defer failing.Close()
	failing.SetInstallStatus(http.StatusInternalServerError)
	failing.Publish(true, appCatalogManifest(failing, "failing-app", "1.0.0", []string{"read_demo2"}, nil))

	// a signed index whose payload was replaced (the original signature is kept)
	tampered := tests.NewApplicationVendor()
	defer tampered.Close()
	tampered.Publish(true, appCatalogManifest(tampered, "tampered-app", "1.0.0", nil, nil))
	envelope := map[string]string{}
	_ = json.Unmarshal(mustFetch(t, tampered.IndexURL()), &envelope)
	tampered.Publish(false, appCatalogManifest(tampered, "evil-app", "1.0.0", nil, nil))
	tamperedIndex, _ := json.Marshal(map[string]string{
		"payload":   base64.RawURLEncoding.EncodeToString(mustFetch(t, tampered.IndexURL())),
		"signature": envelope["signature"],
	})
	tampered.SetFile("/catalog/index.json", tamperedIndex)

	setup := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		appStaffSetup(t, app)
		appCatalogSources(t, app,
			core.ApplicationCatalogSource{Name: "Vendor", URL: vendor.IndexURL(), PublicKey: vendor.PublicKey},
			core.ApplicationCatalogSource{Name: "Failing", URL: failing.IndexURL(), PublicKey: failing.PublicKey},
			core.ApplicationCatalogSource{Name: "Tampered", URL: tampered.IndexURL(), PublicKey: tampered.PublicKey},
		)
	}

	installedSetup := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		setup(t, app, e)

		demo2, _ := app.FindCollectionByNameOrId("demo2")
		imported, err := app.ImportApplicationCatalogEntry(t.Context(), "Vendor", "vendor-app", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.InstallApplication(imported.Application, core.Permissions{Collections: map[string][]string{demo2.Id: {"list", "view"}}}, ""); err != nil {
			t.Fatal(err)
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "catalog as guest",
			Method:          http.MethodGet,
			URL:             "/api/applications/catalog",
			TestAppFactory:  newDevTestApp,
			BeforeTestFunc:  setup,
			ExpectedStatus:  401,
			ExpectedContent: []string{`"status":401`},
		},
		{
			Name:            "catalog as customer",
			Method:          http.MethodGet,
			URL:             "/api/applications/catalog",
			Headers:         map[string]string{"Authorization": customer},
			TestAppFactory:  newDevTestApp,
			BeforeTestFunc:  setup,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
		},
		{
			Name:           "catalog as staff with applications read",
			Method:         http.MethodGet,
			URL:            "/api/applications/catalog?refresh=1",
			Headers:        map[string]string{"Authorization": reader},
			TestAppFactory: newDevTestApp,
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"name":"Vendor","url":"` + vendor.IndexURL() + `","signed":true,"error":"","total":2`,
				`"name":"Failing"`,
				`"name":"Tampered","url":"` + tampered.IndexURL() + `","signed":false,"error":"Invalid catalog index: invalid catalog index signature","total":0`,
				`"source":"Vendor","signed":true,"handle":"vendor-app"`,
				`"installed":false`,
				// the vendor icons are inlined
				`"iconURL":"data:image/png;base64,`,
			},
			NotExpectedContent: []string{`"evil-app"`, `"tampered-app"`, `"publicKey"`, `"iconURL":"http`},
		},
		{
			Name:           "catalog with an installed application",
			Method:         http.MethodGet,
			URL:            "/api/applications/catalog",
			Headers:        map[string]string{"Authorization": reader},
			TestAppFactory: newDevTestApp,
			BeforeTestFunc: installedSetup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"handle":"vendor-app"`,
				`"installed":true,"installedVersion":"1.0.0","updateAvailable":false`,
			},
		},
		{
			Name:           "catalog manifest preview",
			Method:         http.MethodGet,
			URL:            "/api/applications/catalog/manifest?source=Vendor&handle=vendor-wide",
			Headers:        map[string]string{"Authorization": reader},
			TestAppFactory: newDevTestApp,
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"manifest":{`,
				`"install_url":"` + vendor.URL() + `/install"`,
				`{"scope":"read_demo3","label":"Read your demo3 data","optional":false}`,
				`{"scope":"write_demo2","label":"Read, create, update and delete your demo2 data","optional":false}`,
			},
		},
		{
			Name:            "catalog install as staff with applications read",
			Method:          http.MethodPost,
			URL:             "/api/applications/catalog/install",
			Body:            strings.NewReader(`{"source":"Vendor","handle":"vendor-app"}`),
			Headers:         map[string]string{"Authorization": reader},
			TestAppFactory:  newDevTestApp,
			BeforeTestFunc:  setup,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "catalog install with a grant beyond the manifest scopes",
			Method:          http.MethodPost,
			URL:             "/api/applications/catalog/install",
			Body:            strings.NewReader(`{"source":"Vendor","handle":"vendor-app","permissions":{"collections":{"sz5l5z67tg7gku0":["list","create"]}}}`),
			Headers:         map[string]string{"Authorization": owner},
			TestAppFactory:  newDevTestApp,
			BeforeTestFunc:  setup,
			ExpectedStatus:  400,
			ExpectedContent: []string{`"permissions":{"code":"validation_grant_exceeds_manifest_scopes"`, `write_demo2`},
		},
		{
			Name:            "catalog install from a tampered catalog",
			Method:          http.MethodPost,
			URL:             "/api/applications/catalog/install",
			Body:            strings.NewReader(`{"source":"Tampered","handle":"evil-app"}`),
			Headers:         map[string]string{"Authorization": owner},
			TestAppFactory:  newDevTestApp,
			BeforeTestFunc:  setup,
			ExpectedStatus:  400,
			ExpectedContent: []string{`invalid catalog index signature`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "catalog install rejected by the application (rollback)",
			Method:          http.MethodPost,
			URL:             "/api/applications/catalog/install",
			Body:            strings.NewReader(`{"source":"Failing","handle":"failing-app","permissions":{"collections":{"sz5l5z67tg7gku0":["list"]}}}`),
			Headers:         map[string]string{"Authorization": owner},
			TestAppFactory:  newDevTestApp,
			BeforeTestFunc:  setup,
			ExpectedStatus:  400,
			ExpectedContent: []string{`(status 500): vendor install failure`, `"installURL":{"code":"validation_application_notification_failed"`},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if total, _ := app.CountRecords(core.CollectionNameApplicationInstallations); total != 0 {
					t.Fatalf("Expected the installation to be rolled back, got %d", total)
				}
			},
		},
		{
			Name:           "catalog install as staff covering the grant",
			Method:         http.MethodPost,
			URL:            "/api/applications/catalog/install",
			Body:           strings.NewReader(`{"source":"Vendor","handle":"vendor-app","permissions":{"collections":{"sz5l5z67tg7gku0":["list","view"]}}}`),
			Headers:        map[string]string{"Authorization": installer},
			TestAppFactory: newDevTestApp,
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"notified":true`,
				`"clientSecret":""`,
				`"webhookSecret":""`,
				`"status":"active"`,
				`"webhooks":[{`,
				`"topics":["demo2.create"]`,
			},
			NotExpectedContent: []string{`"secret"`},
			ExpectedEvents:     map[string]int{"OnApplicationInstallRequest": 1},
		},
		{
			Name:            "catalog import as staff with applications read",
			Method:          http.MethodPost,
			URL:             "/api/applications/catalog/import",
			Body:            strings.NewReader(`{"source":"Vendor","handle":"vendor-app"}`),
			Headers:         map[string]string{"Authorization": reader},
			TestAppFactory:  newDevTestApp,
			BeforeTestFunc:  setup,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"status":403`},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

// TestApplicationsCatalogFlow covers the whole catalog application lifecycle through the real HTTP API:
// install (the credentials are delivered only to the vendor and they can't be used before the activation),
// client_credentials, read-only managed webhooks, update re-approval, rotation and uninstall.
func TestApplicationsCatalogFlow(t *testing.T) {
	t.Parallel()

	app := newDevTestApp(t)
	defer app.Cleanup()

	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(mux)
	defer server.Close()

	app.Settings().Meta.AppURL = server.URL
	if err := app.Save(app.Settings()); err != nil {
		t.Fatal(err)
	}

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	demo3, _ := app.FindCollectionByNameOrId("demo3")
	owner := mustOwnerToken(t, app)

	send := func(method string, path string, token string, body string, form url.Values) (int, map[string]any) {
		var reader io.Reader = strings.NewReader(body)
		if form != nil {
			reader = strings.NewReader(form.Encode())
		}

		req, _ := http.NewRequest(method, server.URL+path, reader)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", token)
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()

		data := map[string]any{}
		_ = json.NewDecoder(res.Body).Decode(&data)

		return res.StatusCode, data
	}

	clientCredentials := func(clientId string, secret string) (int, map[string]any) {
		return send(http.MethodPost, appTokenURL, basicAuth(clientId, secret), "", url.Values{"grant_type": {"client_credentials"}})
	}

	installations, _ := app.FindCollectionByNameOrId(core.CollectionNameApplicationInstallations)
	jwks, err := installations.OAuth2Server.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	vendor := tests.NewApplicationVendor()
	defer vendor.Close()

	// the vendor verifies the install notification with the issuer JWKS and
	// tries to use the credentials before acknowledging the notification
	var clientId, clientSecret string
	var pendingStatus int
	var pendingError any
	vendor.SetInstallHandler(func(token string) int {
		claims, err := security.ParseSignedJWT(token, jwks)
		if err != nil {
			return http.StatusUnauthorized
		}
		if claims["event"] != core.ApplicationEventInstalled {
			return http.StatusOK
		}

		clientId, _ = claims["client_id"].(string)
		clientSecret, _ = claims["client_secret"].(string)

		var data map[string]any
		pendingStatus, data = clientCredentials(clientId, clientSecret)
		pendingError = data["error_description"]

		return http.StatusOK
	})

	appCatalogSources(t, app, core.ApplicationCatalogSource{Name: "Vendor", URL: vendor.IndexURL(), PublicKey: vendor.PublicKey})
	vendor.Publish(true, appCatalogManifest(vendor, "flow-app", "1.0.0", []string{"read_demo2"}, []string{"demo2.create"}))

	// install
	status, data := send(http.MethodPost, "/api/applications/catalog/install", owner, `{"source":"Vendor","handle":"flow-app","permissions":{"collections":{"`+demo2.Id+`":["list","view"]}}}`, nil)
	if status != 200 || data["notified"] != true || data["clientSecret"] != "" {
		t.Fatalf("Unexpected install response %d %v", status, data)
	}
	if pendingStatus != 400 || !strings.Contains(pendingError.(string), "not active") {
		t.Fatalf("Expected the pending installation credentials to be rejected, got %d %v", pendingStatus, pendingError)
	}

	installationId := data["installation"].(map[string]any)["id"].(string)

	status, data = clientCredentials(clientId, clientSecret)
	if status != 200 || data["scope"] != "read_demo2" {
		t.Fatalf("Expected client_credentials to work after the activation, got %d %v", status, data)
	}
	token := data["access_token"].(string)

	if status, _ := send(http.MethodGet, "/api/collections/demo2/records", token, "", nil); status != 200 {
		t.Fatalf("Expected the application token to list demo2, got %d", status)
	}

	// the managed webhooks are read-only for the records API (even for the Owners)
	webhooks, _ := app.FindAllWebhooksByApplicationInstallation(installationId)
	if len(webhooks) != 1 {
		t.Fatalf("Expected 1 managed webhook, got %d", len(webhooks))
	}
	if status, _ := send(http.MethodPatch, "/api/collections/_webhooks/records/"+webhooks[0].Id, owner, `{"uri":"https://evil.example.com"}`, nil); status != 400 {
		t.Fatalf("Expected the managed webhook update to be rejected, got %d", status)
	}
	if status, _ := send(http.MethodDelete, "/api/collections/_webhooks/records/"+webhooks[0].Id, owner, "", nil); status != 400 {
		t.Fatalf("Expected the managed webhook delete to be rejected, got %d", status)
	}

	// v2 requests more scopes => the update requires the staff approval
	vendor.Publish(true, appCatalogManifest(vendor, "flow-app", "2.0.0", []string{"read_demo2", "read_demo3"}, []string{"demo2.update"}))

	status, data = send(http.MethodGet, "/api/applications/catalog?refresh=1", owner, "", nil)
	items := data["items"].([]any)
	if status != 200 || items[0].(map[string]any)["updateAvailable"] != true {
		t.Fatalf("Expected update available, got %d %v", status, data)
	}

	status, data = send(http.MethodPost, "/api/applications/catalog/import", owner, `{"source":"Vendor","handle":"flow-app"}`, nil)
	if status != 200 {
		t.Fatalf("Expected the v2 import, got %d %v", status, data)
	}
	versionId := data["version"].(map[string]any)["id"].(string)

	status, data = send(http.MethodPatch, "/api/applications/installations/"+installationId, owner, `{"versionRef":"`+versionId+`"}`, nil)
	if status != 400 || !strings.Contains(toJSON(data), "validation_application_update_requires_approval") {
		t.Fatalf("Expected the update to require approval, got %d %v", status, data)
	}

	status, data = send(http.MethodPatch, "/api/applications/installations/"+installationId, owner,
		`{"versionRef":"`+versionId+`","permissions":{"collections":{"`+demo2.Id+`":["list","view"],"`+demo3.Id+`":["list"]}}}`, nil)
	if status != 200 || data["version"] != "2.0.0" || !strings.Contains(toJSON(data["webhooks"]), `demo2.update`) {
		t.Fatalf("Expected the approved update, got %d %v", status, data)
	}

	// rotate (catalog application => the secrets are delivered only to the vendor)
	status, data = send(http.MethodPost, "/api/applications/installations/"+installationId+"/rotate-secret", owner, "", nil)
	if status != 200 || data["notified"] != true || data["clientSecret"] != "" {
		t.Fatalf("Unexpected rotate response %d %v", status, data)
	}
	notifications := vendor.Notifications()
	rotated, err := security.ParseSignedJWT(notifications[len(notifications)-1].Token, jwks)
	if err != nil || rotated["event"] != core.ApplicationEventCredentialsRotated {
		t.Fatalf("Expected the credentials_rotated notification, got %v %v", rotated, err)
	}
	if status, _ := clientCredentials(clientId, clientSecret); status != 401 {
		t.Fatalf("Expected the old secret to be rejected, got %d", status)
	}
	status, data = clientCredentials(clientId, rotated["client_secret"].(string))
	if status != 200 {
		t.Fatalf("Expected the rotated secret to work, got %d %v", status, data)
	}
	token = data["access_token"].(string)

	// uninstall
	if status, data := send(http.MethodDelete, "/api/applications/installations/"+installationId, owner, "", nil); status != 204 {
		t.Fatalf("Expected uninstall 204, got %d %v", status, data)
	}
	notifications = vendor.Notifications()
	if last := notifications[len(notifications)-1]; last.Path != "/uninstall" {
		t.Fatalf("Expected the uninstall notification, got %+v", last)
	}
	if status, _ := send(http.MethodGet, "/api/permissions/me", token, "", nil); status != 401 {
		t.Fatalf("Expected the token to be rejected after uninstall, got %d", status)
	}
	if total, _ := app.CountRecords(core.CollectionNameWebhooks); total != 0 {
		t.Fatalf("Expected the managed webhooks to be deleted, got %d", total)
	}
}

func toJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// TestApplicationsLifecycleTopicsRecordsApi checks that the applications can't subscribe
// to the application lifecycle topics through the records API.
func TestApplicationsLifecycleTopicsRecordsApi(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	result := appInstall(t, app, "lifecycle-records", core.Permissions{
		Collections: map[string][]string{demo2.Id: {core.PermissionActionView}},
		System:      map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
	})
	token := appToken(t, app, result.Client.ClientId(), result.ClientSecret, "")

	status, body := appApi(t, app, http.MethodPost, "/api/collections/_webhooks/records", token,
		`{"name":"x","uri":"https://example.com/hook","topics":["application.installed"]}`)
	if status != 400 || !strings.Contains(body, "validation_webhook_topic_application_lifecycle") {
		t.Fatalf("Expected the lifecycle topic to be rejected, got %d %s", status, body)
	}

	status, body = appApi(t, app, http.MethodPost, "/api/collections/_webhooks/records", token,
		`{"name":"x","uri":"https://example.com/hook","topics":["demo2.create","orders.paid"]}`)
	if status != 200 {
		t.Fatalf("Expected the other topics to be allowed, got %d %s", status, body)
	}

	// the Owners could still subscribe to the lifecycle topics
	status, body = appApi(t, app, http.MethodPost, "/api/collections/_webhooks/records", mustOwnerToken(t, app),
		`{"name":"x","uri":"https://example.com/hook","topics":["application.*"]}`)
	if status != 200 {
		t.Fatalf("Expected the Owner lifecycle subscription, got %d %s", status, body)
	}
}
