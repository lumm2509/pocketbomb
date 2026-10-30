package apis_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

const extSessionTokenType = "urn:pocketbase:params:oauth:token-type:session_token"

func extSessionToken(t testing.TB, app core.App, token string, installationId string, extension string, recordId string) (int, string) {
	t.Helper()

	body, _ := json.Marshal(map[string]string{"extension": extension, "recordId": recordId})

	status, raw := appApi(t, app, http.MethodPost, "/api/applications/installations/"+installationId+"/session-token", token, string(body))

	data := struct {
		SessionToken string `json:"sessionToken"`
	}{}
	_ = json.Unmarshal([]byte(raw), &data)

	return status, data.SessionToken
}

func extExchangeSessionToken(t testing.TB, app core.App, installed *core.ApplicationInstallResult, token string) (int, map[string]any) {
	t.Helper()

	return extExchange(t, app, installed, token, url.Values{"subject_token_type": {extSessionTokenType}})
}

func TestApplicationSessionToken(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	app.Settings().Meta.AppURL = "http://example.com"

	installed := extInstall(t, app, "embedded-app", core.Permissions{
		Collections: map[string][]string{"*": {"list", "view"}},
	})

	session, staffToken := extStaffSession(t, app, "test@example.com")

	t.Run("same checks as the launch", func(t *testing.T) {
		status, token := extSessionToken(t, app, staffToken, installed.Installation.Id, "home", "")
		if status != http.StatusOK || token == "" {
			t.Fatalf("Unexpected response %d %q", status, token)
		}

		// claims and typ
		parts := strings.Split(token, ".")
		header := decodeTestJWT(t, parts[1]+"."+parts[0]+"."+parts[2])
		if header["typ"] != core.ApplicationSessionTokenType {
			t.Fatalf("Unexpected header %v", header)
		}

		claims := decodeTestJWT(t, token)
		if claims["aud"] != installed.Client.ClientId() || claims["sid"] != session.Id || claims["extension"] != "home" ||
			claims["installation_id"] != installed.Installation.Id || claims["jti"] == "" {
			t.Fatalf("Unexpected claims %v", claims)
		}
		if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat != 60 {
			t.Fatalf("Expected a 60s token, got %v", exp-iat)
		}

		if status, _ := extSessionToken(t, app, staffToken, installed.Installation.Id, "missing", ""); status != http.StatusNotFound {
			t.Fatalf("Expected 404, got %d", status)
		}
		if status, _ := extSessionToken(t, app, "", installed.Installation.Id, "home", ""); status != http.StatusUnauthorized {
			t.Fatalf("Expected 401, got %d", status)
		}

		// not the dashboard first-party token (online token)
		online, _ := extOnlineToken(t, app, installed, "test@example.com")
		if status, _ := extSessionToken(t, app, online, installed.Installation.Id, "home", ""); status != http.StatusForbidden {
			t.Fatalf("Expected 403, got %d", status)
		}

		// not an application actor
		appToken := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")
		if status, _ := extSessionToken(t, app, appToken, installed.Installation.Id, "home", ""); status != http.StatusForbidden {
			t.Fatalf("Expected 403, got %d", status)
		}
	})

	t.Run("exchange: reusable token, single use jti only in the exchange", func(t *testing.T) {
		_, token := extSessionToken(t, app, staffToken, installed.Installation.Id, "home", "")

		// the session token itself isn't consumed by a verification (it could be parsed many times)
		for range 2 {
			if _, err := core.ParseApplicationSessionToken(app, token); err != nil {
				t.Fatal(err)
			}
		}

		status, data := extExchangeSessionToken(t, app, installed, token)
		if status != http.StatusOK || data["access_token"] == "" {
			t.Fatalf("Unexpected exchange %d %v", status, data)
		}

		status, data = extExchangeSessionToken(t, app, installed, token)
		if status != http.StatusBadRequest || data["error"] != "invalid_grant" {
			t.Fatalf("Expected the replayed exchange to be rejected, got %d %v", status, data)
		}
	})

	t.Run("exchange: token types can't be mixed", func(t *testing.T) {
		_, sessionToken := extSessionToken(t, app, staffToken, installed.Installation.Id, "home", "")

		if status, _ := extExchange(t, app, installed, sessionToken, nil); status != http.StatusBadRequest {
			t.Fatalf("Expected a session token with the launch type to be rejected, got %d", status)
		}

		launchToken := extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")
		if status, _ := extExchangeSessionToken(t, app, installed, launchToken); status != http.StatusBadRequest {
			t.Fatalf("Expected a launch token with the session type to be rejected, got %d", status)
		}
	})

	t.Run("exchange: another application client", func(t *testing.T) {
		other := extInstall(t, app, "embedded-other", core.Permissions{})
		_, token := extSessionToken(t, app, staffToken, installed.Installation.Id, "home", "")

		if status, _ := extExchangeSessionToken(t, app, other, token); status != http.StatusBadRequest {
			t.Fatalf("Expected 400, got %d", status)
		}
	})

	t.Run("never an auth token", func(t *testing.T) {
		_, token := extSessionToken(t, app, staffToken, installed.Installation.Id, "home", "")

		scenarios := []struct {
			name string
			path string
			post bool
			body string
		}{
			{"records", "/api/collections/demo2/records", false, ""},
			{"permissions", "/api/permissions/me", false, ""},
			{"file token", "/api/files/token", true, ""},
			{"launch", "/api/applications/installations/" + installed.Installation.Id + "/launch", true, `{"extension":"home"}`},
			{"session token", "/api/applications/installations/" + installed.Installation.Id + "/session-token", true, `{"extension":"home"}`},
			{"graphql", "/api/graphql?query=%7B__typename%7D", false, ""},
		}
		for _, s := range scenarios {
			method := http.MethodGet
			if s.post {
				method = http.MethodPost
			}
			status, body := appApi(t, app, method, s.path, token, s.body)
			if status != http.StatusUnauthorized && status != http.StatusForbidden && status != http.StatusBadRequest {
				t.Fatalf("[%s] Expected the session token to be rejected, got %d %s", s.name, status, body)
			}
		}

		for _, issuer := range []string{"_superusers", core.CollectionNameApplicationInstallations} {
			res := oauth2Mux(t, app).do(http.MethodGet, "/oauth2/"+issuer+"/userinfo", nil, map[string]string{"Authorization": "Bearer " + token})
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				t.Fatalf("[%s] Expected userinfo to reject the session token", issuer)
			}
		}

		// and it is still usable for the exchange
		if status, data := extExchangeSessionToken(t, app, installed, token); status != http.StatusOK {
			t.Fatalf("Expected the exchange to succeed, got %d %v", status, data)
		}
	})

	t.Run("logout ends the exchange", func(t *testing.T) {
		_, token := extSessionToken(t, app, staffToken, installed.Installation.Id, "home", "")

		if err := app.EndAuthSession(session, "logout"); err != nil {
			t.Fatal(err)
		}

		if status, _ := extExchangeSessionToken(t, app, installed, token); status != http.StatusBadRequest {
			t.Fatalf("Expected the exchange to be rejected after the logout, got %d", status)
		}
	})
}

func TestApplicationOnlineTokenEndsWithTheLaunchingSession(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	installed := extInstall(t, app, "embedded-child", core.Permissions{
		Collections: map[string][]string{"*": {"list", "view"}},
	})

	session, staffToken := extStaffSession(t, app, "test@example.com")

	status, data := extExchange(t, app, installed, extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", ""), nil)
	if status != http.StatusOK {
		t.Fatalf("Unexpected exchange %d %v", status, data)
	}
	online, _ := data["access_token"].(string)

	if status, body := appApi(t, app, http.MethodGet, "/api/permissions/me", online, ""); status != http.StatusOK {
		t.Fatalf("Expected a valid online token, got %d %s", status, body)
	}

	// another dashboard session of the same root isn't enough to keep it alive
	if err := app.EndAuthSession(session, "test"); err != nil {
		t.Fatal(err)
	}

	if status, _ := appApi(t, app, http.MethodGet, "/api/permissions/me", online, ""); status != http.StatusUnauthorized {
		t.Fatalf("Expected the online token to be rejected, got %d", status)
	}

	root, err := app.FindAuthSessionById(session.Parent())
	if err != nil {
		t.Fatal(err)
	}
	if !root.IsActive() {
		t.Fatal("Expected the root SSO session to be still alive")
	}

}

func TestApplicationEmbeddedSameOriginRefused(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	app.Settings().Meta.AppURL = "https://dashboard.example.com"

	manifest, err := core.ParseApplicationManifest([]byte(`{
		"handle":"same-origin","name":"x","version":"1.0.0","application_url":"https://dashboard.example.com",
		"extensions":[{"type":"dashboard.navigation","handle":"home","label":"Home","path":"/x"}]
	}`), core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}
	installed, err := app.InstallApplication(imported.Application, core.Permissions{}, "")
	if err != nil {
		t.Fatal(err)
	}

	_, staffToken := extStaffSession(t, app, "test@example.com")

	for _, path := range []string{"launch", "session-token"} {
		status, body := appApi(t, app, http.MethodPost, "/api/applications/installations/"+installed.Installation.Id+"/"+path, staffToken, `{"extension":"home"}`)
		if status != http.StatusBadRequest || !strings.Contains(body, "same origin") {
			t.Fatalf("[%s] Expected the same origin app to be refused, got %d %s", path, status, body)
		}
	}
}

func TestApplicationEmbeddedIssuerOriginMismatch(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	installed := extInstall(t, app, "origin-mismatch", core.Permissions{})
	_, staffToken := extStaffSession(t, app, "test@example.com")

	app.Settings().Meta.AppURL = "https://other.example.com"

	for _, path := range []string{"launch", "session-token"} {
		status, body := appApi(t, app, http.MethodPost, "/api/applications/installations/"+installed.Installation.Id+"/"+path, staffToken, `{"extension":"home"}`)
		if status != http.StatusBadRequest || !strings.Contains(body, "set Application URL to http://example.com") {
			t.Fatalf("[%s] Expected the origin mismatch error, got %d %s", path, status, body)
		}
	}

	app.Settings().Meta.AppURL = "http://example.com"

	if status, body := appApi(t, app, http.MethodPost, "/api/applications/installations/"+installed.Installation.Id+"/launch", staffToken, `{"extension":"home"}`); status != http.StatusOK {
		t.Fatalf("Expected 200, got %d %s", status, body)
	}
}

func TestDashboardFrameSrcCSP(t *testing.T) {
	// note: not parallel to avoid conflicts with the ui.DistDirFS nil tests

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	base := "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' http://127.0.0.1:* https://tile.openstreetmap.org data: blob:; connect-src 'self' http://127.0.0.1:* https://nominatim.openstreetmap.org; script-src 'none'; frame-ancestors 'none'"

	router, err := appRouterWithServe(t, app)
	if err != nil {
		t.Fatal(err)
	}

	csp := func() string {
		t.Helper()

		req := httptest.NewRequest(http.MethodGet, "/_/extensions.js", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		return rec.Header().Get("Content-Security-Policy")
	}

	if v := csp(); v != base {
		t.Fatalf("Expected the unchanged CSP without installations, got %q", v)
	}

	first := extInstall(t, app, "csp-first", core.Permissions{})

	if v := csp(); v != base+"; frame-src https://ext.example.com" {
		t.Fatalf("Unexpected CSP %q", v)
	}

	// an installation without extensions isn't listed
	manifest, err := core.ParseApplicationManifest([]byte(`{"handle":"csp-none","name":"x","version":"1.0.0","application_url":"https://none.example.com"}`), core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.InstallApplication(imported.Application, core.Permissions{}, ""); err != nil {
		t.Fatal(err)
	}

	// another origin
	manifest, err = core.ParseApplicationManifest([]byte(`{
		"handle":"csp-second","name":"x","version":"1.0.0","application_url":"https://a.example.com:8443/some/path",
		"extensions":[{"type":"dashboard.navigation","handle":"home","label":"Home","path":"/x"}]
	}`), core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	imported, err = app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.InstallApplication(imported.Application, core.Permissions{}, "")
	if err != nil {
		t.Fatal(err)
	}

	if v := csp(); v != base+"; frame-src https://a.example.com:8443 https://ext.example.com" {
		t.Fatalf("Unexpected CSP %q", v)
	}

	if err := app.UninstallApplication(second.Installation); err != nil {
		t.Fatal(err)
	}
	if v := csp(); v != base+"; frame-src https://ext.example.com" {
		t.Fatalf("Unexpected CSP after the uninstall %q", v)
	}

	if err := app.UninstallApplication(first.Installation); err != nil {
		t.Fatal(err)
	}
	if v := csp(); v != base {
		t.Fatalf("Unexpected CSP after the last uninstall %q", v)
	}
}

func TestDashboardIndexNonce(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	const html = `<script id="a" src="./a.js"></script><script type="module" src="./b.js"></script><link href="./c.css">`
	dist := fstest.MapFS{"index.html": {Data: []byte(html)}, "a.js": {Data: []byte("1")}}

	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	apis.BindDashboardRoute(r, dist)
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	get := func(path string, host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	nonceRegex := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9]+)' 'strict-dynamic'; frame-ancestors 'none'$`)

	nonces := map[string]struct{}{}
	for _, host := range []string{"example.com", "127.0.0.1:8090", "a;script-src*"} {
		rec := get("/_/", host)
		csp := rec.Header().Get("Content-Security-Policy")
		match := nonceRegex.FindStringSubmatch(csp)
		if rec.Code != http.StatusOK || match == nil {
			t.Fatalf("[%s] Unexpected response %d %q", host, rec.Code, csp)
		}
		if strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "'strict-dynamic' http") || strings.Contains(csp, host) {
			t.Fatalf("[%s] Unexpected CSP %q", host, csp)
		}

		expected := `<script nonce="` + match[1] + `" id="a" src="./a.js"></script><script nonce="` + match[1] + `" type="module" src="./b.js"></script><link href="./c.css">`
		if rec.Body.String() != expected {
			t.Fatalf("[%s] Unexpected body %q", host, rec.Body.String())
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("[%s] Expected the index to not be cached", host)
		}

		nonces[match[1]] = struct{}{}
	}
	if len(nonces) != 3 {
		t.Fatalf("Expected a nonce per request, got %v", nonces)
	}

	// the assets have no nonce and the embedded file isn't changed
	asset := get("/_/a.js", "example.com")
	if asset.Code != http.StatusOK || !strings.Contains(asset.Header().Get("Content-Security-Policy"), "script-src 'none'") {
		t.Fatalf("Unexpected asset response %d %v", asset.Code, asset.Header())
	}
	if string(dist["index.html"].Data) != html {
		t.Fatal("The index file must not be changed")
	}
}

func TestApplicationOrigin(t *testing.T) {
	t.Parallel()

	for input, expected := range map[string]string{
		"https://Example.com/path?x=1": "https://example.com",
		"https://example.com:443":      "https://example.com",
		"http://example.com:80":        "http://example.com",
		"http://127.0.0.1:8090":        "http://127.0.0.1:8090",
		"https://a;b.example.com":      "",
		"https://a b":                  "",
		"":                             "",
	} {
		if got := core.ApplicationOrigin(input); got != expected {
			t.Fatalf("[%s] Expected %q, got %q", input, expected, got)
		}
	}
}

func appRouterWithServe(t testing.TB, app core.App) (http.Handler, error) {
	t.Helper()

	router, err := apis.NewRouter(app)
	if err != nil {
		return nil, err
	}

	serveEvent := new(core.ServeEvent)
	serveEvent.App = app
	serveEvent.Router = router

	err = app.OnServe().Trigger(serveEvent, func(e *core.ServeEvent) error {
		return nil
	})
	if err != nil {
		return nil, err
	}

	return router.BuildMux()
}
