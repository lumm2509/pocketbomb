package apis_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
)

// proxyVendor is the application backend of the proxy tests.
type proxyVendor struct {
	*httptest.Server

	mu       sync.Mutex
	requests []*proxyVendorRequest
	respond  func(w http.ResponseWriter, r *http.Request)
}

type proxyVendorRequest struct {
	*http.Request
	Body string
}

func newProxyVendor(t testing.TB) *proxyVendor {
	t.Helper()

	v := &proxyVendor{}
	v.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		v.mu.Lock()
		v.requests = append(v.requests, &proxyVendorRequest{Request: r, Body: string(body)})
		respond := v.respond
		v.mu.Unlock()

		if respond != nil {
			respond(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(v.Close)

	return v
}

func (v *proxyVendor) setRespond(fn func(w http.ResponseWriter, r *http.Request)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.respond = fn
}

func (v *proxyVendor) last(t testing.TB) *proxyVendorRequest {
	t.Helper()

	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.requests) == 0 {
		t.Fatal("The vendor didn't receive any request")
	}

	return v.requests[len(v.requests)-1]
}

func (v *proxyVendor) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.requests)
}

func proxyInstall(t testing.TB, app core.App, vendor *proxyVendor) *core.ApplicationInstallResult {
	t.Helper()

	raw, _ := json.Marshal(map[string]any{
		"handle":          "proxy-app",
		"name":            "Proxy app",
		"version":         "1.0.0",
		"application_url": vendor.URL,
		"access":          map[string]any{"scopes": []string{"write_app_proxy"}},
		"app_proxy":       map[string]any{"url": vendor.URL + "/proxy", "prefix": "apps", "subpath": "reviews"},
	})

	manifest, err := core.ParseApplicationManifest(raw, core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}

	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}

	result, err := app.InstallApplication(imported.Application, core.Permissions{
		System: map[string]string{core.PermissionResourceAppProxy: core.PermissionLevelWrite},
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func proxyDo(t testing.TB, app core.App, method string, rawURL string, body string, headers map[string]string) (*http.Response, string) {
	t.Helper()

	res := oauth2Mux(t, app).do(method, rawURL, strings.NewReader(body), headers)
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	return res, string(raw)
}

func proxyAssertSigned(t testing.TB, req *proxyVendorRequest, secret string) url.Values {
	t.Helper()

	params, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		t.Fatal(err)
	}

	if signature := core.ApplicationProxySignature(params, secret); params.Get("signature") != signature {
		t.Fatalf("Expected signature %q, got %q", signature, params.Get("signature"))
	}

	if params.Get("body_sha256") != security.SHA256(req.Body) {
		t.Fatalf("Unexpected body_sha256 %q", params.Get("body_sha256"))
	}

	timestamp, _ := strconv.ParseInt(params.Get("timestamp"), 10, 64)
	if d := time.Now().Unix() - timestamp; d < -5 || d > 5 {
		t.Fatalf("Unexpected timestamp %d", timestamp)
	}

	return params
}

func TestApplicationProxyForward(t *testing.T) {
	t.Parallel()

	app := newDevTestApp(t)
	defer app.Cleanup()

	vendor := newProxyVendor(t)
	installed := proxyInstall(t, app, vendor)
	secret := installed.WebhookSecret

	t.Run("public guest request, path, query, reserved params and signature", func(t *testing.T) {
		res, body := proxyDo(t, app, http.MethodPost, "/apps/reviews/x/y%2Fz?a=1&a=2&empty=&issuer=spoof&signature=spoof&timestamp=1&logged_in_customer_id=spoof&path_prefix=spoof&body_sha256=spoof", "payload", map[string]string{
			"Content-Type":  "text/plain",
			"X-Custom":      "keep",
			"Cookie":        "a=b",
			"X-PB-Buyer-IP": "1.2.3.4",
			"Connection":    "X-Hop",
			"X-Hop":         "drop",
		})

		if res.StatusCode != http.StatusOK || body != "hello" {
			t.Fatalf("Unexpected response %d %q", res.StatusCode, body)
		}

		req := vendor.last(t)
		if req.URL.EscapedPath() != "/proxy/x/y%2Fz" || req.Method != http.MethodPost || req.Body != "payload" {
			t.Fatalf("Unexpected request %s %s %q", req.Method, req.URL.EscapedPath(), req.Body)
		}

		params := proxyAssertSigned(t, req, secret)
		if params.Get("logged_in_customer_id") != "" || !params.Has("logged_in_customer_id") {
			t.Fatalf("Unexpected logged_in_customer_id %q", params.Get("logged_in_customer_id"))
		}
		if params.Get("path_prefix") != "/apps/reviews" || !strings.HasSuffix(params.Get("issuer"), "/oauth2/_applicationInstallations") {
			t.Fatalf("Unexpected params %v", params)
		}
		if strings.Join(params["a"], ",") != "1,2" || !params.Has("empty") {
			t.Fatalf("Unexpected client params %v", params)
		}

		for _, h := range []string{"Cookie", "Authorization", "X-Pb-Buyer-Ip", "X-Hop"} {
			if v := req.Header.Get(h); v != "" {
				t.Fatalf("Unexpected %s header %q", h, v)
			}
		}
		if req.Header.Get("X-Custom") != "keep" || req.Header.Get("X-Forwarded-For") == "" ||
			req.Header.Get("X-Forwarded-Host") == "" || req.Header.Get("X-Forwarded-Proto") == "" {
			t.Fatalf("Unexpected headers %v", req.Header)
		}
	})

	t.Run("no rest path", func(t *testing.T) {
		res, _ := proxyDo(t, app, http.MethodGet, "/apps/reviews", "", nil)
		if res.StatusCode != http.StatusOK || vendor.last(t).URL.Path != "/proxy" {
			t.Fatalf("Unexpected %d %s", res.StatusCode, vendor.last(t).URL.Path)
		}
	})

	t.Run("response headers", func(t *testing.T) {
		vendor.setRespond(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Type", "text/html")
			h.Set("Content-Security-Policy", "default-src *")
			h.Set("X-Content-Type-Options", "sniff")
			h.Set("Referrer-Policy", "unsafe-url")
			h.Add("Set-Cookie", "a=b")
			h.Set("Server", "x")
			h.Set("Date", "x")
			h.Set("Pragma", "x")
			h.Set("X-Powered-By", "x")
			h.Set("Clear-Site-Data", `"storage"`)
			h.Set("Strict-Transport-Security", "max-age=1")
			h.Set("Access-Control-Allow-Origin", "https://evil.example.com")
			h.Set("X-Keep", "keep")
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte("<html>"))
		})
		defer vendor.setRespond(nil)

		res, body := proxyDo(t, app, http.MethodGet, "/apps/reviews/page", "", nil)
		if res.StatusCode != http.StatusTeapot || body != "<html>" {
			t.Fatalf("Unexpected response %d %q", res.StatusCode, body)
		}

		expected := map[string]string{
			"Content-Security-Policy":     "sandbox allow-scripts allow-forms allow-popups",
			"X-Content-Type-Options":      "nosniff",
			"Referrer-Policy":             "no-referrer",
			"Content-Type":                "text/html",
			"X-Keep":                      "keep",
			"Set-Cookie":                  "",
			"Server":                      "",
			"Pragma":                      "",
			"X-Powered-By":                "",
			"Clear-Site-Data":             "",
			"Strict-Transport-Security":   "",
			"Access-Control-Allow-Origin": "",
		}
		for k, v := range expected {
			if res.Header.Get(k) != v {
				t.Fatalf("Expected %s %q, got %q", k, v, res.Header.Get(k))
			}
		}
	})

	t.Run("unknown and dot segments", func(t *testing.T) {
		before := vendor.count()

		for _, path := range []string{"/apps/unknown/x", "/tools/reviews/x", "/apps/reviews/..%2f..%2fadmin", "/apps/reviews/x/%2e%2e/y"} {
			res, _ := proxyDo(t, app, http.MethodGet, path, "", nil)
			if res.StatusCode != http.StatusNotFound {
				t.Fatalf("[%s] Expected 404, got %d", path, res.StatusCode)
			}
		}

		if vendor.count() != before {
			t.Fatal("The vendor must not be called")
		}
	})

	t.Run("hook", func(t *testing.T) {
		app.OnApplicationProxyRequest().BindFunc(func(e *core.ApplicationProxyRequestEvent) error {
			if e.Request.Header.Get("X-Hook-Block") != "" {
				return e.ForbiddenError("blocked "+e.Installation.Id+" "+e.Application.Handle(), nil)
			}
			return e.Next()
		})

		res, body := proxyDo(t, app, http.MethodGet, "/apps/reviews/x", "", map[string]string{"X-Hook-Block": "1"})
		if res.StatusCode != http.StatusForbidden || !strings.Contains(body, installed.Installation.Id) || !strings.Contains(body, "proxy-app") {
			t.Fatalf("Unexpected response %d %s", res.StatusCode, body)
		}
	})
}

func TestApplicationProxyCredentials(t *testing.T) {
	t.Parallel()

	app := newDevTestApp(t)
	defer app.Cleanup()

	vendor := newProxyVendor(t)
	installed := proxyInstall(t, app, vendor)

	customer, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, customerToken := ownSessionToken(t, app, customer)

	_, staffToken := extStaffSession(t, app, "test@example.com")

	t.Run("customer bearer", func(t *testing.T) {
		res, _ := proxyDo(t, app, http.MethodGet, "/apps/reviews/x", "", map[string]string{"Authorization": "Bearer " + customerToken})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Unexpected status %d", res.StatusCode)
		}

		req := vendor.last(t)
		params := proxyAssertSigned(t, req, installed.WebhookSecret)
		if params.Get("logged_in_customer_id") != customer.Id {
			t.Fatalf("Unexpected logged_in_customer_id %q", params.Get("logged_in_customer_id"))
		}
		if req.Header.Get("Authorization") != "" {
			t.Fatal("The Authorization header must be stripped")
		}
	})

	t.Run("staff bearer is not a customer", func(t *testing.T) {
		res, _ := proxyDo(t, app, http.MethodGet, "/apps/reviews/x", "", map[string]string{"Authorization": staffToken})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Unexpected status %d", res.StatusCode)
		}
		if id := proxyAssertSigned(t, vendor.last(t), installed.WebhookSecret).Get("logged_in_customer_id"); id != "" {
			t.Fatalf("Unexpected logged_in_customer_id %q", id)
		}
	})

	t.Run("invalid credentials", func(t *testing.T) {
		before := vendor.count()

		for name, headers := range map[string]map[string]string{
			"token":       {"Authorization": "Bearer invalid"},
			"public key":  {"X-PB-Public-Key": "pb_pk_invalid"},
			"private key": {"X-PB-Private-Key": "pb_sk_invalid"},
		} {
			res, _ := proxyDo(t, app, http.MethodGet, "/apps/reviews/x", "", headers)
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("[%s] Expected 401, got %d", name, res.StatusCode)
			}
		}

		if vendor.count() != before {
			t.Fatal("The vendor must not be called")
		}
	})
}

func TestApplicationProxyRejectsExtensionTokens(t *testing.T) {
	t.Parallel()

	app := newDevTestApp(t)
	defer app.Cleanup()

	vendor := newProxyVendor(t)
	proxyInstall(t, app, vendor)
	installed := extInstall(t, app, "proxy-tokens", core.Permissions{})

	_, staffToken := extStaffSession(t, app, "test@example.com")
	launchToken := extMustLaunch(t, app, staffToken, installed.Installation.Id, "home", "")
	status, sessionToken := extSessionToken(t, app, staffToken, installed.Installation.Id, "home", "")
	if status != http.StatusOK {
		t.Fatalf("Unexpected status %d", status)
	}

	before := vendor.count()

	for name, token := range map[string]string{"launch": launchToken, "session": sessionToken} {
		for _, auth := range []string{token, "Bearer " + token} {
			res, _ := proxyDo(t, app, http.MethodGet, "/apps/reviews/x", "", map[string]string{"Authorization": auth})
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("[%s] Expected 401, got %d", name, res.StatusCode)
			}
		}
	}

	if vendor.count() != before {
		t.Fatal("The vendor must not be called")
	}
}

func TestApplicationProxyLifecycle(t *testing.T) {
	t.Parallel()

	app := newDevTestApp(t)
	defer app.Cleanup()

	vendor := newProxyVendor(t)
	installed := proxyInstall(t, app, vendor)

	expectStatus := func(t *testing.T, path string, status int) {
		t.Helper()
		res, _ := proxyDo(t, app, http.MethodGet, path, "", nil)
		if res.StatusCode != status {
			t.Fatalf("[%s] Expected %d, got %d", path, status, res.StatusCode)
		}
	}

	expectStatus(t, "/apps/reviews/x", http.StatusOK)

	// staff customization
	owner := mustOwnerToken(t, app)
	status, body := appApi(t, app, http.MethodPatch, "/api/applications/installations/"+installed.Installation.Id, owner, `{"proxyPrefix":"tools","proxySubpath":"custom"}`)
	if status != http.StatusOK || !strings.Contains(body, `"proxySubpath":"custom"`) {
		t.Fatalf("Unexpected response %d %s", status, body)
	}
	expectStatus(t, "/apps/reviews/x", http.StatusNotFound)
	expectStatus(t, "/tools/custom/x", http.StatusOK)

	for name, payload := range map[string]string{
		"reserved": `{"proxySubpath":"admin"}`,
		"prefix":   `{"proxyPrefix":"api"}`,
		"mixed":    `{"proxySubpath":"z","versionRef":""}`,
	} {
		if status, body := appApi(t, app, http.MethodPatch, "/api/applications/installations/"+installed.Installation.Id, owner, payload); status != http.StatusBadRequest {
			t.Fatalf("[%s] Expected 400, got %d %s", name, status, body)
		}
	}

	// the applications read permission isn't enough for customizing (RBAC)
	extCreateStaff(t, app, "proxy-reader@example.com", core.Permissions{System: map[string]string{core.PermissionResourceApplications: core.PermissionLevelRead}})
	_, reader := extStaffSession(t, app, "proxy-reader@example.com")
	if status, _ := appApi(t, app, http.MethodPatch, "/api/applications/installations/"+installed.Installation.Id, reader, `{"proxySubpath":"nope"}`); status != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", status)
	}

	// manifest url change applies on update while the customized path stays
	raw, _ := json.Marshal(map[string]any{
		"handle":          "proxy-app",
		"name":            "Proxy app",
		"version":         "2.0.0",
		"application_url": vendor.URL,
		"access":          map[string]any{"scopes": []string{"write_app_proxy"}},
		"app_proxy":       map[string]any{"url": vendor.URL + "/new", "prefix": "a", "subpath": "other"},
	})
	manifest, err := core.ParseApplicationManifest(raw, core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.UpdateApplicationInstallation(installed.Installation, imported.Version.Id, nil); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, "/a/other/x", http.StatusNotFound)
	expectStatus(t, "/tools/custom/x", http.StatusOK)
	if p := vendor.last(t).URL.Path; p != "/new/x" {
		t.Fatalf("Unexpected path %q", p)
	}

	// inactive
	inactive, _ := app.FindApplicationInstallationById(installed.Installation.Id)
	if _, err := app.DB().NewQuery("UPDATE _applicationInstallations SET status='pending' WHERE id='" + inactive.Id + "'").Execute(); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, "/tools/custom/x", http.StatusNotFound)
	if _, err := app.DB().NewQuery("UPDATE _applicationInstallations SET status='active' WHERE id='" + inactive.Id + "'").Execute(); err != nil {
		t.Fatal(err)
	}

	// uninstall
	if err := app.UninstallApplication(installed.Installation); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, "/tools/custom/x", http.StatusNotFound)
}

func TestApplicationProxyRedirectsAndLimits(t *testing.T) {
	t.Parallel()

	app := newDevTestApp(t)
	defer app.Cleanup()

	vendor := newProxyVendor(t)
	proxyInstall(t, app, vendor)

	internal := newProxyVendor(t) // aka. the SSRF target

	t.Run("same host redirect", func(t *testing.T) {
		vendor.setRespond(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/final") {
				_, _ = w.Write([]byte("final " + r.Method))
				return
			}
			http.Redirect(w, r, "/proxy/final", http.StatusFound)
		})

		res, body := proxyDo(t, app, http.MethodPost, "/apps/reviews/start", "x", nil)
		if res.StatusCode != http.StatusOK || body != "final GET" {
			t.Fatalf("Unexpected response %d %q", res.StatusCode, body)
		}
	})

	t.Run("cross host redirect (SSRF)", func(t *testing.T) {
		before := internal.count()

		vendor.setRespond(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, internal.URL+"/secret", http.StatusFound)
		})

		res, body := proxyDo(t, app, http.MethodGet, "/apps/reviews/x", "", nil)
		if res.StatusCode != http.StatusBadGateway || strings.Contains(body, "signature") {
			t.Fatalf("Unexpected response %d %s", res.StatusCode, body)
		}
		if internal.count() != before {
			t.Fatal("The redirect must not be followed")
		}
	})

	t.Run("too many redirects", func(t *testing.T) {
		vendor.setRespond(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/proxy/again", http.StatusFound)
		})

		before := vendor.count()
		res, _ := proxyDo(t, app, http.MethodGet, "/apps/reviews/x", "", nil)
		if res.StatusCode != http.StatusBadGateway {
			t.Fatalf("Unexpected status %d", res.StatusCode)
		}
		if total := vendor.count() - before; total != 4 {
			t.Fatalf("Expected 4 requests (1 + 3 redirects), got %d", total)
		}
	})

	t.Run("request and response limits", func(t *testing.T) {
		vendor.setRespond(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/proxy/large" {
				_, _ = w.Write(make([]byte, core.ApplicationProxyMaxBodySize+1))
				return
			}
			_, _ = w.Write(make([]byte, core.ApplicationProxyMaxBodySize))
		})

		res, _ := proxyDo(t, app, http.MethodGet, "/apps/reviews/large", "", nil)
		if res.StatusCode != http.StatusBadGateway {
			t.Fatalf("Expected 502, got %d", res.StatusCode)
		}

		res, body := proxyDo(t, app, http.MethodGet, "/apps/reviews/max", "", nil)
		if res.StatusCode != http.StatusOK || int64(len(body)) != core.ApplicationProxyMaxBodySize {
			t.Fatalf("Unexpected response %d %d", res.StatusCode, len(body))
		}

		before := vendor.count()
		res, _ = proxyDo(t, app, http.MethodPost, "/apps/reviews/x", strings.Repeat("a", int(core.ApplicationProxyMaxBodySize)+1), nil)
		if res.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("Expected 413, got %d", res.StatusCode)
		}
		if vendor.count() != before {
			t.Fatal("The vendor must not be called")
		}
	})
}

func TestApplicationProxyStaticFallthrough(t *testing.T) {
	t.Parallel()

	app := newDevTestApp(t)
	defer app.Cleanup()

	vendor := newProxyVendor(t)
	proxyInstall(t, app, vendor)

	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	r.GET("/{path...}", apis.Static(fstest.MapFS{
		"tools/docs/page.txt":   {Data: []byte("static tools")},
		"apps/reviews/file.txt": {Data: []byte("shadowed")},
		"apps/other/file.txt":   {Data: []byte("static apps")},
	}, false))
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	do := func(method string, path string, headers map[string]string) (int, string) {
		req := httptest.NewRequest(method, path, nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	scenarios := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		status  int
		body    string
	}{
		{"unknown path: static file", http.MethodGet, "/tools/docs/page.txt", nil, http.StatusOK, "static tools"},
		{"unknown subpath: static file", http.MethodGet, "/apps/other/file.txt", nil, http.StatusOK, "static apps"},
		{"unknown subpath with a stale token: static file", http.MethodGet, "/apps/other/file.txt", map[string]string{"Authorization": "invalid"}, http.StatusOK, "static apps"},
		{"unknown path: missing static file", http.MethodGet, "/tools/docs/missing.txt", nil, http.StatusNotFound, ""},
		{"unknown path: other methods", http.MethodPost, "/tools/docs/page.txt", nil, http.StatusNotFound, ""},
		{"known proxy path wins over a static file", http.MethodGet, "/apps/reviews/file.txt", nil, http.StatusOK, "hello"},
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			status, body := do(s.method, s.path, s.headers)
			if status != s.status || (s.body != "" && body != s.body) {
				t.Fatalf("Unexpected response %d %q", status, body)
			}
		})
	}
}

func TestApplicationProxySSRFBlocked(t *testing.T) {
	t.Parallel()

	// not in dev mode -> the loopback target of a manifest is not allowed
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	vendor := newProxyVendor(t)
	proxyInstall(t, app, vendor)

	res, body := proxyDo(t, app, http.MethodGet, "/apps/reviews/x", "", nil)
	if res.StatusCode != http.StatusBadGateway || strings.Contains(body, "signature") {
		t.Fatalf("Unexpected response %d %s", res.StatusCode, body)
	}
	if vendor.count() != 0 {
		t.Fatal("The vendor must not be called")
	}
}

func TestApplicationProxyRateLimitAndLogs(t *testing.T) {
	t.Parallel()

	app := newDevTestApp(t)
	defer app.Cleanup()

	vendor := newProxyVendor(t)
	proxyInstall(t, app, vendor)

	app.Settings().RateLimits.Enabled = true
	app.Settings().RateLimits.Rules = []core.RateLimitRule{{Label: "/apps/", MaxRequests: 1, Duration: 60}}

	res, _ := proxyDo(t, app, http.MethodGet, "/apps/reviews/x", "", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Unexpected status %d", res.StatusCode)
	}

	res, _ = proxyDo(t, app, http.MethodGet, "/apps/reviews/x", "", nil)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("Expected 429, got %d", res.StatusCode)
	}
}
