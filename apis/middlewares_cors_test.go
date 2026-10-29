package apis_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/tests"
)

// TestOAuth2ServerCORS checks that the protocol endpoints are CORS enabled
// for the browser based (public) clients but never with credentials (cookies).
func TestOAuth2ServerCORS(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	// the same CORS config as in apis.Serve (default AllowedOrigins = *)
	r.Bind(apis.CORS(apis.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	}))
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/oauth2/users/token", "/oauth2/users/userinfo", "/oauth2/users/revoke", "/oauth2/users/introspect", "/oauth2/users/login"} {
		// preflight
		req := httptest.NewRequest(http.MethodOptions, path, nil)
		req.Header.Set("Origin", "https://spa.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if v := rec.Header().Get("Access-Control-Allow-Credentials"); v != "" {
			t.Fatalf("%s: unexpected Access-Control-Allow-Credentials %q", path, v)
		}
		if v := rec.Header().Get("Access-Control-Allow-Origin"); v != "*" {
			t.Fatalf("%s: expected wildcard (credential-less) origin, got %q", path, v)
		}

		// actual request
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(""))
		req.Header.Set("Origin", "https://spa.example.com")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if v := rec.Header().Get("Access-Control-Allow-Credentials"); v != "" {
			t.Fatalf("%s: unexpected Access-Control-Allow-Credentials %q", path, v)
		}
	}

	// the hosted pages are never frameable and are not cached
	req := httptest.NewRequest(http.MethodGet, oauth2AuthorizeURL("users", "app", map[string]string{"redirect_uri": "https://evil.example.com"}), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	h := rec.Header()
	if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		!strings.Contains(h.Get("Content-Security-Policy"), "script-src 'none'") ||
		h.Get("X-Frame-Options") != "DENY" ||
		h.Get("Cache-Control") != "no-store" ||
		h.Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("Unexpected hosted page security headers: %v", h)
	}
}
