package pages_test

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/pages"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestNewBranding(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	c := core.NewAuthCollection("test")

	app.Settings().Meta.AccentColor = "invalid"
	b := pages.NewBranding(app, c)
	if b.Title != app.Settings().Meta.AppName || b.PrimaryColor != template.CSS(pages.DefaultPrimaryColor) {
		t.Fatalf("Expected app name and default color fallbacks, got %#v", b)
	}

	app.Settings().Meta.AccentColor = "#123456"
	b = pages.NewBranding(app, c)
	if b.PrimaryColor != "#123456" {
		t.Fatalf("Expected app accent color fallback, got %q", b.PrimaryColor)
	}

	c.OAuth2Server.LoginPage = core.OAuth2ServerLoginPageConfig{Title: "Custom", LogoURL: "https://example.com/logo.png", PrimaryColor: "#abc"}
	b = pages.NewBranding(app, c)
	if b.Title != "Custom" || b.LogoURL != "https://example.com/logo.png" || b.PrimaryColor != "#abc" {
		t.Fatalf("Unexpected branding %#v", b)
	}

	// invalid configured color (e.g. css injection attempt)
	c.OAuth2Server.LoginPage.PrimaryColor = "red; } body { display:none"
	b = pages.NewBranding(app, c)
	if b.PrimaryColor != "#123456" {
		t.Fatalf("Expected fallback for invalid color, got %q", b.PrimaryColor)
	}
}

func TestRender(t *testing.T) {
	t.Parallel()

	branding := pages.Branding{Title: "Test <b>", PrimaryColor: "#000"}

	rec := httptest.NewRecorder()
	if err := pages.Render(rec, 200, "oauth2/unknown", branding, nil); err == nil {
		t.Fatal("Expected unknown page error")
	}

	names := map[string]any{
		"oauth2/login":                  pages.LoginPage{Form: pages.Form{AuthState: "state<x>", CSRF: "csrf"}, PasswordAction: "/p", IdentityLabel: "Email", Providers: []pages.Provider{{Name: "a", DisplayName: "A", URL: "/a?x=1&y=2"}}},
		"oauth2/otp":                    pages.OTPPage{Action: "/v"},
		"oauth2/mfa":                    pages.MFAPage{OTPAction: "/o"},
		"oauth2/consent":                pages.ConsentPage{Action: "/c", Scopes: []string{"s1"}},
		"oauth2/signup":                 pages.SignupPage{Action: "/s"},
		"oauth2/password_reset":         pages.PasswordResetPage{Action: "/r"},
		"oauth2/password_reset_confirm": pages.TokenFormPage{Action: "/rc", Token: "t"},
		"oauth2/verify_email":           pages.TokenFormPage{Action: "/ve", Token: "t"},
		"oauth2/email_change_confirm":   pages.TokenFormPage{Action: "/ec", Token: "t"},
		"oauth2/message":                pages.MessagePage{Heading: "Hello", Message: "World"},
	}

	for name, page := range names {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if err := pages.Render(rec, 201, name, branding, page); err != nil {
				t.Fatal(err)
			}

			res := rec.Result()
			body := rec.Body.String()

			if res.StatusCode != 201 {
				t.Fatalf("Expected status 201, got %d", res.StatusCode)
			}

			csp := res.Header.Get("Content-Security-Policy")
			nonceStart := strings.Index(csp, "'nonce-")
			if nonceStart < 0 || !strings.Contains(csp, "script-src 'none'") || !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Fatalf("Unexpected CSP %q", csp)
			}
			nonce := csp[nonceStart+7 : nonceStart+7+24]
			if !strings.Contains(body, `<style nonce="`+nonce+`">`) {
				t.Fatal("Expected the style nonce to match the CSP")
			}

			for header, expected := range map[string]string{
				"X-Frame-Options": "DENY",
				"Cache-Control":   "no-store",
				"Referrer-Policy": "same-origin",
				"Content-Type":    "text/html; charset=utf-8",
			} {
				if res.Header.Get(header) != expected {
					t.Fatalf("Expected %s %q, got %q", header, expected, res.Header.Get(header))
				}
			}

			if strings.Contains(body, "<script") {
				t.Fatal("Unexpected script tag")
			}

			// escaped
			if strings.Contains(body, "Test <b>") || strings.Contains(body, "state<x>") {
				t.Fatal("Expected escaped template values")
			}
		})
	}
}
