package apis_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/types"
)

func TestOAuth2AttackAuthStateTheftAndReplay(t *testing.T) {
	t.Parallel()

	t.Run("stolen auth_state without the binding cookie", func(t *testing.T) {
		app := oauth2AttackApp(t)

		victim := newOAuth2Browser(t, app)
		handle := victim.startLogin("users", "app", nil)

		// the attacker has its own CSRF cookie but not the victim binding cookie
		attacker := newOAuth2Browser(t, app)
		attacker.cookies["pb_oauth2_csrf"] = oauth2TestCSRF

		res, body := attacker.get("/oauth2/users/login?auth_state=" + url.QueryEscape(handle))
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Missing or expired sign-in request") {
			t.Fatalf("Expected invalid flow page, got %d", res.StatusCode)
		}

		res, _ = attacker.post("/oauth2/users/login/password", url.Values{
			"auth_state": {handle},
			"csrf":       {oauth2TestCSRF},
			"identity":   {"test@example.com"},
			"password":   {"1234567890"},
		})
		if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
			t.Fatalf("Expected invalid flow, got %d %q", res.StatusCode, res.Header.Get("Location"))
		}

		if n := oauth2CountFactors(t, app, handle); n != 0 {
			t.Fatalf("Expected no factor, got %d", n)
		}
	})

	t.Run("binding cookie of another flow", func(t *testing.T) {
		app := oauth2AttackApp(t)

		attacker := newOAuth2Browser(t, app)
		attacker.startLogin("users", "app", nil)

		victim := newOAuth2Browser(t, app)
		victimHandle := victim.startLogin("users", "app", nil)
		victimSession := victim.sessionByHandle(victimHandle)

		// copy the attacker's own binding value under the victim flow cookie name
		for name, value := range attacker.cookies {
			if strings.HasPrefix(name, "pb_binding_") {
				attacker.cookies["pb_binding_"+victimSession.Id] = value
			}
		}

		res, _ := attacker.get("/oauth2/users/login?auth_state=" + url.QueryEscape(victimHandle))
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected invalid flow, got %d", res.StatusCode)
		}
	})

	t.Run("auth_state replay after the code was issued", func(t *testing.T) {
		app := oauth2AttackApp(t)

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)
		b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)

		// the binding cookie is cleared but even with it the authorized flow can't be continued
		replay := b.clone(true)
		replay.cookies["pb_binding_"+b.sessionByHandle(handle).Id] = "anything"

		for _, u := range []string{"/oauth2/users/login", "/oauth2/users/consent", "/oauth2/users/login/mfa"} {
			res, _ := replay.get(u + "?auth_state=" + url.QueryEscape(handle))
			if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
				t.Fatalf("%s: expected invalid flow, got %d %q", u, res.StatusCode, res.Header.Get("Location"))
			}
		}
	})

	t.Run("expired flow", func(t *testing.T) {
		app := oauth2AttackApp(t)

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)

		session := b.sessionByHandle(handle)
		session.SetExpiresAt(types.NowDateTime().Add(-time.Second))
		if err := app.Save(session); err != nil {
			t.Fatal(err)
		}

		res := b.loginPassword("users", "test@example.com", "1234567890")
		if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" {
			t.Fatalf("Expected invalid flow, got %d %q", res.StatusCode, res.Header.Get("Location"))
		}
	})

	t.Run("auth_state of another issuer", func(t *testing.T) {
		app := oauth2AttackApp(t)

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)

		res, _ := b.get("/oauth2/clients/login?auth_state=" + url.QueryEscape(handle))
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected invalid flow, got %d", res.StatusCode)
		}
	})
}

func TestOAuth2AttackSSOCookie(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name   string
		cookie func(t *testing.T, app core.App) string
	}{
		{"wrong secret", func(t *testing.T, app core.App) string {
			_, root := oauth2StubSSO(t, app, oauth2FindRecord(t, app, "users", "test@example.com"), types.NowDateTime())
			return "pb_session=" + root.Id + ".invalid"
		}},
		{"root of another issuer", func(t *testing.T, app core.App) string {
			cookie, _ := oauth2StubSSO(t, app, oauth2FindRecord(t, app, "clients", "test@example.com"), types.NowDateTime())
			return cookie
		}},
		{"ended root", func(t *testing.T, app core.App) string {
			cookie, root := oauth2StubSSO(t, app, oauth2FindRecord(t, app, "users", "test@example.com"), types.NowDateTime())
			_ = root.End()
			if err := app.Save(root); err != nil {
				t.Fatal(err)
			}
			return cookie
		}},
		{"expired root", func(t *testing.T, app core.App) string {
			cookie, root := oauth2StubSSO(t, app, oauth2FindRecord(t, app, "users", "test@example.com"), types.NowDateTime())
			root.SetExpiresAt(types.NowDateTime().Add(-time.Second))
			if err := app.Save(root); err != nil {
				t.Fatal(err)
			}
			return cookie
		}},
		{"a child (non root) session id", func(t *testing.T, app core.App) string {
			client := oauth2FindClient(t, app, "app")
			_, session := oauth2AccessToken(t, app, client, oauth2FindRecord(t, app, "users", "test@example.com"), []string{"openid"})
			return "pb_session=" + session.Id + ".anything"
		}},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app := oauth2AttackApp(t)

			b := newOAuth2Browser(t, app)
			res, _ := b.do(http.MethodGet, oauth2AuthorizeURL("users", "app", nil), "", map[string]string{"Cookie": s.cookie(t, app)})

			oauth2ExpectRedirect(t, res, "/oauth2/users/login?", map[string]string{"auth_state": "*", "code": ""})
		})
	}
}

func TestOAuth2AttackSessionLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("root end vs offline_access", func(t *testing.T) {
		app := oauth2AttackApp(t)

		client := oauth2FindClient(t, app, "app")
		user := oauth2FindRecord(t, app, "users", "test@example.com")
		_, root := oauth2StubSSO(t, app, user, types.NowDateTime())

		newChild := func(scopes []string) string {
			session, err := app.CreateAuthSession(user, client, core.AuthSessionOptions{Scopes: scopes, Parent: root.Id})
			if err != nil {
				t.Fatal(err)
			}
			token, err := session.NewAccessToken()
			if err != nil {
				t.Fatal(err)
			}
			return token
		}

		online := newChild([]string{"openid"})
		offline := newChild([]string{"openid", "offline_access"})

		if err := root.End(); err != nil {
			t.Fatal(err)
		}
		if err := app.Save(root); err != nil {
			t.Fatal(err)
		}

		if _, err := app.FindAuthRecordByToken(online, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the online child token to be rejected after the root end")
		}
		if _, err := app.FindAuthRecordByToken(offline, core.TokenTypeAuth); err != nil {
			t.Fatalf("Expected the offline_access child to survive the root end, got %v", err)
		}

		// but not the tokenKey rotation (e.g. password change)
		user.RefreshTokenKey()
		if err := app.Save(user); err != nil {
			t.Fatal(err)
		}
		if _, err := app.FindAuthRecordByToken(offline, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the offline_access token to be rejected after the tokenKey rotation")
		}

		// and a new token for the old (ended) session can't be issued
		user2 := oauth2FindRecord(t, app, "users", "test@example.com")
		sessions, _ := app.FindAllAuthSessionsByRecord(user2)
		for _, s := range sessions {
			if s.Status() != core.AuthSessionStatusEnded {
				t.Fatalf("Expected all record sessions to be ended, got %q for %s", s.Status(), s.Id)
			}
		}
	})

	t.Run("expired root", func(t *testing.T) {
		app := oauth2AttackApp(t)

		client := oauth2FindClient(t, app, "app")
		user := oauth2FindRecord(t, app, "users", "test@example.com")
		_, root := oauth2StubSSO(t, app, user, types.NowDateTime())

		session, err := app.CreateAuthSession(user, client, core.AuthSessionOptions{Scopes: []string{"openid"}, Parent: root.Id})
		if err != nil {
			t.Fatal(err)
		}
		token, _ := session.NewAccessToken()

		root.SetExpiresAt(types.NowDateTime().Add(-time.Second))
		if err := app.Save(root); err != nil {
			t.Fatal(err)
		}

		if _, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the token of an expired root to be rejected")
		}
	})

	t.Run("client disable", func(t *testing.T) {
		app := oauth2AttackApp(t)

		client := oauth2FindClient(t, app, "3p")
		user := oauth2FindRecord(t, app, "users", "test@example.com")
		token, session := oauth2AccessToken(t, app, client, user, []string{"openid"})

		client.SetDisabled(true)
		if err := app.Save(client); err != nil {
			t.Fatal(err)
		}

		if _, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the token of a disabled client to be rejected")
		}
		if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the client sessions to be ended, got %q", s.Status())
		}

		// re-enabling the client doesn't revive the session
		client.SetDisabled(false)
		if err := app.Save(client); err != nil {
			t.Fatal(err)
		}
		if _, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the token to stay rejected after re-enabling the client")
		}
	})
}

func oauth2FindCookie(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}

	return nil
}

func TestOAuth2ServerCookieAttributes(t *testing.T) {
	t.Parallel()

	assertFlags := func(t *testing.T, cookie *http.Cookie, path string, secure bool) {
		t.Helper()

		if cookie == nil {
			t.Fatal("Expected cookie to be set")
		}
		if !cookie.HttpOnly {
			t.Fatal("Expected HttpOnly cookie")
		}
		if cookie.Path != path {
			t.Fatalf("Expected path %q, got %q", path, cookie.Path)
		}
		if cookie.Secure != secure {
			t.Fatalf("Expected Secure=%v, got %v", secure, cookie.Secure)
		}
	}

	run := func(t *testing.T, appURL string, secure bool) {
		t.Helper()

		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		app.Settings().Meta.AppURL = appURL
		if err := app.Save(app.Settings()); err != nil {
			t.Fatal(err)
		}

		b := newOAuth2Browser(t, app)

		// binding cookie (authorize response)
		res := b.authorize("users", "app", nil)
		b.expectStatus(res, "", http.StatusFound)
		var binding *http.Cookie
		for _, c := range res.Cookies() {
			if strings.HasPrefix(c.Name, "pb_binding_") {
				binding = c
				break
			}
		}
		assertFlags(t, binding, "/oauth2/users", secure)
		if binding.SameSite != http.SameSiteLaxMode {
			t.Fatalf("Expected the binding cookie to be Lax, got %v", binding.SameSite)
		}

		// csrf cookie (login page response)
		res, body := b.follow(res)
		b.expectStatus(res, body, http.StatusOK)
		csrf := oauth2FindCookie(res, "pb_oauth2_csrf")
		assertFlags(t, csrf, "/oauth2/users", secure)
		if csrf.SameSite != http.SameSiteStrictMode {
			t.Fatalf("Expected the csrf cookie to be Strict, got %v", csrf.SameSite)
		}

		// root SSO cookie (set after a successful login factor)
		if secure {
			// the request origin must match the https AppURL
			form := url.Values{}
			form.Set("auth_state", hiddenField(b.lastHTML, "auth_state"))
			form.Set("csrf", hiddenField(b.lastHTML, "csrf"))
			form.Set("identity", "test@example.com")
			form.Set("password", "1234567890")
			res, _ = b.do(http.MethodPost, "/oauth2/users/login/password", form.Encode(), map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"Origin":       "https://localhost:8090",
			})
		} else {
			res = b.loginPassword("users", "test@example.com", "1234567890")
		}
		if res.StatusCode != http.StatusFound && res.StatusCode != http.StatusSeeOther {
			t.Fatalf("Expected the login to succeed, got %d", res.StatusCode)
		}
		sso := oauth2FindCookie(res, "pb_session")
		assertFlags(t, sso, "/oauth2/users", secure)
		if sso.SameSite != http.SameSiteLaxMode {
			t.Fatalf("Expected the pb_session cookie to be Lax, got %v", sso.SameSite)
		}
		if sso.Value == "" {
			t.Fatal("Expected a non-empty pb_session cookie value")
		}
	}

	t.Run("http", func(t *testing.T) {
		run(t, "http://localhost:8090", false)
	})

	t.Run("https app url", func(t *testing.T) {
		run(t, "https://localhost:8090", true)
	})
}
