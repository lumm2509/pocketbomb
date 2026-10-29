package apis_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
)

// oauth2TokensSetup creates an active "app" client session with the
// "test_refresh_token" refresh token and returns its access token.
func oauth2TokensSetup(t testing.TB, app *tests.TestApp) (string, *core.AuthSession) {
	oauth2AuthorizeSetup(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	session := oauth2StubRefreshSession(t, app, oauth2FindClient(t, app, "app"), user, []string{"openid", "email", "offline_access"}, "test_refresh_token")

	if err := session.AttachActor(user, oauth2FindClient(t, app, "app")); err != nil {
		t.Fatal(err)
	}

	access, err := session.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}

	return access, session
}

func oauth2ExpectSessionEnded(t testing.TB, app *tests.TestApp, session *core.AuthSession, access string, ended bool) {
	t.Helper()

	fresh := oauth2ReloadSession(t, app, session.Id)
	if (fresh.Status() == core.AuthSessionStatusEnded) != ended {
		t.Fatalf("Expected session ended %v, got %q", ended, fresh.Status())
	}

	_, err := app.FindAuthRecordByToken(access, core.TokenTypeAuth)
	if ended && err == nil {
		t.Fatal("Expected the access token to be invalid")
	}
	if !ended && err != nil {
		t.Fatalf("Expected the access token to be valid, got %v", err)
	}
}

func TestOAuth2ServerRevoke(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name   string
		form   map[string]string
		status int
		error  string
		ended  bool
	}{
		{"missing client", map[string]string{"token": "test_refresh_token"}, 401, "invalid_client", false},
		{"missing token", map[string]string{"client_id": "app"}, 400, "invalid_request", false},
		{"invalid token (silently ignored)", map[string]string{"client_id": "app", "token": "invalid"}, 200, "", false},
		{"token of another client (silently ignored)", map[string]string{"client_id": "3p", "token": "test_refresh_token"}, 200, "", false},
		{"refresh token", map[string]string{"client_id": "app", "token": "test_refresh_token"}, 200, "", true},
		{"refresh token with access_token hint", map[string]string{"client_id": "app", "token": "test_refresh_token", "token_type_hint": "access_token"}, 200, "", true},
		{"access token", map[string]string{"client_id": "app", "token": "{access}"}, 200, "", true},
		{"access token with access_token hint", map[string]string{"client_id": "app", "token": "{access}", "token_type_hint": "access_token"}, 200, "", true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app, _ := tests.NewTestApp()
			defer app.Cleanup()

			access, session := oauth2TokensSetup(t, app)

			var hookCalls int
			app.OnOAuth2RevokeRequest("users").BindFunc(func(e *core.OAuth2RevokeRequestEvent) error {
				hookCalls++
				if e.Session == nil || e.Session.Id != session.Id {
					t.Errorf("Unexpected revoke event session")
				}
				return e.Next()
			})

			form := map[string]string{}
			for k, v := range s.form {
				if v == "{access}" {
					v = access
				}
				form[k] = v
			}

			b := newOAuth2Browser(t, app)
			res, body := b.do(http.MethodPost, "/oauth2/users/revoke", oauth2Form(form), oauth2FormHeaders(nil))
			b.expectStatus(res, body, s.status)

			if s.error != "" && !strings.Contains(body, `"error":"`+s.error+`"`) {
				t.Fatalf("Expected error %q, got %s", s.error, body)
			}

			oauth2ExpectSessionEnded(t, app, session, access, s.ended)

			if s.ended != (hookCalls == 1) {
				t.Fatalf("Unexpected hook calls %d", hookCalls)
			}
		})
	}

	t.Run("hook rejection", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		access, session := oauth2TokensSetup(t, app)

		app.OnOAuth2RevokeRequest().BindFunc(func(e *core.OAuth2RevokeRequestEvent) error {
			return errors.New("rejected")
		})

		b := newOAuth2Browser(t, app)
		res, _ := b.do(http.MethodPost, "/oauth2/users/revoke", oauth2Form(map[string]string{"client_id": "app", "token": access}), oauth2FormHeaders(nil))
		if res.StatusCode == http.StatusOK {
			t.Fatal("Expected rejected revoke")
		}

		oauth2ExpectSessionEnded(t, app, session, access, false)
	})
}

func TestOAuth2ServerIntrospect(t *testing.T) {
	t.Parallel()

	// note: a client could introspect only its own tokens
	// (the confidential "conf" client tokens)
	setup := func(t testing.TB) (*tests.TestApp, string, *core.AuthSession) {
		app, _ := tests.NewTestApp()
		oauth2AuthorizeSetup(t, app)

		conf := oauth2FindClient(t, app, "conf")
		user := oauth2FindRecord(t, app, "users", "test@example.com")
		session := oauth2StubRefreshSession(t, app, conf, user, []string{"openid", "email", "offline_access"}, "test_refresh_token")
		if err := session.AttachActor(user, conf); err != nil {
			t.Fatal(err)
		}

		access, err := session.NewAccessToken()
		if err != nil {
			t.Fatal(err)
		}

		return app, access, session
	}

	introspect := func(b *oauth2Browser, form map[string]string, headers map[string]string) (*http.Response, map[string]any) {
		res, body := b.do(http.MethodPost, "/oauth2/users/introspect", oauth2Form(form), oauth2FormHeaders(headers))
		return res, parseJSONMap(b.t, body)
	}

	confAuth := map[string]string{"Authorization": basicAuth("conf", "secret_conf")}

	t.Run("public client is not allowed", func(t *testing.T) {
		app, access, _ := setup(t)
		defer app.Cleanup()

		b := newOAuth2Browser(t, app)
		res, data := introspect(b, map[string]string{"client_id": "app", "token": access}, nil)
		if res.StatusCode != 401 || data["error"] != "invalid_client" {
			t.Fatalf("Expected invalid_client, got %d %v", res.StatusCode, data)
		}
	})

	t.Run("active access and refresh tokens", func(t *testing.T) {
		app, access, session := setup(t)
		defer app.Cleanup()

		b := newOAuth2Browser(t, app)

		res, data := introspect(b, map[string]string{"token": access}, confAuth)
		b.expectStatus(res, "", http.StatusOK)
		if data["active"] != true || data["sid"] != session.Id || data["client_id"] != "conf" || data["token_type"] != "Bearer" || data["scope"] != "openid email offline_access" {
			t.Fatalf("Unexpected access token introspection %v", data)
		}

		_, data = introspect(b, map[string]string{"token": "test_refresh_token"}, confAuth)
		if data["active"] != true || data["token_type"] != "refresh_token" || data["sid"] != session.Id {
			t.Fatalf("Unexpected refresh token introspection %v", data)
		}

		_, data = introspect(b, map[string]string{"token": "invalid"}, confAuth)
		if data["active"] != false || len(data) != 1 {
			t.Fatalf("Expected inactive, got %v", data)
		}

		// ended session
		_ = session.End()
		if err := app.Save(session); err != nil {
			t.Fatal(err)
		}
		_, data = introspect(b, map[string]string{"token": access}, confAuth)
		if data["active"] != false {
			t.Fatalf("Expected inactive access token, got %v", data)
		}
		_, data = introspect(b, map[string]string{"token": "test_refresh_token"}, confAuth)
		if data["active"] != false {
			t.Fatalf("Expected inactive refresh token, got %v", data)
		}
	})

	t.Run("tokens of another client are inactive", func(t *testing.T) {
		app, _, _ := setup(t)
		defer app.Cleanup()

		// another confidential client of the same issuer
		oauth2StubClient(t, app, "users", "conf2", oauth2Confidential, oauth2FirstParty)

		// a still valid "app" client session
		user := oauth2FindRecord(t, app, "users", "test@example.com")
		appClient := oauth2FindClient(t, app, "app")
		appSession := oauth2StubRefreshSession(t, app, appClient, user, []string{"openid"}, "app_refresh_token")
		if err := appSession.AttachActor(user, appClient); err != nil {
			t.Fatal(err)
		}
		appAccess, err := appSession.NewAccessToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.FindAuthRecordByToken(appAccess, core.TokenTypeAuth); err != nil {
			t.Fatalf("Expected the app access token to be valid, got %v", err)
		}

		b := newOAuth2Browser(t, app)

		// the conf client can't introspect the app client tokens (both hints)
		for _, form := range []map[string]string{
			{"token": appAccess},
			{"token": appAccess, "token_type_hint": "access_token"},
			{"token": "app_refresh_token"},
			{"token": "app_refresh_token", "token_type_hint": "refresh_token"},
		} {
			res, data := introspect(b, form, confAuth)
			b.expectStatus(res, "", http.StatusOK)
			if data["active"] != false || len(data) != 1 {
				t.Fatalf("Expected only active:false for another client token, got %v", data)
			}
		}

		// the conf2 client can't introspect the conf client tokens
		_, data := introspect(b, map[string]string{"token": "test_refresh_token"}, map[string]string{"Authorization": basicAuth("conf2", "secret_conf2")})
		if data["active"] != false || len(data) != 1 {
			t.Fatalf("Expected only active:false for another client token, got %v", data)
		}

		// the token own client still can
		_, data = introspect(b, map[string]string{"token": "test_refresh_token"}, confAuth)
		if data["active"] != true {
			t.Fatalf("Expected active token for its own client, got %v", data)
		}
	})

	t.Run("impersonation act", func(t *testing.T) {
		app, _, _ := setup(t)
		defer app.Cleanup()

		staff := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		staffSession, err := tests.CreateAuthSession(app, staff)
		if err != nil {
			t.Fatal(err)
		}

		user := oauth2FindRecord(t, app, "users", "test2@example.com")
		session, err := app.CreateAuthSession(user, oauth2FindClient(t, app, "conf"), core.AuthSessionOptions{
			Scopes:              []string{"openid"},
			Impersonator:        staff.Id,
			ImpersonatorSession: staffSession.Id,
		})
		if err != nil {
			t.Fatal(err)
		}
		token, err := session.NewAccessToken()
		if err != nil {
			t.Fatal(err)
		}

		b := newOAuth2Browser(t, app)
		_, data := introspect(b, map[string]string{"token": token}, confAuth)
		act, _ := data["act"].(map[string]any)
		if data["active"] != true || act["sub"] != staff.Id {
			t.Fatalf("Expected act in the introspection, got %v", data)
		}

		// the impersonator session ended -> inactive
		_ = staffSession.End()
		if err := app.Save(staffSession); err != nil {
			t.Fatal(err)
		}
		_, data = introspect(b, map[string]string{"token": token}, confAuth)
		if data["active"] != false {
			t.Fatalf("Expected inactive impersonation token after the impersonator session end, got %v", data)
		}
	})
}

func TestOAuth2ServerUserinfo(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	access, session := oauth2TokensSetup(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	noOpenIdToken, _ := oauth2AccessToken(t, app, oauth2FindClient(t, app, "app"), user, []string{"email"})

	b := newOAuth2Browser(t, app)

	res, body := b.do(http.MethodGet, "/oauth2/users/userinfo", "", nil)
	if res.StatusCode != 401 || !strings.Contains(res.Header.Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("Expected 401 invalid_token, got %d %s", res.StatusCode, body)
	}

	res, body = b.do(http.MethodGet, "/oauth2/users/userinfo", "", map[string]string{"Authorization": "Bearer " + noOpenIdToken})
	if res.StatusCode != 403 || !strings.Contains(body, "insufficient_scope") {
		t.Fatalf("Expected 403 insufficient_scope, got %d %s", res.StatusCode, body)
	}

	// sid-less auth token (valid signature) is rejected
	legacy := oauth2SidlessToken(t, user)
	res, _ = b.do(http.MethodGet, "/oauth2/users/userinfo", "", map[string]string{"Authorization": "Bearer " + legacy})
	if res.StatusCode != 401 {
		t.Fatalf("Expected 401 for legacy token, got %d", res.StatusCode)
	}

	res, body = b.do(http.MethodGet, "/oauth2/users/userinfo", "", map[string]string{"Authorization": "Bearer " + access})
	b.expectStatus(res, body, http.StatusOK)
	data := parseJSONMap(t, body)
	if data["sub"] != user.Id || data["email"] != user.Email() {
		t.Fatalf("Unexpected userinfo %v", data)
	}

	// form body token (RFC 6750 section 2.2)
	res, body = b.do(http.MethodPost, "/oauth2/users/userinfo", "access_token="+url.QueryEscape(access), oauth2FormHeaders(nil))
	b.expectStatus(res, body, http.StatusOK)

	// ended session
	_ = session.End()
	if err := app.Save(session); err != nil {
		t.Fatal(err)
	}
	res, _ = b.do(http.MethodGet, "/oauth2/users/userinfo", "", map[string]string{"Authorization": "Bearer " + access})
	if res.StatusCode != 401 {
		t.Fatalf("Expected 401 for ended session, got %d", res.StatusCode)
	}

	// token of another issuer
	clientsUser := oauth2FindRecord(t, app, "clients", "test@example.com")
	otherToken, _ := oauth2AccessToken(t, app, oauth2FindClient(t, app, "other"), clientsUser, []string{"openid"})
	res, _ = b.do(http.MethodGet, "/oauth2/users/userinfo", "", map[string]string{"Authorization": "Bearer " + otherToken})
	if res.StatusCode != 401 {
		t.Fatalf("Expected 401 for token of another issuer, got %d", res.StatusCode)
	}
}

func TestOAuth2ServerLogout(t *testing.T) {
	t.Parallel()

	// login + code exchange with the provided scopes; returns the browser and token response
	login := func(t testing.TB, app *tests.TestApp, b *oauth2Browser, scope string) map[string]any {
		b.startLogin("users", "app", map[string]string{"scope": scope})
		code := b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)
		_, data := b.exchange("users", "app", code, nil)
		return data
	}

	t.Run("confirmation page without id_token_hint", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		data := login(t, app, b, "openid")
		access, _ := data["access_token"].(string)
		rootId, _, _ := strings.Cut(b.cookies["pb_session"], ".")

		res, body := b.get("/oauth2/users/logout?client_id=app&post_logout_redirect_uri=" + url.QueryEscape(oauth2TestLogoutURI) + "&state=abc")
		b.expectStatus(res, body, http.StatusOK)
		if !strings.Contains(body, "Do you want to sign out?") {
			t.Fatalf("Expected confirmation page:\n%s", body)
		}

		// GET without confirmation doesn't end anything (logout CSRF protection)
		if s := oauth2ReloadSession(t, app, rootId); s.Status() != core.AuthSessionStatusActive {
			t.Fatal("Expected the root session to remain active")
		}

		// cross-site confirmation
		res, _ = b.do(http.MethodPost, "/oauth2/users/logout", oauth2Form(map[string]string{"csrf": hiddenField(body, "csrf")}), map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Origin":       "https://evil.example.com",
		})
		b.expectStatus(res, "", http.StatusBadRequest)

		b.lastHTML = body
		res, _ = b.submit("/oauth2/users/logout", map[string]string{
			"client_id":                "app",
			"post_logout_redirect_uri": oauth2TestLogoutURI,
			"state":                    "abc",
		})
		oauth2ExpectRedirect(t, res, oauth2TestLogoutURI+"?", map[string]string{"state": "abc"})

		if s := oauth2ReloadSession(t, app, rootId); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected ended root, got %q", s.Status())
		}
		if _, ok := b.cookies["pb_session"]; ok {
			t.Fatal("Expected the pb_session cookie to be removed")
		}

		// the non-offline child is ended by the cascade
		if _, err := app.FindAuthRecordByToken(access, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the child access token to be invalid after logout")
		}

		// the next authorize requires login
		res = b.authorize("users", "app", nil)
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login?", nil)
	})

	t.Run("offline_access children survive the SSO logout", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		offlineData := login(t, app, b, "openid offline_access")
		offlineAccess, _ := offlineData["access_token"].(string)
		offlineRefresh, _ := offlineData["refresh_token"].(string)

		// a second (SSO reuse) child without offline_access
		code := b.expectCode(b.authorize("users", "app", nil), oauth2TestIssuer)
		_, data := b.exchange("users", "app", code, nil)
		access, _ := data["access_token"].(string)

		b.get("/oauth2/users/logout")
		b.submit("/oauth2/users/logout", nil)

		if _, err := app.FindAuthRecordByToken(access, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the non-offline child token to be invalid")
		}
		if _, err := app.FindAuthRecordByToken(offlineAccess, core.TokenTypeAuth); err != nil {
			t.Fatalf("Expected the offline_access child token to remain valid, got %v", err)
		}

		res, _ := b.tokenRequest("users", map[string]string{"grant_type": "refresh_token", "client_id": "app", "refresh_token": offlineRefresh})
		b.expectStatus(res, "", http.StatusOK)
	})

	t.Run("id_token_hint ends the hinted session", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		data := login(t, app, b, "openid offline_access")
		idToken, _ := data["id_token"].(string)
		access, _ := data["access_token"].(string)

		claims, _ := security.ParseUnverifiedJWT(idToken)
		sid, _ := claims["sid"].(string)

		res, _ := b.get("/oauth2/users/logout?id_token_hint=" + url.QueryEscape(idToken) + "&post_logout_redirect_uri=" + url.QueryEscape(oauth2TestLogoutURI))
		oauth2ExpectRedirect(t, res, oauth2TestLogoutURI, nil)

		if s := oauth2ReloadSession(t, app, sid); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the hinted (offline) session to be ended, got %q", s.Status())
		}
		if _, err := app.FindAuthRecordByToken(access, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the hinted session token to be invalid")
		}
	})

	t.Run("invalid params", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)

		res, _ := b.get("/oauth2/users/logout?id_token_hint=invalid")
		b.expectStatus(res, "", http.StatusBadRequest)

		// no open redirects
		res, _ = b.get("/oauth2/users/logout?client_id=app&post_logout_redirect_uri=" + url.QueryEscape("https://evil.example.com"))
		b.expectStatus(res, "", http.StatusBadRequest)

		res, _ = b.get("/oauth2/users/logout?post_logout_redirect_uri=" + url.QueryEscape(oauth2TestLogoutURI))
		b.expectStatus(res, "", http.StatusBadRequest)
	})
}

func TestOAuth2AttackIntrospectAndRevokeByOtherClients(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)
	b := newOAuth2Browser(t, app)

	record := oauth2FindRecord(t, app, "users", "test@example.com")
	access, session := oauth2AccessToken(t, app, oauth2FindClient(t, app, "app"), record, []string{"openid"})

	// a public client can't introspect
	res, body := b.do(http.MethodPost, "/oauth2/users/introspect", url.Values{"client_id": {"3p"}, "token": {access}}.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if res.StatusCode != http.StatusUnauthorized || strings.Contains(body, `"active":true`) {
		t.Fatalf("Expected public client introspection to be rejected, got %d %s", res.StatusCode, body)
	}

	// another client can't revoke
	res, _ = b.do(http.MethodPost, "/oauth2/users/revoke", url.Values{"client_id": {"3p"}, "token": {access}}.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected silent revoke response, got %d", res.StatusCode)
	}
	if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusActive {
		t.Fatalf("Expected the session to remain active, got %q", s.Status())
	}

	// the client of another issuer can't revoke either
	res, _ = b.do(http.MethodPost, "/oauth2/clients/revoke", url.Values{"client_id": {"other"}, "token": {access}}.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusActive {
		t.Fatalf("Expected the session to remain active, got %q (%d)", s.Status(), res.StatusCode)
	}
}
