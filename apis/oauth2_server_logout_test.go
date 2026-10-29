package apis_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/types"
)

func TestOAuth2AttackLogoutCSRF(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)

	client := oauth2FindClient(t, app, "app")
	victim := oauth2FindRecord(t, app, "users", "test@example.com")
	attacker := oauth2FindRecord(t, app, "users", "test2@example.com")

	cookie, root := oauth2StubSSO(t, app, victim, types.NowDateTime())

	// a valid id_token of the attacker's own account
	_, attackerSession := oauth2AccessToken(t, app, client, attacker, []string{"openid"})
	attackerIdToken, err := attacker.NewOIDCIdToken(core.OIDCIdTokenOptions{Issuer: oauth2TestIssuer, Client: client, Session: attackerSession})
	if err != nil {
		t.Fatal(err)
	}

	b := newOAuth2Browser(t, app)

	// top-level cross-site navigation of the victim browser
	res, body := b.do(http.MethodGet, "/oauth2/users/logout?"+url.Values{
		"id_token_hint":            {attackerIdToken},
		"client_id":                {"app"},
		"post_logout_redirect_uri": {oauth2TestLogoutURI},
	}.Encode(), "", map[string]string{"Cookie": cookie})

	if res.StatusCode != http.StatusOK || res.Header.Get("Location") != "" || !strings.Contains(body, "Do you want to sign out?") {
		t.Fatalf("Expected the logout confirmation page, got %d %q", res.StatusCode, res.Header.Get("Location"))
	}

	if s := oauth2ReloadSession(t, app, root.Id); s.Status() != core.AuthSessionStatusActive {
		t.Fatalf("Expected the victim SSO session to remain active, got %q", s.Status())
	}

	// the hint of the SSO actor itself still logs out without confirmation
	_, victimSession := oauth2AccessToken(t, app, client, victim, []string{"openid"})
	victimIdToken, _ := victim.NewOIDCIdToken(core.OIDCIdTokenOptions{Issuer: oauth2TestIssuer, Client: client, Session: victimSession})

	res, _ = b.do(http.MethodGet, "/oauth2/users/logout?"+url.Values{
		"id_token_hint":            {victimIdToken},
		"client_id":                {"app"},
		"post_logout_redirect_uri": {oauth2TestLogoutURI},
	}.Encode(), "", map[string]string{"Cookie": cookie})
	if !strings.HasPrefix(res.Header.Get("Location"), oauth2TestLogoutURI) {
		t.Fatalf("Expected logout redirect, got %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if s := oauth2ReloadSession(t, app, root.Id); s.Status() != core.AuthSessionStatusEnded {
		t.Fatalf("Expected the SSO session to be ended, got %q", s.Status())
	}
	if s := oauth2ReloadSession(t, app, victimSession.Id); s.Status() != core.AuthSessionStatusEnded {
		t.Fatalf("Expected the hinted session to be ended, got %q", s.Status())
	}
}

// oauth2DashboardLogin performs an interactive pb_dashboard login (password factor)
// and returns the token response.
func oauth2DashboardLogin(t *testing.T, b *oauth2Browser) map[string]any {
	t.Helper()

	params := map[string]string{"redirect_uri": oauth2TestDashboardCallback}

	b.startLogin(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, params)

	res := b.loginPassword(core.CollectionNameSuperusers, "test@example.com", "1234567890")
	query := oauth2ExpectRedirect(t, res, oauth2TestDashboardCallback+"?", map[string]string{"code": "*"})

	res, data := b.exchange(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, query.Get("code"), map[string]string{
		"redirect_uri": oauth2TestDashboardCallback,
	})
	b.expectStatus(res, "", http.StatusOK)

	return data
}

// TestOAuth2LogoutConcurrentSSOAuthorize reproduces deterministically the
// dashboard logout flake: an authorize request that loaded the root SSO session
// right before a concurrent logout ended it must not "resurrect" the root
// (previously the stale root lastUsedAt save overwrote the ended status
// and the dashboard was signed back in through SSO).
func TestOAuth2LogoutConcurrentSSOAuthorize(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers)

	b := newOAuth2Browser(t, app)
	oauth2DashboardLogin(t, b)

	rootId, _, _ := strings.Cut(b.cookies["pb_session"], ".")
	if rootId == "" {
		t.Fatal("Missing pb_session cookie")
	}

	// simulate the logout request committing between the authorize SSO load and its root save
	fired := false
	app.OnRecordUpdate(core.CollectionNameAuthSessions).Bind(&hook.Handler[*core.RecordEvent]{
		Func: func(e *core.RecordEvent) error {
			if !fired && e.Record.Id == rootId {
				fired = true

				fresh, err := e.App.FindAuthSessionById(rootId)
				if err != nil {
					t.Fatal(err)
				}
				if err := fresh.End(); err != nil {
					t.Fatal(err)
				}
				if err := e.App.Save(fresh); err != nil {
					t.Fatal(err)
				}
			}

			return e.Next()
		},
	})

	res := b.authorize(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, map[string]string{
		"redirect_uri": oauth2TestDashboardCallback,
	})
	if !fired {
		t.Fatal("Expected the concurrent logout to be simulated")
	}

	// must ask for credentials instead of issuing a code
	oauth2ExpectRedirect(t, res, "/oauth2/_superusers/login?", map[string]string{"auth_state": "*", "code": ""})

	if root := oauth2ReloadSession(t, app, rootId); root.Status() != core.AuthSessionStatusEnded {
		t.Fatalf("Expected the root SSO session to stay ended, got %q", root.Status())
	}

	if _, ok := b.cookies["pb_session"]; ok {
		t.Fatal("Expected the stale pb_session cookie to be cleared")
	}
}

// TestOAuth2LogoutConcurrentSSOAuthorizePromptNone checks the prompt=none variant of the race above.
func TestOAuth2LogoutConcurrentSSOAuthorizePromptNone(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2PrepareIssuer(t, app, "users")
	oauth2StubClient(t, app, "users", "app", oauth2FirstParty)

	record := oauth2FindRecord(t, app, "users", "test@example.com")
	cookie, root := oauth2StubSSO(t, app, record, types.NowDateTime())

	fired := false
	app.OnRecordUpdate(core.CollectionNameAuthSessions).BindFunc(func(e *core.RecordEvent) error {
		if !fired && e.Record.Id == root.Id {
			fired = true
			fresh, _ := e.App.FindAuthSessionById(root.Id)
			_ = fresh.End()
			if err := e.App.Save(fresh); err != nil {
				t.Fatal(err)
			}
		}
		return e.Next()
	})

	b := newOAuth2Browser(t, app)
	res, _ := b.do(http.MethodGet, oauth2AuthorizeURL("users", "app", map[string]string{"prompt": "none"}), "", map[string]string{"Cookie": cookie})

	b.expectError(res, "login_required")
}

// TestOAuth2LogoutEndsSSOAndDashboardSession checks the server-side logout guarantees:
// after the dashboard logout no authorize with the old SSO cookie can succeed
// silently and the (possibly in-flight) refresh of the dashboard session fails.
func TestOAuth2LogoutEndsSSOAndDashboardSession(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers)

	b := newOAuth2Browser(t, app)
	tokens := oauth2DashboardLogin(t, b)

	oldCookie := b.cookies["pb_session"]
	refreshToken, _ := tokens["refresh_token"].(string)
	idToken, _ := tokens["id_token"].(string)
	accessToken, _ := tokens["access_token"].(string)
	if oldCookie == "" || refreshToken == "" || idToken == "" {
		t.Fatalf("Missing SSO cookie or tokens: %v", tokens)
	}

	// the dashboard logout navigation (RP-initiated logout with id_token_hint)
	logoutURL := "/oauth2/_superusers/logout?" + url.Values{
		"client_id":                {core.OAuth2DashboardClientId},
		"post_logout_redirect_uri": {oauth2TestDashboardCallback},
		"id_token_hint":            {idToken},
	}.Encode()
	res, body := b.get(logoutURL)
	if res.StatusCode != http.StatusFound || !strings.HasPrefix(res.Header.Get("Location"), oauth2TestDashboardCallback) {
		t.Fatalf("Expected logout redirect, got %d %q %s", res.StatusCode, res.Header.Get("Location"), body)
	}

	// authorize with the old SSO cookie (e.g. a request already in flight before the cookie was cleared)
	stale := b.clone(false)
	stale.cookies["pb_session"] = oldCookie
	res = stale.authorize(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, map[string]string{
		"redirect_uri": oauth2TestDashboardCallback,
	})
	oauth2ExpectRedirect(t, res, "/oauth2/_superusers/login?", map[string]string{"auth_state": "*", "code": ""})

	// the in-flight background refresh
	res, data := b.tokenRequest(core.CollectionNameSuperusers, map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     core.OAuth2DashboardClientId,
		"refresh_token": refreshToken,
	})
	if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" {
		t.Fatalf("Expected invalid_grant refresh after logout, got %d %v", res.StatusCode, data)
	}

	// the old access token
	if _, err := app.FindAuthRecordByToken(accessToken, core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the access token to be rejected after logout")
	}
}

// TestOAuth2CodeExchangeConcurrentEnd checks that a session ended between the
// code consumption and the token issue (e.g. concurrent password change) is not reactivated.
func TestOAuth2CodeExchangeConcurrentEnd(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2PrepareIssuer(t, app, "users")
	client := oauth2StubClient(t, app, "users", "app")
	record := oauth2FindRecord(t, app, "users", "test@example.com")

	session := oauth2StubAuthorizedSession(t, app, client, record, "test_code", []string{"openid", "offline_access"})

	app.OnOAuth2TokenRequest().BindFunc(func(e *core.OAuth2TokenRequestEvent) error {
		fresh, _ := e.App.FindAuthSessionById(session.Id)
		_ = fresh.End()
		if err := e.App.Save(fresh); err != nil {
			t.Fatal(err)
		}
		return e.Next()
	})

	b := newOAuth2Browser(t, app)
	res, data := b.exchange("users", "app", "test_code", nil)
	if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" || data["access_token"] != nil {
		t.Fatalf("Expected invalid_grant, got %d %v", res.StatusCode, data)
	}

	if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusEnded {
		t.Fatalf("Expected the session to stay ended, got %q", s.Status())
	}
}
