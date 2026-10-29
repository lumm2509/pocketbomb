package apis_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocketbase/dbx"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
)

func basicAuth(clientId, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(clientId)+":"+url.QueryEscape(secret)))
}

// oauth2LazyBody is a request body which content could be set
// after the scenario initialization (e.g. in BeforeTestFunc).
type oauth2LazyBody struct {
	content string
	reader  *strings.Reader
}

func (b *oauth2LazyBody) Read(p []byte) (int, error) {
	if b.reader == nil {
		b.reader = strings.NewReader(b.content)
	}
	return b.reader.Read(p)
}

func TestOAuth2ServerTokenClientAuth(t *testing.T) {
	t.Parallel()

	scenario := func(name string, body map[string]string, headers map[string]string, status int, content ...string) tests.ApiScenario {
		return tests.ApiScenario{
			Name:    name,
			Method:  http.MethodPost,
			URL:     "/oauth2/users/token",
			Body:    strings.NewReader(oauth2Form(body)),
			Headers: oauth2FormHeaders(headers),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2AuthorizeSetup(t, app)
			},
			ExpectedStatus:  status,
			ExpectedContent: content,
			ExpectedEvents:  map[string]int{"*": 0},
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "non-auth collection",
			Method:          http.MethodPost,
			URL:             "/oauth2/demo1/token",
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		scenario("missing client", map[string]string{"grant_type": "authorization_code"}, nil, 401, `"error":"invalid_client"`),
		scenario("unknown client", map[string]string{"client_id": "missing", "grant_type": "authorization_code"}, nil, 401, `"error":"invalid_client"`),
		scenario("disabled client", map[string]string{"client_id": "disabled", "grant_type": "authorization_code"}, nil, 401, `"error":"invalid_client"`),
		scenario("client of another collection", map[string]string{"client_id": "other", "grant_type": "authorization_code"}, nil, 401, `"error":"invalid_client"`),
		scenario("public client with secret", map[string]string{"client_id": "app", "client_secret": "abc", "grant_type": "authorization_code"}, nil, 401, `"error":"invalid_client"`),
		scenario("confidential client without secret", map[string]string{"client_id": "conf", "grant_type": "authorization_code"}, nil, 401, `"error":"invalid_client"`),
		scenario("confidential client with invalid secret", map[string]string{"client_id": "conf", "client_secret": "invalid", "grant_type": "authorization_code"}, nil, 401, `"error":"invalid_client"`),
		scenario("confidential client with invalid basic auth", map[string]string{"grant_type": "authorization_code"}, map[string]string{"Authorization": basicAuth("conf", "invalid")}, 401, `"error":"invalid_client"`),
		scenario("multiple client auth methods", map[string]string{"client_secret": "secret_conf", "grant_type": "authorization_code"}, map[string]string{"Authorization": basicAuth("conf", "secret_conf")}, 400, `"error":"invalid_request"`),
		scenario("mismatched client_id", map[string]string{"client_id": "app", "grant_type": "authorization_code"}, map[string]string{"Authorization": basicAuth("conf", "secret_conf")}, 401, `"error":"invalid_client"`),
		scenario("valid public client (missing grant_type)", map[string]string{"client_id": "app"}, nil, 400, `"error":"invalid_request"`),
		scenario("valid confidential client post (unsupported grant)", map[string]string{"client_id": "conf", "client_secret": "secret_conf", "grant_type": "password"}, nil, 400, `"error":"unsupported_grant_type"`),
		scenario("valid confidential client basic (client_credentials allowed only for the applications managed clients)", map[string]string{"grant_type": "client_credentials"}, map[string]string{"Authorization": basicAuth("conf", "secret_conf")}, 400, `"error":"unauthorized_client"`),
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestOAuth2ServerTokenAuthorizationCode(t *testing.T) {
	t.Parallel()

	type scenario struct {
		name    string
		client  string
		code    string
		extra   map[string]string
		modify  func(s *core.AuthSession)
		status  int
		error   string
		consume bool // whether the code is expected to be consumed
	}

	scenarios := []scenario{
		{name: "missing code", client: "app", code: "", status: 400, error: "invalid_request"},
		{name: "missing redirect_uri", client: "app", code: "test_code", extra: map[string]string{"redirect_uri": ""}, status: 400, error: "invalid_request"},
		{name: "unknown code", client: "app", code: "unknown", status: 400, error: "invalid_grant"},
		{name: "code of another client", client: "3p", code: "test_code", status: 400, error: "invalid_grant"},
		{name: "expired code", client: "app", code: "test_code", modify: func(s *core.AuthSession) {
			s.SetCode("test_code", types.NowDateTime().Add(-time.Second))
		}, status: 400, error: "invalid_grant"},
		{name: "expired session", client: "app", code: "test_code", modify: func(s *core.AuthSession) {
			s.SetExpiresAt(types.NowDateTime().Add(-time.Second))
		}, status: 400, error: "invalid_grant"},
		{name: "redirect_uri mismatch", client: "app", code: "test_code", extra: map[string]string{"redirect_uri": "https://example.com/other"}, status: 400, error: "invalid_grant"},
		{name: "missing PKCE code_verifier", client: "app", code: "test_code", extra: map[string]string{"code_verifier": ""}, status: 400, error: "invalid_grant"},
		{name: "invalid PKCE code_verifier", client: "app", code: "test_code", extra: map[string]string{"code_verifier": oauth2TestCodeVerifier + "x"}, status: 400, error: "invalid_grant"},
		{name: "plain PKCE method stored", client: "app", code: "test_code", modify: func(s *core.AuthSession) {
			s.SetCodeChallenge(oauth2TestCodeVerifier, "plain")
		}, extra: map[string]string{"code_verifier": oauth2TestCodeVerifier}, status: 400, error: "invalid_grant"},
		{name: "valid", client: "app", code: "test_code", status: 200, consume: true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app, _ := tests.NewTestApp()
			defer app.Cleanup()

			oauth2AuthorizeSetup(t, app)

			user := oauth2FindRecord(t, app, "users", "test@example.com")
			session := oauth2StubAuthorizedSession(t, app, oauth2FindClient(t, app, "app"), user, "test_code", []string{"openid", "email"}, func(as *core.AuthSession) {
				if s.modify != nil {
					s.modify(as)
				}
			})

			b := newOAuth2Browser(t, app)
			res, data := b.exchange("users", s.client, s.code, s.extra)
			b.expectStatus(res, "", s.status)

			if s.error != "" && data["error"] != s.error {
				t.Fatalf("Expected error %q, got %v", s.error, data)
			}

			if res.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("Expected no-store cache header")
			}

			fresh := oauth2ReloadSession(t, app, session.Id)
			if fresh.CodeConsumed() != s.consume {
				t.Fatalf("Expected code consumed %v, got %v", s.consume, fresh.CodeConsumed())
			}

			if !s.consume {
				// the failed attempts don't end or activate the session
				if fresh.Status() != core.AuthSessionStatusAuthorized {
					t.Fatalf("Expected authorized session, got %q", fresh.Status())
				}
				return
			}

			if fresh.Status() != core.AuthSessionStatusActive {
				t.Fatalf("Expected active session, got %q", fresh.Status())
			}

			// every session has a refresh token family (the stub session has no root
			// so it is bounded only by the RefreshTokenDuration)
			if rt, _ := data["refresh_token"].(string); rt == "" || !fresh.ValidateRefreshToken(rt) {
				t.Fatalf("Expected refresh token, got %v", data)
			}

			// id_token
			idToken, _ := data["id_token"].(string)
			users, _ := app.FindCollectionByNameOrId("users")
			jwks, _ := users.OAuth2Server.JWKS()
			claims, err := security.ParseSignedJWT(idToken, jwks)
			if err != nil {
				t.Fatalf("Expected valid id_token, got %v", err)
			}
			if claims["sid"] != session.Id || claims["nonce"] != "test_nonce" || claims["aud"] != "app" || claims["sub"] != user.Id || claims["iss"] != oauth2TestIssuer || claims["email"] != user.Email() {
				t.Fatalf("Unexpected id_token claims %v", claims)
			}
			if _, ok := claims["auth_time"]; !ok {
				t.Fatal("Expected auth_time claim")
			}

			// access token claims
			accessToken, _ := data["access_token"].(string)
			accessClaims, _ := security.ParseUnverifiedJWT(accessToken)
			for k, v := range map[string]any{
				core.TokenClaimType:            core.TokenTypeAuth,
				core.TokenClaimId:              user.Id,
				core.TokenClaimCollectionId:    user.Collection().Id,
				core.TokenClaimOAuth2ClientId:  "app",
				core.TokenClaimOAuth2Scope:     "openid email",
				core.TokenClaimOAuth2SessionId: session.Id,
			} {
				if accessClaims[k] != v {
					t.Fatalf("Expected access token claim %q = %v, got %v", k, v, accessClaims[k])
				}
			}

			// the session expires with its refresh token family
			if d := time.Until(fresh.ExpiresAt().Time()) - users.OAuth2Server.RefreshTokenDurationTime(); d > 5*time.Second || d < -5*time.Second {
				t.Fatalf("Expected session expiration ~RefreshTokenDuration, got %v", fresh.ExpiresAt())
			}
			if !fresh.RefreshExpiresAt().Time().Equal(fresh.ExpiresAt().Time()) {
				t.Fatal("Expected the session expiration to match the refresh token family expiration")
			}
		})
	}
}

func TestOAuth2ServerTokenPKCEFailureDoesNotBurnCode(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	oauth2StubAuthorizedSession(t, app, oauth2FindClient(t, app, "app"), user, "test_code", []string{"openid"})

	b := newOAuth2Browser(t, app)

	// an attacker with a stolen code but without the verifier
	res, _ := b.exchange("users", "app", "test_code", map[string]string{"code_verifier": "wrong_verifier_0123456789_0123456789_abcdefgh"})
	b.expectStatus(res, "", http.StatusBadRequest)

	// the legit client could still exchange the code
	res, _ = b.exchange("users", "app", "test_code", nil)
	b.expectStatus(res, "", http.StatusOK)
}

func TestOAuth2ServerTokenCodeReuse(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	session := oauth2StubAuthorizedSession(t, app, oauth2FindClient(t, app, "app"), user, "test_code", []string{"openid", "offline_access"})

	b := newOAuth2Browser(t, app)

	res, data := b.exchange("users", "app", "test_code", nil)
	b.expectStatus(res, "", http.StatusOK)
	accessToken, _ := data["access_token"].(string)
	refreshToken, _ := data["refresh_token"].(string)

	if _, err := app.FindAuthRecordByToken(accessToken, core.TokenTypeAuth); err != nil {
		t.Fatalf("Expected valid access token, got %v", err)
	}

	// another client can't use the code (and it doesn't end the session)
	res, data = b.exchange("users", "3p", "test_code", nil)
	if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" {
		t.Fatalf("Expected invalid_grant, got %d %v", res.StatusCode, data)
	}
	if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusActive {
		t.Fatalf("Expected the session to remain active, got %q", s.Status())
	}

	// reuse -> the session is ended
	res, data = b.exchange("users", "app", "test_code", nil)
	if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" {
		t.Fatalf("Expected invalid_grant, got %d %v", res.StatusCode, data)
	}

	if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusEnded {
		t.Fatalf("Expected ended session after code reuse, got %q", s.Status())
	}

	if _, err := app.FindAuthRecordByToken(accessToken, core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the access token to be invalid after code reuse")
	}

	res, data = b.tokenRequest("users", map[string]string{"grant_type": "refresh_token", "client_id": "app", "refresh_token": refreshToken})
	if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" {
		t.Fatalf("Expected the refresh token to be invalid after code reuse, got %d %v", res.StatusCode, data)
	}
}

func TestOAuth2ServerTokenRefresh(t *testing.T) {
	t.Parallel()

	t.Run("rotation and reuse detection", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		session := oauth2StubRefreshSession(t, app, oauth2FindClient(t, app, "app"), user, []string{"openid", "email", "offline_access"}, "rt1")

		b := newOAuth2Browser(t, app)

		refresh := func(token string, extra map[string]string) (*http.Response, map[string]any) {
			values := map[string]string{"grant_type": "refresh_token", "client_id": "app", "refresh_token": token}
			for k, v := range extra {
				values[k] = v
			}
			return b.tokenRequest("users", values)
		}

		res, data := refresh("", nil)
		if res.StatusCode != 400 || data["error"] != "invalid_request" {
			t.Fatalf("Expected invalid_request, got %v", data)
		}

		// scope exceeding the granted ones
		res, data = refresh("rt1", map[string]string{"scope": "openid profile"})
		if res.StatusCode != 400 || data["error"] != "invalid_scope" {
			t.Fatalf("Expected invalid_scope, got %v", data)
		}

		// another client
		res, data = b.tokenRequest("users", map[string]string{"grant_type": "refresh_token", "client_id": "3p", "refresh_token": "rt1"})
		if res.StatusCode != 400 || data["error"] != "invalid_grant" {
			t.Fatalf("Expected invalid_grant for another client, got %v", data)
		}

		res, data = refresh("rt1", map[string]string{"scope": "openid"})
		b.expectStatus(res, "", http.StatusOK)
		rt2, _ := data["refresh_token"].(string)
		at2, _ := data["access_token"].(string)
		if rt2 == "" || rt2 == "rt1" || at2 == "" || data["id_token"] == "" || data["scope"] != "openid email offline_access" {
			t.Fatalf("Unexpected refresh response %v", data)
		}

		fresh := oauth2ReloadSession(t, app, session.Id)
		if !fresh.ValidateRefreshToken(rt2) || fresh.ValidateRefreshToken("rt1") {
			t.Fatal("Expected the refresh token to be rotated")
		}

		res, data = refresh(rt2, nil)
		b.expectStatus(res, "", http.StatusOK)
		rt3, _ := data["refresh_token"].(string)

		// the latest rotated token (rt2) reuse outside of the concurrent refresh
		// grace period -> the session is ended
		oauth2AgeRefreshRotation(t, app, session.Id, 11*time.Second)
		res, data = refresh(rt2, nil)
		if res.StatusCode != 400 || data["error"] != "invalid_grant" {
			t.Fatalf("Expected invalid_grant on reuse, got %v", data)
		}

		if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected ended session after refresh token reuse, got %q", s.Status())
		}

		// the current refresh token and the issued access tokens are no longer valid
		res, data = refresh(rt3, nil)
		if res.StatusCode != 400 || data["error"] != "invalid_grant" {
			t.Fatalf("Expected invalid_grant for the ended session, got %v", data)
		}
		if _, err := app.FindAuthRecordByToken(at2, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the access token to be invalid")
		}
	})

	t.Run("expired refresh token family", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		session := oauth2StubRefreshSession(t, app, oauth2FindClient(t, app, "app"), user, []string{"openid", "offline_access"}, "rt1")
		session.SetRefreshExpiresAt(types.NowDateTime().Add(-time.Second))
		if err := app.Save(session); err != nil {
			t.Fatal(err)
		}

		b := newOAuth2Browser(t, app)
		res, data := b.tokenRequest("users", map[string]string{"grant_type": "refresh_token", "client_id": "app", "refresh_token": "rt1"})
		if res.StatusCode != 400 || data["error"] != "invalid_grant" {
			t.Fatalf("Expected invalid_grant, got %v", data)
		}
	})

	t.Run("full flow with offline_access", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", map[string]string{"scope": "openid offline_access"})
		code := b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)

		_, data := b.exchange("users", "app", code, nil)
		rt, _ := data["refresh_token"].(string)

		session := b.sessionByCode(code)
		users, _ := app.FindCollectionByNameOrId("users")
		if d := time.Until(session.RefreshExpiresAt().Time()) - users.OAuth2Server.RefreshTokenDurationTime(); d > 5*time.Second || d < -5*time.Second {
			t.Fatalf("Expected refresh expiration ~RefreshTokenDuration, got %v", session.RefreshExpiresAt())
		}

		res, data := b.tokenRequest("users", map[string]string{"grant_type": "refresh_token", "client_id": "app", "refresh_token": rt})
		b.expectStatus(res, "", http.StatusOK)
	})
}

func TestOAuth2ServerTokenHooks(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	oauth2StubAuthorizedSession(t, app, oauth2FindClient(t, app, "app"), user, "code1", []string{"openid"})
	oauth2StubAuthorizedSession(t, app, oauth2FindClient(t, app, "app"), user, "code2", []string{"openid"})

	app.OnOAuth2TokenRequest("users").BindFunc(func(e *core.OAuth2TokenRequestEvent) error {
		if e.Session == nil || e.Session.RecordRef() != user.Id || e.GrantType != "authorization_code" {
			t.Errorf("Unexpected token event data")
		}
		if e.Session.Nonce() == "reject" {
			return errors.New("rejected")
		}
		e.IdTokenClaims["custom"] = "abc"
		return e.Next()
	})

	b := newOAuth2Browser(t, app)

	res, data := b.exchange("users", "app", "code1", nil)
	b.expectStatus(res, "", http.StatusOK)
	idClaims, _ := security.ParseUnverifiedJWT(data["id_token"].(string))
	if idClaims["custom"] != "abc" {
		t.Fatalf("Expected custom id_token claim, got %v", idClaims)
	}

	s2, _ := app.FindAuthSessionByCode("code2")
	s2.SetNonce("reject")
	if err := app.Save(s2); err != nil {
		t.Fatal(err)
	}
	res, _ = b.exchange("users", "app", "code2", nil)
	if res.StatusCode == http.StatusOK {
		t.Fatal("Expected the hook to reject the token request")
	}
}

func TestOAuth2ServerTokenExchangeImpersonation(t *testing.T) {
	t.Parallel()

	setup := func(t testing.TB) (*tests.TestApp, *oauth2Browser) {
		app, _ := tests.NewTestApp()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers)
		oauth2StubClient(t, app, core.CollectionNameSuperusers, "dashboard", oauth2FirstParty, func(c *core.OAuth2Client) {
			c.SetScopes([]string{"openid", "email"})
		})

		return app, newOAuth2Browser(t, app)
	}

	exchange := func(b *oauth2Browser, actorToken string, extra map[string]string) (*http.Response, map[string]any) {
		values := map[string]string{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"client_id":          "app",
			"subject_token":      "4q1xlclmfloku33",
			"subject_token_type": "urn:pocketbase:params:oauth:token-type:record_id",
			"actor_token":        actorToken,
			"actor_token_type":   "urn:ietf:params:oauth:token-type:access_token",
		}
		for k, v := range extra {
			if v == "" {
				delete(values, k)
			} else {
				values[k] = v
			}
		}
		return b.tokenRequest("users", values)
	}

	t.Run("Owner (superuser) actor", func(t *testing.T) {
		app, b := setup(t)
		defer app.Cleanup()

		superuser := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")

		// sid backed staff token
		staffToken, _ := oauth2AccessToken(t, app, oauth2FindClient(t, app, "dashboard"), superuser, []string{"openid"})

		for name, actor := range map[string]string{
			"session staff token":      staffToken,
			"pb_dashboard staff token": oauth2TestSuperuserToken,
		} {
			res, data := exchange(b, actor, map[string]string{"scope": "openid email"})
			if res.StatusCode != http.StatusOK {
				t.Fatalf("[%s] Expected 200, got %d %v", name, res.StatusCode, data)
			}

			if data["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" || data["token_type"] != "Bearer" || data["scope"] != "openid email" {
				t.Fatalf("[%s] Unexpected response %v", name, data)
			}
			if _, ok := data["refresh_token"]; ok {
				t.Fatalf("[%s] Expected no refresh token", name)
			}
			if _, ok := data["id_token"]; ok {
				t.Fatalf("[%s] Expected no id_token", name)
			}

			token, _ := data["access_token"].(string)
			claims, _ := security.ParseUnverifiedJWT(token)
			act, _ := claims["act"].(map[string]any)
			if act["sub"] != superuser.Id || claims["id"] != "4q1xlclmfloku33" || claims["cid"] != "app" {
				t.Fatalf("[%s] Unexpected impersonation token claims %v", name, claims)
			}

			session := oauth2ReloadSession(t, app, claims["sid"].(string))
			if session.Impersonator() != superuser.Id || !session.HasAuthMethod(core.AuthSessionMethodImpersonation) || !session.IsActive() {
				t.Fatalf("[%s] Unexpected impersonation session %v", name, session.PublicExport())
			}

			record, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth)
			if err != nil || record.Id != "4q1xlclmfloku33" {
				t.Fatalf("[%s] Expected valid impersonation token, got %v", name, err)
			}

			res, body := b.do(http.MethodGet, "/api/collections/users/records/4q1xlclmfloku33", "", map[string]string{"Authorization": token})
			b.expectStatus(res, body, http.StatusOK)
		}
	})

	t.Run("rejected actors and params", func(t *testing.T) {
		app, b := setup(t)
		defer app.Cleanup()

		user := oauth2FindRecord(t, app, "users", "test2@example.com")
		userToken, _ := oauth2AccessToken(t, app, oauth2FindClient(t, app, "app"), user, []string{"openid"})

		superuser := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		endedStaffToken, endedStaffSession := oauth2AccessToken(t, app, oauth2FindClient(t, app, "dashboard"), superuser, []string{"openid"})
		_ = endedStaffSession.End()
		if err := app.Save(endedStaffSession); err != nil {
			t.Fatal(err)
		}

		scenarios := []struct {
			name   string
			actor  string
			extra  map[string]string
			status int
			error  string
		}{
			{"non-superuser actor", userToken, nil, 400, "invalid_grant"},
			{"sid-less superuser actor (valid signature)", oauth2SidlessToken(t, superuser), nil, 400, "invalid_grant"},
			{"ended staff session actor", endedStaffToken, nil, 400, "invalid_grant"},
			{"invalid actor token", "invalid", nil, 400, "invalid_grant"},
			{"missing actor token", "", map[string]string{"actor_token": ""}, 400, "invalid_request"},
			{"invalid actor token type", oauth2TestSuperuserToken, map[string]string{"actor_token_type": "urn:ietf:params:oauth:token-type:jwt"}, 400, "invalid_request"},
			{"missing subject", oauth2TestSuperuserToken, map[string]string{"subject_token": ""}, 400, "invalid_request"},
			{"unsupported subject type", oauth2TestSuperuserToken, map[string]string{"subject_token_type": "urn:ietf:params:oauth:token-type:access_token"}, 400, "invalid_request"},
			{"unknown subject", oauth2TestSuperuserToken, map[string]string{"subject_token": "missing"}, 400, "invalid_grant"},
			{"subject of another collection", oauth2TestSuperuserToken, map[string]string{"subject_token": superuser.Id}, 400, "invalid_grant"},
			{"unsupported requested token type", oauth2TestSuperuserToken, map[string]string{"requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token"}, 400, "invalid_request"},
			{"scope not allowed for the client", oauth2TestSuperuserToken, map[string]string{"client_id": "3p", "scope": "unknown"}, 400, "invalid_scope"},
		}

		for _, s := range scenarios {
			res, data := exchange(b, s.actor, s.extra)
			if res.StatusCode != s.status || data["error"] != s.error {
				t.Fatalf("[%s] Expected %d %q, got %d %v", s.name, s.status, s.error, res.StatusCode, data)
			}
		}

		// no impersonation sessions were created
		total := 0
		sessions, _ := app.FindAllRecords(core.CollectionNameAuthSessions)
		for _, s := range sessions {
			if s.GetString("impersonator") != "" {
				total++
			}
		}
		if total != 0 {
			t.Fatalf("Expected no impersonation sessions, got %d", total)
		}
	})
}

func TestOAuth2ServerRefreshTokenBoundedByRoot(t *testing.T) {
	t.Parallel()

	// login + code exchange; returns the token response and the flow session
	login := func(t testing.TB, app *tests.TestApp, b *oauth2Browser, scope string) (map[string]any, *core.AuthSession) {
		b.startLogin("users", "app", map[string]string{"scope": scope})
		code := b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)
		session := b.sessionByCode(code)
		res, data := b.exchange("users", "app", code, nil)
		b.expectStatus(res, "", http.StatusOK)
		return data, oauth2ReloadSession(t, app, session.Id)
	}

	refresh := func(b *oauth2Browser, token string) (*http.Response, map[string]any) {
		return b.tokenRequest("users", map[string]string{"grant_type": "refresh_token", "client_id": "app", "refresh_token": token})
	}

	t.Run("non-offline session family ends with the root (logout)", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		data, session := login(t, app, b, "openid email")

		rt, _ := data["refresh_token"].(string)
		if rt == "" {
			t.Fatalf("Expected refresh token for the non-offline session, got %v", data)
		}

		root := oauth2ReloadSession(t, app, session.Parent())
		if !root.IsRoot() {
			t.Fatal("Expected the session parent to be the root SSO session")
		}

		// SessionDuration (14d) < RefreshTokenDuration (30d) -> bounded by the root
		if !session.RefreshExpiresAt().Time().Equal(root.ExpiresAt().Time()) {
			t.Fatalf("Expected the refresh family expiration %v to match the root expiration %v", session.RefreshExpiresAt(), root.ExpiresAt())
		}

		res, data := refresh(b, rt)
		b.expectStatus(res, "", http.StatusOK)
		rt2, _ := data["refresh_token"].(string)

		// logout -> the root and its non-offline children end
		b.get("/oauth2/users/logout")
		b.submit("/oauth2/users/logout", nil)

		res, data = refresh(b, rt2)
		if res.StatusCode != 400 || data["error"] != "invalid_grant" {
			t.Fatalf("Expected invalid_grant after the SSO logout, got %d %v", res.StatusCode, data)
		}
	})

	t.Run("non-offline session family ends with the root expiration", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		data, session := login(t, app, b, "openid")
		rt, _ := data["refresh_token"].(string)

		// expire the root without ending it (aka. no cascade)
		root := oauth2ReloadSession(t, app, session.Parent())
		root.SetExpiresAt(types.NowDateTime().Add(-time.Second))
		if err := app.Save(root); err != nil {
			t.Fatal(err)
		}

		res, data := refresh(b, rt)
		if res.StatusCode != 400 || data["error"] != "invalid_grant" {
			t.Fatalf("Expected invalid_grant for expired root, got %d %v", res.StatusCode, data)
		}

		// the refresh token is no longer introspectable as active
		res, body := b.do(http.MethodPost, "/oauth2/users/introspect", oauth2Form(map[string]string{"token": rt}), oauth2FormHeaders(map[string]string{"Authorization": basicAuth("conf", "secret_conf")}))
		if !strings.Contains(body, `"active":false`) {
			t.Fatalf("Expected inactive refresh token, got %d %s", res.StatusCode, body)
		}
	})

	t.Run("shorter RefreshTokenDuration than the root", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
			c.OAuth2Server.RefreshTokenDuration = 600
		})

		b := newOAuth2Browser(t, app)
		_, session := login(t, app, b, "openid")

		if d := time.Until(session.RefreshExpiresAt().Time()) - 600*time.Second; d > 5*time.Second || d < -5*time.Second {
			t.Fatalf("Expected refresh family expiration ~600s, got %v", session.RefreshExpiresAt())
		}
	})

	t.Run("offline_access session has its own duration and survives the root", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		data, session := login(t, app, b, "openid offline_access")
		rt, _ := data["refresh_token"].(string)

		users, _ := app.FindCollectionByNameOrId("users")
		if d := time.Until(session.RefreshExpiresAt().Time()) - users.OAuth2Server.RefreshTokenDurationTime(); d > 5*time.Second || d < -5*time.Second {
			t.Fatalf("Expected refresh family expiration ~RefreshTokenDuration, got %v", session.RefreshExpiresAt())
		}

		root := oauth2ReloadSession(t, app, session.Parent())
		_ = root.End()
		if err := app.Save(root); err != nil {
			t.Fatal(err)
		}

		res, data := refresh(b, rt)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected the offline_access refresh to work after the root ended, got %d %v", res.StatusCode, data)
		}
	})
}

// oauth2AgeRefreshRotation moves the last refresh token rotation time of the specified session back in time.
func oauth2AgeRefreshRotation(t testing.TB, app core.App, sessionId string, age time.Duration) {
	t.Helper()

	_, err := app.DB().Update(
		core.CollectionNameAuthSessions,
		dbx.Params{"refreshRotatedAt": types.NowDateTime().Add(-age).String()},
		dbx.HashExp{"id": sessionId},
	).Execute()
	if err != nil {
		t.Fatal(err)
	}
}

func TestOAuth2ServerRefreshGraceWindow(t *testing.T) {
	t.Parallel()

	setup := func(t testing.TB, refreshToken string) (*tests.TestApp, *oauth2Browser, *core.AuthSession) {
		app, _ := tests.NewTestApp()
		oauth2AuthorizeSetup(t, app)

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		session := oauth2StubRefreshSession(t, app, oauth2FindClient(t, app, "app"), user, []string{"openid", "email"}, refreshToken)

		return app, newOAuth2Browser(t, app), session
	}

	refresh := func(b *oauth2Browser, clientId string, token string) (*http.Response, map[string]any) {
		return b.tokenRequest("users", map[string]string{"grant_type": "refresh_token", "client_id": clientId, "refresh_token": token})
	}

	rotate := func(t testing.TB, b *oauth2Browser, token string) string {
		t.Helper()

		res, data := refresh(b, "app", token)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected successful refresh, got %d %v", res.StatusCode, data)
		}

		rt, _ := data["refresh_token"].(string)
		if rt == "" {
			t.Fatalf("Missing rotated refresh token %v", data)
		}

		return rt
	}

	expectInvalidGrant := func(t testing.TB, res *http.Response, data map[string]any) {
		t.Helper()

		if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" {
			t.Fatalf("Expected invalid_grant, got %d %v", res.StatusCode, data)
		}
	}

	expectStatus := func(t testing.TB, app core.App, sessionId string, status string) {
		t.Helper()

		if s := oauth2ReloadSession(t, app, sessionId); s.Status() != status {
			t.Fatalf("Expected session status %q, got %q", status, s.Status())
		}
	}

	t.Run("rotation time is stored", func(t *testing.T) {
		app, b, session := setup(t, "rt1")
		defer app.Cleanup()

		if !session.RefreshRotatedAt().IsZero() {
			t.Fatal("Expected no rotation time before the first rotation")
		}

		rotate(t, b, "rt1")

		fresh := oauth2ReloadSession(t, app, session.Id)
		if d := time.Since(fresh.RefreshRotatedAt().Time()); d < 0 || d > 5*time.Second {
			t.Fatalf("Expected recent rotation time, got %v", fresh.RefreshRotatedAt())
		}
	})

	t.Run("previous token inside the window (same client and session)", func(t *testing.T) {
		app, b, session := setup(t, "rt1")
		defer app.Cleanup()

		rt2 := rotate(t, b, "rt1")

		res, data := refresh(b, "app", "rt1")
		expectInvalidGrant(t, res, data)
		expectStatus(t, app, session.Id, core.AuthSessionStatusActive)

		// the current refresh token still works
		rt3 := rotate(t, b, rt2)

		// and the grace applies again to the just rotated token
		res, data = refresh(b, "app", rt2)
		expectInvalidGrant(t, res, data)
		expectStatus(t, app, session.Id, core.AuthSessionStatusActive)

		rotate(t, b, rt3)
	})

	t.Run("previous token outside the window", func(t *testing.T) {
		app, b, session := setup(t, "rt1")
		defer app.Cleanup()

		rt2 := rotate(t, b, "rt1")
		oauth2AgeRefreshRotation(t, app, session.Id, 11*time.Second)

		res, data := refresh(b, "app", "rt1")
		expectInvalidGrant(t, res, data)
		expectStatus(t, app, session.Id, core.AuthSessionStatusEnded)

		res, data = refresh(b, "app", rt2)
		expectInvalidGrant(t, res, data)
	})

	t.Run("previous token inside the window but by another client", func(t *testing.T) {
		app, b, session := setup(t, "rt1")
		defer app.Cleanup()

		rotate(t, b, "rt1")

		// "3p" is another (public) client of the same issuer
		res, data := refresh(b, "3p", "rt1")
		expectInvalidGrant(t, res, data)
		expectStatus(t, app, session.Id, core.AuthSessionStatusEnded)
	})

	t.Run("previous token of another session", func(t *testing.T) {
		app, b, sessionA := setup(t, "a1")
		defer app.Cleanup()

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		sessionB := oauth2StubRefreshSession(t, app, oauth2FindClient(t, app, "app"), user, []string{"openid"}, "b1")

		a2 := rotate(t, b, "a1")
		rotate(t, b, "b1")
		oauth2AgeRefreshRotation(t, app, sessionB.Id, time.Minute)

		// the recent rotation of session A doesn't cover the previous token of session B
		res, data := refresh(b, "app", "b1")
		expectInvalidGrant(t, res, data)
		expectStatus(t, app, sessionB.Id, core.AuthSessionStatusEnded)
		expectStatus(t, app, sessionA.Id, core.AuthSessionStatusActive)

		// session A previous token is still within its own window
		res, data = refresh(b, "app", "a1")
		expectInvalidGrant(t, res, data)
		expectStatus(t, app, sessionA.Id, core.AuthSessionStatusActive)

		rotate(t, b, a2)
	})

	t.Run("concurrent refreshes with the same token", func(t *testing.T) {
		app, _, session := setup(t, "rt1")
		defer app.Cleanup()

		const total = 5

		browsers := make([]*oauth2Browser, total)
		for i := range browsers {
			browsers[i] = newOAuth2Browser(t, app)
		}

		var wg sync.WaitGroup
		statuses := make([]int, total)
		for i := 0; i < total; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				res, _ := refresh(browsers[i], "app", "rt1")
				statuses[i] = res.StatusCode
			}(i)
		}
		wg.Wait()

		ok := 0
		for _, s := range statuses {
			switch s {
			case http.StatusOK:
				ok++
			case http.StatusBadRequest:
			default:
				t.Fatalf("Unexpected status %d (%v)", s, statuses)
			}
		}
		if ok != 1 {
			t.Fatalf("Expected exactly 1 successful refresh, got %v", statuses)
		}

		expectStatus(t, app, session.Id, core.AuthSessionStatusActive)
	})
}

func TestOAuth2ServerImpersonationTiedToImpersonator(t *testing.T) {
	t.Parallel()

	setup := func(t testing.TB) (*tests.TestApp, *oauth2Browser) {
		app, _ := tests.NewTestApp()

		oauth2AuthorizeSetup(t, app)
		oauth2StubClient(t, app, core.CollectionNameSuperusers, "dashboard", oauth2FirstParty, func(c *core.OAuth2Client) {
			c.SetScopes([]string{"openid", "email"})
		})

		return app, newOAuth2Browser(t, app)
	}

	exchange := func(t testing.TB, b *oauth2Browser, actorToken string) (string, *core.AuthSession) {
		t.Helper()

		res, data := b.tokenRequest("users", map[string]string{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"client_id":          "app",
			"subject_token":      "4q1xlclmfloku33",
			"subject_token_type": "urn:pocketbase:params:oauth:token-type:record_id",
			"actor_token":        actorToken,
			"actor_token_type":   "urn:ietf:params:oauth:token-type:access_token",
			"scope":              "openid",
		})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected successful token exchange, got %d %v", res.StatusCode, data)
		}

		token, _ := data["access_token"].(string)
		claims, _ := security.ParseUnverifiedJWT(token)

		return token, oauth2ReloadSession(t, b.app, claims["sid"].(string))
	}

	expectValid := func(t testing.TB, app core.App, token string, valid bool) {
		t.Helper()

		_, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth)
		if valid && err != nil {
			t.Fatalf("Expected valid impersonation token, got %v", err)
		}
		if !valid && err == nil {
			t.Fatal("Expected the impersonation token to be rejected")
		}
	}

	staffToken := func(t testing.TB, app *tests.TestApp, staff *core.Record) (string, *core.AuthSession) {
		return oauth2AccessToken(t, app, oauth2FindClient(t, app, "dashboard"), staff, []string{"openid"})
	}

	t.Run("the impersonator session is stored", func(t *testing.T) {
		app, b := setup(t)
		defer app.Cleanup()

		staff := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		actor, actorSession := staffToken(t, app, staff)

		token, session := exchange(t, b, actor)
		if session.Impersonator() != staff.Id || session.ImpersonatorSession() != actorSession.Id {
			t.Fatalf("Expected impersonator %q/%q, got %q/%q", staff.Id, actorSession.Id, session.Impersonator(), session.ImpersonatorSession())
		}
		expectValid(t, app, token, true)

		// hidden field
		if _, ok := session.PublicExport()["impersonatorSession"]; ok {
			t.Fatal("Expected impersonatorSession to be hidden")
		}
	})

	t.Run("impersonator session ended (cascade)", func(t *testing.T) {
		app, b := setup(t)
		defer app.Cleanup()

		staff := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		actor, actorSession := staffToken(t, app, staff)
		token, session := exchange(t, b, actor)

		_ = actorSession.End()
		if err := app.Save(actorSession); err != nil {
			t.Fatal(err)
		}

		expectValid(t, app, token, false)
		if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the impersonation session to be ended by the cascade, got %q", s.Status())
		}

		res, body := b.do(http.MethodGet, "/api/collections/users/records/4q1xlclmfloku33", "", map[string]string{"Authorization": token})
		if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusNotFound && res.StatusCode != http.StatusForbidden {
			t.Fatalf("Expected rejected impersonation token, got %d %s", res.StatusCode, body)
		}
	})

	t.Run("impersonator root ended (logout cascade)", func(t *testing.T) {
		app, b := setup(t)
		defer app.Cleanup()

		staff := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		staffSession, err := tests.CreateAuthSession(app, staff)
		if err != nil {
			t.Fatal(err)
		}
		actor, err := staffSession.NewAccessToken()
		if err != nil {
			t.Fatal(err)
		}

		token, session := exchange(t, b, actor)
		expectValid(t, app, token, true)

		root := oauth2ReloadSession(t, app, staffSession.Parent())
		_ = root.End()
		if err := app.Save(root); err != nil {
			t.Fatal(err)
		}

		expectValid(t, app, token, false)
		if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the impersonation session to be ended by the cascade, got %q", s.Status())
		}
	})

	t.Run("impersonator session expired (no cascade)", func(t *testing.T) {
		app, b := setup(t)
		defer app.Cleanup()

		staff := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		actor, actorSession := staffToken(t, app, staff)
		token, _ := exchange(t, b, actor)

		actorSession.SetExpiresAt(types.NowDateTime().Add(-time.Second))
		if err := app.Save(actorSession); err != nil {
			t.Fatal(err)
		}

		expectValid(t, app, token, false)
	})

	t.Run("impersonator tokenKey changed", func(t *testing.T) {
		app, b := setup(t)
		defer app.Cleanup()

		staff := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		actor, _ := staffToken(t, app, staff)
		token, session := exchange(t, b, actor)

		staff.RefreshTokenKey()
		if err := app.Save(staff); err != nil {
			t.Fatal(err)
		}

		expectValid(t, app, token, false)
		if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the impersonation session to be ended by the cascade, got %q", s.Status())
		}
	})

	t.Run("impersonator tokenKey changed without hooks", func(t *testing.T) {
		app, b := setup(t)
		defer app.Cleanup()

		staff := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		actor, _ := staffToken(t, app, staff)
		token, _ := exchange(t, b, actor)

		// raw update (aka. the impersonator session is still active)
		_, err := app.DB().Update(core.CollectionNameSuperusers, dbx.Params{"tokenKey": security.RandomString(50)}, dbx.HashExp{"id": staff.Id}).Execute()
		if err != nil {
			t.Fatal(err)
		}

		expectValid(t, app, token, false)
	})

	t.Run("impersonator deleted", func(t *testing.T) {
		app, b := setup(t)
		defer app.Cleanup()

		staff := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test2@example.com")
		actor, _ := staffToken(t, app, staff)
		token, session := exchange(t, b, actor)
		expectValid(t, app, token, true)

		if err := app.Delete(staff); err != nil {
			t.Fatal(err)
		}

		expectValid(t, app, token, false)
		if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the impersonation session to be ended on the impersonator delete, got %q", s.Status())
		}
	})

	t.Run("impersonate permission revoked", func(t *testing.T) {
		app, b := setup(t)
		defer app.Cleanup()

		role, err := tests.CreateRole(app, "impersonators", core.Permissions{
			System: map[string]string{core.PermissionResourceImpersonate: core.PermissionLevelWrite},
		})
		if err != nil {
			t.Fatal(err)
		}
		staff, err := tests.CreateStaff(app, "impersonator@example.com", role.Id)
		if err != nil {
			t.Fatal(err)
		}

		actor, _ := staffToken(t, app, staff)
		token, _ := exchange(t, b, actor)
		expectValid(t, app, token, true)

		// role permission removed
		role.SetPermissions(core.Permissions{System: map[string]string{core.PermissionResourceLogs: core.PermissionLevelRead}})
		if err := app.Save(role); err != nil {
			t.Fatal(err)
		}
		expectValid(t, app, token, false)

		// restored
		role.SetPermissions(core.Permissions{System: map[string]string{core.PermissionResourceImpersonate: core.PermissionLevelWrite}})
		if err := app.Save(role); err != nil {
			t.Fatal(err)
		}
		expectValid(t, app, token, true)

		// role assignment removed
		assignments, err := app.FindAllRoleAssignmentsByRecord(staff)
		if err != nil || len(assignments) != 1 {
			t.Fatalf("Expected 1 role assignment, got %d (%v)", len(assignments), err)
		}
		if err := app.Delete(assignments[0]); err != nil {
			t.Fatal(err)
		}
		expectValid(t, app, token, false)
	})

	t.Run("Owner implicitly holds impersonate", func(t *testing.T) {
		app, b := setup(t)
		defer app.Cleanup()

		staff := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		if !app.IsOwnerRecord(staff) {
			t.Fatal("Expected Owner staff")
		}

		actor, _ := staffToken(t, app, staff)
		token, _ := exchange(t, b, actor)
		expectValid(t, app, token, true)
	})

	t.Run("programmatic impersonation requires a live impersonator session", func(t *testing.T) {
		app, _ := setup(t)
		defer app.Cleanup()

		staff := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		user := oauth2FindRecord(t, app, "users", "test2@example.com")
		client := oauth2FindClient(t, app, "app")

		_, err := app.CreateAuthSession(user, client, core.AuthSessionOptions{Scopes: []string{"openid"}, Impersonator: staff.Id})
		if err == nil {
			t.Fatal("Expected error for missing impersonator session")
		}

		_, endedSession := staffToken(t, app, staff)
		_ = endedSession.End()
		if err := app.Save(endedSession); err != nil {
			t.Fatal(err)
		}
		_, err = app.CreateAuthSession(user, client, core.AuthSessionOptions{Scopes: []string{"openid"}, Impersonator: staff.Id, ImpersonatorSession: endedSession.Id})
		if err == nil {
			t.Fatal("Expected error for ended impersonator session")
		}

		// another staff session
		other := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test2@example.com")
		_, otherSession := staffToken(t, app, other)
		_, err = app.CreateAuthSession(user, client, core.AuthSessionOptions{Scopes: []string{"openid"}, Impersonator: staff.Id, ImpersonatorSession: otherSession.Id})
		if err == nil {
			t.Fatal("Expected error for impersonator session of another staff member")
		}

		// legacy impersonation session without impersonator session (e.g. created before the migration)
		_, staffSession := staffToken(t, app, staff)
		legacy, err := app.CreateAuthSession(user, client, core.AuthSessionOptions{Scopes: []string{"openid"}, Impersonator: staff.Id, ImpersonatorSession: staffSession.Id})
		if err != nil {
			t.Fatal(err)
		}
		legacyToken, err := legacy.NewAccessToken()
		if err != nil {
			t.Fatal(err)
		}
		expectValid(t, app, legacyToken, true)
		if _, err := app.DB().Update(core.CollectionNameAuthSessions, dbx.Params{"impersonatorSession": ""}, dbx.HashExp{"id": legacy.Id}).Execute(); err != nil {
			t.Fatal(err)
		}
		expectValid(t, app, legacyToken, false)
	})
}

func TestOAuth2AttackCredentialsInQuery(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)

	b := newOAuth2Browser(t, app)
	b.startLogin("users", "conf", nil)
	code := b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)

	// all params (incl. the client secret and the code) in the URL query
	query := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"conf"},
		"client_secret": {"secret_conf"},
		"code":          {code},
		"redirect_uri":  {oauth2TestRedirectURI},
		"code_verifier": {oauth2TestCodeVerifier},
	}
	res, body := b.do(http.MethodPost, "/oauth2/users/token?"+query.Encode(), "x=1", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if res.StatusCode == http.StatusOK || strings.Contains(body, "access_token") {
		t.Fatalf("Expected the query credentials to be ignored, got %d %s", res.StatusCode, body)
	}

	// only the client secret in the query
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"conf"},
		"code":          {code},
		"redirect_uri":  {oauth2TestRedirectURI},
		"code_verifier": {oauth2TestCodeVerifier},
	}
	res, body = b.do(http.MethodPost, "/oauth2/users/token?client_secret=secret_conf", form.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "invalid_client") {
		t.Fatalf("Expected invalid_client for a query client_secret, got %d %s", res.StatusCode, body)
	}

	// the same request with the secret in the body works
	form.Set("client_secret", "secret_conf")
	res, body = b.do(http.MethodPost, "/oauth2/users/token", form.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected successful exchange, got %d %s", res.StatusCode, body)
	}

	// hosted forms: the password in the query is ignored
	lb := newOAuth2Browser(t, app)
	handle := lb.startLogin("users", "app", nil)
	csrf := hiddenField(lb.lastHTML, "csrf")
	res, _ = lb.do(http.MethodPost, "/oauth2/users/login/password?"+url.Values{
		"identity": {"test@example.com"},
		"password": {"1234567890"},
	}.Encode(), url.Values{"auth_state": {handle}, "csrf": {csrf}}.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Origin":       oauth2TestOrigin,
	})
	if strings.Contains(res.Header.Get("Location"), "code=") {
		t.Fatal("Expected the query password to be ignored")
	}
}

func TestOAuth2AttackClientAuthentication(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)
	b := newOAuth2Browser(t, app)

	record := oauth2FindRecord(t, app, "users", "test@example.com")
	conf := oauth2FindClient(t, app, "conf")
	oauth2StubRefreshSession(t, app, conf, record, []string{"openid"}, "conf_refresh_token")

	scenarios := []struct {
		name    string
		values  map[string]string
		headers map[string]string
	}{
		{"confidential without secret", map[string]string{"client_id": "conf"}, nil},
		{"confidential with wrong secret", map[string]string{"client_id": "conf", "client_secret": "wrong"}, nil},
		{"confidential with another client secret", map[string]string{"client_id": "conf", "client_secret": "secret_app"}, nil},
		{"public client presenting a secret", map[string]string{"client_id": "app", "client_secret": "x"}, nil},
		{"basic and post secrets", map[string]string{"client_id": "conf", "client_secret": "secret_conf"}, map[string]string{"Authorization": basicAuth("conf", "secret_conf")}},
		{"basic with mismatched client_id", map[string]string{"client_id": "app"}, map[string]string{"Authorization": basicAuth("conf", "secret_conf")}},
		{"basic with wrong secret", nil, map[string]string{"Authorization": basicAuth("conf", "wrong")}},
		{"disabled client", map[string]string{"client_id": "disabled"}, nil},
		{"client of another issuer", map[string]string{"client_id": "other"}, nil},
	}

	for _, s := range scenarios {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"conf_refresh_token"}}
		for k, v := range s.values {
			form.Set(k, v)
		}

		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		for k, v := range s.headers {
			headers[k] = v
		}

		res, body := b.do(http.MethodPost, "/oauth2/users/token", form.Encode(), headers)
		if res.StatusCode == http.StatusOK || strings.Contains(body, "access_token") {
			t.Fatalf("%s: expected client authentication failure, got %d %s", s.name, res.StatusCode, body)
		}
	}

	// the refresh token is still valid for its own authenticated client
	res, body := b.do(http.MethodPost, "/oauth2/users/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"conf_refresh_token"},
	}.Encode(), map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": basicAuth("conf", "secret_conf"),
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected successful refresh, got %d %s", res.StatusCode, body)
	}
}

func TestOAuth2AttackCodeAndPKCE(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)

	login := func() (*oauth2Browser, string) {
		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		return b, b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)
	}

	// PKCE downgrade attempts at the authorization endpoint
	b := newOAuth2Browser(t, app)
	for _, params := range []map[string]string{
		{"code_challenge": "", "code_challenge_method": ""},
		{"code_challenge_method": "plain"},
		{"code_challenge_method": ""},
		{"code_challenge": "short"},
	} {
		res, _ := b.get(oauth2AuthorizeURL("users", "app", params))
		b.expectError(res, "invalid_request")
	}

	// code injection with another client (stolen code)
	b, code := login()
	res, data := b.exchange("users", "3p", code, nil)
	if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" {
		t.Fatalf("Expected invalid_grant for another client, got %d %v", res.StatusCode, data)
	}

	// missing/other verifier
	for _, verifier := range []string{"", oauth2TestCodeChallenge, oauth2TestCodeVerifier + "x"} {
		extra := map[string]string{"code_verifier": verifier}
		if verifier == "" {
			extra = map[string]string{"code_verifier": ""}
		}
		res, data = b.exchange("users", "app", code, extra)
		if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" {
			t.Fatalf("Expected invalid_grant for verifier %q, got %d %v", verifier, res.StatusCode, data)
		}
	}

	// another redirect_uri
	res, data = b.exchange("users", "app", code, map[string]string{"redirect_uri": "https://example.com/other"})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected redirect_uri mismatch error, got %d %v", res.StatusCode, data)
	}

	// valid exchange and replay (the replay ends the session)
	res, data = b.exchange("users", "app", code, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected successful exchange, got %d %v", res.StatusCode, data)
	}
	access, _ := data["access_token"].(string)

	res, data = b.exchange("users", "app", code, nil)
	if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" {
		t.Fatalf("Expected invalid_grant on replay, got %d %v", res.StatusCode, data)
	}
	if _, err := app.FindAuthRecordByToken(access, core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the code replay to end the session")
	}
}

func TestOAuth2AttackConcurrentRefresh(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)

	record := oauth2FindRecord(t, app, "users", "test@example.com")
	oauth2StubRefreshSession(t, app, oauth2FindClient(t, app, "app"), record, []string{"openid"}, "concurrent_refresh_token")

	b := newOAuth2Browser(t, app)

	const total = 8

	var wg sync.WaitGroup
	var mu sync.Mutex
	succeeded := 0

	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			res, _ := b.do(http.MethodPost, "/oauth2/users/token", url.Values{
				"grant_type":    {"refresh_token"},
				"client_id":     {"app"},
				"refresh_token": {"concurrent_refresh_token"},
			}.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

			if res.StatusCode == http.StatusOK {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if succeeded > 1 {
		t.Fatalf("Expected at most 1 successful concurrent refresh, got %d", succeeded)
	}
}

func TestOAuth2AttackTokenExchange(t *testing.T) {
	t.Parallel()

	exchange := func(b *oauth2Browser, collection string, clientId string, subject string, actor string) (*http.Response, map[string]any) {
		return b.tokenRequest(collection, map[string]string{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"client_id":          clientId,
			"subject_token":      subject,
			"subject_token_type": "urn:pocketbase:params:oauth:token-type:record_id",
			"actor_token":        actor,
			"actor_token_type":   "urn:ietf:params:oauth:token-type:access_token",
		})
	}

	setup := func(t *testing.T) (*tests.TestApp, *oauth2Browser) {
		app := oauth2AttackApp(t)
		oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers)
		return app, newOAuth2Browser(t, app)
	}

	t.Run("chained impersonation (act token as actor)", func(t *testing.T) {
		app, b := setup(t)

		owner := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		staff := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test2@example.com")
		user := oauth2FindRecord(t, app, "users", "test@example.com")

		ownerToken, err := tests.NewSessionAuthToken(app, owner)
		if err != nil {
			t.Fatal(err)
		}

		// Owner impersonates another superuser
		res, data := exchange(b, core.CollectionNameSuperusers, core.OAuth2DashboardClientId, staff.Id, ownerToken)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected Owner impersonation, got %d %v", res.StatusCode, data)
		}
		impToken, _ := data["access_token"].(string)

		// ... and uses the impersonation token as actor
		res, data = exchange(b, "users", core.OAuth2DashboardClientId, user.Id, impToken)
		if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" {
			t.Fatalf("Expected the chained impersonation to be rejected, got %d %v", res.StatusCode, data)
		}
	})

	t.Run("non Owner staff impersonating an Owner", func(t *testing.T) {
		app, b := setup(t)

		role, err := tests.CreateRole(app, "impersonators", core.Permissions{System: map[string]string{
			core.PermissionResourceImpersonate: core.PermissionLevelWrite,
			core.PermissionResourceStaff:       core.PermissionLevelWrite,
		}})
		if err != nil {
			t.Fatal(err)
		}

		staff, err := tests.CreateStaff(app, "impersonator@example.com", role.Id)
		if err != nil {
			t.Fatal(err)
		}
		staffToken, err := tests.NewSessionAuthToken(app, staff)
		if err != nil {
			t.Fatal(err)
		}

		owner := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		res, data := exchange(b, core.CollectionNameSuperusers, core.OAuth2DashboardClientId, owner.Id, staffToken)
		if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_grant" {
			t.Fatalf("Expected the Owner impersonation to be rejected, got %d %v", res.StatusCode, data)
		}

		// a customer is allowed
		user := oauth2FindRecord(t, app, "users", "test@example.com")
		res, data = exchange(b, "users", core.OAuth2DashboardClientId, user.Id, staffToken)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected the customer impersonation to succeed, got %d %v", res.StatusCode, data)
		}
	})

	t.Run("invalid actors", func(t *testing.T) {
		app, b := setup(t)

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		other := oauth2FindRecord(t, app, "users", "test2@example.com")

		customerToken, err := tests.NewSessionAuthToken(app, user)
		if err != nil {
			t.Fatal(err)
		}

		installer := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
		installerToken, err := installer.NewInstallerToken(time.Minute)
		if err != nil {
			t.Fatal(err)
		}

		fileToken, _ := installer.NewFileToken()

		for name, actor := range map[string]string{
			"customer token":  customerToken,
			"installer token": installerToken,
			"file token":      fileToken,
			"garbage":         "abc",
		} {
			res, data := exchange(b, "users", core.OAuth2DashboardClientId, other.Id, actor)
			if res.StatusCode == http.StatusOK {
				t.Fatalf("%s: expected the exchange to be rejected, got %v", name, data)
			}
		}

		// a third-party (non dashboard) client of another issuer can't be used cross-issuer
		ownerToken, _ := tests.NewSessionAuthToken(app, installer)
		res, data := exchange(b, core.CollectionNameSuperusers, "app", installer.Id, ownerToken)
		if res.StatusCode == http.StatusOK {
			t.Fatalf("Expected cross-issuer exchange with a users client to be rejected, got %v", data)
		}
	})
}

func TestOAuth2ServerTokenEndpointHeaders(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	b := newOAuth2Browser(t, app)
	b.startLogin("users", "app", nil)
	code := b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)

	res, data := b.exchange("users", "app", code, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected a successful token response, got %d", res.StatusCode)
	}
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Expected Cache-Control no-store on the token response, got %q", cc)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Expected a JSON token response, got %q", ct)
	}

	access, _ := data["access_token"].(string)
	if access == "" {
		t.Fatal("Expected an access token")
	}

	// userinfo is no-store and invalid bearer tokens get a WWW-Authenticate header
	res, _ = b.do(http.MethodGet, "/oauth2/users/userinfo", "", map[string]string{"Authorization": access})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected userinfo 200, got %d", res.StatusCode)
	}
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Expected Cache-Control no-store on userinfo, got %q", cc)
	}

	res, _ = b.do(http.MethodGet, "/oauth2/users/userinfo", "", map[string]string{"Authorization": "Bearer invalid"})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected userinfo 401, got %d", res.StatusCode)
	}
	if www := res.Header.Get("WWW-Authenticate"); !strings.HasPrefix(www, "Bearer ") {
		t.Fatalf("Expected a Bearer WWW-Authenticate header, got %q", www)
	}

	// revoke is also no-store
	res, _ = b.tokenRequest("users", map[string]string{
		"client_id": "app",
		"token":     access,
	})
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Expected Cache-Control no-store on revoke, got %q", cc)
	}
}

func TestOAuth2ServerTokenAlgorithmAndIssuerConfusion(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	b := newOAuth2Browser(t, app)
	b.startLogin("users", "app", nil)
	code := b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)

	_, data := b.exchange("users", "app", code, nil)
	access, _ := data["access_token"].(string)
	if access == "" {
		t.Fatal("Expected an access token")
	}

	record := oauth2FindRecord(t, app, "users", "test@example.com")
	claims := map[string]any{
		"id":           record.Id,
		"collectionId": record.Collection().Id,
		"type":         core.TokenTypeAuth,
		"exp":          time.Now().Add(time.Hour).Unix(),
		"sid":          "any",
		"cid":          "app",
		"scope":        "openid",
	}

	expectRejected := func(name string, token string) {
		t.Helper()

		res, _ := b.do(http.MethodGet, "/oauth2/users/userinfo", "", map[string]string{"Authorization": token})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d", name, res.StatusCode)
		}
	}

	// alg=none must never be accepted as an access token
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	expectRejected("alg none", header+"."+base64.RawURLEncoding.EncodeToString(payload)+".")

	// HS256 signed with an arbitrary secret
	wrongSecret, err := security.NewJWT(claims, "not-the-collection-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	expectRejected("wrong secret", wrongSecret)

	// a valid access token of the users issuer is not accepted by another issuer
	res, _ := b.do(http.MethodGet, "/oauth2/clients/userinfo", "", map[string]string{"Authorization": access})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected the cross-issuer userinfo to be rejected, got %d", res.StatusCode)
	}
}
