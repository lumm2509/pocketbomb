package apis_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
)

const (
	oauth2TestResource      = "urn:example:payments"
	oauth2TestOtherResource = "https://reports.example.com"
)

// oauth2ResourceSetup registers two protected resources in the users issuer
// and allows only oauth2TestResource for the "app" client.
func oauth2ResourceSetup(t testing.TB, app *tests.TestApp) {
	t.Helper()

	oauth2AuthorizeSetup(t, app)

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	users.OAuth2Server.Resources = []core.OAuth2Resource{
		{Identifier: oauth2TestResource, Name: "Payments", AccessTokenDuration: 120},
		{Identifier: oauth2TestOtherResource, AccessTokenDuration: 300},
	}
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	client := oauth2FindClient(t, app, "app")
	client.SetResources([]string{oauth2TestResource})
	if err := app.Save(client); err != nil {
		t.Fatal(err)
	}
}

// oauth2ParseResourceToken verifies the resource access token with the users issuer JWKS.
func oauth2ParseResourceToken(t testing.TB, app core.App, token string) map[string]any {
	t.Helper()

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	keySet, err := users.OAuth2Server.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	claims, err := security.ParseSignedJWTWithType(token, keySet, core.OAuth2ResourceAccessTokenType)
	if err != nil {
		t.Fatalf("Expected a valid %s token, got error %v", core.OAuth2ResourceAccessTokenType, err)
	}

	return claims
}

func TestOAuth2ServerTokenResourceAuthorizationCode(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2ResourceSetup(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	session := oauth2StubAuthorizedSession(t, app, oauth2FindClient(t, app, "app"), user, "code1", []string{"openid", "email", "offline_access"})

	var hookResource *core.OAuth2Resource
	app.OnOAuth2TokenRequest("users").BindFunc(func(e *core.OAuth2TokenRequestEvent) error {
		hookResource = e.Resource
		e.AccessTokenClaims["roles"] = []string{"analyst"}
		// the registered claims can't be replaced
		e.AccessTokenClaims["sub"] = "forged"
		e.AccessTokenClaims["aud"] = "forged"
		e.AccessTokenClaims["scope"] = "forged"
		return e.Next()
	})

	b := newOAuth2Browser(t, app)
	res, data := b.exchange("users", "app", "code1", map[string]string{"resource": oauth2TestResource})
	b.expectStatus(res, "", http.StatusOK)

	if hookResource == nil || hookResource.Identifier != oauth2TestResource {
		t.Fatalf("Expected the hook event resource %q, got %v", oauth2TestResource, hookResource)
	}

	if data["expires_in"] != float64(120) {
		t.Fatalf("Expected the resource access token duration, got %v", data["expires_in"])
	}

	if rt, _ := data["refresh_token"].(string); rt == "" {
		t.Fatalf("Expected a refresh token, got %v", data)
	}

	if idToken, _ := data["id_token"].(string); idToken == "" {
		t.Fatalf("Expected an id_token, got %v", data)
	}

	claims := oauth2ParseResourceToken(t, app, data["access_token"].(string))

	expected := map[string]any{
		"iss":       oauth2TestIssuer,
		"sub":       user.Id,
		"aud":       oauth2TestResource,
		"client_id": "app",
		"scope":     "openid email offline_access",
		"sid":       session.Id,
	}
	for k, v := range expected {
		if claims[k] != v {
			t.Errorf("Expected claim %q to be %v, got %v", k, v, claims[k])
		}
	}

	if jti, _ := claims["jti"].(string); len(jti) != 32 {
		t.Errorf("Expected a jti claim, got %v", claims["jti"])
	}

	if _, ok := claims["auth_time"]; !ok {
		t.Errorf("Expected an auth_time claim")
	}

	if roles, _ := claims["roles"].([]any); len(roles) != 1 || roles[0] != "analyst" {
		t.Errorf("Expected the custom roles claim, got %v", claims["roles"])
	}

	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	if exp-iat != 120 {
		t.Errorf("Expected a 120s token lifetime, got %v", exp-iat)
	}

	// the resource token is not a token of the server itself
	res, _ = b.do(http.MethodGet, "/oauth2/users/userinfo", "", map[string]string{"Authorization": "Bearer " + data["access_token"].(string)})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected the resource access token to be rejected by the server, got %d", res.StatusCode)
	}
}

func TestOAuth2ServerTokenResourceRefresh(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2ResourceSetup(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	oauth2StubRefreshSession(t, app, oauth2FindClient(t, app, "app"), user, []string{"openid", "offline_access"}, "rt1")

	app.OnOAuth2TokenRequest("users").BindFunc(func(e *core.OAuth2TokenRequestEvent) error {
		e.AccessTokenClaims["roles"] = []string{"customer"}
		return e.Next()
	})

	b := newOAuth2Browser(t, app)

	// a resource token of the session
	res, data := b.tokenRequest("users", map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     "app",
		"refresh_token": "rt1",
		"resource":      oauth2TestResource,
	})
	b.expectStatus(res, "", http.StatusOK)

	claims := oauth2ParseResourceToken(t, app, data["access_token"].(string))
	if claims["aud"] != oauth2TestResource || claims["sub"] != user.Id {
		t.Fatalf("Unexpected resource token claims %v", claims)
	}

	rt2, _ := data["refresh_token"].(string)
	if rt2 == "" || rt2 == "rt1" {
		t.Fatalf("Expected a rotated refresh token, got %v", data)
	}

	// the server own access token of the same session (no resource)
	res, data = b.tokenRequest("users", map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     "app",
		"refresh_token": rt2,
	})
	b.expectStatus(res, "", http.StatusOK)

	ownToken := data["access_token"].(string)
	if _, err := app.FindAuthRecordByToken(ownToken, core.TokenTypeAuth); err != nil {
		t.Fatalf("Expected the server own access token without resource, got error %v", err)
	}

	ownClaims, _ := security.ParseUnverifiedJWT(ownToken)
	if ownClaims["roles"] != nil {
		t.Fatalf("The access token claims must apply only to the resource tokens, got %v", ownClaims)
	}
}

func TestOAuth2ServerTokenResourceInvalidTarget(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name   string
		values url.Values
	}{
		{
			name:   "unknown resource",
			values: url.Values{"resource": {"urn:example:unknown"}},
		},
		{
			name:   "registered but not allowed for the client",
			values: url.Values{"resource": {oauth2TestOtherResource}},
		},
		{
			name:   "more than one resource",
			values: url.Values{"resource": {oauth2TestResource, oauth2TestOtherResource}},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app, _ := tests.NewTestApp()
			defer app.Cleanup()

			oauth2ResourceSetup(t, app)

			user := oauth2FindRecord(t, app, "users", "test@example.com")
			oauth2StubAuthorizedSession(t, app, oauth2FindClient(t, app, "app"), user, "code1", []string{"openid"})

			b := newOAuth2Browser(t, app)

			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("client_id", "app")
			form.Set("code", "code1")
			form.Set("redirect_uri", oauth2TestRedirectURI)
			form.Set("code_verifier", oauth2TestCodeVerifier)
			for k, v := range s.values {
				form[k] = v
			}

			res, body := b.do(http.MethodPost, "/oauth2/users/token", form.Encode(), map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			})
			data := parseJSONMap(t, body)
			if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_target" {
				t.Fatalf("Expected invalid_target, got %d %v", res.StatusCode, data)
			}

			// an invalid target doesn't consume the authorization code
			res, _ = b.exchange("users", "app", "code1", nil)
			b.expectStatus(res, "", http.StatusOK)
		})
	}

	t.Run("not supported grant type", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2ResourceSetup(t, app)

		b := newOAuth2Browser(t, app)
		res, data := b.tokenRequest("users", map[string]string{
			"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
			"client_id":          "app",
			"subject_token":      "x",
			"subject_token_type": "urn:pocketbase:params:oauth:token-type:record_id",
			"resource":           oauth2TestResource,
		})
		if res.StatusCode != http.StatusBadRequest || data["error"] != "invalid_target" {
			t.Fatalf("Expected invalid_target, got %d %v", res.StatusCode, data)
		}
	})
}
