package apis_test

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
)

var (
	oauth2TestUserToken      = tests.AuthToken("users", "test@example.com")
	oauth2TestSuperuserToken = tests.AuthToken("_superusers", "test@example.com")
)

func TestOAuth2ClientGenerateSecret(t *testing.T) {
	t.Parallel()

	setup := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		oauth2PrepareIssuer(t, app, "users")
		oauth2StubClient(t, app, "users", "public_app")
		oauth2StubClient(t, app, "users", "conf_app", oauth2Confidential)
	}

	clientRecordId := func(t testing.TB, app *tests.TestApp, clientId string) string {
		client, err := app.FindOAuth2ClientByClientId(clientId)
		if err != nil {
			t.Fatal(err)
		}
		return client.Id
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodPost,
			URL:             "/api/oauth2/clients/missing/rotate-secret",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "regular user",
			Method:          http.MethodPost,
			URL:             "/api/oauth2/clients/missing/rotate-secret",
			Headers:         map[string]string{"Authorization": oauth2TestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "superuser with missing client",
			Method:          http.MethodPost,
			URL:             "/api/oauth2/clients/missing/rotate-secret",
			Headers:         map[string]string{"Authorization": oauth2TestSuperuserToken},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}

	// public client
	// ---
	t.Run("superuser with public client", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		setup(t, app, nil)

		mux := oauth2Mux(t, app)
		res := mux.do(http.MethodPost, "/api/oauth2/clients/"+clientRecordId(t, app, "public_app")+"/rotate-secret", nil, map[string]string{"Authorization": oauth2TestSuperuserToken})
		if res.StatusCode != 400 {
			t.Fatalf("Expected status 400, got %d", res.StatusCode)
		}

		client, _ := app.FindOAuth2ClientByClientId("public_app")
		if client.ClientSecretHash() != "" {
			t.Fatal("Expected no secret to be set for the public client")
		}
	})

	// confidential client
	// ---
	t.Run("superuser with confidential client", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		setup(t, app, nil)

		oldClient, _ := app.FindOAuth2ClientByClientId("conf_app")
		oldHash := oldClient.ClientSecretHash()

		mux := oauth2Mux(t, app)
		res := mux.do(http.MethodPost, "/api/oauth2/clients/"+oldClient.Id+"/rotate-secret", nil, map[string]string{"Authorization": oauth2TestSuperuserToken})
		if res.StatusCode != 200 {
			t.Fatalf("Expected status 200, got %d", res.StatusCode)
		}

		raw, _ := io.ReadAll(res.Body)
		result := map[string]string{}
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}

		if result["clientId"] != "conf_app" {
			t.Fatalf("Expected clientId conf_app, got %q", result["clientId"])
		}
		if len(result["clientSecret"]) < 40 {
			t.Fatalf("Expected high entropy secret, got %q", result["clientSecret"])
		}

		client, _ := app.FindOAuth2ClientByClientId("conf_app")
		if client.ClientSecretHash() == oldHash {
			t.Fatal("Expected the secret hash to be changed")
		}
		if client.ClientSecretHash() != security.SHA256(result["clientSecret"]) {
			t.Fatal("Expected only the secret hash to be stored")
		}
		if !client.ValidateClientSecret(result["clientSecret"]) || client.ValidateClientSecret("secret_conf_app") {
			t.Fatal("Expected the new secret to replace the old one")
		}
	})
}

func TestOAuth2ConfidentialClientWithoutSecret(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2PrepareIssuer(t, app, "users")

	// creating a confidential client without a secret is allowed...
	client := oauth2StubClient(t, app, "users", "conf_no_secret", func(c *core.OAuth2Client) {
		c.SetType(core.OAuth2ClientTypeConfidential)
	})
	if client.IsUsable() {
		t.Fatal("Expected the confidential client without secret to be unusable")
	}

	mux := oauth2Mux(t, app)

	// ...but it can't be used for authorization
	res := mux.do(http.MethodGet, oauth2AuthorizeURL("users", "conf_no_secret", nil), nil, nil)
	if res.StatusCode != 400 {
		t.Fatalf("Expected authorize status 400, got %d", res.StatusCode)
	}

	// and for the token endpoint
	form := oauth2Form(map[string]string{
		"grant_type":   "authorization_code",
		"client_id":    "conf_no_secret",
		"code":         "test",
		"redirect_uri": oauth2TestRedirectURI,
	})
	res = mux.do(http.MethodPost, "/oauth2/users/token", strings.NewReader(form), oauth2FormHeaders(nil))
	if res.StatusCode != 401 {
		t.Fatalf("Expected token status 401, got %d", res.StatusCode)
	}

	// the superusers see whether the client has a secret (without the hash)
	res = mux.do(http.MethodGet, "/api/collections/_oauth2Clients/records/"+client.Id, nil, map[string]string{"Authorization": oauth2TestSuperuserToken})
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(raw), `"hasClientSecret":false`) || strings.Contains(string(raw), "clientSecretHash") {
		t.Fatalf("Expected hasClientSecret false without hash, got %d %s", res.StatusCode, raw)
	}

	client.SetClientSecret("test")
	if err := app.Save(client); err != nil {
		t.Fatal(err)
	}
	if !client.IsUsable() {
		t.Fatal("Expected the confidential client with secret to be usable")
	}

	res = mux.do(http.MethodGet, "/api/collections/_oauth2Clients/records/"+client.Id, nil, map[string]string{"Authorization": oauth2TestSuperuserToken})
	raw, _ = io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(raw), `"hasClientSecret":true`) {
		t.Fatalf("Expected hasClientSecret true, got %d %s", res.StatusCode, raw)
	}
}

func TestOAuth2ServerRotateSigningKey(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodPost,
			URL:             "/api/oauth2/users/keys/rotate",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "regular user",
			Method:          http.MethodPost,
			URL:             "/api/oauth2/users/keys/rotate",
			Headers:         map[string]string{"Authorization": oauth2TestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "superuser with non-auth collection",
			Method:          http.MethodPost,
			URL:             "/api/oauth2/demo1/keys/rotate",
			Headers:         map[string]string{"Authorization": oauth2TestSuperuserToken},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:            "superuser with invalid alg",
			Method:          http.MethodPost,
			URL:             "/api/oauth2/users/keys/rotate",
			Body:            strings.NewReader(`{"alg":"HS256"}`),
			Headers:         map[string]string{"Authorization": oauth2TestSuperuserToken},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"alg":{"code":"validation_in_invalid"`},
		},
		{
			Name:   "superuser rotating ES256 key",
			Method: http.MethodPost,
			URL:    "/api/oauth2/users/keys/rotate",
			Body:   strings.NewReader(`{"alg":"ES256"}`),
			Headers: map[string]string{
				"Authorization": oauth2TestSuperuserToken,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				oauth2PrepareIssuer(t, app, "users")
			},
			ExpectedStatus:     200,
			ExpectedContent:    []string{`"name":"users"`, `"signingKeys":[`, `"alg":"ES256"`},
			NotExpectedContent: []string{`"privateKey"`},
			ExpectedEvents: map[string]int{
				"*":                              0,
				"OnCollectionUpdate":             1,
				"OnCollectionUpdateExecute":      1,
				"OnCollectionAfterUpdateSuccess": 1,
				"OnCollectionValidate":           1,
				"OnModelUpdate":                  1,
				"OnModelUpdateExecute":           1,
				"OnModelAfterUpdateSuccess":      1,
				"OnModelValidate":                1,
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				collection, err := app.FindCollectionByNameOrId("users")
				if err != nil {
					t.Fatal(err)
				}

				keys := collection.OAuth2Server.SigningKeys
				if len(keys) != 2 {
					t.Fatalf("Expected 2 signing keys, got %d", len(keys))
				}
				if keys[0].Active || keys[0].PrivateKey == "" {
					t.Fatal("Expected the old key to be inactive and preserved")
				}
				if !keys[1].Active || keys[1].Alg != "ES256" || keys[1].PrivateKey == "" {
					t.Fatalf("Expected new active ES256 key, got %v", keys[1])
				}

				active, ok := collection.OAuth2Server.ActiveSigningKey()
				if !ok || active.Kid != keys[1].Kid {
					t.Fatal("Expected the new key to be used for signing")
				}

				jwks, err := collection.OAuth2Server.JWKS()
				if err != nil || len(jwks.Keys) != 2 {
					t.Fatalf("Expected both keys to be published in the JWKS, got %v (%v)", jwks, err)
				}
			},
		},
		{
			Name:   "superuser rotating with default alg (fixture issuer)",
			Method: http.MethodPost,
			URL:    "/api/oauth2/users/keys/rotate",
			Headers: map[string]string{
				"Authorization": oauth2TestSuperuserToken,
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"alg":"RS256"`},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				collection, err := app.FindCollectionByNameOrId("users")
				if err != nil {
					t.Fatal(err)
				}

				if _, ok := collection.OAuth2Server.ActiveSigningKey(); !ok {
					t.Fatal("Expected an active signing key")
				}
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}
