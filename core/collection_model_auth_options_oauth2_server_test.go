package core_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
)

func newTestSigningKey(t testing.TB, alg string) core.OAuth2SigningKey {
	t.Helper()

	key, err := core.NewOAuth2SigningKey(alg)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func TestOAuth2ServerConfigDefaults(t *testing.T) {
	t.Parallel()

	collection := core.NewAuthCollection("test")
	c := collection.OAuth2Server

	if c.SessionDuration != 1209600 || c.RefreshTokenDuration != 2592000 || c.CodeDuration != 60 {
		t.Fatalf("Unexpected default durations %d, %d, %d", c.SessionDuration, c.RefreshTokenDuration, c.CodeDuration)
	}

	// the access tokens duration is the collection auth token duration (aka. single knob)
	if collection.AuthToken.Duration != 3600 {
		t.Fatalf("Expected default auth (aka. access) token duration 3600, got %d", collection.AuthToken.Duration)
	}

	if !c.ConsentRequired {
		t.Fatal("Expected ConsentRequired to be true by default")
	}

	if len(c.SigningKeys) != 0 {
		t.Fatalf("Expected no default signing keys before save, got %d", len(c.SigningKeys))
	}

	if c.SessionDurationTime() != 14*24*time.Hour ||
		c.RefreshTokenDurationTime() != 30*24*time.Hour ||
		c.CodeDurationTime() != time.Minute {
		t.Fatal("Unexpected duration time helpers result")
	}

	// the removed duplicated options must not be serialized
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{`"enabled"`, `"accessTokenDuration"`, `"methods"`} {
		if strings.Contains(string(raw), removed) {
			t.Fatalf("Expected %s to be removed from the serialized config, got %s", removed, raw)
		}
	}
}

func TestOAuth2ServerConfigValidate(t *testing.T) {
	t.Parallel()

	validKey := newTestSigningKey(t, security.JWTAlgRS256)

	inactiveKey := newTestSigningKey(t, security.JWTAlgES256)
	inactiveKey.Active = false

	scenarios := []struct {
		name           string
		config         func() core.OAuth2ServerConfig
		expectedErrors []string
	}{
		{
			"zero config",
			func() core.OAuth2ServerConfig {
				return core.OAuth2ServerConfig{}
			},
			[]string{"sessionDuration", "refreshTokenDuration", "codeDuration"},
		},
		{
			"default config without keys (generated on save)",
			func() core.OAuth2ServerConfig {
				return core.NewAuthCollection("test").OAuth2Server
			},
			[]string{},
		},
		{
			"config with only inactive keys",
			func() core.OAuth2ServerConfig {
				c := core.NewAuthCollection("test").OAuth2Server
				c.SigningKeys = []core.OAuth2SigningKey{inactiveKey}
				return c
			},
			[]string{"signingKeys"},
		},
		{
			"invalid fields",
			func() core.OAuth2ServerConfig {
				c := core.NewAuthCollection("test").OAuth2Server
				c.SessionDuration = 1
				c.RefreshTokenDuration = 1
				c.CodeDuration = 601
				c.Scopes = []string{"valid", "invalid scope", core.OAuth2ScopeOpenId}
				c.LoginPage.LogoURL = "invalid"
				c.LoginPage.PrimaryColor = "invalid"
				c.SigningKeys = []core.OAuth2SigningKey{validKey}
				return c
			},
			[]string{"sessionDuration", "refreshTokenDuration", "codeDuration", "scopes", "loginPage"},
		},
		{
			"duplicated custom scope",
			func() core.OAuth2ServerConfig {
				c := core.NewAuthCollection("test").OAuth2Server
				c.Scopes = []string{"a", "b", "a"}
				c.SigningKeys = []core.OAuth2SigningKey{validKey}
				return c
			},
			[]string{"scopes"},
		},
		{
			"duplicated signing key kids",
			func() core.OAuth2ServerConfig {
				c := core.NewAuthCollection("test").OAuth2Server
				c.SigningKeys = []core.OAuth2SigningKey{validKey, validKey}
				return c
			},
			[]string{"signingKeys"},
		},
		{
			"valid config",
			func() core.OAuth2ServerConfig {
				c := core.NewAuthCollection("test").OAuth2Server
				c.Scopes = []string{"posts:read", "posts:write"}
				c.LoginPage.Title = "Test"
				c.LoginPage.LogoURL = "https://example.com/logo.png"
				c.LoginPage.PrimaryColor = "#1055c9"
				c.SigningKeys = []core.OAuth2SigningKey{inactiveKey, validKey}
				return c
			},
			[]string{},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			result := s.config().Validate()

			tests.TestValidationErrors(t, result, s.expectedErrors)
		})
	}
}

func TestOAuth2SigningKeyValidate(t *testing.T) {
	t.Parallel()

	rsaKey := newTestSigningKey(t, security.JWTAlgRS256)
	ecKey := newTestSigningKey(t, security.JWTAlgES256)

	scenarios := []struct {
		name           string
		key            core.OAuth2SigningKey
		expectedErrors []string
	}{
		{"zero key", core.OAuth2SigningKey{}, []string{"kid", "alg", "privateKey"}},
		{"invalid kid and alg", core.OAuth2SigningKey{Kid: "a b", Alg: "HS256", PrivateKey: rsaKey.PrivateKey}, []string{"kid", "alg"}},
		{"invalid private key", core.OAuth2SigningKey{Kid: "test", Alg: security.JWTAlgRS256, PrivateKey: "invalid"}, []string{"privateKey"}},
		{"alg and private key mismatch", core.OAuth2SigningKey{Kid: "test", Alg: security.JWTAlgRS256, PrivateKey: ecKey.PrivateKey}, []string{"privateKey"}},
		{"valid RS256", rsaKey, []string{}},
		{"valid ES256", ecKey, []string{}},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			tests.TestValidationErrors(t, s.key.Validate(), s.expectedErrors)
		})
	}
}

func TestNewOAuth2SigningKey(t *testing.T) {
	t.Parallel()

	if _, err := core.NewOAuth2SigningKey("HS256"); err == nil {
		t.Fatal("Expected error for unsupported alg")
	}

	for _, alg := range []string{security.JWTAlgRS256, security.JWTAlgES256} {
		t.Run(alg, func(t *testing.T) {
			key := newTestSigningKey(t, alg)

			if key.Kid == "" || key.Alg != alg || key.PrivateKey == "" || key.CreatedAt.IsZero() || !key.Active {
				t.Fatalf("Unexpected key %#v", key)
			}

			if err := key.Validate(); err != nil {
				t.Fatal(err)
			}

			jwk, err := key.JWK()
			if err != nil {
				t.Fatal(err)
			}

			if jwk.Kid != key.Kid || jwk.Alg != alg || jwk.Use != "sig" {
				t.Fatalf("Unexpected jwk %#v", jwk)
			}
		})
	}
}

func TestOAuth2ServerConfigActiveSigningKey(t *testing.T) {
	t.Parallel()

	k1 := newTestSigningKey(t, security.JWTAlgRS256)
	k1.Kid = "k1"
	k1.CreatedAt = types.NowDateTime().Add(-2 * time.Hour)

	k2 := newTestSigningKey(t, security.JWTAlgES256)
	k2.Kid = "k2"
	k2.CreatedAt = types.NowDateTime().Add(-1 * time.Hour)

	k3 := newTestSigningKey(t, security.JWTAlgRS256)
	k3.Kid = "k3"
	k3.Active = false

	scenarios := []struct {
		name     string
		keys     []core.OAuth2SigningKey
		expected string
	}{
		{"no keys", nil, ""},
		{"only inactive keys", []core.OAuth2SigningKey{k3}, ""},
		{"single active key", []core.OAuth2SigningKey{k1, k3}, "k1"},
		{"latest active key", []core.OAuth2SigningKey{k2, k1, k3}, "k2"},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			c := core.OAuth2ServerConfig{SigningKeys: s.keys}

			key, ok := c.ActiveSigningKey()

			if ok != (s.expected != "") {
				t.Fatalf("Expected exists %v, got %v", s.expected != "", ok)
			}

			if key.Kid != s.expected {
				t.Fatalf("Expected key %q, got %q", s.expected, key.Kid)
			}
		})
	}
}

func TestOAuth2ServerConfigJWKS(t *testing.T) {
	t.Parallel()

	k1 := newTestSigningKey(t, security.JWTAlgRS256)
	k2 := newTestSigningKey(t, security.JWTAlgES256)
	k2.Active = false

	c := core.OAuth2ServerConfig{SigningKeys: []core.OAuth2SigningKey{k1, k2}}

	jwks, err := c.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	if len(jwks.Keys) != 2 || jwks.Find(k1.Kid) == nil || jwks.Find(k2.Kid) == nil {
		t.Fatalf("Expected both active and inactive keys to be exported, got %v", jwks.Keys)
	}

	raw, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), `"d"`) {
		t.Fatalf("The JWKS must contain only public keys, got %s", raw)
	}

	// invalid key
	c.SigningKeys = append(c.SigningKeys, core.OAuth2SigningKey{Kid: "invalid", Alg: security.JWTAlgRS256, PrivateKey: "invalid"})
	if _, err := c.JWKS(); err == nil {
		t.Fatal("Expected JWKS error for invalid key")
	}
}

func TestOAuth2ServerConfigAllowedScopes(t *testing.T) {
	t.Parallel()

	c := core.OAuth2ServerConfig{Scopes: []string{"a", core.OAuth2ScopeEmail, "b"}}

	result := c.AllowedScopes()

	expected := []string{"openid", "email", "profile", "offline_access", "a", "b"}
	if strings.Join(result, " ") != strings.Join(expected, " ") {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestOAuth2Issuer(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	collection, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		appURL   string
		expected string
	}{
		{"https://example.com", "https://example.com/oauth2/users"},
		{"https://example.com/", "https://example.com/oauth2/users"},
		{"https://example.com/sub/", "https://example.com/sub/oauth2/users"},
	}

	for _, s := range scenarios {
		t.Run(s.appURL, func(t *testing.T) {
			app.Settings().Meta.AppURL = s.appURL

			if v := core.OAuth2Issuer(app, collection); v != s.expected {
				t.Fatalf("Expected %q, got %q", s.expected, v)
			}
		})
	}
}

func TestCollectionOAuth2ServerSigningKeysAutoGenerate(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	collection, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	// every auth collection is an issuer -> auto generated key when there is none
	collection.OAuth2Server.SigningKeys = nil
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}
	if len(collection.OAuth2Server.SigningKeys) != 1 {
		t.Fatalf("Expected 1 auto generated signing key, got %d", len(collection.OAuth2Server.SigningKeys))
	}
	generated := collection.OAuth2Server.SigningKeys[0]
	if !generated.Active || generated.Alg != security.JWTAlgRS256 || generated.PrivateKey == "" {
		t.Fatalf("Unexpected generated key %#v", generated)
	}

	// resave - no new key
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}
	if len(collection.OAuth2Server.SigningKeys) != 1 || collection.OAuth2Server.SigningKeys[0].Kid != generated.Kid {
		t.Fatalf("Expected the same single signing key, got %v", collection.OAuth2Server.SigningKeys)
	}

	// refetch to ensure that the private key was persisted
	collection, err = app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	if len(collection.OAuth2Server.SigningKeys) != 1 || collection.OAuth2Server.SigningKeys[0].PrivateKey != generated.PrivateKey {
		t.Fatal("Expected the signing key private key to be persisted")
	}

	// keys without private key (e.g. from redacted export) are removed
	// and a new one is generated if there are no other active keys
	collection.OAuth2Server.SigningKeys = []core.OAuth2SigningKey{{Kid: "redacted", Alg: security.JWTAlgRS256, Active: true}}
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}
	if len(collection.OAuth2Server.SigningKeys) != 1 ||
		collection.OAuth2Server.SigningKeys[0].Kid == "redacted" ||
		collection.OAuth2Server.SigningKeys[0].PrivateKey == "" {
		t.Fatalf("Expected the redacted key to be replaced, got %v", collection.OAuth2Server.SigningKeys)
	}
}

func TestCollectionOAuth2ServerSigningKeysSerialization(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	collection, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	k1 := newTestSigningKey(t, security.JWTAlgRS256)
	k1.Kid = "k1"
	k2 := newTestSigningKey(t, security.JWTAlgES256)
	k2.Kid = "k2"
	k2.Active = false

	collection.OAuth2Server.SigningKeys = []core.OAuth2SigningKey{k1, k2}
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}

	// private keys must be hidden from the JSON serialization
	// ---
	raw, err := json.Marshal(collection)
	if err != nil {
		t.Fatal(err)
	}
	rawStr := string(raw)
	if strings.Contains(rawStr, "PRIVATE KEY") || strings.Contains(rawStr, `"privateKey"`) {
		t.Fatalf("Expected the private keys to be hidden, got\n%s", rawStr)
	}
	if !strings.Contains(rawStr, `"kid":"k1"`) || !strings.Contains(rawStr, `"kid":"k2"`) {
		t.Fatalf("Expected the public key data to be serialized, got\n%s", rawStr)
	}

	// the model state must remain unchanged
	if collection.OAuth2Server.SigningKeys[0].PrivateKey == "" || collection.OAuth2Server.SigningKeys[1].PrivateKey == "" {
		t.Fatal("Expected the collection model private keys to remain unchanged")
	}

	// partial update (e.g. from the redacted API response) should
	// merge the submitted keys data with the existing private keys
	// ---
	err = json.Unmarshal([]byte(`{"oauth2Server":{"signingKeys":[{"kid":"k2","active":true},{"kid":"k1","active":false}]}}`), collection)
	if err != nil {
		t.Fatal(err)
	}
	if len(collection.OAuth2Server.SigningKeys) != 2 {
		t.Fatalf("Expected 2 signing keys, got %d", len(collection.OAuth2Server.SigningKeys))
	}
	if v := collection.OAuth2Server.SigningKeys[0]; v.Kid != "k2" || !v.Active || v.PrivateKey != k2.PrivateKey || v.Alg != k2.Alg {
		t.Fatalf("Expected merged k2 key, got %#v", v)
	}
	if v := collection.OAuth2Server.SigningKeys[1]; v.Kid != "k1" || v.Active || v.PrivateKey != k1.PrivateKey || v.Alg != k1.Alg {
		t.Fatalf("Expected merged k1 key, got %#v", v)
	}
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}

	// removing a key from the submitted list deletes it
	// ---
	err = json.Unmarshal([]byte(`{"oauth2Server":{"signingKeys":[{"kid":"k2"}]}}`), collection)
	if err != nil {
		t.Fatal(err)
	}
	if len(collection.OAuth2Server.SigningKeys) != 1 || collection.OAuth2Server.SigningKeys[0].PrivateKey != k2.PrivateKey {
		t.Fatalf("Expected only k2 key, got %v", collection.OAuth2Server.SigningKeys)
	}
}

func TestCollectionOAuth2ServerValidation(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	collection, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	collection.OAuth2Server.CodeDuration = 0
	collection.OAuth2Server.Scopes = []string{"invalid scope"}

	err = app.Validate(collection)

	tests.TestValidationErrors(t, err, []string{"oauth2Server"})
}

func TestNewAuthCollectionSigningKeysOnCreate(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	collection := core.NewAuthCollection("new_issuer")
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}

	if _, ok := collection.OAuth2Server.ActiveSigningKey(); !ok {
		t.Fatal("Expected an active signing key to be generated on auth collection create")
	}

	// the existing fixture auth collections are also issuers (generated by the migration)
	for _, name := range []string{"users", "clients", "nologin", core.CollectionNameSuperusers} {
		c, err := app.FindCollectionByNameOrId(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := c.OAuth2Server.ActiveSigningKey(); !ok {
			t.Fatalf("Expected %q to have an active signing key", name)
		}
		if c.OAuth2Server.SessionDuration <= 0 {
			t.Fatalf("Expected %q to have a session duration", name)
		}
	}
}

func TestOAuth2ServerReservedScopesOnlyNew(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	// legacy conflicting scopes stored before the prefixes reservation
	users.OAuth2Server.Scopes = []string{"posts:read", "read_legacy", "system:legacy"}
	if err := app.SaveNoValidate(users); err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name        string
		scopes      []string
		expectError bool
	}{
		{"unchanged legacy scopes", []string{"posts:read", "read_legacy", "system:legacy"}, false},
		{"reordered legacy scopes", []string{"system:legacy", "read_legacy", "posts:read"}, false},
		{"removed legacy scope", []string{"posts:read", "read_legacy"}, false},
		{"new regular scope", []string{"posts:read", "read_legacy", "system:legacy", "posts:write"}, false},
		{"new read_ scope", []string{"posts:read", "read_legacy", "system:legacy", "read_orders"}, true},
		{"new write_ scope", []string{"posts:read", "write_legacy"}, true},
		{"new system: scope", []string{"posts:read", "system:read_settings"}, true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			fresh, err := app.FindCollectionByNameOrId("users")
			if err != nil {
				t.Fatal(err)
			}

			fresh.OAuth2Server.Scopes = s.scopes

			err = app.Validate(fresh)
			hasErr := err != nil && strings.Contains(err.Error(), "reserved")
			if hasErr != s.expectError {
				t.Fatalf("Expected reserved error %v, got %v", s.expectError, err)
			}
		})
	}

	// a new collection cannot be created with conflicting scopes
	clients := core.NewAuthCollection("new_auth")
	clients.OAuth2Server.Scopes = []string{"read_legacy"}
	if err := app.Validate(clients); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("Expected reserved scope error for a new collection, got %v", err)
	}

	if err := core.CheckNewOAuth2ReservedScopes([]string{"a", "system:x"}, []string{"system:x"}); err != nil {
		t.Fatalf("Expected the stored scope to be tolerated, got %v", err)
	}
	if err := core.CheckNewOAuth2ReservedScopes([]string{"a", "system:x"}, nil); err == nil {
		t.Fatal("Expected the new system: scope to be rejected")
	}
}
