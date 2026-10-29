package core_test

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
)

// apiKeyTestClient creates a regular (third-party) OAuth2 client of the users collection.
func apiKeyTestClient(t testing.TB, app core.App, clientId string) *core.OAuth2Client {
	t.Helper()

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	client := core.NewOAuth2Client(app)
	client.SetName("Storefront " + clientId)
	client.SetClientId(clientId)
	client.SetType(core.OAuth2ClientTypePublic)
	client.SetCollectionRef(users.Id)
	client.SetRedirectURIs([]string{"https://example.com/callback"})
	client.SetScopes([]string{"openid"})
	if err := app.Save(client); err != nil {
		t.Fatal(err)
	}

	return client
}

func TestNewAPIKey(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	key := core.NewAPIKey(app)

	if key.Collection().Name != core.CollectionNameAPIKeys {
		t.Fatalf("Expected record with %q collection, got %q", core.CollectionNameAPIKeys, key.Collection().Name)
	}
}

func TestAPIKeyProxyRecord(t *testing.T) {
	t.Parallel()

	record := core.NewRecord(core.NewBaseCollection("test"))
	record.Id = "test_id"

	key := core.APIKey{}
	key.SetProxyRecord(record)

	if key.ProxyRecord() == nil || key.ProxyRecord().Id != record.Id {
		t.Fatalf("Expected proxy record with id %q, got %v", record.Id, key.ProxyRecord())
	}
}

func TestAPIKeyGenerateToken(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	tokenRegex := regexp.MustCompile(`^pb_(pk|sk)_[0-9a-zA-Z]{43}$`)

	public := core.NewAPIKey(app)
	public.SetKind(core.APIKeyKindPublic)
	publicToken := public.GenerateToken()

	if !strings.HasPrefix(publicToken, core.APIKeyPublicTokenPrefix) || !tokenRegex.MatchString(publicToken) {
		t.Fatalf("Invalid public token %q", publicToken)
	}
	if public.Token() != publicToken {
		t.Fatalf("Expected the public token value to be stored, got %q", public.Token())
	}
	if public.TokenHash() != security.SHA256(publicToken) {
		t.Fatalf("Expected sha256 token hash, got %q", public.TokenHash())
	}
	if public.TokenPrefix() != publicToken[:10] {
		t.Fatalf("Expected token prefix %q, got %q", publicToken[:10], public.TokenPrefix())
	}

	private := core.NewAPIKey(app)
	private.SetKind(core.APIKeyKindPrivate)
	privateToken := private.GenerateToken()

	if !strings.HasPrefix(privateToken, core.APIKeyPrivateTokenPrefix) || !tokenRegex.MatchString(privateToken) {
		t.Fatalf("Invalid private token %q", privateToken)
	}
	if private.Token() != "" {
		t.Fatalf("Expected the private token value to not be stored, got %q", private.Token())
	}
	if private.TokenHash() != security.SHA256(privateToken) {
		t.Fatalf("Expected sha256 token hash, got %q", private.TokenHash())
	}

	if again := private.GenerateToken(); again == privateToken {
		t.Fatal("Expected a new random token")
	}
}

func TestNormalizeAPIKeyOrigin(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		origin   string
		expected string
		fail     bool
	}{
		{"https://example.com", "https://example.com", false},
		{"HTTPS://Example.COM/", "https://example.com", false},
		{"https://example.com:443", "https://example.com", false},
		{"http://example.com:80", "http://example.com", false},
		{"http://localhost:5173", "http://localhost:5173", false},
		{"http://[::1]:8090", "http://[::1]:8090", false},
		{"", "", true},
		{"example.com", "", true},
		{"ftp://example.com", "", true},
		{"https://example.com/path", "", true},
		{"https://example.com?a=1", "", true},
		{"https://user:pass@example.com", "", true},
	}

	for _, s := range scenarios {
		t.Run(s.origin, func(t *testing.T) {
			result, err := core.NormalizeAPIKeyOrigin(s.origin)
			if (err != nil) != s.fail {
				t.Fatalf("Expected fail %v, got %v", s.fail, err)
			}
			if result != s.expected {
				t.Fatalf("Expected %q, got %q", s.expected, result)
			}
		})
	}
}

func TestAPIKeyAllowsOriginAndExpiration(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	key := core.NewAPIKey(app)
	key.SetKind(core.APIKeyKindPublic)

	if !key.AllowsOrigin("https://any.example.com") {
		t.Fatal("Expected any origin to be allowed without allowed origins")
	}

	key.SetAllowedOrigins([]string{"https://shop.example.com"})
	if !key.AllowsOrigin("https://shop.example.com") || !key.AllowsOrigin("https://SHOP.example.com:443") {
		t.Fatal("Expected the allowed origin to match")
	}
	for _, o := range []string{"http://shop.example.com", "https://shop.example.com:8443", "https://evil.example.com", "null", ""} {
		if key.AllowsOrigin(o) {
			t.Fatalf("Expected origin %q to be not allowed", o)
		}
	}

	if key.IsExpired() || !key.IsUsable() {
		t.Fatal("Expected a key without expiration to be usable")
	}

	key.SetExpiresAt(types.NowDateTime().Add(-time.Second))
	if !key.IsExpired() || key.IsUsable() {
		t.Fatal("Expected an expired key")
	}

	key.SetExpiresAt(types.NowDateTime().Add(time.Hour))
	key.SetDisabled(true)
	if key.IsExpired() || key.IsUsable() {
		t.Fatal("Expected a disabled not expired key")
	}
}

func TestAPIKeyModelInvariants(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, err := app.FindCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}

	client := apiKeyTestClient(t, app, "storefront")

	disabledClient := apiKeyTestClient(t, app, "disabled_storefront")
	disabledClient.SetDisabled(true)
	if err := app.Save(disabledClient); err != nil {
		t.Fatal(err)
	}

	dashboard, err := app.FindOAuth2ClientByClientId(core.OAuth2DashboardClientId)
	if err != nil {
		t.Fatal(err)
	}

	_, installed := installTestApplication(t, app, "keys-app", core.Permissions{})

	newKey := func(kind string, modify func(k *core.APIKey)) *core.APIKey {
		key := core.NewAPIKey(app)
		key.SetName("test")
		key.SetClientRef(client.Id)
		key.SetKind(kind)
		if kind == core.APIKeyKindPrivate {
			key.SetBuyerContext(core.APIKeyBuyerContextRequired)
		}
		key.SetPermissions(core.Permissions{Collections: map[string][]string{demo2.Id: {"list", "view"}}})
		key.GenerateToken()
		if modify != nil {
			modify(key)
		}
		return key
	}

	scenarios := []struct {
		name          string
		key           *core.APIKey
		expectedError string // the expected validation error field (empty = success)
	}{
		{"valid public key", newKey(core.APIKeyKindPublic, nil), ""},
		{"valid private key", newKey(core.APIKeyKindPrivate, nil), ""},
		{"valid private key without buyer context", newKey(core.APIKeyKindPrivate, func(k *core.APIKey) {
			k.SetBuyerContext(core.APIKeyBuyerContextNone)
		}), ""},
		{"valid all collections permissions", newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
			k.SetPermissions(tests.AllCollectionsActions)
		}), ""},
		{"valid allowed origins", newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
			k.SetAllowedOrigins([]string{"https://shop.example.com", "http://localhost:3000"})
		}), ""},
		{"missing name", newKey(core.APIKeyKindPublic, func(k *core.APIKey) { k.SetName("") }), "name"},
		{"missing client", newKey(core.APIKeyKindPublic, func(k *core.APIKey) { k.SetClientRef("") }), "clientRef"},
		{"unknown client", newKey(core.APIKeyKindPublic, func(k *core.APIKey) { k.SetClientRef("missing") }), "clientRef"},
		{"dashboard client", newKey(core.APIKeyKindPublic, func(k *core.APIKey) { k.SetClientRef(dashboard.Id) }), "clientRef"},
		{"managed (application installation) client", newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
			k.SetClientRef(installed.Client.Id)
		}), "clientRef"},
		{"disabled client", newKey(core.APIKeyKindPublic, func(k *core.APIKey) { k.SetClientRef(disabledClient.Id) }), "clientRef"},
		{"invalid kind", newKey(core.APIKeyKindPublic, func(k *core.APIKey) { k.SetKind("other") }), "kind"},
		{"public key with buyer context", newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
			k.SetBuyerContext(core.APIKeyBuyerContextRequired)
		}), "buyerContext"},
		{"private key without buyer context mode", newKey(core.APIKeyKindPrivate, func(k *core.APIKey) { k.SetBuyerContext("") }), "buyerContext"},
		{"private key with allowed origins", newKey(core.APIKeyKindPrivate, func(k *core.APIKey) {
			k.SetAllowedOrigins([]string{"https://shop.example.com"})
		}), "allowedOrigins"},
		{"invalid allowed origin", newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
			k.SetAllowedOrigins([]string{"https://shop.example.com/path"})
		}), "allowedOrigins"},
		{"private token on a public key", newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
			k.SetToken(core.APIKeyPrivateTokenPrefix + "abc")
		}), "tokenHash"},
		{"public token on a private key", newKey(core.APIKeyKindPrivate, func(k *core.APIKey) {
			k.Set("tokenPrefix", core.APIKeyPublicTokenPrefix+"abcd")
		}), "tokenHash"},
		{"system permissions", newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
			k.SetPermissions(core.Permissions{System: map[string]string{core.PermissionResourceLogs: core.PermissionLevelRead}})
		}), "permissions"},
		{"system collection permissions", newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
			superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
			k.SetPermissions(core.Permissions{Collections: map[string][]string{superusers.Id: {"list"}}})
		}), "permissions"},
		{"unknown collection permissions", newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
			k.SetPermissions(core.Permissions{Collections: map[string][]string{"missing": {"list"}}})
		}), "permissions"},
		{"unknown action permissions", newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
			k.SetPermissions(core.Permissions{Collections: map[string][]string{demo2.Id: {"manage"}}})
		}), "permissions"},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			err := app.Save(s.key)

			if s.expectedError == "" {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("Expected %q validation error, got nil", s.expectedError)
			}

			raw, _ := json.Marshal(err)
			if !strings.Contains(string(raw), `"`+s.expectedError+`"`) {
				t.Fatalf("Expected %q validation error, got %s", s.expectedError, raw)
			}
		})
	}

	t.Run("normalized allowed origins", func(t *testing.T) {
		key := newKey(core.APIKeyKindPublic, func(k *core.APIKey) {
			k.SetAllowedOrigins([]string{"HTTPS://Shop.Example.com:443/", "https://shop.example.com"})
		})
		if err := app.Save(key); err != nil {
			t.Fatal(err)
		}
		if origins := key.AllowedOrigins(); len(origins) != 1 || origins[0] != "https://shop.example.com" {
			t.Fatalf("Expected normalized and deduplicated origins, got %v", origins)
		}
	})

	t.Run("missing token on create", func(t *testing.T) {
		key := core.NewAPIKey(app)
		key.SetName("test")
		key.SetClientRef(client.Id)
		key.SetKind(core.APIKeyKindPrivate)
		key.SetBuyerContext(core.APIKeyBuyerContextNone)
		if err := app.Save(key); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(key.TokenPrefix(), core.APIKeyPrivateTokenPrefix) || key.TokenHash() == "" || key.Token() != "" {
			t.Fatalf("Expected a random private token, got %q %q %q", key.TokenPrefix(), key.TokenHash(), key.Token())
		}
	})

	t.Run("immutable client and kind", func(t *testing.T) {
		key := newKey(core.APIKeyKindPublic, nil)
		if err := app.Save(key); err != nil {
			t.Fatal(err)
		}

		other := apiKeyTestClient(t, app, "other_storefront")

		key.SetClientRef(other.Id)
		if err := app.Save(key); err == nil || !strings.Contains(err.Error(), "clientRef") {
			t.Fatalf("Expected clientRef error, got %v", err)
		}

		key.SetClientRef(client.Id)
		key.SetKind(core.APIKeyKindPrivate)
		key.SetBuyerContext(core.APIKeyBuyerContextNone)
		if err := app.Save(key); err == nil || !strings.Contains(err.Error(), "kind") {
			t.Fatalf("Expected kind error, got %v", err)
		}
	})

	t.Run("disabled client existing keys can still be changed (e.g. disabled)", func(t *testing.T) {
		c := apiKeyTestClient(t, app, "later_disabled")
		key := newKey(core.APIKeyKindPublic, func(k *core.APIKey) { k.SetClientRef(c.Id) })
		if err := app.Save(key); err != nil {
			t.Fatal(err)
		}

		c.SetDisabled(true)
		if err := app.Save(c); err != nil {
			t.Fatal(err)
		}

		key.SetDisabled(true)
		if err := app.Save(key); err != nil {
			t.Fatalf("Expected the key of a disabled client to be updatable, got %v", err)
		}
	})

	t.Run("cascade delete with the client", func(t *testing.T) {
		c := apiKeyTestClient(t, app, "deleted_storefront")
		key := newKey(core.APIKeyKindPublic, func(k *core.APIKey) { k.SetClientRef(c.Id) })
		if err := app.Save(key); err != nil {
			t.Fatal(err)
		}

		if err := app.Delete(c); err != nil {
			t.Fatal(err)
		}

		if _, err := app.FindAPIKeyById(key.Id); err == nil {
			t.Fatal("Expected the client API key to be deleted")
		}
	})
}

func TestAPIKeyQueries(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client := apiKeyTestClient(t, app, "storefront")
	other := apiKeyTestClient(t, app, "other")

	tokens := map[string]string{}
	for _, c := range []*core.OAuth2Client{client, client, other} {
		key, token, err := tests.NewClientAPIKey(app, c, core.APIKeyKindPrivate, core.Permissions{})
		if err != nil {
			t.Fatal(err)
		}
		tokens[key.Id] = token
	}

	for id, token := range tokens {
		key, err := app.FindAPIKeyByToken(token)
		if err != nil || key.Id != id {
			t.Fatalf("Expected key %q for its token, got %v (%v)", id, key, err)
		}

		byId, err := app.FindAPIKeyById(id)
		if err != nil || byId.Id != id {
			t.Fatalf("Expected key %q, got %v (%v)", id, byId, err)
		}
	}

	for _, token := range []string{"", "pb_sk_missing", security.SHA256(tokens[""])} {
		if _, err := app.FindAPIKeyByToken(token); err == nil {
			t.Fatalf("Expected error for token %q", token)
		}
	}

	keys, err := app.FindAllAPIKeysByClient(client.Id)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("Expected 2 client keys, got %d", len(keys))
	}
	for _, k := range keys {
		if k.ClientRef() != client.Id {
			t.Fatalf("Expected only the %q client keys, got %q", client.Id, k.ClientRef())
		}
	}
}

func TestAuthorizeAPIKeyCeiling(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo1, _ := app.FindCollectionByNameOrId("demo1")
	demo2, _ := app.FindCollectionByNameOrId("demo2")
	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	externalAuths, _ := app.FindCollectionByNameOrId(core.CollectionNameExternalAuths)

	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	customer, _ := app.FindAuthRecordByEmail("users", "test@example.com")

	limitedRole, err := tests.CreateRole(app, "limited", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view", "create"}},
		System:      map[string]string{core.PermissionResourceSessions: core.PermissionLevelRead},
	})
	if err != nil {
		t.Fatal(err)
	}
	limited, err := tests.CreateStaff(app, "limited@example.com", limitedRole.Id)
	if err != nil {
		t.Fatal(err)
	}

	readKey := &core.RequestInfoAPIKey{ClientId: "storefront", KeyId: "k1", KeyKind: core.APIKeyKindPublic, Permissions: core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
	}}
	allKey := &core.RequestInfoAPIKey{ClientId: "storefront", KeyId: "k2", KeyKind: core.APIKeyKindPrivate, Permissions: tests.AllCollectionsActions}
	emptyKey := &core.RequestInfoAPIKey{ClientId: "storefront", KeyId: "k3", KeyKind: core.APIKeyKindPublic}

	info := func(auth *core.Record, key *core.RequestInfoAPIKey) *core.RequestInfo {
		return &core.RequestInfo{Auth: auth, APIKey: key}
	}

	type expect struct {
		allowed bool
		bypass  bool
	}

	scenarios := []struct {
		name     string
		info     *core.RequestInfo
		target   core.AuthorizeTarget
		expected expect
	}{
		// guest + key (a key alone is still a guest governed by the rules)
		{"guest key allowed action", info(nil, readKey), core.AuthorizeTarget{Collection: demo2, Action: "list"}, expect{true, false}},
		{"guest key not allowed action", info(nil, readKey), core.AuthorizeTarget{Collection: demo2, Action: "create"}, expect{false, false}},
		{"guest key other collection", info(nil, readKey), core.AuthorizeTarget{Collection: demo1, Action: "list"}, expect{false, false}},
		{"guest all actions key (never bypass)", info(nil, allKey), core.AuthorizeTarget{Collection: demo1, Action: "delete"}, expect{true, false}},
		{"guest empty key", info(nil, emptyKey), core.AuthorizeTarget{Collection: demo2, Action: "view"}, expect{false, false}},
		{"guest key system collection (unchanged guest)", info(nil, allKey), core.AuthorizeTarget{Collection: externalAuths, Action: "list"}, expect{true, false}},
		{"guest key system resource", info(nil, allKey), core.AuthorizeTarget{Resource: "logs", Level: "read"}, expect{false, false}},

		// customer + key
		{"customer key allowed action", info(customer, readKey), core.AuthorizeTarget{Collection: demo2, Action: "view"}, expect{true, false}},
		{"customer key ceiling", info(customer, readKey), core.AuthorizeTarget{Collection: demo2, Action: "delete"}, expect{false, false}},
		{"customer empty key", info(customer, emptyKey), core.AuthorizeTarget{Collection: demo2, Action: "list"}, expect{false, false}},
		{"customer key system resource", info(customer, allKey), core.AuthorizeTarget{Resource: "logs", Level: "read"}, expect{false, false}},

		// staff + key (the actor bypass is kept only within the ceiling)
		{"staff key within the ceiling", info(limited, readKey), core.AuthorizeTarget{Collection: demo2, Action: "list"}, expect{true, true}},
		{"staff key outside the ceiling", info(limited, readKey), core.AuthorizeTarget{Collection: demo2, Action: "create"}, expect{false, false}},
		{"staff all actions key doesn't add role permissions", info(limited, allKey), core.AuthorizeTarget{Collection: demo1, Action: "list"}, expect{false, false}},
		{"staff key mapped system collection (unchanged)", info(limited, emptyKey), core.AuthorizeTarget{Collection: externalAuths, Action: "list"}, expect{true, true}},
		{"staff key system resource (unchanged)", info(limited, emptyKey), core.AuthorizeTarget{Resource: "sessions", Level: "read"}, expect{true, true}},

		// Owner + key
		{"Owner key within the ceiling", info(owner, readKey), core.AuthorizeTarget{Collection: demo2, Action: "view"}, expect{true, true}},
		{"Owner key outside the ceiling", info(owner, readKey), core.AuthorizeTarget{Collection: demo1, Action: "view"}, expect{false, false}},
		{"Owner key system collection (unchanged)", info(owner, emptyKey), core.AuthorizeTarget{Collection: superusers, Action: "delete"}, expect{true, true}},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			access := core.Authorize(app, s.info, s.target)
			if access.Allowed != s.expected.allowed || access.BypassRules != s.expected.bypass {
				t.Fatalf("Expected %+v, got %+v", s.expected, access)
			}
		})
	}
}

func TestRequestInfoAPIKeyClone(t *testing.T) {
	t.Parallel()

	var nilClient *core.RequestInfoAPIKey
	if nilClient.Clone() != nil {
		t.Fatal("Expected nil clone")
	}

	original := &core.RequestInfoAPIKey{
		ClientId:    "storefront",
		KeyId:       "k1",
		KeyKind:     core.APIKeyKindPrivate,
		BuyerIP:     "127.0.0.1",
		Permissions: core.Permissions{Collections: map[string][]string{"*": {"list"}}},
	}

	clone := original.Clone()
	clone.Permissions.Collections["*"][0] = "delete"
	clone.Permissions.Collections["other"] = []string{"view"}
	clone.BuyerIP = "changed"

	if original.Permissions.Collections["*"][0] != "list" || len(original.Permissions.Collections) != 1 || original.BuyerIP != "127.0.0.1" {
		t.Fatalf("Expected a deep copy, got original %+v", original)
	}

	info := &core.RequestInfo{APIKey: original}
	infoClone := info.Clone()
	if infoClone.APIKey == original || infoClone.APIKey.KeyId != "k1" {
		t.Fatalf("Expected the request info clone to have a copy of the client, got %+v", infoClone.APIKey)
	}
}
