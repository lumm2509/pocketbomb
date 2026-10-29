package core_test

import (
	"slices"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/tools/types"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
)

func TestNewOAuth2Client(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client := core.NewOAuth2Client(app)

	if client.Collection().Name != core.CollectionNameOAuth2Clients {
		t.Fatalf("Expected record with %q collection, got %q", core.CollectionNameOAuth2Clients, client.Collection().Name)
	}
}

func TestOAuth2ClientProxyRecord(t *testing.T) {
	t.Parallel()

	record := core.NewRecord(core.NewBaseCollection("test"))
	record.Id = "test_id"

	client := core.OAuth2Client{}
	client.SetProxyRecord(record)

	if client.ProxyRecord() == nil || client.ProxyRecord().Id != record.Id {
		t.Fatalf("Expected proxy record with id %q, got %v", record.Id, client.ProxyRecord())
	}
}

func TestOAuth2ClientGettersAndSetters(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client := core.NewOAuth2Client(app)

	client.SetName("test_name")
	if v := client.Name(); v != "test_name" {
		t.Fatalf("Expected name %q, got %q", "test_name", v)
	}

	client.SetClientId("test_client_id")
	if v := client.ClientId(); v != "test_client_id" {
		t.Fatalf("Expected clientId %q, got %q", "test_client_id", v)
	}

	client.SetType(core.OAuth2ClientTypeConfidential)
	if v := client.Type(); v != core.OAuth2ClientTypeConfidential || !client.IsConfidential() {
		t.Fatalf("Expected confidential type, got %q", v)
	}
	client.SetType(core.OAuth2ClientTypePublic)
	if client.IsConfidential() {
		t.Fatal("Expected public client")
	}

	client.SetCollectionRef("test_collection")
	if v := client.CollectionRef(); v != "test_collection" {
		t.Fatalf("Expected collectionRef %q, got %q", "test_collection", v)
	}

	client.SetRedirectURIs([]string{"https://a.example.com", "https://b.example.com"})
	if v := client.RedirectURIs(); len(v) != 2 || v[1] != "https://b.example.com" {
		t.Fatalf("Unexpected redirectURIs %v", v)
	}

	client.SetPostLogoutRedirectURIs([]string{"https://c.example.com"})
	if v := client.PostLogoutRedirectURIs(); len(v) != 1 || v[0] != "https://c.example.com" {
		t.Fatalf("Unexpected postLogoutRedirectURIs %v", v)
	}

	client.SetScopes([]string{"openid"})
	if v := client.Scopes(); len(v) != 1 || v[0] != "openid" {
		t.Fatalf("Unexpected scopes %v", v)
	}

	client.SetFirstParty(true)
	if !client.FirstParty() {
		t.Fatal("Expected firstParty true")
	}

	client.SetLogo("https://example.com/logo.png")
	if v := client.Logo(); v != "https://example.com/logo.png" {
		t.Fatalf("Unexpected logo %q", v)
	}

	client.SetDisabled(true)
	if !client.Disabled() {
		t.Fatal("Expected disabled true")
	}
}

func TestOAuth2ClientSecret(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client := core.NewOAuth2Client(app)

	if client.ValidateClientSecret("") || client.ValidateClientSecret("test") {
		t.Fatal("Expected secret validation to fail for client without secret")
	}

	client.SetClientSecret("test")

	if v := client.ClientSecretHash(); v == "test" || v != security.SHA256("test") {
		t.Fatalf("Expected the secret to be stored as sha256 hash, got %q", v)
	}

	if !client.ValidateClientSecret("test") {
		t.Fatal("Expected valid secret")
	}

	if client.ValidateClientSecret("test2") || client.ValidateClientSecret("") {
		t.Fatal("Expected invalid secret")
	}

	client.SetClientSecret("")
	if client.ClientSecretHash() != "" {
		t.Fatal("Expected the secret hash to be cleared")
	}
}

func TestOAuth2ClientRedirectURIs(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client := core.NewOAuth2Client(app)
	client.SetRedirectURIs([]string{"https://example.com/callback", "com.example.app:/callback"})
	client.SetPostLogoutRedirectURIs([]string{"https://example.com/logout"})

	scenarios := []struct {
		uri            string
		expectRedirect bool
		expectLogout   bool
	}{
		{"", false, false},
		{"https://example.com/callback", true, false},
		{"https://example.com/callback/", false, false},
		{"https://example.com/callback?a=1", false, false},
		{"HTTPS://example.com/callback", false, false},
		{"com.example.app:/callback", true, false},
		{"https://example.com/logout", false, true},
	}

	for _, s := range scenarios {
		t.Run(s.uri, func(t *testing.T) {
			if v := client.HasRedirectURI(s.uri); v != s.expectRedirect {
				t.Fatalf("Expected HasRedirectURI %v, got %v", s.expectRedirect, v)
			}

			if v := client.HasPostLogoutRedirectURI(s.uri); v != s.expectLogout {
				t.Fatalf("Expected HasPostLogoutRedirectURI %v, got %v", s.expectLogout, v)
			}
		})
	}
}

func TestOAuth2ClientValidateHook(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	users.OAuth2Server.Scopes = []string{"posts:read"}
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	demo1, err := app.FindCollectionByNameOrId("demo1")
	if err != nil {
		t.Fatal(err)
	}

	stubOAuth2Client(t, app, "users", "existing")

	scenarios := []struct {
		name           string
		client         func() *core.OAuth2Client
		expectedErrors []string
	}{
		{
			"empty client",
			func() *core.OAuth2Client {
				return core.NewOAuth2Client(app)
			},
			// note: the field validators run first
			[]string{"name", "clientId", "type", "collectionRef"},
		},
		{
			"non-auth collectionRef",
			func() *core.OAuth2Client {
				c := core.NewOAuth2Client(app)
				c.SetName("test")
				c.SetClientId("test")
				c.SetType(core.OAuth2ClientTypePublic)
				c.SetCollectionRef(demo1.Id)
				c.SetRedirectURIs([]string{"https://example.com"})
				return c
			},
			[]string{"collectionRef"},
		},
		{
			"invalid fields",
			func() *core.OAuth2Client {
				c := core.NewOAuth2Client(app)
				c.SetName("test")
				c.SetClientId("invalid client id")
				c.SetType(core.OAuth2ClientTypeConfidential) // missing secret
				c.SetCollectionRef(users.Id)
				c.SetRedirectURIs([]string{"https://example.com", "/relative", "https://example.com#fragment", "https://user:pass@example.com", "https:///missing-host"})
				c.SetPostLogoutRedirectURIs([]string{"invalid"})
				c.SetScopes([]string{"openid", "posts:write"})
				return c
			},
			[]string{"clientId", "redirectURIs", "postLogoutRedirectURIs", "scopes"},
		},
		{
			"valid public client",
			func() *core.OAuth2Client {
				c := core.NewOAuth2Client(app)
				c.SetName("test")
				c.SetClientId("new_public")
				c.SetType(core.OAuth2ClientTypePublic)
				c.SetCollectionRef(users.Id)
				c.SetRedirectURIs([]string{"https://example.com/callback", "com.example.app:/callback", "http://127.0.0.1:1234/callback"})
				c.SetScopes([]string{"openid", "offline_access", "posts:read"})
				return c
			},
			[]string{},
		},
		{
			"valid confidential client",
			func() *core.OAuth2Client {
				c := core.NewOAuth2Client(app)
				c.SetName("test")
				c.SetClientId("new_confidential")
				c.SetClientSecret("secret")
				c.SetType(core.OAuth2ClientTypeConfidential)
				c.SetCollectionRef(users.Id)
				c.SetRedirectURIs([]string{"https://example.com/callback"})
				return c
			},
			[]string{},
		},
		{
			"non first-party _superusers client",
			func() *core.OAuth2Client {
				superusers, err := app.FindCachedCollectionByNameOrId(core.CollectionNameSuperusers)
				if err != nil {
					t.Fatal(err)
				}

				c := core.NewOAuth2Client(app)
				c.SetName("test")
				c.SetClientId("new_superusers_3p")
				c.SetType(core.OAuth2ClientTypePublic)
				c.SetCollectionRef(superusers.Id)
				c.SetRedirectURIs([]string{"https://example.com/callback"})
				return c
			},
			[]string{"firstParty"},
		},
		{
			"first-party _superusers client",
			func() *core.OAuth2Client {
				superusers, err := app.FindCachedCollectionByNameOrId(core.CollectionNameSuperusers)
				if err != nil {
					t.Fatal(err)
				}

				c := core.NewOAuth2Client(app)
				c.SetName("test")
				c.SetClientId("new_superusers_1p")
				c.SetType(core.OAuth2ClientTypePublic)
				c.SetCollectionRef(superusers.Id)
				c.SetFirstParty(true)
				c.SetRedirectURIs([]string{"https://example.com/callback"})
				return c
			},
			[]string{},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			tests.TestValidationErrors(t, app.Validate(s.client()), s.expectedErrors)
		})
	}

	t.Run("duplicated clientId", func(t *testing.T) {
		c := core.NewOAuth2Client(app)
		c.SetName("test")
		c.SetClientId("existing")
		c.SetType(core.OAuth2ClientTypePublic)
		c.SetCollectionRef(users.Id)
		c.SetRedirectURIs([]string{"https://example.com"})

		if err := app.Save(c); err == nil {
			t.Fatal("Expected unique clientId constraint error")
		}
	})
}

func TestOAuth2ClientDeleteOnAuthCollectionDelete(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	clientsCollection := core.NewAuthCollection("new_auth")
	if err := app.Save(clientsCollection); err != nil {
		t.Fatal(err)
	}

	record := core.NewRecord(clientsCollection)
	record.SetEmail("test@example.com")
	record.SetPassword("1234567890")
	if err := app.Save(record); err != nil {
		t.Fatal(err)
	}

	usersClient := stubOAuth2Client(t, app, "users", "users_client")
	clientsClient := stubOAuth2Client(t, app, "new_auth", "clients_client")

	session := stubAuthSession(t, app, clientsClient, record, []string{"openid"})

	if _, err := app.SaveOAuth2Consent(record, clientsClient, []string{"openid"}); err != nil {
		t.Fatal(err)
	}

	if err := app.Delete(clientsCollection); err != nil {
		t.Fatal(err)
	}

	if _, err := app.FindOAuth2ClientById(clientsClient.Id); err == nil {
		t.Fatal("Expected the clients collection OAuth2 client to be deleted")
	}

	if _, err := app.FindAuthSessionById(session.Id); err == nil {
		t.Fatal("Expected the clients collection auth session to be deleted")
	}

	total, err := app.CountRecords(core.CollectionNameOAuth2Consents)
	if err != nil || total != 0 {
		t.Fatalf("Expected the clients collection consents to be deleted, got %d (%v)", total, err)
	}

	if _, err := app.FindOAuth2ClientById(usersClient.Id); err != nil {
		t.Fatalf("Expected the users OAuth2 client to remain, got %v", err)
	}
}

func TestOAuth2ClientDeleteCascade(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client1 := stubOAuth2Client(t, app, "users", "client1")
	client2 := stubOAuth2Client(t, app, "users", "client2")

	session1 := stubAuthSession(t, app, client1, user, []string{"openid"})
	session2 := stubAuthSession(t, app, client2, user, []string{"openid"})

	consent1, err := app.SaveOAuth2Consent(user, client1, []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}

	if err := app.Delete(client1); err != nil {
		t.Fatal(err)
	}

	if _, err := app.FindAuthSessionById(session1.Id); err == nil {
		t.Fatal("Expected session1 to be deleted")
	}

	if _, err := app.FindRecordById(core.CollectionNameOAuth2Consents, consent1.Id); err == nil {
		t.Fatal("Expected consent1 to be deleted")
	}

	if _, err := app.FindAuthSessionById(session2.Id); err != nil {
		t.Fatalf("Expected session2 to remain, got %v", err)
	}
}

func TestFindOAuth2Clients(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client1 := stubOAuth2Client(t, app, "users", "client1")
	client2 := stubOAuth2Client(t, app, "users", "client2")
	client3 := stubOAuth2Client(t, app, "clients", "client3")

	// FindOAuth2ClientByClientId
	// ---
	if _, err := app.FindOAuth2ClientByClientId("missing"); err == nil {
		t.Fatal("Expected error for missing client")
	}

	found, err := app.FindOAuth2ClientByClientId("client2")
	if err != nil {
		t.Fatal(err)
	}
	if found.Id != client2.Id {
		t.Fatalf("Expected client %q, got %q", client2.Id, found.Id)
	}

	// FindOAuth2ClientById
	// ---
	if _, err := app.FindOAuth2ClientById("client1"); err == nil {
		t.Fatal("Expected error when searching by clientId")
	}

	found, err = app.FindOAuth2ClientById(client3.Id)
	if err != nil {
		t.Fatal(err)
	}
	if found.ClientId() != "client3" {
		t.Fatalf("Expected client3, got %q", found.ClientId())
	}

	// FindAllOAuth2ClientsByCollection
	// ---
	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	all, err := app.FindAllOAuth2ClientsByCollection(users)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("Expected 2 users clients, got %d", len(all))
	}
	for _, c := range all {
		if c.Id != client1.Id && c.Id != client2.Id {
			t.Fatalf("Unexpected client %q", c.ClientId())
		}
	}
}

func TestOAuth2ClientIsUsable(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	scenarios := []struct {
		name       string
		clientType string
		secret     string
		disabled   bool
		expected   bool
	}{
		{"public", core.OAuth2ClientTypePublic, "", false, true},
		{"disabled public", core.OAuth2ClientTypePublic, "", true, false},
		{"confidential without secret", core.OAuth2ClientTypeConfidential, "", false, false},
		{"confidential with secret", core.OAuth2ClientTypeConfidential, "test", false, true},
		{"disabled confidential with secret", core.OAuth2ClientTypeConfidential, "test", true, false},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			c := core.NewOAuth2Client(app)
			c.SetType(s.clientType)
			c.SetClientSecret(s.secret)
			c.SetDisabled(s.disabled)

			if v := c.IsUsable(); v != s.expected {
				t.Fatalf("Expected %v, got %v", s.expected, v)
			}
		})
	}
}

func TestIsDashboardClientIdValidation(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	usersClient := stubOAuth2Client(t, app, "users", "dashboard_check")

	// an impersonation session with a regular (non-dashboard) client is valid
	// and its client relation is checked against the issuer collection
	s := newPendingAuthSession(t, app, usersClient)
	if err := app.Save(s); err != nil {
		t.Fatal(err)
	}

	s.SetRecordRef(user.Id)
	s.SetImpersonator("staff_id")
	if err := app.Save(s); err != nil {
		t.Fatalf("Expected the impersonation session to be valid, got %v", err)
	}

	// a missing client id is not the dashboard client
	s.SetImpersonator("staff_id")
	s.SetClient("")
	if err := app.Validate(s); err == nil {
		t.Fatal("Expected a missing client error")
	}
}

// stubOAuth2Client creates and persists a new confidential OAuth2 client
// for the specified auth collection.
func stubOAuth2Client(t testing.TB, app *tests.TestApp, collectionNameOrId string, clientId string) *core.OAuth2Client {
	t.Helper()

	collection, err := app.FindCollectionByNameOrId(collectionNameOrId)
	if err != nil {
		t.Fatal(err)
	}

	client := core.NewOAuth2Client(app)
	client.SetName("Test " + clientId)
	client.SetClientId(clientId)
	client.SetClientSecret("secret_" + clientId)
	client.SetType(core.OAuth2ClientTypeConfidential)
	client.SetCollectionRef(collection.Id)
	client.SetRedirectURIs([]string{"https://example.com/callback"})
	client.SetScopes([]string{core.OAuth2ScopeOpenId, core.OAuth2ScopeEmail})

	if err := app.Save(client); err != nil {
		t.Fatal(err)
	}

	return client
}

// stubAuthSession creates and persists a new active auth session for the specified
// client and auth record (the missing custom scopes are registered in the
// collection and client to simplify the tests setup).
func stubAuthSession(t testing.TB, app *tests.TestApp, client *core.OAuth2Client, record *core.Record, scopes []string, optModifiers ...func(s *core.AuthSession)) *core.AuthSession {
	t.Helper()

	collection, err := app.FindCollectionByNameOrId(record.Collection().Id)
	if err != nil {
		t.Fatal(err)
	}

	clientScopes := client.Scopes()
	var collectionChanged, clientChanged bool
	for _, s := range scopes {
		if !slices.Contains(collection.OAuth2Server.AllowedScopes(), s) {
			collection.OAuth2Server.Scopes = append(collection.OAuth2Server.Scopes, s)
			collectionChanged = true
		}
		if !slices.Contains(clientScopes, s) {
			clientScopes = append(clientScopes, s)
			clientChanged = true
		}
	}
	if collectionChanged {
		if err := app.Save(collection); err != nil {
			t.Fatal(err)
		}
	}
	if clientChanged {
		client.SetScopes(clientScopes)
		if err := app.Save(client); err != nil {
			t.Fatal(err)
		}
	}

	// refetch to ensure that the latest collection state is loaded
	fresh, err := app.FindRecordById(collection, record.Id)
	if err != nil {
		t.Fatal(err)
	}

	session, err := app.CreateAuthSession(fresh, client, core.AuthSessionOptions{
		Scopes:      scopes,
		AuthMethods: []core.AuthSessionMethod{{Method: core.AuthSessionMethodPassword, Time: types.NowDateTime()}},
		Duration:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(optModifiers) > 0 {
		for _, m := range optModifiers {
			m(session)
		}
		if err := app.Save(session); err != nil {
			t.Fatal(err)
		}
	}

	return session
}

// stubSSORoot creates and persists a new root SSO session (without client) for the specified auth record.
func stubSSORoot(t testing.TB, app *tests.TestApp, record *core.Record, optModifiers ...func(s *core.AuthSession)) *core.AuthSession {
	t.Helper()

	root := core.NewAuthSession(app)
	root.Set("status", core.AuthSessionStatusActive)
	root.SetCollectionRef(record.Collection().Id)
	root.SetRecordRef(record.Id)
	root.SetSSOSecret("sso_secret")
	root.SetAuthTime(types.NowDateTime())
	root.SetExpiresAt(types.NowDateTime().Add(time.Hour))

	for _, m := range optModifiers {
		m(root)
	}

	if err := app.Save(root); err != nil {
		t.Fatal(err)
	}

	return root
}

func TestDashboardOAuth2ClientProtection(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	client, err := app.FindOAuth2ClientByClientId(core.OAuth2DashboardClientId)
	if err != nil {
		t.Fatalf("Expected the built-in dashboard client, got %v", err)
	}

	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	users, _ := app.FindCollectionByNameOrId("users")

	if !client.IsDashboard() || !client.FirstParty() || client.IsConfidential() || client.Disabled() || client.CollectionRef() != superusers.Id {
		t.Fatalf("Unexpected dashboard client state %v", client.PublicExport())
	}

	scenarios := []struct {
		name           string
		modify         func(c *core.OAuth2Client)
		expectedErrors []string
	}{
		{"disable", func(c *core.OAuth2Client) { c.SetDisabled(true) }, []string{"disabled"}},
		{"confidential", func(c *core.OAuth2Client) { c.SetType(core.OAuth2ClientTypeConfidential) }, []string{"type"}},
		{"third-party", func(c *core.OAuth2Client) { c.SetFirstParty(false) }, []string{"firstParty"}},
		{"redirect uris", func(c *core.OAuth2Client) { c.SetRedirectURIs([]string{"https://evil.example.com/_/"}) }, []string{"redirectURIs"}},
		{"post logout redirect uris", func(c *core.OAuth2Client) { c.SetPostLogoutRedirectURIs([]string{"https://evil.example.com"}) }, []string{"postLogoutRedirectURIs"}},
		{"collection", func(c *core.OAuth2Client) { c.SetCollectionRef(users.Id) }, []string{"collectionRef"}},
		{"client id", func(c *core.OAuth2Client) { c.SetClientId("renamed") }, []string{"clientId"}},
		{"name and logo (allowed)", func(c *core.OAuth2Client) {
			c.SetName("Admin")
			c.SetLogo("https://example.com/logo.png")
		}, []string{}},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			c, err := app.FindOAuth2ClientByClientId(core.OAuth2DashboardClientId)
			if err != nil {
				t.Fatal(err)
			}

			s.modify(c)

			tests.TestValidationErrors(t, app.Validate(c), s.expectedErrors)
		})
	}

	if err := app.Delete(client); err == nil {
		t.Fatal("Expected the dashboard client delete to fail")
	}

	if _, err := app.FindOAuth2ClientByClientId(core.OAuth2DashboardClientId); err != nil {
		t.Fatal("Expected the dashboard client to remain")
	}

	// a regular client without redirect URIs is still invalid
	regular := core.NewOAuth2Client(app)
	regular.SetName("regular")
	regular.SetClientId("regular")
	regular.SetType(core.OAuth2ClientTypePublic)
	regular.SetCollectionRef(users.Id)
	tests.TestValidationErrors(t, app.Validate(regular), []string{"redirectURIs"})
}

func TestIsDashboardRedirectURI(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name          string
		uri           string
		appURL        string
		requestOrigin string
		expected      bool
	}{
		{"empty", "", "http://localhost:8090", "http://localhost:8090", false},
		{"app url origin", "https://example.com/_/", "https://example.com", "", true},
		{"app url origin with different request host", "https://example.com/_/", "https://example.com", "http://internal:8090", true},
		{"app url origin but different scheme", "http://example.com/_/", "https://example.com", "", false},
		{"request host (empty app url)", "http://127.0.0.1:8090/_/", "", "http://127.0.0.1:8090", true},
		{"request origin https (TLS or trusted proxy)", "https://127.0.0.1:8090/_/", "", "https://127.0.0.1:8090", true},
		{"https redirect for http request origin", "https://127.0.0.1:8090/_/", "", "http://127.0.0.1:8090", false},
		{"http redirect for https request origin (downgrade)", "http://127.0.0.1:8090/_/", "", "https://127.0.0.1:8090", false},
		{"http redirect for https request origin with matching http app url host but https request", "http://internal:8090/_/", "https://example.com", "https://internal:8090", false},
		{"request origin without scheme", "http://127.0.0.1:8090/_/", "", "127.0.0.1:8090", false},
		{"request host case insensitive", "http://LOCALHOST:8090/_/", "", "http://localhost:8090", true},
		{"other host (open redirect)", "https://evil.example.com/_/", "https://example.com", "http://example.com", false},
		{"other port", "https://example.com:8443/_/", "https://example.com", "http://example.com", false},
		{"subdomain", "https://evil.example.com/_/", "https://example.com", "", false},
		{"userinfo", "https://example.com@evil.example.com/_/", "https://example.com", "http://example.com", false},
		{"userinfo of the app host", "https://user@example.com/_/", "https://example.com", "http://example.com", false},
		{"other path", "https://example.com/other/", "https://example.com", "http://example.com", false},
		{"path without trailing slash", "https://example.com/_", "https://example.com", "http://example.com", false},
		{"sub path", "https://example.com/_/x", "https://example.com", "http://example.com", false},
		{"encoded path", "https://example.com/%5F/", "https://example.com", "http://example.com", false},
		{"query", "https://example.com/_/?next=https://evil.example.com", "https://example.com", "http://example.com", false},
		{"fragment", "https://example.com/_/#/evil", "https://example.com", "http://example.com", false},
		{"empty fragment", "https://example.com/_/#", "https://example.com", "http://example.com", false},
		{"non http scheme", "javascript://example.com/_/", "https://example.com", "http://example.com", false},
		{"relative", "/_/", "https://example.com", "http://example.com", false},
		{"scheme relative", "//evil.example.com/_/", "https://example.com", "http://example.com", false},
		{"backslash trick", "https://example.com\\@evil.example.com/_/", "https://example.com", "http://example.com", false},
		{"empty app url and request host", "https://example.com/_/", "", "", false},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			result := core.IsDashboardRedirectURI(s.uri, s.appURL, s.requestOrigin)
			if result != s.expected {
				t.Fatalf("Expected %v, got %v", s.expected, result)
			}
		})
	}

	// the regular clients use only the stored exact redirect URIs
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	dashboard, err := app.FindOAuth2ClientByClientId(core.OAuth2DashboardClientId)
	if err != nil {
		t.Fatal(err)
	}
	if !dashboard.AllowsRedirectURI("http://localhost:8090/_/", "", "http://localhost:8090") ||
		dashboard.AllowsRedirectURI("https://evil.example.com/_/", "", "http://localhost:8090") ||
		dashboard.AllowsRedirectURI("http://localhost:8090/_/", "", "https://localhost:8090") ||
		!dashboard.AllowsPostLogoutRedirectURI("http://localhost:8090/_/", "", "http://localhost:8090") ||
		dashboard.AllowsPostLogoutRedirectURI("http://localhost:8090/_/", "", "https://localhost:8090") {
		t.Fatal("Unexpected dashboard client redirect checks")
	}

	regular := core.NewOAuth2Client(app)
	regular.SetRedirectURIs([]string{"https://example.com/callback"})
	if !regular.AllowsRedirectURI("https://example.com/callback", "", "") ||
		regular.AllowsRedirectURI("http://localhost:8090/_/", "", "http://localhost:8090") {
		t.Fatal("Unexpected regular client redirect checks")
	}
}
