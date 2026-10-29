package core_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestOAuth2CollectionScopes(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	view1, _ := app.FindCollectionByNameOrId("view1")
	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	users, _ := app.FindCollectionByNameOrId("users")

	if s := core.OAuth2CollectionScopes(demo2); !slices.Equal(s, []string{"read_demo2", "write_demo2"}) {
		t.Fatalf("Unexpected demo2 scopes %v", s)
	}
	if s := core.OAuth2CollectionScopes(view1); !slices.Equal(s, []string{"read_view1"}) {
		t.Fatalf("Unexpected view scopes %v", s)
	}
	if s := core.OAuth2CollectionScopes(superusers); len(s) != 0 {
		t.Fatalf("Expected no system collection scopes, got %v", s)
	}

	system := core.OAuth2SystemScopes()
	if !slices.Contains(system, "system:read_settings") || !slices.Contains(system, "system:write_impersonate") || slices.Contains(system, "system:write_sql") {
		t.Fatalf("Unexpected system scopes %v", system)
	}

	allowed := core.OAuth2AllowedScopes(app, users)
	for _, s := range []string{"openid", "read_demo2", "write_demo2", "read_view1"} {
		if !slices.Contains(allowed, s) {
			t.Fatalf("Expected %q in the allowed scopes %v", s, allowed)
		}
	}
	if slices.Contains(allowed, "read__superusers") {
		t.Fatal("Expected no system collection scopes")
	}
	for _, s := range system {
		if slices.Contains(allowed, s) {
			t.Fatalf("Expected the system scope %q to not be grantable", s)
		}
	}
	if slices.Contains(allowed, "read_logs") || slices.Contains(allowed, "write_settings") {
		t.Fatal("Expected the system scopes to not be grantable")
	}

	checks := []struct {
		scopes   []string
		action   string
		expected bool
	}{
		{[]string{"read_demo2"}, "list", true},
		{[]string{"read_demo2"}, "view", true},
		{[]string{"read_demo2"}, "create", false},
		{[]string{"write_demo2"}, "view", true},
		{[]string{"write_demo2"}, "delete", true},
		{[]string{"read_demo1"}, "list", false},
		{nil, "list", false},
	}
	for _, c := range checks {
		if v := core.OAuth2ScopesAllowCollection(c.scopes, demo2, c.action); v != c.expected {
			t.Fatalf("Expected %v for %v %s, got %v", c.expected, c.scopes, c.action, v)
		}
	}

	if l := core.OAuth2ScopeLabel(app, "write_demo2"); l == "" {
		t.Fatal("Expected label for write_demo2")
	}
	if l := core.OAuth2ScopeLabel(app, "read__superusers"); l != "" {
		t.Fatalf("Expected no label for system collection, got %q", l)
	}

	renamed, changed := core.RenameOAuth2CollectionScopes([]string{"openid", "read_demo2", "write_demo2", "read_demo22"}, "demo2", "posts")
	if !changed || !slices.Equal(renamed, []string{"openid", "read_posts", "write_posts", "read_demo22"}) {
		t.Fatalf("Unexpected renamed scopes %v", renamed)
	}
}

func TestCollectionRenameRewritesOAuth2Scopes(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, _ := app.FindCollectionByNameOrId("users")
	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client := core.NewOAuth2Client(app)
	client.SetName("rename test")
	client.SetClientId("rename_test")
	client.SetType(core.OAuth2ClientTypePublic)
	client.SetCollectionRef(users.Id)
	client.SetRedirectURIs([]string{"https://example.com/callback"})
	client.SetScopes([]string{"openid", "read_demo2", "write_demo2"})
	if err := app.Save(client); err != nil {
		t.Fatal(err)
	}

	consent, err := app.SaveOAuth2Consent(user, client, []string{"openid", "read_demo2"})
	if err != nil {
		t.Fatal(err)
	}

	session, err := app.CreateAuthSession(user, client, core.AuthSessionOptions{Scopes: []string{"openid", "write_demo2"}})
	if err != nil {
		t.Fatal(err)
	}

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	demo2.Name = "posts_renamed"
	if err := app.Save(demo2); err != nil {
		t.Fatal(err)
	}

	client, _ = app.FindOAuth2ClientByClientId("rename_test")
	if !slices.Equal(client.Scopes(), []string{"openid", "read_posts_renamed", "write_posts_renamed"}) {
		t.Fatalf("Unexpected client scopes %v", client.Scopes())
	}

	consentRecord, _ := app.FindRecordById(core.CollectionNameOAuth2Consents, consent.Id)
	if !slices.Equal(consentRecord.GetStringSlice("scopes"), []string{"openid", "read_posts_renamed"}) {
		t.Fatalf("Unexpected consent scopes %v", consentRecord.GetStringSlice("scopes"))
	}

	sessionRecord, _ := app.FindAuthSessionById(session.Id)
	if !slices.Equal(sessionRecord.Scopes(), []string{"openid", "write_posts_renamed"}) ||
		!slices.Equal(sessionRecord.ScopesRequested(), []string{"openid", "write_posts_renamed"}) {
		t.Fatalf("Unexpected session scopes %v / %v", sessionRecord.Scopes(), sessionRecord.ScopesRequested())
	}
}

func TestOAuth2SystemScopesNamespace(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// a regular collection with the same name as a system resource
	settings := core.NewBaseCollection("settings")
	if err := app.Save(settings); err != nil {
		t.Fatal(err)
	}

	if s := core.OAuth2CollectionScopes(settings); !slices.Equal(s, []string{"read_settings", "write_settings"}) {
		t.Fatalf("Unexpected settings collection scopes %v", s)
	}

	for _, s := range core.OAuth2SystemScopes() {
		if !strings.HasPrefix(s, "system:read_") && !strings.HasPrefix(s, "system:write_") {
			t.Fatalf("Expected the system scope %q to be in the system: namespace", s)
		}
		if core.IsOAuth2CollectionScope(s) || !core.IsOAuth2SystemScope(s) {
			t.Fatalf("Expected %q to be detected only as system scope", s)
		}
	}
	if slices.Contains(core.OAuth2SystemScopes(), "read_settings") {
		t.Fatal("Expected the collection scope format to not be part of the system scopes")
	}

	if core.OAuth2SystemScope(core.PermissionResourceSettings, core.PermissionLevelRead) != "system:read_settings" ||
		core.OAuth2SystemScope(core.PermissionResourceLogs, core.PermissionLevelWrite) != "system:write_logs" {
		t.Fatal("Unexpected OAuth2SystemScope result")
	}

	// read_settings is the collection scope and never maps to the settings system resource
	if !core.OAuth2ScopesAllowCollection([]string{"read_settings"}, settings, core.PermissionActionList) {
		t.Fatal("Expected read_settings to grant the settings collection list")
	}

	users, _ := app.FindCollectionByNameOrId("users")
	allowed := core.OAuth2AllowedScopes(app, users)
	if !slices.Contains(allowed, "read_settings") || slices.Contains(allowed, "system:read_settings") {
		t.Fatalf("Unexpected allowed scopes %v", allowed)
	}

	customer, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	info := &core.RequestInfo{
		Auth: customer,
		OAuth2: core.RequestInfoOAuth2{
			ClientId: "3p",
			Scopes:   []string{"read_settings", "write_settings", "system:read_settings", "system:write_settings"},
		},
	}
	actor, err := core.ResolveActorPermissions(app, info)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(actor.Scopes, []string{"read_settings", "write_settings"}) {
		t.Fatalf("Expected only the collection scopes to be kept, got %v", actor.Scopes)
	}
	if info.Can(app, core.PermissionResourceSettings, core.PermissionLevelRead) {
		t.Fatal("Expected no settings system resource access")
	}

	// labels
	labels := map[string]string{
		"read_settings":           "Read your settings data",
		"write_settings":          "Read, create, update and delete your settings data",
		"system:read_settings":    "Read the Application settings (system)",
		"system:write_logs":       "Read and manage the Logs (system)",
		"system:read_unknown":     "",
		"system:delete_logs":      "",
		"read_missing":            "",
		"openid":                  "",
		"system:read_impersonate": "",
	}
	for scope, expected := range labels {
		if label := core.OAuth2ScopeLabel(app, scope); label != expected {
			t.Errorf("%s: expected label %q, got %q", scope, expected, label)
		}
	}
}
