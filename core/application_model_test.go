package core_test

import (
	"slices"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/types"
)

const testManifestTOML = `
handle = "acme-sync"
name = "ACME sync"
version = "1.0.0"
description = "Syncs the demo2 records"
application_url = "https://acme.example.com"

[developer]
name = "ACME"
url = "https://dev.acme.example.com"

[access]
scopes = ["write_demo2", "read_demo2", "system:read_logs", "read_demo2"]
optional_scopes = ["read_demo3"]
`

func TestApplicationModelInvariants(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, err := app.FindCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}

	superusers, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}

	application, installed := installTestApplication(t, app, "inv-app", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
		System:      map[string]string{core.PermissionResourceLogs: core.PermissionLevelRead},
	})
	installation := installed.Installation
	client := installed.Client

	t.Run("managed client", func(t *testing.T) {
		if !client.IsManaged() || !client.IsConfidential() || client.FirstParty() ||
			!slices.Equal(client.GrantTypes(), core.OAuth2ManagedClientGrantTypes) ||
			!client.ValidateClientSecret(installed.ClientSecret) {
			t.Fatalf("Unexpected managed client %v", client.PublicExport())
		}
	})

	t.Run("versions are immutable (any save path)", func(t *testing.T) {
		version, err := app.FindApplicationVersionById(installation.VersionRef())
		if err != nil {
			t.Fatal(err)
		}

		version.Set("version", "9.9.9")
		if err := app.Save(version); err == nil {
			t.Fatal("Expected Save to fail")
		}
		if err := app.SaveNoValidate(version); err == nil {
			t.Fatal("Expected SaveNoValidate to fail")
		}
	})

	t.Run("installed version can't be deleted", func(t *testing.T) {
		version, _ := app.FindApplicationVersionById(installation.VersionRef())
		if err := app.Delete(version); err == nil {
			t.Fatal("Expected the installed version delete to fail")
		}
	})

	t.Run("version manifest must match", func(t *testing.T) {
		version := core.NewApplicationVersion(app)
		version.Set("applicationRef", application.Id)
		version.Set("version", "3.0.0")
		version.Set("sourceFormat", "json")
		version.Set("manifest", types.JSONRaw(`{"handle":"other-handle","name":"x","version":"3.0.0"}`))
		tests.TestValidationErrors(t, app.Save(version), []string{"manifest"})

		version.Set("manifest", types.JSONRaw(`{"handle":"inv-app","name":"x","version":"3.0.1"}`))
		tests.TestValidationErrors(t, app.Save(version), []string{"version"})

		version.Set("manifest", types.JSONRaw(`{"handle":"inv-app","name":"x","version":"3.0.0","unknown":1}`))
		tests.TestValidationErrors(t, app.Save(version), []string{"manifest"})
	})

	t.Run("grant validated against the registry", func(t *testing.T) {
		scenarios := []struct {
			name  string
			grant core.Permissions
		}{
			{"owner only level", core.Permissions{System: map[string]string{core.PermissionResourceSettings: core.PermissionLevelWrite}}},
			{"owner only resource", core.Permissions{System: map[string]string{core.PermissionResourceBackups: core.PermissionLevelRead}}},
			{"sql", core.Permissions{System: map[string]string{core.PermissionResourceSQL: core.PermissionLevelWrite}}},
			{"staff", core.Permissions{System: map[string]string{core.PermissionResourceStaff: core.PermissionLevelRead}}},
			{"roles", core.Permissions{System: map[string]string{core.PermissionResourceRoles: core.PermissionLevelRead}}},
			{"sessions", core.Permissions{System: map[string]string{core.PermissionResourceSessions: core.PermissionLevelRead}}},
			{"impersonate", core.Permissions{System: map[string]string{core.PermissionResourceImpersonate: core.PermissionLevelWrite}}},
			{"oauth2 clients", core.Permissions{System: map[string]string{core.PermissionResourceOAuth2Clients: core.PermissionLevelRead}}},
			{"applications", core.Permissions{System: map[string]string{core.PermissionResourceApplications: core.PermissionLevelRead}}},
			{"system collection", core.Permissions{Collections: map[string][]string{superusers.Id: {"list"}}}},
			{"unknown collection", core.Permissions{Collections: map[string][]string{"missing": {"list"}}}},
			{"unknown action", core.Permissions{Collections: map[string][]string{demo2.Id: {"admin"}}}},
		}

		for _, s := range scenarios {
			t.Run(s.name, func(t *testing.T) {
				fresh, _ := app.FindApplicationInstallationById(installation.Id)
				fresh.SetPermissions(s.grant)
				tests.TestValidationErrors(t, app.Save(fresh), []string{"permissions"})
			})
		}

		fresh, _ := app.FindApplicationInstallationById(installation.Id)
		fresh.SetPermissions(core.Permissions{
			Collections: map[string][]string{"*": {"list"}},
			System: map[string]string{
				core.PermissionResourceSettings:    core.PermissionLevelRead,
				core.PermissionResourceCollections: core.PermissionLevelRead,
				core.PermissionResourceLogs:        core.PermissionLevelWrite,
				core.PermissionResourceCrons:       core.PermissionLevelWrite,
				core.PermissionResourceWebhooks:    core.PermissionLevelWrite,
				core.PermissionResourceLLM:         core.PermissionLevelWrite,
			},
		})
		if err := app.Save(fresh); err != nil {
			t.Fatalf("Expected all application grantable levels to be valid, got %v", err)
		}
	})

	t.Run("installation application and version binding", func(t *testing.T) {
		_, other := installTestApplication(t, app, "inv-other", core.Permissions{})

		fresh, _ := app.FindApplicationInstallationById(installation.Id)
		fresh.SetVersionRef(other.Installation.VersionRef())
		tests.TestValidationErrors(t, app.Save(fresh), []string{"versionRef"})

		fresh, _ = app.FindApplicationInstallationById(installation.Id)
		fresh.Set("applicationRef", other.Installation.ApplicationRef())
		tests.TestValidationErrors(t, app.Save(fresh), []string{"applicationRef", "versionRef"})
	})

	t.Run("one installation per application", func(t *testing.T) {
		_, err := app.InstallApplication(application, core.Permissions{}, "")
		if err == nil {
			t.Fatal("Expected the second installation to fail")
		}
	})

	t.Run("managed client can't be changed outside of the installation", func(t *testing.T) {
		fresh, _ := app.FindOAuth2ClientById(client.Id)
		fresh.SetDisabled(true)
		if err := app.Save(fresh); err == nil {
			t.Fatal("Expected the managed client update to fail")
		}
		if err := app.SaveNoValidate(fresh); err == nil {
			t.Fatal("Expected the managed client SaveNoValidate to fail")
		}
		if err := app.Delete(fresh); err == nil {
			t.Fatal("Expected the managed client delete to fail")
		}

		// a new managed client can't be created directly
		users, _ := app.FindCollectionByNameOrId("users")
		created := core.NewOAuth2Client(app)
		created.SetName("x")
		created.SetClientId("x_managed")
		created.SetType(core.OAuth2ClientTypeConfidential)
		created.SetCollectionRef(installation.Collection().Id)
		created.SetGrantTypes([]string{core.OAuth2GrantTypeClientCredentials})
		created.Set("applicationInstallationRef", installation.Id)
		if err := app.Save(created); err == nil {
			t.Fatal("Expected the direct managed client create to fail")
		}

		// a regular client can't use the installations issuer or the client_credentials grant
		regular := core.NewOAuth2Client(app)
		regular.SetName("x")
		regular.SetClientId("x_regular")
		regular.SetType(core.OAuth2ClientTypeConfidential)
		regular.SetCollectionRef(installation.Collection().Id)
		regular.SetRedirectURIs([]string{"https://example.com"})
		tests.TestValidationErrors(t, app.Save(regular), []string{"applicationInstallationRef", "grantTypes", "redirectURIs"})

		regular.SetCollectionRef(users.Id)
		regular.SetGrantTypes([]string{core.OAuth2GrantTypeAuthorizationCode, core.OAuth2GrantTypeClientCredentials})
		tests.TestValidationErrors(t, app.Save(regular), []string{"grantTypes"})

		regular.SetGrantTypes([]string{"password"})
		tests.TestValidationErrors(t, app.Save(regular), []string{"grantTypes"})

		// default grant types of the new regular clients
		regular.SetGrantTypes(nil)
		if err := app.Save(regular); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(regular.GrantTypes(), core.OAuth2DefaultGrantTypes) {
			t.Fatalf("Expected the default grant types, got %v", regular.GrantTypes())
		}
	})

	t.Run("roles can't be assigned to installations", func(t *testing.T) {
		customer, _ := app.FindRoleByName(core.RoleNameCustomer)
		err := tests.AssignRoles(app, installation.Record, customer.Id)
		tests.TestValidationErrors(t, err, []string{"collectionRef"})

		roles, _ := app.FindRecordRoles(installation.Record)
		if len(roles) != 0 {
			t.Fatalf("Expected no roles, got %d", len(roles))
		}
	})

	t.Run("installations collection options are fixed", func(t *testing.T) {
		mutations := []struct {
			name string
			fn   func(c *core.Collection)
		}{
			{"passwordAuth", func(c *core.Collection) { c.PasswordAuth.Enabled = true }},
			{"otp", func(c *core.Collection) { c.OTP.Enabled = true }},
			{"listRule", func(c *core.Collection) { c.ListRule = types.Pointer("") }},
			{"defaultRoles", func(c *core.Collection) { c.DefaultRoles = []string{core.RoleIdCustomer} }},
		}

		for _, m := range mutations {
			t.Run(m.name, func(t *testing.T) {
				c, _ := app.FindCollectionByNameOrId(core.CollectionNameApplicationInstallations)
				m.fn(c)
				tests.TestValidationErrors(t, app.Save(c), []string{m.name})
			})
		}
	})

	t.Run("installation sessions only via client_credentials", func(t *testing.T) {
		if _, err := app.CreateAuthSession(installation.Record, client, core.AuthSessionOptions{
			AuthMethods: []core.AuthSessionMethod{{Method: core.AuthSessionMethodClientCredentials}},
		}); err == nil {
			t.Fatal("Expected NewAuthSession to refuse the installations")
		}

		now := types.NowDateTime()
		newSession := func(record *core.Record, clientId string, method string) *core.AuthSession {
			s := core.NewAuthSession(app)
			s.Set("status", core.AuthSessionStatusActive)
			s.SetCollectionRef(record.Collection().Id)
			s.SetClient(clientId)
			s.SetRecordRef(record.Id)
			s.SetAuthMethods([]core.AuthSessionMethod{{Method: method, Time: now}})
			s.SetExpiresAt(now.Add(core.AuthSessionFlowDuration))
			return s
		}

		tests.TestValidationErrors(t, app.Save(newSession(installation.Record, client.Id, core.AuthSessionMethodPassword)), []string{"amr"})

		root := newSession(installation.Record, client.Id, core.AuthSessionMethodClientCredentials)
		root.SetClient("")
		root.SetSSOSecret("secret")
		tests.TestValidationErrors(t, app.Save(root), []string{"amr"})

		user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
		dashboard, _ := app.FindOAuth2ClientByClientId(core.OAuth2DashboardClientId)
		tests.TestValidationErrors(t, app.Save(newSession(user, dashboard.Id, core.AuthSessionMethodClientCredentials)), []string{"amr", "client"})

		if err := app.Save(newSession(installation.Record, client.Id, core.AuthSessionMethodClientCredentials)); err != nil {
			t.Fatalf("Expected a valid client_credentials session, got %v", err)
		}
	})

	t.Run("rotate secret ends the sessions", func(t *testing.T) {
		before, _ := app.FindApplicationInstallationById(installation.Id)

		rotatedClient, secret, err := app.RotateApplicationInstallationSecret(before)
		if err != nil {
			t.Fatal(err)
		}

		if rotatedClient.ValidateClientSecret(installed.ClientSecret) || !rotatedClient.ValidateClientSecret(secret) {
			t.Fatal("Expected the old secret to be replaced")
		}

		after, _ := app.FindApplicationInstallationById(installation.Id)
		if after.TokenKey() == before.Original().TokenKey() || after.SecretRotatedAt().IsZero() {
			t.Fatal("Expected the tokenKey and secretRotatedAt to change")
		}

		sessions, _ := app.FindAllAuthSessionsByRecord(after.Record)
		for _, s := range sessions {
			if s.Status() != core.AuthSessionStatusEnded {
				t.Fatalf("Expected all sessions to be ended, got %q", s.Status())
			}
		}
	})

	t.Run("uninstall deletes the managed client and the sessions", func(t *testing.T) {
		_, other := installTestApplication(t, app, "inv-uninstall", core.Permissions{})

		if err := app.Delete(other.Installation); err != nil {
			t.Fatal(err)
		}

		if _, err := app.FindOAuth2ClientById(other.Client.Id); err == nil {
			t.Fatal("Expected the managed client to be deleted")
		}

		// the application and its (no longer installed) versions could be deleted
		otherApp, err := app.FindApplicationById(other.Installation.ApplicationRef())
		if err != nil {
			t.Fatal(err)
		}
		if err := app.Delete(otherApp); err != nil {
			t.Fatal(err)
		}
		if versions, _ := app.FindAllApplicationVersionsByApplication(otherApp.Id); len(versions) != 0 {
			t.Fatal("Expected the versions to be deleted")
		}
	})

	t.Run("application delete cascades the installation", func(t *testing.T) {
		otherApp, other := installTestApplication(t, app, "inv-cascade", core.Permissions{})

		if err := app.Delete(otherApp); err != nil {
			t.Fatal(err)
		}

		if _, err := app.FindApplicationInstallationById(other.Installation.Id); err == nil {
			t.Fatal("Expected the installation to be deleted")
		}
		if _, err := app.FindOAuth2ClientById(other.Client.Id); err == nil {
			t.Fatal("Expected the managed client to be deleted")
		}
	})

	t.Run("handle can't change", func(t *testing.T) {
		fresh, _ := app.FindApplicationById(application.Id)
		fresh.Set("handle", "renamed")
		tests.TestValidationErrors(t, app.Save(fresh), []string{"handle"})
	})
}
