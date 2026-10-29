package migrations_test

import (
	"slices"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestApplicationsMigrationUpstreamDB(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	downToUpstream(t, app)
	upFromUpstream(t, app)

	assertApplicationsFinalState(t, app)
}

func TestApplicationsMigrationFreshDB(t *testing.T) {
	assertApplicationsFinalState(t, newFreshApp(t))
}

func assertApplicationsFinalState(t testing.TB, app core.App) {
	t.Helper()

	// the clients created before the applications migration keep exactly their behavior
	for _, clientId := range []string{core.OAuth2DashboardClientId} {
		client, err := app.FindOAuth2ClientByClientId(clientId)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(client.GrantTypes(), core.OAuth2DefaultGrantTypes) || client.IsManaged() {
			t.Fatalf("[%s] Expected the default grant types, got %v", clientId, client.GrantTypes())
		}
		if err := app.Validate(client); err != nil {
			t.Fatalf("[%s] Expected the migrated client to be valid, got %v", clientId, err)
		}
	}

	installations, err := app.FindCollectionByNameOrId(core.CollectionNameApplicationInstallations)
	if err != nil {
		t.Fatal(err)
	}
	if !installations.IsAuth() || !installations.System ||
		installations.PasswordAuth.Enabled || installations.OTP.Enabled || installations.OAuth2.Enabled || installations.MFA.Enabled ||
		len(installations.DefaultRoles) != 0 ||
		installations.ListRule != nil || installations.ViewRule != nil || installations.CreateRule != nil ||
		installations.UpdateRule != nil || installations.DeleteRule != nil || installations.AuthRule != nil || installations.ManageRule != nil ||
		installations.AuthToken.Duration != core.ApplicationInstallationTokenDuration {
		t.Fatalf("Unexpected _applicationInstallations options %v", installations)
	}

	for _, name := range []string{core.CollectionNameApplications, core.CollectionNameApplicationVersions} {
		c, err := app.FindCollectionByNameOrId(name)
		if err != nil || !c.System || c.ListRule != nil {
			t.Fatalf("Unexpected %s collection %v (%v)", name, c, err)
		}
	}

	// the whole flow works after the migration
	manifest, _ := core.ParseApplicationManifest([]byte(`{"handle":"mig-app","name":"x","version":"1.0.0"}`), core.ApplicationManifestFormatJSON)
	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}
	installed, err := app.InstallApplication(imported.Application, core.Permissions{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !installed.Installation.IsActive() || installed.Installation.GetDateTime("created").IsZero() {
		t.Fatalf("Expected an active installation with a created date, got %q", installed.Installation.Status())
	}
	if !slices.Equal(installed.Client.GrantTypes(), core.OAuth2ManagedClientGrantTypes) {
		t.Fatalf("Expected the managed client grant types, got %v", installed.Client.GrantTypes())
	}
	managed, err := app.FindApplicationInstallationClient(installed.Installation.Id)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Validate(managed); err != nil {
		t.Fatalf("Expected the managed client to be valid, got %v", err)
	}

	for _, name := range []string{"status", "webhookSecret", "created", "updated"} {
		if installations.Fields.GetByName(name) == nil {
			t.Fatalf("Missing the %s installations field", name)
		}
	}
	if installations.GetIndex("idx_applicationInstallations_status") == "" || installations.GetIndex("idx_applicationInstallations_application") == "" {
		t.Fatal("Missing the _applicationInstallations indexes")
	}

	applications, _ := app.FindCollectionByNameOrId(core.CollectionNameApplications)
	if f, ok := applications.Fields.GetByName("iconURL").(*core.TextField); !ok || f.Max != 100000 {
		t.Fatalf("Expected the iconURL text field, got %v", applications.Fields.GetByName("iconURL"))
	}
	if applications.Fields.GetByName("latestVersionRef") == nil {
		t.Fatal("Missing the _applications latestVersionRef field")
	}

	clients, _ := app.FindCollectionByNameOrId(core.CollectionNameOAuth2Clients)
	if clients.Fields.GetByName("grantTypes") == nil || clients.Fields.GetByName("applicationInstallationRef") == nil ||
		clients.GetIndex("idx_oauth2Clients_applicationInstallationRef") == "" {
		t.Fatal("Missing the _oauth2Clients application fields")
	}

	sessions, _ := app.FindCollectionByNameOrId(core.CollectionNameAuthSessions)
	if sessions.Fields.GetByName("launchJti") == nil || sessions.GetIndex("idx_authSessions_launchJti") == "" {
		t.Fatal("Expected the launchJti field and its unique index")
	}
}
