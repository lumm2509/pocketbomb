package core_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	validation "github.com/pocketbase/ozzo-validation/v4"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestApplicationOperationHooks(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	calls := []string{}

	app.OnApplicationManifestImport().BindFunc(func(e *core.ApplicationManifestImportEvent) error {
		calls = append(calls, "import:"+e.Manifest.Handle)
		err := e.Next()
		if err == nil && e.Result == nil {
			t.Error("Expected the import result to be set after e.Next()")
		}
		return err
	})
	app.OnApplicationInstall().BindFunc(func(e *core.ApplicationInstallEvent) error {
		calls = append(calls, "install:"+e.Application.Handle())
		err := e.Next()
		if err == nil && (e.Result == nil || e.Result.ClientSecret == "") {
			t.Error("Expected the install result to be set after e.Next()")
		}
		return err
	})
	app.OnApplicationInstallationUpdate().BindFunc(func(e *core.ApplicationInstallationUpdateEvent) error {
		calls = append(calls, "update:"+e.Installation.Id)
		return e.Next()
	})
	app.OnApplicationSecretRotate().BindFunc(func(e *core.ApplicationSecretRotateEvent) error {
		calls = append(calls, "rotate:"+e.Installation.Id)
		err := e.Next()
		if err == nil && (e.Client == nil || e.ClientSecret == "") {
			t.Error("Expected the rotated client and secret to be set after e.Next()")
		}
		return err
	})
	app.OnApplicationUninstall().BindFunc(func(e *core.ApplicationUninstallEvent) error {
		calls = append(calls, "uninstall:"+e.Installation.Id)
		return e.Next()
	})

	grant := core.Permissions{Collections: map[string][]string{"*": {core.PermissionActionList}}}

	_, installed := installTestApplication(t, app, "hooks-app", grant)
	installation := installed.Installation

	if err := app.UpdateApplicationInstallation(installation, "", &grant); err != nil {
		t.Fatal(err)
	}

	if _, _, err := app.RotateApplicationInstallationSecret(installation); err != nil {
		t.Fatal(err)
	}

	if err := app.UninstallApplication(installation); err != nil {
		t.Fatal(err)
	}

	if _, err := app.FindApplicationInstallationById(installation.Id); err == nil {
		t.Fatal("Expected the installation to be deleted")
	}

	expected := []string{
		"import:hooks-app",
		"install:hooks-app",
		"update:" + installation.Id,
		"rotate:" + installation.Id,
		"uninstall:" + installation.Id,
	}
	if !slices.Equal(calls, expected) {
		t.Fatalf("Expected hook calls\n%v\ngot\n%v", expected, calls)
	}
}

func TestApplicationOperationHooksReject(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	rejectErr := errors.New("rejected")

	grant := core.Permissions{Collections: map[string][]string{"*": {core.PermissionActionList}}}

	application, installed := installTestApplication(t, app, "reject-app", grant)

	app.OnApplicationUninstall().BindFunc(func(e *core.ApplicationUninstallEvent) error {
		return rejectErr
	})

	if err := app.UninstallApplication(installed.Installation); !errors.Is(err, rejectErr) {
		t.Fatalf("Expected the hook error, got %v", err)
	}

	if _, err := app.FindApplicationInstallationByApplication(application.Id); err != nil {
		t.Fatalf("Expected the installation to still exist, got %v", err)
	}

	app.OnApplicationInstall().BindFunc(func(e *core.ApplicationInstallEvent) error {
		return rejectErr
	})

	if _, err := app.InstallApplication(application, grant, ""); !errors.Is(err, rejectErr) {
		t.Fatalf("Expected the install hook error, got %v", err)
	}
}

func TestApplicationConcurrentInstall(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	manifest, _ := core.ParseApplicationManifest([]byte(`{"handle":"race-app","name":"x","version":"1.0.0"}`), core.ApplicationManifestFormatJSON)
	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	succeeded := 0

	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := app.InstallApplication(imported.Application, core.Permissions{}, ""); err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("Expected exactly 1 successful install, got %d", succeeded)
	}

	clients, _ := app.FindAllRecords(core.CollectionNameOAuth2Clients)
	managed := 0
	for _, c := range clients {
		if c.GetString("applicationInstallationRef") != "" {
			managed++
		}
	}
	if managed != 1 {
		t.Fatalf("Expected exactly 1 managed client, got %d", managed)
	}
}

func TestApplicationInstallationManagedClientContext(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	_, installed := installTestApplication(t, app, "ctx-app", core.Permissions{})

	// a random context value can't unlock the managed client changes
	type fakeKey struct{}
	ctx := context.WithValue(context.Background(), fakeKey{}, true)

	client, _ := app.FindOAuth2ClientById(installed.Client.Id)
	client.SetName("renamed")
	err := app.SaveWithContext(ctx, client)
	if err == nil || !strings.Contains(err.Error(), "managed") {
		t.Fatalf("Expected managed client error, got %v", err)
	}

	var verrs validation.Errors
	if errors.As(err, &verrs) {
		t.Fatalf("Expected a non validation error, got %v", verrs)
	}
}
