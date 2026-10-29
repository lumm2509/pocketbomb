package core_test

import (
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

// installTestApplication imports a manifest and installs the application with the provided grant.
func installTestApplication(t testing.TB, app core.App, handle string, grant core.Permissions) (*core.Application, *core.ApplicationInstallResult) {
	t.Helper()

	manifest, err := core.ParseApplicationManifest([]byte(`{"handle":"`+handle+`","name":"Test `+handle+`","version":"1.0.0"}`), core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}

	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}

	result, err := app.InstallApplication(imported.Application, grant, "")
	if err != nil {
		t.Fatal(err)
	}

	return imported.Application, result
}

func TestImportApplicationManifest(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	v1, err := core.ParseApplicationManifest([]byte(testManifestTOML), core.ApplicationManifestFormatTOML)
	if err != nil {
		t.Fatal(err)
	}

	first, err := app.ImportApplicationManifest(v1, core.ApplicationManifestFormatTOML, "staff_id")
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || first.Unchanged || first.Application.Source() != core.ApplicationSourceCustom {
		t.Fatalf("Unexpected first import result %#v", first)
	}
	if first.Application.LatestVersionRef() != first.Version.Id || first.Version.GetString("createdBy") != "staff_id" {
		t.Fatal("Expected latestVersionRef and createdBy to be set")
	}
	if digest, _ := v1.Digest(); first.Version.ManifestDigest() != digest {
		t.Fatalf("Expected digest %q, got %q", digest, first.Version.ManifestDigest())
	}

	// same version + same manifest => idempotent
	again, err := app.ImportApplicationManifest(v1, core.ApplicationManifestFormatTOML, "")
	if err != nil {
		t.Fatal(err)
	}
	if !again.Unchanged || again.Created || again.Version.Id != first.Version.Id {
		t.Fatalf("Expected unchanged import, got %#v", again)
	}

	// same version + different manifest => rejected (immutable versions)
	changed := *v1
	changed.Description = "changed"
	_, err = app.ImportApplicationManifest(&changed, core.ApplicationManifestFormatTOML, "")
	tests.TestValidationErrors(t, err, []string{"version"})

	// new version => new immutable version and updated metadata
	changed.Version = "1.1.0"
	second, err := app.ImportApplicationManifest(&changed, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}
	if second.Created || second.Version.Id == first.Version.Id || second.Application.LatestVersionRef() != second.Version.Id {
		t.Fatal("Expected a new version")
	}
	fresh, _ := app.FindApplicationById(first.Application.Id)
	if fresh.GetString("description") != "changed" {
		t.Fatal("Expected the application metadata to be updated from the latest manifest")
	}

	versions, _ := app.FindAllApplicationVersionsByApplication(first.Application.Id)
	if len(versions) != 2 {
		t.Fatalf("Expected 2 versions, got %d", len(versions))
	}

	// catalog applications can't be deployed as custom
	fresh.Set("source", core.ApplicationSourceCatalog)
	if err := app.Save(fresh); err != nil {
		t.Fatal(err)
	}
	changed.Version = "2.0.0"
	_, err = app.ImportApplicationManifest(&changed, core.ApplicationManifestFormatJSON, "")
	tests.TestValidationErrors(t, err, []string{"handle"})
}
