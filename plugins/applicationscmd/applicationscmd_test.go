package applicationscmd_test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/plugins/applicationscmd"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/spf13/cobra"
)

func TestApplicationsDeployCommand(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(mux)
	defer server.Close()

	owner, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	token, err := tests.NewSessionAuthToken(app, owner)
	if err != nil {
		t.Fatal(err)
	}

	customer, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	customerToken, err := tests.NewSessionAuthToken(app, customer)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	write := func(name string, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	tomlV1 := write("pocketbase.app.toml", "handle = \"cli-app\"\nname = \"CLI app\"\nversion = \"1.0.0\"\n[access]\nscopes = [\"read_demo2\"]\n")
	tomlV1Changed := write("changed.app.toml", "handle = \"cli-app\"\nname = \"CLI app changed\"\nversion = \"1.0.0\"\n")
	jsonV2 := write("pocketbase.app.json", `{"handle":"cli-app","name":"CLI app","version":"1.1.0"}`)
	unknownKey := write("unknown.app.toml", "handle = \"cli-app\"\nname = \"x\"\nversion = \"3.0.0\"\nadmin_extensions = []\n")
	yaml := write("pocketbase.app.yaml", "handle: cli-app")

	scenarios := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{"missing manifest", []string{"deploy", "--url", server.URL, "--token", token}, true},
		{"missing token", []string{"deploy", tomlV1, "--url", server.URL}, true},
		{"unsupported extension", []string{"deploy", yaml, "--url", server.URL, "--token", token}, true},
		{"missing file", []string{"deploy", filepath.Join(dir, "missing.toml"), "--url", server.URL, "--token", token}, true},
		{"not allowed actor", []string{"deploy", tomlV1, "--url", server.URL, "--token", customerToken}, true},
		{"toml create", []string{"deploy", tomlV1, "--url", server.URL, "--token", token}, false},
		{"toml same version (idempotent)", []string{"deploy", tomlV1, "--url", server.URL + "/", "--token", token}, false},
		{"toml same version with a different manifest (immutable)", []string{"deploy", tomlV1Changed, "--url", server.URL, "--token", token}, true},
		{"json new version", []string{"deploy", jsonV2, "--url", server.URL, "--token", token}, false},
		{"unknown manifest key", []string{"deploy", unknownKey, "--url", server.URL, "--token", token}, true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			command := newApplicationsCommand(t, app)
			command.SetArgs(s.args)
			command.SetOut(&discard{})
			command.SetErr(&discard{})

			err := command.Execute()
			if (err != nil) != s.expectError {
				t.Fatalf("Expected error %v, got %v", s.expectError, err)
			}
		})
	}

	application, err := app.FindApplicationByHandle("cli-app")
	if err != nil {
		t.Fatal(err)
	}

	versions, _ := app.FindAllApplicationVersionsByApplication(application.Id)
	if len(versions) != 2 {
		t.Fatalf("Expected 2 versions, got %d", len(versions))
	}

	latest, _ := app.FindApplicationVersionById(application.LatestVersionRef())
	if latest.Version() != "1.1.0" || latest.GetString("sourceFormat") != core.ApplicationManifestFormatJSON {
		t.Fatalf("Unexpected latest version %q (%s)", latest.Version(), latest.GetString("sourceFormat"))
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// newApplicationsCommand returns a root command with the registered plugin
// that executes the "applications" subcommands (the args are prefixed with "applications").
func newApplicationsCommand(t testing.TB, app core.App) *applicationsTestCommand {
	root := &cobra.Command{Use: "pocketbase"}
	if err := applicationscmd.Register(app, root); err != nil {
		t.Fatal(err)
	}
	return &applicationsTestCommand{Command: root}
}

type applicationsTestCommand struct {
	*cobra.Command
}

func (c *applicationsTestCommand) SetArgs(args []string) {
	c.Command.SetArgs(append([]string{"applications"}, args...))
}
