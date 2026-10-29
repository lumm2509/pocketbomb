package applicationscmd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestApplicationsCatalogCommands(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	dir := t.TempDir()
	manifests := filepath.Join(dir, "manifests")
	out := filepath.Join(dir, "out")
	keyPath := filepath.Join(dir, "catalog.key")

	run := func(args ...string) (string, error) {
		var buf bytes.Buffer
		command := newApplicationsCommand(t, app)
		command.SetArgs(args)
		command.SetOut(&buf)
		command.SetErr(&discard{})
		err := command.Execute()
		return buf.String(), err
	}

	// keygen
	output, err := run("catalog", "keygen", "--out", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	publicKey := lines[len(lines)-1]
	if _, err := core.ParseApplicationCatalogPublicKey(publicKey); err != nil {
		t.Fatalf("Expected the printed public key, got %q (%v)", publicKey, err)
	}
	if raw, _ := os.ReadFile(keyPath); !strings.Contains(string(raw), "BEGIN PRIVATE KEY") {
		t.Fatalf("Expected a PEM private key file, got %q", raw)
	}

	if err := os.MkdirAll(manifests, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, content string) {
		if err := os.WriteFile(filepath.Join(manifests, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	write("a.toml", "handle = \"cat-a\"\nname = \"A\"\nversion = \"1.0.0\"\napplication_url = \"https://a.example.com\"\ninstall_url = \"https://a.example.com/install\"\n[access]\nscopes = [\"read_demo2\"]\n")
	write("b.json", `{"handle":"cat-b","name":"B","version":"2.0.0","application_url":"https://b.example.com","install_url":"https://b.example.com/install","icon_url":"https://b.example.com/icon.png"}`)
	write("notes.txt", "ignored")

	// errors
	if _, err := run("catalog", "build", manifests, "--key", keyPath, "--out", out); err == nil {
		t.Fatal("Expected missing --base-url error")
	}
	if _, err := run("catalog", "build", manifests, "--key", filepath.Join(dir, "missing.key"), "--base-url", "https://x.com", "--out", out); err == nil {
		t.Fatal("Expected missing key file error")
	}

	// signed build
	if _, err := run("catalog", "build", manifests, "--key", keyPath, "--base-url", "https://apps.example.com/catalog/", "--out", out); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(out, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	index, signed, err := core.ParseApplicationCatalogIndex(raw, publicKey)
	if err != nil || !signed || len(index.Applications) != 2 {
		t.Fatalf("Expected a valid signed index with 2 entries, got %v %v %v", index, signed, err)
	}

	if index.Applications[1].IconURL != "https://b.example.com/icon.png" {
		t.Fatalf("Expected the manifest icon_url as entry icon, got %q", index.Applications[1].IconURL)
	}

	for _, entry := range index.Applications {
		name := entry.Handle + "-" + entry.Version + ".json"
		if entry.ManifestURL != "https://apps.example.com/catalog/"+name {
			t.Fatalf("Unexpected manifest url %q", entry.ManifestURL)
		}
		manifestRaw, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if core.ApplicationManifestRawDigest(manifestRaw) != entry.ManifestDigest {
			t.Fatalf("Unexpected %s digest", name)
		}
		if _, err := core.ParseApplicationManifest(manifestRaw, core.ApplicationManifestFormatJSON); err != nil {
			t.Fatalf("Expected a valid normalized manifest, got %v", err)
		}
	}

	// unsigned build (without key)
	unsignedOut := filepath.Join(dir, "unsigned")
	if _, err := run("catalog", "build", manifests, "--base-url", "https://apps.example.com", "--out", unsignedOut); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(unsignedOut, "index.json"))
	if _, _, err := core.ParseApplicationCatalogIndex(raw, publicKey); err == nil {
		t.Fatal("Expected the unsigned index to be rejected with a pinned key")
	}

	// a catalog manifest without install_url and a duplicated handle are rejected
	write("c.json", `{"handle":"cat-c","name":"C","version":"1.0.0"}`)
	if _, err := run("catalog", "build", manifests, "--key", keyPath, "--base-url", "https://x.com", "--out", out); err == nil || !strings.Contains(err.Error(), "install_url") {
		t.Fatalf("Expected missing install_url error, got %v", err)
	}
	write("c.json", `{"handle":"cat-a","name":"A2","version":"1.1.0","application_url":"https://a.example.com","install_url":"https://a.example.com/install"}`)
	if _, err := run("catalog", "build", manifests, "--key", keyPath, "--base-url", "https://x.com", "--out", out); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("Expected duplicated handle error, got %v", err)
	}
}
