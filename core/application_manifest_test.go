package core_test

import (
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestParseApplicationManifest(t *testing.T) {
	t.Parallel()

	manifest, err := core.ParseApplicationManifest([]byte(testManifestTOML), core.ApplicationManifestFormatTOML)
	if err != nil {
		t.Fatalf("Expected valid TOML manifest, got %v", err)
	}

	if manifest.Handle != "acme-sync" || manifest.Version != "1.0.0" || manifest.Developer.URL != "https://dev.acme.example.com" {
		t.Fatalf("Unexpected manifest %#v", manifest)
	}

	// normalized (deduped + sorted)
	if strings.Join(manifest.Access.Scopes, " ") != "read_demo2 system:read_logs write_demo2" {
		t.Fatalf("Unexpected normalized scopes %v", manifest.Access.Scopes)
	}

	// the same manifest in JSON has the same canonical form and digest
	jsonManifest, err := core.ParseApplicationManifest([]byte(`{
		"handle": "acme-sync",
		"name": " ACME sync ",
		"version": "1.0.0",
		"description": "Syncs the demo2 records",
		"application_url": "https://acme.example.com",
		"developer": {"name": "ACME", "url": "https://dev.acme.example.com"},
		"access": {"scopes": ["system:read_logs", "read_demo2", "write_demo2"], "optional_scopes": ["read_demo3"]}
	}`), core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatalf("Expected valid JSON manifest, got %v", err)
	}

	d1, _ := manifest.Digest()
	d2, _ := jsonManifest.Digest()
	if d1 == "" || d1 != d2 {
		t.Fatalf("Expected the same TOML/JSON digest, got %q vs %q", d1, d2)
	}

	scenarios := []struct {
		name         string
		format       string
		data         string
		expectedKeys []string
	}{
		{"empty", core.ApplicationManifestFormatTOML, ``, []string{"manifest"}},
		{"unsupported format", "yaml", `handle: x`, []string{"manifest"}},
		{"invalid toml", core.ApplicationManifestFormatTOML, `handle = `, []string{"manifest"}},
		{"invalid json", core.ApplicationManifestFormatJSON, `{"handle":`, []string{"manifest"}},
		{
			"unknown root and nested keys (toml)",
			core.ApplicationManifestFormatTOML,
			"handle = \"ab\"\nname = \"a\"\nversion = \"1.0.0\"\nlaunch_url = \"https://x.com\"\n[developer]\nemail = \"a@b.c\"\n[[webhooks]]\ntopic = \"x\"",
			[]string{"launch_url", "developer.email", "webhooks"},
		},
		{
			"unknown keys (json)",
			core.ApplicationManifestFormatJSON,
			`{"handle":"ab","name":"a","version":"1.0.0","admin_extensions":[],"access":{"scopes":[],"admin":true}}`,
			[]string{"admin_extensions", "access.admin"},
		},
		{"table expected", core.ApplicationManifestFormatJSON, `{"handle":"ab","name":"a","version":"1.0.0","developer":"ACME"}`, []string{"developer"}},
		{"invalid value type", core.ApplicationManifestFormatTOML, "handle = \"ab\"\nname = \"a\"\nversion = 1", []string{"version"}},
		{"invalid list item type", core.ApplicationManifestFormatJSON, `{"handle":"ab","name":"a","version":"1.0.0","access":{"scopes":[1]}}`, []string{"access.scopes"}},
		{"missing required", core.ApplicationManifestFormatJSON, `{"description":"x"}`, []string{"handle", "name", "version"}},
		{"invalid handle (uppercase)", core.ApplicationManifestFormatJSON, `{"handle":"Acme","name":"a","version":"1.0.0"}`, []string{"handle"}},
		{"invalid handle (dash prefix)", core.ApplicationManifestFormatJSON, `{"handle":"-acme","name":"a","version":"1.0.0"}`, []string{"handle"}},
		{"invalid handle (too short)", core.ApplicationManifestFormatJSON, `{"handle":"a","name":"a","version":"1.0.0"}`, []string{"handle"}},
		{"invalid handle (too long)", core.ApplicationManifestFormatJSON, `{"handle":"` + strings.Repeat("a", 64) + `","name":"a","version":"1.0.0"}`, []string{"handle"}},
		{"invalid version", core.ApplicationManifestFormatJSON, `{"handle":"ab","name":"a","version":"latest"}`, []string{"version"}},
		{"invalid urls", core.ApplicationManifestFormatJSON, `{"handle":"ab","name":"a","version":"1.0.0","application_url":"javascript:alert(1)","developer":{"url":"ftp://x"}}`, []string{"application_url", "developer.url"}},
		{
			"invalid and not application grantable scopes",
			core.ApplicationManifestFormatJSON,
			`{"handle":"ab","name":"a","version":"1.0.0","access":{"scopes":["openid","system:read_staff"],"optional_scopes":["system:write_settings"]}}`,
			[]string{"access.scopes", "access.optional_scopes"},
		},
		{"too large", core.ApplicationManifestFormatJSON, `{"description":"` + strings.Repeat("a", core.ApplicationManifestMaxSize) + `"}`, []string{"manifest"}},
		{"valid minimal", core.ApplicationManifestFormatTOML, "handle = \"ab\"\nname = \"a\"\nversion = \"v2.1.0-beta.1\"", nil},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			_, err := core.ParseApplicationManifest([]byte(s.data), s.format)
			tests.TestValidationErrors(t, err, s.expectedKeys)

			// the error must name the unknown keys
			if strings.HasPrefix(s.name, "unknown") {
				for _, k := range s.expectedKeys {
					if !strings.Contains(err.Error(), k) {
						t.Fatalf("Expected the error to name the key %q, got %v", k, err)
					}
				}
			}
		})
	}
}
