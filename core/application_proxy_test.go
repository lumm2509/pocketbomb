package core_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestParseApplicationManifestAppProxy(t *testing.T) {
	t.Parallel()

	base := `handle = "proxy-app"
name = "Proxy app"
version = "1.0.0"
application_url = "https://app.example.com"
`
	scopes := "[access]\nscopes = [\"write_app_proxy\"]\n"

	scenarios := []struct {
		name  string
		raw   string
		error string // the expected error key (empty = valid)
	}{
		{"valid", base + scopes + "[app_proxy]\nurl=\"https://app.example.com/proxy\"\nprefix=\"apps\"\nsubpath=\"reviews\"\n", ""},
		{"valid optional scope", base + "[access]\noptional_scopes = [\"write_app_proxy\"]\n[app_proxy]\nurl=\"https://app.example.com/proxy\"\nprefix=\"a\"\nsubpath=\"R_1-x\"\n", ""},
		{"missing scope", base + "[app_proxy]\nurl=\"https://app.example.com/proxy\"\nprefix=\"apps\"\nsubpath=\"reviews\"\n", "access.scopes"},
		{"other host", base + scopes + "[app_proxy]\nurl=\"https://other.example.com/proxy\"\nprefix=\"apps\"\nsubpath=\"reviews\"\n", "app_proxy.url"},
		{"http non loopback", base + scopes + "[app_proxy]\nurl=\"http://app.example.com/proxy\"\nprefix=\"apps\"\nsubpath=\"reviews\"\n", "app_proxy.url"},
		{"url with query", base + scopes + "[app_proxy]\nurl=\"https://app.example.com/proxy?a=1\"\nprefix=\"apps\"\nsubpath=\"reviews\"\n", "app_proxy.url"},
		{"missing url", base + scopes + "[app_proxy]\nprefix=\"apps\"\nsubpath=\"reviews\"\n", "app_proxy.url"},
		{"invalid prefix", base + scopes + "[app_proxy]\nurl=\"https://app.example.com/proxy\"\nprefix=\"api\"\nsubpath=\"reviews\"\n", "app_proxy.prefix"},
		{"invalid subpath", base + scopes + "[app_proxy]\nurl=\"https://app.example.com/proxy\"\nprefix=\"apps\"\nsubpath=\"a/b\"\n", "app_proxy.subpath"},
		{"long subpath", base + scopes + "[app_proxy]\nurl=\"https://app.example.com/proxy\"\nprefix=\"apps\"\nsubpath=\"" + strings.Repeat("a", 31) + "\"\n", "app_proxy.subpath"},
		{"reserved admin", base + scopes + "[app_proxy]\nurl=\"https://app.example.com/proxy\"\nprefix=\"apps\"\nsubpath=\"admin\"\n", "app_proxy.subpath"},
		{"reserved services", base + scopes + "[app_proxy]\nurl=\"https://app.example.com/proxy\"\nprefix=\"apps\"\nsubpath=\"services\"\n", "app_proxy.subpath"},
		{"reserved password", base + scopes + "[app_proxy]\nurl=\"https://app.example.com/proxy\"\nprefix=\"apps\"\nsubpath=\"password\"\n", "app_proxy.subpath"},
		{"reserved login case", base + scopes + "[app_proxy]\nurl=\"https://app.example.com/proxy\"\nprefix=\"apps\"\nsubpath=\"LOGIN\"\n", "app_proxy.subpath"},
		{"unknown key", base + scopes + "[app_proxy]\nurl=\"https://app.example.com/proxy\"\nprefix=\"apps\"\nsubpath=\"reviews\"\nextra=\"x\"\n", "app_proxy.extra"},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			manifest, err := core.ParseApplicationManifest([]byte(s.raw), core.ApplicationManifestFormatTOML)
			if s.error == "" {
				if err != nil {
					t.Fatalf("Unexpected error %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), s.error) {
				t.Fatalf("Expected %q error, got %v (%v)", s.error, err, manifest)
			}
		})
	}
}

func TestApplicationManifestAppProxyScopeNormalized(t *testing.T) {
	t.Parallel()

	manifest := &core.ApplicationManifest{Access: core.ApplicationManifestAccess{Scopes: []string{"write_app_proxy", "read_posts"}}}
	manifest.Normalize()

	if strings.Join(manifest.Access.Scopes, ",") != "read_posts,system:write_app_proxy" {
		t.Fatalf("Unexpected scopes %v", manifest.Access.Scopes)
	}
}

func TestApplicationProxySignature(t *testing.T) {
	t.Parallel()

	params := url.Values{
		"extra":       {"1", "2"},
		"shop":        {"shop-name.myshopify.com"},
		"path_prefix": {"/apps/awesome_reviews"},
		"timestamp":   {"1317327555"},
		"empty":       {""},
		"signature":   {"ignored"},
	}

	signature := core.ApplicationProxySignature(params, "hush")

	// echo -n 'empty=extra=1,2path_prefix=/apps/awesome_reviewsshop=shop-name.myshopify.comtimestamp=1317327555' | openssl dgst -sha256 -hmac hush
	if expected := "3bd472d5cc1c0322c7ae64eb60867a4b1118aaa8a6b01e09343e67b3e29d5436"; signature != expected {
		t.Fatalf("Expected signature %q, got %q", expected, signature)
	}
}

func TestApplicationInstallationProxyPath(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	install := func(handle string, grant core.Permissions) (*core.ApplicationInstallResult, error) {
		manifest, err := core.ParseApplicationManifest([]byte(`{
			"handle":"`+handle+`","name":"x","version":"1.0.0","application_url":"https://app.example.com",
			"access":{"scopes":["write_app_proxy"]},
			"app_proxy":{"url":"https://app.example.com/proxy","prefix":"apps","subpath":"reviews"}
		}`), core.ApplicationManifestFormatJSON)
		if err != nil {
			t.Fatal(err)
		}

		imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
		if err != nil {
			t.Fatal(err)
		}

		return app.InstallApplication(imported.Application, grant, "")
	}

	granted := core.Permissions{System: map[string]string{core.PermissionResourceAppProxy: core.PermissionLevelWrite}}

	// not granted -> no proxy path is reserved
	first, err := install("proxy-no-grant", core.Permissions{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Installation.ProxyPathPrefix() != "" {
		t.Fatalf("Unexpected proxy path %q", first.Installation.ProxyPathPrefix())
	}

	second, err := install("proxy-first", granted)
	if err != nil {
		t.Fatal(err)
	}
	if second.Installation.ProxyPathPrefix() != "/apps/reviews" {
		t.Fatalf("Unexpected proxy path %q", second.Installation.ProxyPathPrefix())
	}

	// conflict -> install error
	if _, err := install("proxy-conflict", granted); err == nil || !strings.Contains(err.Error(), "used by another installation") {
		t.Fatalf("Expected a conflict error, got %v", err)
	}

	// granting it later assigns the manifest path (here still taken)
	if err := app.UpdateApplicationInstallation(first.Installation, "", &granted); err == nil {
		t.Fatal("Expected a conflict error")
	}

	// customized and the old pair is free again
	if err := app.UpdateApplicationInstallationProxyPath(second.Installation, "tools", "custom"); err != nil {
		t.Fatal(err)
	}
	if err := app.UpdateApplicationInstallation(first.Installation, "", &granted); err != nil {
		t.Fatal(err)
	}
	if first.Installation.ProxyPathPrefix() != "/apps/reviews" {
		t.Fatalf("Unexpected proxy path %q", first.Installation.ProxyPathPrefix())
	}

	for _, invalid := range [][]string{{"api", "x"}, {"apps", "admin"}, {"apps", "a b"}, {"apps", ""}, {"", "x"}} {
		if err := app.UpdateApplicationInstallationProxyPath(second.Installation, invalid[0], invalid[1]); err == nil {
			t.Fatalf("Expected a validation error for %v", invalid)
		}
	}

	if _, _, _, err := app.FindActiveApplicationProxy("tools", "custom"); err != nil {
		t.Fatalf("Expected the proxy to be active: %v", err)
	}

	// the live grant narrowing disables the proxy
	if err := app.UpdateApplicationInstallation(second.Installation, "", &core.Permissions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := app.FindActiveApplicationProxy("tools", "custom"); err == nil {
		t.Fatal("Expected the narrowed proxy to be inactive")
	}
}
