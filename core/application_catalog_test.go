package core_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// newDevTestApp returns a test app in dev mode (the http loopback urls of the
// test vendors are allowed only in dev mode).
func newDevTestApp(t testing.TB) *tests.TestApp {
	t.Helper()

	app, err := tests.NewTestAppWithConfig(core.BaseAppConfig{IsDev: true, EncryptionEnv: "pb_test_env"})
	if err != nil {
		t.Fatal(err)
	}

	return app
}

// testCatalogManifest returns a catalog manifest JSON of the provided vendor.
func testCatalogManifest(v *tests.ApplicationVendor, handle string, version string, scopes []string, optional []string, webhookTopics []string) string {
	manifest := map[string]any{
		"handle":          handle,
		"name":            "Vendor " + handle,
		"version":         version,
		"application_url": v.URL(),
		"install_url":     v.URL() + "/install",
		"uninstall_url":   v.URL() + "/uninstall",
		"access":          map[string]any{"scopes": scopes, "optional_scopes": optional},
	}

	if len(webhookTopics) > 0 {
		manifest["webhooks"] = map[string]any{
			"subscriptions": []any{map[string]any{"topics": webhookTopics, "uri": v.URL() + "/webhooks"}},
		}
	}

	raw, _ := json.Marshal(manifest)

	return string(raw)
}

func setTestCatalogSource(t testing.TB, app core.App, name string, url string, publicKey string) {
	t.Helper()

	app.Settings().Applications.Catalogs = append(app.Settings().Applications.Catalogs, core.ApplicationCatalogSource{
		Name:      name,
		URL:       url,
		PublicKey: publicKey,
	})

	if err := app.Save(app.Settings()); err != nil {
		t.Fatal(err)
	}
}

// parseTestNotification verifies the notification JWT with the _applicationInstallations issuer JWKS.
func parseTestNotification(t testing.TB, app core.App, token string) map[string]any {
	t.Helper()

	collection, err := app.FindCollectionByNameOrId(core.CollectionNameApplicationInstallations)
	if err != nil {
		t.Fatal(err)
	}

	jwks, err := collection.OAuth2Server.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	claims, err := security.ParseSignedJWT(token, jwks)
	if err != nil {
		t.Fatalf("Expected the notification to be verifiable with the issuer JWKS, got %v", err)
	}

	return claims
}

func testCatalogDeliveriesTopics(t testing.TB, app core.App) []string {
	t.Helper()

	app.Webhooks().FlushEvents()

	topics := []string{}
	err := app.AuxDB().Select("topic").From(core.WebhookDeliveriesTableName).OrderBy("created ASC", "rowid ASC").Column(&topics)
	if err != nil {
		t.Fatal(err)
	}

	return topics
}

func TestParseApplicationCatalogIndex(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	otherPublicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	encodedKey := base64.StdEncoding.EncodeToString(publicKey)
	encodedOtherKey := base64.StdEncoding.EncodeToString(otherPublicKey)

	entry := `{"handle":"acme","name":"ACME","version":"1.0.0","manifestURL":"https://acme.example.com/m.json","manifestDigest":"` + strings.Repeat("a", 64) + `"}`
	indexRaw := []byte(`{"applications":[` + entry + `]}`)

	signed, err := core.SignApplicationCatalogIndex(indexRaw, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	envelope := map[string]string{}
	_ = json.Unmarshal(signed, &envelope)

	tamperedPayload, _ := json.Marshal(map[string]string{
		"payload":   base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(indexRaw), "ACME", "EVIL", 1))),
		"signature": envelope["signature"],
	})

	badSignature, _ := json.Marshal(map[string]string{"payload": envelope["payload"], "signature": "AAAA"})

	scenarios := []struct {
		name         string
		raw          []byte
		key          string
		expectSigned bool
		expectErr    string
	}{
		{"unsigned without key", indexRaw, "", false, ""},
		{"signed envelope without key (accepted, not verified)", signed, "", false, ""},
		{"signed envelope with key", signed, encodedKey, true, ""},
		{"signed envelope with wrong key", signed, encodedOtherKey, false, "invalid catalog index signature"},
		{"bad signature", badSignature, encodedKey, false, "invalid catalog index signature"},
		{"tampered payload", tamperedPayload, encodedKey, false, "invalid catalog index signature"},
		{"unsigned with pinned key", indexRaw, encodedKey, false, "not signed"},
		{"invalid json", []byte(`{`), "", false, "invalid catalog index JSON"},
		{"invalid entry", []byte(`{"applications":[{"handle":"A","name":"x","version":"1","manifestURL":"https://x.com","manifestDigest":"x"}]}`), "", false, "invalid catalog index entry"},
		{"duplicated handles", []byte(`{"applications":[` + entry + `,` + entry + `]}`), "", false, "duplicated"},
		{"too large", []byte(`{"applications":[],"x":"` + strings.Repeat("a", core.ApplicationCatalogIndexMaxSize) + `"}`), "", false, "must be less than"},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			index, isSigned, err := core.ParseApplicationCatalogIndex(s.raw, s.key)

			if s.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), s.expectErr) {
					t.Fatalf("Expected error containing %q, got %v", s.expectErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if isSigned != s.expectSigned {
				t.Fatalf("Expected signed %v, got %v", s.expectSigned, isSigned)
			}

			if len(index.Applications) != 1 || index.Applications[0].Name != "ACME" {
				t.Fatalf("Unexpected index %v", index)
			}
		})
	}
}

func TestApplicationCatalogsFetch(t *testing.T) {
	t.Parallel()

	vendor := tests.NewApplicationVendor()
	defer vendor.Close()

	manifest := testCatalogManifest(vendor, "vendor-app", "1.0.0", []string{"read_demo2"}, nil, nil)
	vendor.Publish(true, manifest)

	t.Run("dev mode", func(t *testing.T) {
		app := newDevTestApp(t)
		defer app.Cleanup()

		setTestCatalogSource(t, app, "signed", vendor.IndexURL(), vendor.PublicKey)
		setTestCatalogSource(t, app, "unpinned", vendor.IndexURL(), "")
		setTestCatalogSource(t, app, "missing", vendor.URL()+"/catalog/missing.json", "")

		results := app.ApplicationCatalogs().List(context.Background(), true)
		if len(results) != 3 {
			t.Fatalf("Expected 3 results, got %d", len(results))
		}

		if results[0].Error != "" || !results[0].Signed || len(results[0].Entries) != 1 || results[0].Entries[0].Handle != "vendor-app" {
			t.Fatalf("Unexpected signed result %+v", results[0])
		}
		if results[1].Error != "" || results[1].Signed || len(results[1].Entries) != 1 {
			t.Fatalf("Unexpected unpinned result %+v", results[1])
		}
		if !strings.Contains(results[2].Error, "status 404") {
			t.Fatalf("Expected a per-source 404 error, got %+v", results[2])
		}

		// manifest digest + parse
		_, entry, err := app.ApplicationCatalogs().FindEntry(context.Background(), "signed", "vendor-app")
		if err != nil {
			t.Fatal(err)
		}
		parsed, format, err := app.ApplicationCatalogs().FetchManifest(context.Background(), entry)
		if err != nil || format != core.ApplicationManifestFormatJSON || parsed.InstallURL != vendor.URL()+"/install" {
			t.Fatalf("Unexpected manifest %v %q %v", parsed, format, err)
		}

		// digest mismatch (the manifest changed after the index was signed)
		vendor.SetFile("/catalog/vendor-app-1.0.0.json", []byte(strings.Replace(manifest, "Vendor vendor-app", "Changed", 1)))
		if _, _, err := app.ApplicationCatalogs().FetchManifest(context.Background(), entry); err == nil || !strings.Contains(err.Error(), "digest") {
			t.Fatalf("Expected digest mismatch error, got %v", err)
		}
		vendor.SetFile("/catalog/vendor-app-1.0.0.json", []byte(manifest))

		// cached (the index change is not visible without refresh)
		vendor.SetFile("/catalog/index.json", []byte(`{"applications":[]}`))
		cached := app.ApplicationCatalogs().List(context.Background(), false)
		if len(cached[0].Entries) != 1 || cached[0].Error != "" {
			t.Fatalf("Expected the cached signed result, got %+v", cached[0])
		}
		fresh := app.ApplicationCatalogs().List(context.Background(), true)
		if !strings.Contains(fresh[0].Error, "not signed") || len(fresh[1].Entries) != 0 {
			t.Fatalf("Expected the refreshed results, got %+v %+v", fresh[0], fresh[1])
		}
		vendor.Publish(true, manifest)
	})

	t.Run("non dev mode", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		// http is not allowed outside of dev mode
		setTestCatalogSource(t, app, "http", vendor.IndexURL(), "")

		// https to a private target is blocked by the SSRF protection
		tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer tlsSrv.Close()
		setTestCatalogSource(t, app, "private", tlsSrv.URL+"/index.json", "")

		results := app.ApplicationCatalogs().List(context.Background(), true)

		if !strings.Contains(results[0].Error, "https is required") {
			t.Fatalf("Expected https required error, got %q", results[0].Error)
		}
		if !strings.Contains(results[1].Error, "not allowed") {
			t.Fatalf("Expected SSRF block error, got %q", results[1].Error)
		}
	})
}

func TestApplicationCatalogInstall(t *testing.T) {
	t.Parallel()

	vendor := tests.NewApplicationVendor()
	defer vendor.Close()

	app := newDevTestApp(t)
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	demo3, _ := app.FindCollectionByNameOrId("demo3")

	setTestCatalogSource(t, app, "vendor", vendor.IndexURL(), vendor.PublicKey)

	// a lifecycle topics subscriber
	subscriber := core.NewWebhook(app)
	subscriber.SetName("lifecycle")
	subscriber.SetURI("https://example.com/hooks")
	subscriber.SetTopics([]string{"application.*"})
	subscriber.SetActive(true)
	if err := app.Save(subscriber); err != nil {
		t.Fatal(err)
	}

	v1 := testCatalogManifest(vendor, "vendor-app", "1.0.0", []string{"read_demo2", "write_demo2"}, []string{"read_demo3"}, []string{"demo2.create"})
	vendor.Publish(true, v1, testCatalogManifest(vendor, "custom-clash", "1.0.0", nil, nil, nil))

	// a catalog install of a custom application handle is rejected
	if _, err := app.ImportApplicationManifest(&core.ApplicationManifest{Handle: "custom-clash", Name: "x", Version: "1.0.0"}, core.ApplicationManifestFormatJSON, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ImportApplicationCatalogEntry(context.Background(), "vendor", "custom-clash", ""); err == nil || !strings.Contains(err.Error(), "custom application") {
		t.Fatalf("Expected custom handle clash error, got %v", err)
	}

	imported, err := app.ImportApplicationCatalogEntry(context.Background(), "vendor", "vendor-app", "")
	if err != nil {
		t.Fatal(err)
	}
	if imported.Application.Source() != core.ApplicationSourceCatalog || imported.Application.GetString("catalogURL") != vendor.IndexURL() {
		t.Fatalf("Unexpected imported application %v", imported.Application)
	}

	// grant beyond the manifest scopes and optional scopes
	_, err = app.InstallApplication(imported.Application, core.Permissions{Collections: map[string][]string{
		demo2.Id: {core.PermissionActionList},
		demo3.Id: {core.PermissionActionCreate},
	}}, "")
	verrs, ok := err.(validation.Errors)
	if !ok || verrs["permissions"] == nil || !strings.Contains(verrs["permissions"].Error(), "write_demo3") {
		t.Fatalf("Expected exceeding grant error, got %v", err)
	}

	// grant not covering the managed webhook topic (demo2 view)
	_, err = app.InstallApplication(imported.Application, core.Permissions{Collections: map[string][]string{
		demo3.Id: {core.PermissionActionList},
	}}, "")
	if err == nil || !strings.Contains(err.Error(), "webhooks.subscriptions.0") {
		t.Fatalf("Expected managed webhook topic error, got %v", err)
	}

	// vendor failure => rollback
	vendor.SetInstallStatus(http.StatusInternalServerError)
	_, err = app.InstallApplication(imported.Application, core.Permissions{Collections: map[string][]string{
		demo2.Id: {core.PermissionActionList, core.PermissionActionView},
	}}, "")
	var notificationErr *core.ApplicationNotificationError
	if !errors.As(err, &notificationErr) || notificationErr.StatusCode != 500 || !strings.Contains(notificationErr.Reason, "vendor install failure") {
		t.Fatalf("Expected notification error with the vendor status and reason, got %v", err)
	}
	if _, err := app.FindApplicationInstallationByApplication(imported.Application.Id); err == nil {
		t.Fatal("Expected the installation to be rolled back")
	}
	if total, _ := app.CountRecords(core.CollectionNameWebhooks, dbx.NewExp("[[applicationInstallationRef]] != ''")); total != 0 {
		t.Fatalf("Expected the managed webhooks to be rolled back, got %d", total)
	}
	if total, _ := app.CountRecords(core.CollectionNameOAuth2Clients, dbx.NewExp("[[applicationInstallationRef]] != ''")); total != 0 {
		t.Fatalf("Expected the managed client to be rolled back, got %d", total)
	}

	// success (reduced grant: demo2 list/view + the optional read_demo3)
	vendor.SetInstallStatus(http.StatusOK)
	result, err := app.InstallApplication(imported.Application, core.Permissions{Collections: map[string][]string{
		demo2.Id: {core.PermissionActionList, core.PermissionActionView},
		demo3.Id: {core.PermissionActionList},
	}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Notified || !result.Installation.IsActive() {
		t.Fatalf("Expected a notified active installation, got %v %q", result.Notified, result.Installation.Status())
	}

	notifications := vendor.Notifications()
	last := notifications[len(notifications)-1]
	if last.Path != "/install" || last.ContentType != "application/jwt" {
		t.Fatalf("Unexpected notification %+v", last)
	}

	claims := parseTestNotification(t, app, last.Token)
	installations, _ := app.FindCollectionByNameOrId(core.CollectionNameApplicationInstallations)
	issuer := core.OAuth2Issuer(app, installations)
	if claims["iss"] != issuer || claims["aud"] != "vendor-app" || claims["event"] != core.ApplicationEventInstalled ||
		claims["installation_id"] != result.Installation.Id || claims["client_id"] != result.Client.ClientId() ||
		claims["token_endpoint"] != issuer+"/token" || claims["version"] != "1.0.0" || claims["jti"] == "" ||
		claims["webhook_secret"] != result.WebhookSecret {
		t.Fatalf("Unexpected install notification claims %v", claims)
	}
	if scopes, _ := json.Marshal(claims["scopes"]); string(scopes) != `["read_demo2","read_demo3"]` {
		t.Fatalf("Unexpected scopes claim %s", scopes)
	}
	client, _ := app.FindApplicationInstallationClient(result.Installation.Id)
	if secret, _ := claims["client_secret"].(string); !client.ValidateClientSecret(secret) {
		t.Fatal("Expected the notification client_secret to be the managed client secret")
	}

	// managed webhooks
	webhooks, err := app.FindAllWebhooksByApplicationInstallation(result.Installation.Id)
	if err != nil || len(webhooks) != 1 {
		t.Fatalf("Expected 1 managed webhook, got %d (%v)", len(webhooks), err)
	}
	managed := webhooks[0]
	if managed.Secret() != result.WebhookSecret || managed.ActorRef() != core.WebhookActorRef(result.Installation.Record) ||
		!slices.Equal(managed.Topics(), []string{demo2.Id + ".create"}) || managed.URI() != vendor.URL()+"/webhooks" {
		t.Fatalf("Unexpected managed webhook %v", managed.Record)
	}

	// read-only for every other save path
	managed.SetURI("https://evil.example.com")
	if err := app.Save(managed); err == nil {
		t.Fatal("Expected the managed webhook update to be rejected")
	}
	fresh, _ := app.FindWebhookById(managed.Id)
	if err := app.Delete(fresh); err == nil {
		t.Fatal("Expected the managed webhook delete to be rejected")
	}
	forged := core.NewWebhook(app)
	forged.SetName("forged")
	forged.SetURI("https://evil.example.com")
	forged.SetTopics([]string{"demo2.create"})
	forged.Set("applicationInstallationRef", result.Installation.Id)
	if err := app.Save(forged); err == nil {
		t.Fatal("Expected the managed webhook create to be rejected")
	}

	// rotate => new secrets delivered with the credentials_rotated notification and shared by the managed webhooks
	installation := result.Installation
	_, newSecret, err := app.RotateApplicationInstallationSecret(installation)
	if err != nil {
		t.Fatal(err)
	}
	notifications = vendor.Notifications()
	rotatedClaims := parseTestNotification(t, app, notifications[len(notifications)-1].Token)
	if rotatedClaims["event"] != core.ApplicationEventCredentialsRotated || rotatedClaims["client_secret"] != newSecret ||
		rotatedClaims["webhook_secret"] != installation.WebhookSecret() || installation.WebhookSecret() == result.WebhookSecret {
		t.Fatalf("Unexpected rotated notification claims %v", rotatedClaims)
	}
	if fresh, _ := app.FindWebhookById(managed.Id); fresh.Secret() != installation.WebhookSecret() {
		t.Fatal("Expected the managed webhook secret to be rotated")
	}

	// update to v2 with more scopes => requires approval
	v2 := testCatalogManifest(vendor, "vendor-app", "2.0.0", []string{"read_demo2", "write_demo2", "read_demo4"}, []string{"read_demo3"}, []string{"demo2.update"})
	vendor.Publish(true, v2)
	importedV2, err := app.ImportApplicationCatalogEntry(context.Background(), "vendor", "vendor-app", "")
	if err != nil {
		t.Fatal(err)
	}

	err = app.UpdateApplicationInstallation(installation, importedV2.Version.Id, nil)
	verrs, ok = err.(validation.Errors)
	if verr, _ := verrs["permissions"].(validation.Error); !ok || verr == nil || verr.Code() != core.ErrApplicationUpdateRequiresApproval.Code() {
		t.Fatalf("Expected update requires approval error, got %v", err)
	}

	demo4, _ := app.FindCollectionByNameOrId("demo4")
	approved := core.Permissions{Collections: map[string][]string{
		demo2.Id: {core.PermissionActionList, core.PermissionActionView},
		demo4.Id: {core.PermissionActionList},
	}}
	if err := app.UpdateApplicationInstallation(installation, importedV2.Version.Id, &approved); err != nil {
		t.Fatal(err)
	}
	if installation.VersionRef() != importedV2.Version.Id {
		t.Fatal("Expected the installation to be updated to v2")
	}
	webhooks, _ = app.FindAllWebhooksByApplicationInstallation(installation.Id)
	if len(webhooks) != 1 || webhooks[0].Id != managed.Id || !slices.Equal(webhooks[0].Topics(), []string{demo2.Id + ".update"}) {
		t.Fatalf("Expected the managed webhook to be re-synced, got %v", webhooks)
	}

	// uninstall => uninstall notification + managed client/webhooks deleted
	if err := app.Delete(installation); err != nil {
		t.Fatal(err)
	}
	notifications = vendor.Notifications()
	uninstalled := notifications[len(notifications)-1]
	uninstalledClaims := parseTestNotification(t, app, uninstalled.Token)
	if uninstalled.Path != "/uninstall" || uninstalledClaims["event"] != core.ApplicationEventUninstalled ||
		uninstalledClaims["client_secret"] != nil || uninstalledClaims["webhook_secret"] != nil || uninstalledClaims["version"] != "2.0.0" {
		t.Fatalf("Unexpected uninstall notification %+v %v", uninstalled, uninstalledClaims)
	}
	if _, err := app.FindWebhookById(managed.Id); err == nil {
		t.Fatal("Expected the managed webhook to be deleted")
	}
	if _, err := app.FindApplicationInstallationClient(installation.Id); err == nil {
		t.Fatal("Expected the managed client to be deleted")
	}

	// lifecycle topics (the failed install is not reported)
	expectedTopics := []string{
		core.ApplicationEventInstalled,
		core.ApplicationEventScopesUpdate,
		core.ApplicationEventUninstalled,
	}
	if topics := testCatalogDeliveriesTopics(t, app); !slices.Equal(topics, expectedTopics) {
		t.Fatalf("Expected lifecycle deliveries %v, got %v", expectedTopics, topics)
	}
}

func TestApplicationCustomInstallNotification(t *testing.T) {
	t.Parallel()

	vendor := tests.NewApplicationVendor()
	defer vendor.Close()

	app := newDevTestApp(t)
	defer app.Cleanup()

	// custom application without install_url => active right away (secrets shown once)
	_, plain := installTestApplication(t, app, "plain-custom", core.Permissions{})
	if plain.Notified || !plain.Installation.IsActive() || plain.WebhookSecret == "" {
		t.Fatalf("Unexpected custom install result %+v", plain)
	}

	// custom application with install_url => the same notification
	manifest, err := core.ParseApplicationManifest([]byte(testCatalogManifest(vendor, "notified-custom", "1.0.0", nil, nil, nil)), core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := app.InstallApplication(imported.Application, core.Permissions{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Notified || !result.Installation.IsActive() || len(vendor.Notifications()) != 1 {
		t.Fatalf("Expected a notified custom installation, got %+v", result)
	}
}

func TestApplicationManifestA2Keys(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name       string
		raw        string
		expectKeys []string
	}{
		{
			"valid",
			`{"handle":"ab","name":"a","version":"1.0.0","application_url":"https://a.example.com","install_url":"https://a.example.com/i","uninstall_url":"https://a.example.com/u",` +
				`"webhooks":{"subscriptions":[{"topics":["posts.create","orders.paid"],"uri":"https://hooks.example.com","filter":"id != ''","fields":["id"]}]}}`,
			nil,
		},
		{
			"loopback http",
			`{"handle":"ab","name":"a","version":"1.0.0","application_url":"http://127.0.0.1:5399","install_url":"http://127.0.0.1:5399/i"}`,
			nil,
		},
		{
			"non https and host mismatch",
			`{"handle":"ab","name":"a","version":"1.0.0","application_url":"https://a.example.com","install_url":"http://a.example.com/i","uninstall_url":"https://b.example.com/u"}`,
			[]string{"install_url", "uninstall_url"},
		},
		{
			"invalid icon_url",
			`{"handle":"ab","name":"a","version":"1.0.0","icon_url":"http://cdn.example.com/icon.png"}`,
			[]string{"icon_url"},
		},
		{
			"install_url without application_url",
			`{"handle":"ab","name":"a","version":"1.0.0","install_url":"https://a.example.com/i"}`,
			[]string{"install_url"},
		},
		{
			"invalid subscriptions",
			`{"handle":"ab","name":"a","version":"1.0.0","webhooks":{"subscriptions":[{"topics":["*.create"],"uri":"http://hooks.example.com"},{"topics":[],"uri":""}]}}`,
			[]string{"webhooks.subscriptions.0.topics", "webhooks.subscriptions.0.uri", "webhooks.subscriptions.1.topics", "webhooks.subscriptions.1.uri"},
		},
		{
			"unknown subscription key",
			`{"handle":"ab","name":"a","version":"1.0.0","webhooks":{"subscriptions":[{"topics":["a.b"],"uri":"https://x.com","secret":"x"}]}}`,
			[]string{"webhooks.subscriptions.0.secret"},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			_, err := core.ParseApplicationManifest([]byte(s.raw), core.ApplicationManifestFormatJSON)

			verrs, _ := err.(validation.Errors)
			if len(verrs) != len(s.expectKeys) {
				t.Fatalf("Expected error keys %v, got %v", s.expectKeys, err)
			}
			for _, k := range s.expectKeys {
				if verrs[k] == nil {
					t.Fatalf("Missing error key %q in %v", k, err)
				}
			}
		})
	}

	// toml array of tables
	manifest, err := core.ParseApplicationManifest([]byte(
		"handle = \"ab\"\nname = \"a\"\nversion = \"1.0.0\"\n[[webhooks.subscriptions]]\ntopics = [\"posts.create\"]\nuri = \"https://hooks.example.com\"\n",
	), core.ApplicationManifestFormatTOML)
	if err != nil || len(manifest.Webhooks.Subscriptions) != 1 || manifest.Webhooks.Subscriptions[0].URI != "https://hooks.example.com" {
		t.Fatalf("Unexpected toml subscriptions %v %v", manifest, err)
	}

	// the canonical JSON of a manifest without the A2 keys is unchanged
	plain, _ := core.ParseApplicationManifest([]byte(`{"handle":"ab","name":"a","version":"1.0.0"}`), core.ApplicationManifestFormatJSON)
	raw, _ := plain.JSON()
	if strings.Contains(string(raw), "install_url") || strings.Contains(string(raw), "webhooks") {
		t.Fatalf("Expected the A2 keys to be omitted, got %s", raw)
	}
}

func TestApplicationStalePendingInstallationsCleanup(t *testing.T) {
	t.Parallel()

	app := newDevTestApp(t)
	defer app.Cleanup()

	runCleanup := func() {
		for _, job := range app.Cron().Jobs() {
			if job.Id() == "__pbAuthSessionsCleanup__" {
				job.Run()
				return
			}
		}
		t.Fatal("Missing the auth sessions cleanup cron job")
	}

	var pendingStatus string

	// the vendor checks the pending state during the notification, then the installation
	// becomes stale (backdated) and it is deleted by the cleanup cron before the response
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		installations, _ := app.FindAllRecords(core.CollectionNameApplicationInstallations)
		for _, installation := range installations {
			pendingStatus = installation.GetString("status")

			// not stale yet
			runCleanup()
			if _, err := app.FindApplicationInstallationById(installation.Id); err != nil {
				t.Errorf("Expected the fresh pending installation to be kept, got %v", err)
			}

			_, err := app.NonconcurrentDB().Update(
				core.CollectionNameApplicationInstallations,
				dbx.Params{"created": "2020-01-01 00:00:00.000Z"},
				dbx.HashExp{"id": installation.Id},
			).Execute()
			if err != nil {
				t.Error(err)
			}
		}

		runCleanup()
	}))
	defer vendor.Close()

	manifest, err := core.ParseApplicationManifest([]byte(`{"handle":"stale-app","name":"Stale","version":"1.0.0","application_url":"`+vendor.URL+`","install_url":"`+vendor.URL+`/install"}`), core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	_, err = app.InstallApplication(imported.Application, core.Permissions{Collections: map[string][]string{demo2.Id: {core.PermissionActionView}}}, "")
	if err == nil || !strings.Contains(err.Error(), "deleted before its activation") {
		t.Fatalf("Expected the stale pending installation to be deleted before its activation, got %v", err)
	}

	if pendingStatus != core.ApplicationInstallationStatusPending {
		t.Fatalf("Expected a pending installation during the notification, got %q", pendingStatus)
	}

	if total, _ := app.CountRecords(core.CollectionNameApplicationInstallations); total != 0 {
		t.Fatalf("Expected no installations, got %d", total)
	}
}

func TestApplicationPendingInstallationWebhooks(t *testing.T) {
	t.Parallel()

	app := newDevTestApp(t)
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")

	createDemo2 := func(title string) {
		record := core.NewRecord(demo2)
		record.Set("title", title)
		if err := app.Save(record); err != nil {
			t.Error(err)
		}
		app.Webhooks().FlushEvents()
	}

	// a demo2 event while the installation is pending (during the install notification)
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/install" {
			createDemo2("while pending")
		}
	}))
	defer vendor.Close()

	raw := `{"handle":"hooks-app","name":"Hooks","version":"1.0.0","application_url":"` + vendor.URL + `","install_url":"` + vendor.URL + `/install",` +
		`"webhooks":{"subscriptions":[{"topics":["demo2.create"],"uri":"` + vendor.URL + `/webhooks"}]}}`
	manifest, err := core.ParseApplicationManifest([]byte(raw), core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}

	result, err := app.InstallApplication(imported.Application, core.Permissions{Collections: map[string][]string{demo2.Id: {core.PermissionActionView}}}, "")
	if err != nil {
		t.Fatal(err)
	}

	createDemo2("while active")

	webhooks, _ := app.FindAllWebhooksByApplicationInstallation(result.Installation.Id)
	if len(webhooks) != 1 {
		t.Fatalf("Expected 1 managed webhook, got %d", len(webhooks))
	}

	payloads := []string{}
	err = app.AuxDB().Select("payload").From(core.WebhookDeliveriesTableName).
		Where(dbx.HashExp{"webhook": webhooks[0].Id}).
		Column(&payloads)
	if err != nil {
		t.Fatal(err)
	}

	if len(payloads) != 1 || !strings.Contains(payloads[0], "while active") {
		t.Fatalf("Expected only the active installation event delivery, got %v", payloads)
	}
}

func TestApplicationCatalogIcons(t *testing.T) {
	t.Parallel()

	icon := tests.ApplicationVendorIcon()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// note: the response content type is never trusted (the bytes are sniffed)
		w.Header().Set("Content-Type", "image/png")
		switch r.URL.Path {
		case "/icon.png":
			w.Write(icon)
		case "/icon.svg":
			w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
		case "/fake.png":
			w.Write([]byte("<html><body>not an image</body></html>"))
		case "/big.png":
			w.Write(append(append([]byte{}, icon...), make([]byte, core.ApplicationIconMaxSize)...))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	expectedIcon := "data:image/png;base64," + base64.StdEncoding.EncodeToString(icon)

	t.Run("dev mode", func(t *testing.T) {
		app := newDevTestApp(t)
		defer app.Cleanup()

		scenarios := []struct {
			path     string
			expected string
		}{
			{"/icon.png", expectedIcon},
			{"/icon.svg", ""},
			{"/fake.png", ""},
			{"/big.png", ""},
			{"/missing.png", ""},
		}

		for _, s := range scenarios {
			if icon := app.ApplicationCatalogs().InlineIcon(context.Background(), srv.URL+s.path); icon != s.expected {
				t.Fatalf("[%s] Expected icon %q, got %q", s.path, s.expected, icon)
			}
		}

		// a remote url is never stored as icon
		application := core.NewApplication(app)
		application.Set("handle", "remote-icon")
		application.Set("name", "Remote icon")
		application.Set("source", core.ApplicationSourceCustom)
		application.Set("iconURL", srv.URL+"/icon.png")
		if err := app.Validate(application); err == nil || !strings.Contains(err.Error(), "iconURL") {
			t.Fatalf("Expected iconURL validation error, got %v", err)
		}

		// custom manifest icon_url => inlined on import
		manifest, err := core.ParseApplicationManifest([]byte(`{"handle":"icon-app","name":"Icon","version":"1.0.0","icon_url":"`+srv.URL+`/icon.png"}`), core.ApplicationManifestFormatJSON)
		if err != nil {
			t.Fatal(err)
		}
		imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
		if err != nil {
			t.Fatal(err)
		}
		if imported.Application.GetString("iconURL") != expectedIcon {
			t.Fatalf("Expected the inlined icon, got %q", imported.Application.GetString("iconURL"))
		}

		// an icon failure only drops the icon
		manifest, _ = core.ParseApplicationManifest([]byte(`{"handle":"svg-app","name":"SVG","version":"1.0.0","icon_url":"`+srv.URL+`/icon.svg"}`), core.ApplicationManifestFormatJSON)
		imported, err = app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
		if err != nil || imported.Application.GetString("iconURL") != "" {
			t.Fatalf("Expected the import without icon, got %q %v", imported.Application.GetString("iconURL"), err)
		}

		// catalog entries icons are inlined (and imported with the application)
		vendor := tests.NewApplicationVendor()
		defer vendor.Close()
		vendor.Publish(true, testCatalogManifest(vendor, "vendor-icon", "1.0.0", nil, nil, nil))
		setTestCatalogSource(t, app, "vendor", vendor.IndexURL(), vendor.PublicKey)

		results := app.ApplicationCatalogs().List(context.Background(), true)
		if len(results[0].Entries) != 1 || results[0].Entries[0].IconURL != expectedIcon {
			t.Fatalf("Expected the inlined catalog entry icon, got %+v", results[0])
		}

		catalogImported, err := app.ImportApplicationCatalogEntry(context.Background(), "vendor", "vendor-icon", "")
		if err != nil || catalogImported.Application.GetString("iconURL") != expectedIcon {
			t.Fatalf("Expected the imported catalog application icon, got %v", err)
		}
	})

	t.Run("non dev mode (SSRF protection and https required)", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(icon)
		}))
		defer tlsSrv.Close()

		if icon := app.ApplicationCatalogs().InlineIcon(context.Background(), tlsSrv.URL+"/icon.png"); icon != "" {
			t.Fatalf("Expected the private target icon to be blocked, got %q", icon)
		}

		if icon := app.ApplicationCatalogs().InlineIcon(context.Background(), srv.URL+"/icon.png"); icon != "" {
			t.Fatalf("Expected the http icon to be rejected, got %q", icon)
		}
	})
}

func TestApplicationLifecycleTopicsActorChecks(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	_, result := installTestApplication(t, app, "lifecycle-actor", core.Permissions{
		Collections: map[string][]string{demo2.Id: {core.PermissionActionView}},
		System:      map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
	})

	// manifest managed webhooks: rejected by the parser
	_, err := core.ParseApplicationManifest([]byte(`{"handle":"ab","name":"a","version":"1.0.0","webhooks":{"subscriptions":[{"topics":["application.installed"],"uri":"https://x.com"}]}}`), core.ApplicationManifestFormatJSON)
	if err == nil || !strings.Contains(err.Error(), "lifecycle") {
		t.Fatalf("Expected the lifecycle topic manifest error, got %v", err)
	}

	// actor checks (records API and managed webhooks sync)
	info := &core.RequestInfo{Auth: result.Installation.Record, OAuth2: core.RequestInfoOAuth2{Scopes: core.ApplicationGrantScopes(app, result.Installation.Permissions())}}
	for _, topic := range []string{"application.installed", "application.*", "Application.uninstalled"} {
		if err := core.CheckWebhookTopicsAccess(app, info, []string{topic}); err == nil {
			t.Fatalf("[%s] Expected the lifecycle topic to be rejected for the application actor", topic)
		}
	}
	if err := core.CheckWebhookTopicsAccess(app, info, []string{"orders.paid", "demo2.create"}); err != nil {
		t.Fatalf("Expected the other topics to be allowed, got %v", err)
	}

	// dispatch time skip (e.g. a subscription saved by a trusted programmatic save)
	appHook := core.NewWebhook(app)
	appHook.SetName("app lifecycle")
	appHook.SetURI("https://example.com/app")
	appHook.SetTopics([]string{"application.*"})
	appHook.SetActive(true)
	appHook.SetActorRef(core.WebhookActorRef(result.Installation.Record))
	if err := app.Save(appHook); err != nil {
		t.Fatal(err)
	}

	ownerHook := core.NewWebhook(app)
	ownerHook.SetName("owner lifecycle")
	ownerHook.SetURI("https://example.com/owner")
	ownerHook.SetTopics([]string{"application.*"})
	ownerHook.SetActive(true)
	if err := app.Save(ownerHook); err != nil {
		t.Fatal(err)
	}

	if err := app.Webhooks().Trigger(context.Background(), core.ApplicationEventInstalled, map[string]any{"handle": "x"}); err != nil {
		t.Fatal(err)
	}

	webhookIds := []string{}
	if err := app.AuxDB().Select("webhook").From(core.WebhookDeliveriesTableName).Column(&webhookIds); err != nil {
		t.Fatal(err)
	}
	if len(webhookIds) != 1 || webhookIds[0] != ownerHook.Id {
		t.Fatalf("Expected only the owner subscription delivery, got %v", webhookIds)
	}
}
