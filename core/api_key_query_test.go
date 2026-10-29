package core_test

import (
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/types"
)

func TestHasPublicAPIKeyForOrigin(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	perms := core.Permissions{Collections: map[string][]string{"*": {core.PermissionActionList}}}

	key, _, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, perms)
	if err != nil {
		t.Fatal(err)
	}
	key.SetAllowedOrigins([]string{"https://shop.example.com"})
	if err := app.Save(key); err != nil {
		t.Fatal(err)
	}

	if app.HasPublicAPIKeyForOrigin("https://other.example.com") {
		t.Fatal("Expected an unknown origin to be rejected")
	}

	if !app.HasPublicAPIKeyForOrigin("HTTPS://shop.example.com:443") {
		t.Fatal("Expected the (normalized) allowed origin to be accepted")
	}

	if app.HasPublicAPIKeyForOrigin("invalid") {
		t.Fatal("Expected an invalid origin to be rejected")
	}

	key.SetExpiresAt(types.NowDateTime().Add(-time.Minute))
	if err := app.SaveNoValidate(key); err != nil {
		t.Fatal(err)
	}
	if app.HasPublicAPIKeyForOrigin("https://shop.example.com") {
		t.Fatal("Expected an expired key origin to be rejected")
	}

	key.SetExpiresAt(types.DateTime{})
	key.SetDisabled(true)
	if err := app.Save(key); err != nil {
		t.Fatal(err)
	}
	if app.HasPublicAPIKeyForOrigin("https://shop.example.com") {
		t.Fatal("Expected a disabled key origin to be rejected")
	}
}
