package core_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestApplicationGrantScopes(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo1, _ := app.FindCollectionByNameOrId("demo1")
	demo2, _ := app.FindCollectionByNameOrId("demo2")

	scopes := core.ApplicationGrantScopes(app, core.Permissions{
		Collections: map[string][]string{
			demo1.Id: {"view"},
			demo2.Id: {"delete"},
		},
		System: map[string]string{
			core.PermissionResourceLogs:     core.PermissionLevelWrite,
			core.PermissionResourceSettings: core.PermissionLevelRead,
			core.PermissionResourceStaff:    core.PermissionLevelRead, // not grantable => ignored
		},
	})

	expected := []string{"read_demo1", "system:read_settings", "system:write_logs", "write_demo2"}
	if !slices.Equal(scopes, expected) {
		t.Fatalf("Expected scopes %v, got %v", expected, scopes)
	}

	// "*" covers every regular collection (only read for the view collections)
	all := core.ApplicationGrantScopes(app, core.Permissions{Collections: map[string][]string{"*": {"list", "create"}}})
	if !slices.Contains(all, "read_demo3") || !slices.Contains(all, "write_demo3") || slices.Contains(all, "write_view1") || !slices.Contains(all, "read_view1") {
		t.Fatalf("Unexpected wildcard scopes %v", all)
	}
	for _, s := range all {
		if strings.HasPrefix(s, "read__") || strings.HasPrefix(s, "write__") {
			t.Fatalf("Unexpected system collection scope %q", s)
		}
	}

	if !core.OAuth2ScopesAllowSystem([]string{"system:write_logs"}, "logs", "read") ||
		core.OAuth2ScopesAllowSystem([]string{"system:read_logs"}, "logs", "write") ||
		core.OAuth2ScopesAllowSystem([]string{"read_logs"}, "logs", "read") {
		t.Fatal("Unexpected OAuth2ScopesAllowSystem results")
	}
}
