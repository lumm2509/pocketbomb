package core_test

import (
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestPermissionsHasSystemAndCovers(t *testing.T) {
	t.Parallel()

	p := core.Permissions{
		Collections: map[string][]string{
			"c1":                          {"list", "view"},
			core.PermissionAllCollections: {"list"},
		},
		System: map[string]string{
			core.PermissionResourceLogs:     core.PermissionLevelWrite,
			core.PermissionResourceSettings: core.PermissionLevelRead,
		},
	}

	if !p.HasSystem(core.PermissionResourceLogs, core.PermissionLevelRead) {
		t.Fatal("Expected write to imply read")
	}
	if p.HasSystem(core.PermissionResourceSettings, core.PermissionLevelWrite) {
		t.Fatal("Expected read to not imply write")
	}
	if p.HasSystem(core.PermissionResourceBackups, core.PermissionLevelRead) {
		t.Fatal("Expected missing resource to be denied")
	}

	if !p.CanCollection("c1", "view") || !p.CanCollection("c2", "list") || p.CanCollection("c2", "view") {
		t.Fatal("Unexpected CanCollection results")
	}

	scenarios := []struct {
		name     string
		other    core.Permissions
		expected bool
	}{
		{"empty", core.Permissions{}, true},
		{"subset collection", core.Permissions{Collections: map[string][]string{"c1": {"view"}}}, true},
		{"collection via wildcard", core.Permissions{Collections: map[string][]string{"c9": {"list"}}}, true},
		{"not held collection action", core.Permissions{Collections: map[string][]string{"c9": {"view"}}}, false},
		{"wildcard requires wildcard", core.Permissions{Collections: map[string][]string{"*": {"view"}}}, false},
		{"held wildcard", core.Permissions{Collections: map[string][]string{"*": {"list"}}}, true},
		{"lower system level", core.Permissions{System: map[string]string{"logs": "read"}}, true},
		{"higher system level", core.Permissions{System: map[string]string{"settings": "write"}}, false},
		{"not held resource", core.Permissions{System: map[string]string{"backups": "read"}}, false},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			if v := p.Covers(s.other); v != s.expected {
				t.Fatalf("Expected Covers %v, got %v", s.expected, v)
			}
		})
	}
}

func TestPermissionsValidate(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo1, _ := app.FindCollectionByNameOrId("demo1")
	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)

	scenarios := []struct {
		name        string
		permissions core.Permissions
		expectError bool
	}{
		{"empty", core.Permissions{}, false},
		{"valid", core.Permissions{
			Collections: map[string][]string{demo1.Id: {"list"}, "*": {"view"}},
			System:      map[string]string{"logs": "read", "impersonate": "write"},
		}, false},
		{"unknown collection", core.Permissions{Collections: map[string][]string{"missing": {"list"}}}, true},
		{"collection name instead of id", core.Permissions{Collections: map[string][]string{"demo1": {"list"}}}, true},
		{"system collection", core.Permissions{Collections: map[string][]string{superusers.Id: {"list"}}}, true},
		{"unknown action", core.Permissions{Collections: map[string][]string{"*": {"manage"}}}, true},
		{"unknown resource", core.Permissions{System: map[string]string{"missing": "read"}}, true},
		{"not assignable sql", core.Permissions{System: map[string]string{"sql": "write"}}, true},
		{"invalid level", core.Permissions{System: map[string]string{"impersonate": "read"}}, true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			err := s.permissions.Validate(app)
			if (err != nil) != s.expectError {
				t.Fatalf("Expected error %v, got %v", s.expectError, err)
			}
		})
	}
}
