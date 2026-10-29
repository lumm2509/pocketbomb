package core

import (
	"reflect"
	"testing"

	"github.com/lumm2509/pocketbomb/tools/types"
)

func TestParseRolePermissionsRawTypes(t *testing.T) {
	t.Parallel()

	permissions := Permissions{
		Collections: map[string][]string{"*": {"view", "list", "list"}},
		System:      map[string]string{PermissionResourceLogs: PermissionLevelRead},
	}
	normalized := permissions.Clone()
	normalized.Normalize()
	empty := Permissions{Collections: map[string][]string{}, System: map[string]string{}}

	scenarios := []struct {
		name     string
		raw      any
		expected Permissions
	}{
		{"Permissions value", permissions, normalized},
		{"Permissions pointer", &permissions, normalized},
		{"nil Permissions pointer", (*Permissions)(nil), empty},
		{"JSONRaw", types.JSONRaw(`{"collections":{"*":["view","list","list"]},"system":{"logs":"read"}}`), normalized},
		{"bytes", []byte(`{"collections":{"*":["view","list","list"]},"system":{"logs":"read"}}`), normalized},
		{"string", `{"collections":{"*":["view","list","list"]},"system":{"logs":"read"}}`, normalized},
		{
			"default map",
			map[string]any{
				"collections": map[string]any{"*": []any{"view", "list", "list"}},
				"system":      map[string]any{"logs": "read"},
			},
			normalized,
		},
		{"nil", nil, empty},
		{"invalid json", `{invalid`, empty},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			result := parseRolePermissions(s.raw)
			if !reflect.DeepEqual(result, s.expected) {
				t.Fatalf("Expected %#v, got %#v", s.expected, result)
			}
		})
	}
}
