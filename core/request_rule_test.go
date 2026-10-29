package core_test

import (
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/types"
)

func TestCanAccessRequestRule(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	superuser, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name          string
		info          *core.RequestInfo
		rule          *string
		expected      bool
		expectedError bool
	}{
		{"nil info + nil rule", nil, nil, false, false},
		{"guest + nil rule", &core.RequestInfo{}, nil, false, false},
		{"superuser + nil rule", &core.RequestInfo{Auth: superuser}, nil, true, false},
		{"superuser + failing rule", &core.RequestInfo{Auth: superuser}, types.Pointer("1=2"), true, false},
		{"guest + public rule", &core.RequestInfo{}, types.Pointer(""), true, false},
		{"guest + auth rule", &core.RequestInfo{}, types.Pointer("@request.auth.id != ''"), false, false},
		{"user + auth rule", &core.RequestInfo{Auth: user}, types.Pointer("@request.auth.id != ''"), true, false},
		{"user + auth collection rule", &core.RequestInfo{Auth: user}, types.Pointer("@request.auth.collectionName = 'users' && @request.auth.verified = false"), true, false},
		{
			"body rule (match)",
			&core.RequestInfo{Body: map[string]any{"model": "a"}},
			types.Pointer("@request.body.model = 'a' || @request.body.model:isset = false"),
			true,
			false,
		},
		{
			"body rule (mismatch)",
			&core.RequestInfo{Body: map[string]any{"model": "b"}},
			types.Pointer("@request.body.model = 'a'"),
			false,
			false,
		},
		{
			"headers rule",
			&core.RequestInfo{Headers: map[string]string{"x_token": "123"}},
			types.Pointer("@request.headers.x_token = '123'"),
			true,
			false,
		},
		{
			"@collection rule (match)",
			&core.RequestInfo{Auth: user},
			types.Pointer("@collection.users.id ?= @request.auth.id"),
			true,
			false,
		},
		{
			"@collection rule (mismatch)",
			&core.RequestInfo{},
			types.Pointer("@collection.users.id ?= @request.auth.id"),
			false,
			false,
		},
		{"plain field (not allowed)", &core.RequestInfo{Auth: user}, types.Pointer("id != ''"), false, true},
		{"invalid rule", &core.RequestInfo{Auth: user}, types.Pointer("@request.auth.id ~~"), false, true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			result, err := core.CanAccessRequestRule(app, s.info, s.rule)

			hasErr := err != nil
			if hasErr != s.expectedError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectedError, hasErr, err)
			}

			if result != s.expected {
				t.Fatalf("Expected %v, got %v", s.expected, result)
			}
		})
	}
}
