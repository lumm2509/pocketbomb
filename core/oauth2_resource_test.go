package core_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

func TestCheckOAuth2ResourceIdentifier(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		value string
		valid bool
	}{
		{"", false},
		{"payments", false},
		{"/payments", false},
		{"https://", false},
		{"https://api.example.com#x", false},
		{"https://api.example.com#", false},
		{"https://api.example.com?a=1", false},
		{"https://api.example.com?", false},
		{"https://user@api.example.com", false},
		{"urn:", false},
		{"https://api.example.com", true},
		{"https://api.example.com/v1", true},
		{"http://localhost:8080", true},
		{"urn:example:payments", true},
	}

	for _, s := range scenarios {
		t.Run(s.value, func(t *testing.T) {
			err := core.CheckOAuth2ResourceIdentifier(s.value)
			if (err == nil) != s.valid {
				t.Fatalf("Expected valid %v, got error %v", s.valid, err)
			}
		})
	}
}

func TestOAuth2ResourceValidate(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name     string
		resource core.OAuth2Resource
		fields   []string
	}{
		{"zero", core.OAuth2Resource{}, []string{"identifier", "accessTokenDuration"}},
		{"too short duration", core.OAuth2Resource{Identifier: "urn:a:b", AccessTokenDuration: 9}, []string{"accessTokenDuration"}},
		{"too long duration", core.OAuth2Resource{Identifier: "urn:a:b", AccessTokenDuration: 86401}, []string{"accessTokenDuration"}},
		{"too long name", core.OAuth2Resource{Identifier: "urn:a:b", Name: strings.Repeat("a", 256), AccessTokenDuration: 60}, []string{"name"}},
		{"valid", core.OAuth2Resource{Identifier: "urn:a:b", Name: "B", AccessTokenDuration: core.OAuth2ResourceDefaultAccessTokenDuration}, nil},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			expectValidationFields(t, s.resource.Validate(), s.fields)
		})
	}
}

func TestOAuth2ServerConfigResources(t *testing.T) {
	t.Parallel()

	config := core.OAuth2ServerConfig{
		SessionDuration:      100,
		RefreshTokenDuration: 100,
		CodeDuration:         60,
		Resources: []core.OAuth2Resource{
			{Identifier: "urn:a:b", AccessTokenDuration: 60},
			{Identifier: "urn:a:b", AccessTokenDuration: 60},
		},
	}

	errs, ok := config.Validate().(validation.Errors)
	if !ok || errs["resources"] == nil {
		t.Fatalf("Expected a duplicated resources error, got %v", errs)
	}

	config.Resources[1].Identifier = "urn:a:c"
	if err := config.Validate(); err != nil {
		t.Fatalf("Expected valid config, got %v", err)
	}

	if r, ok := config.FindResource("urn:a:c"); !ok || r.Identifier != "urn:a:c" {
		t.Fatalf("Expected to find the resource, got %v %v", r, ok)
	}

	if _, ok := config.FindResource("urn:a:missing"); ok {
		t.Fatal("Expected not to find a missing resource")
	}
}

func TestOAuth2ClientResourcesValidation(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	users.OAuth2Server.Resources = []core.OAuth2Resource{{Identifier: "urn:a:b", AccessTokenDuration: 60}}
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	newClient := func(resources []string) *core.OAuth2Client {
		c := core.NewOAuth2Client(app)
		c.SetName("test")
		c.SetClientId("resources_test")
		c.SetType(core.OAuth2ClientTypePublic)
		c.SetCollectionRef(users.Id)
		c.SetRedirectURIs([]string{"https://example.com/callback"})
		c.SetResources(resources)
		return c
	}

	scenarios := []struct {
		name      string
		resources []string
		fields    []string
	}{
		{"unknown resource", []string{"urn:a:missing"}, []string{"resources"}},
		// note: the stored list is normalized (see [core.Record.GetStringSlice])
		{"duplicated resource", []string{"urn:a:b", "urn:a:b"}, nil},
		{"none", nil, nil},
		{"registered resource", []string{"urn:a:b"}, nil},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			client := newClient(s.resources)
			expectValidationFields(t, app.Validate(client), s.fields)

			if len(s.fields) == 0 && len(s.resources) > 0 && !client.AllowsResource(s.resources[0]) {
				t.Fatalf("Expected the client to allow %q", s.resources[0])
			}
		})
	}

	if newClient(nil).AllowsResource("") {
		t.Fatal("Expected an empty resource to never be allowed")
	}
}

func expectValidationFields(t testing.TB, err error, fields []string) {
	t.Helper()

	if len(fields) == 0 {
		if err != nil {
			t.Fatalf("Expected no validation errors, got %v", err)
		}
		return
	}

	var errs validation.Errors
	if !errors.As(err, &errs) {
		t.Fatalf("Expected validation errors for %v, got %v", fields, err)
	}

	if len(errs) != len(fields) {
		t.Fatalf("Expected validation errors for %v, got %v", fields, errs)
	}

	for _, f := range fields {
		if errs[f] == nil {
			t.Fatalf("Missing expected validation error for %q in %v", f, errs)
		}
	}
}
