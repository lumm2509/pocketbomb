package core_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestSecretFieldsRegistryCoversNamingConvention(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	collections, err := app.FindAllCollections()
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range collections {
		if !c.System {
			continue
		}

		secrets := core.SecretFieldNames(c)

		for _, name := range c.Fields.FieldNames() {
			if name == "secret" || strings.HasSuffix(name, "Hash") || strings.HasSuffix(name, "Secret") {
				if !slices.Contains(secrets, name) {
					t.Errorf("[%s] Expected %q to be a secret field", c.Name, name)
				}
			}
		}

		for _, name := range core.InternalFieldNames(c) {
			if !slices.Contains(secrets, name) {
				t.Errorf("[%s] Expected internal field %q to be also a secret field", c.Name, name)
			}
		}
	}
}

func TestSecretFieldsUnregisteredSystemCollection(t *testing.T) {
	t.Parallel()

	c := core.NewBaseCollection("_custom")
	c.System = true
	c.Fields.Add(
		&core.TextField{Name: "apiSecret"},
		&core.TextField{Name: "keyHash"},
		&core.TextField{Name: "secret"},
		&core.TextField{Name: "title"},
	)

	names := core.SecretFieldNames(c)
	slices.Sort(names)

	expected := []string{"apiSecret", "keyHash", "secret"}
	if !slices.Equal(names, expected) {
		t.Fatalf("Expected %v, got %v", expected, names)
	}

	c.System = false
	if names := core.SecretFieldNames(c); len(names) != 0 {
		t.Fatalf("Expected no secret fields for a regular collection, got %v", names)
	}
}

func TestSecretFields(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	scenarios := []struct {
		collection string
		expected   []string
	}{
		{"users", []string{"password", "tokenKey"}},
		{core.CollectionNameSuperusers, []string{"password", "tokenKey"}},
		{core.CollectionNameOTPs, []string{"password"}},
		{"demo1", []string{}},
	}

	for _, s := range scenarios {
		c, err := app.FindCollectionByNameOrId(s.collection)
		if err != nil {
			t.Fatal(err)
		}

		names := core.SecretFieldNames(c)
		slices.Sort(names)
		if !slices.Equal(names, s.expected) {
			t.Fatalf("[%s] Expected secret fields %v, got %v", s.collection, s.expected, names)
		}
	}

	// the hashes and the upstream login state (union of the former heuristic and API enrich lists)
	sessions, _ := app.FindCollectionByNameOrId(core.CollectionNameAuthSessions)
	sessionSecrets := core.SecretFieldNames(sessions)
	slices.Sort(sessionSecrets)
	expectedSessionSecrets := []string{
		"bindingHash", "codeHash", "handleHash", "impersonatorKeyHash", "prevRefreshTokenHash", "refreshTokenHash",
		"ssoSecretHash", "upstreamCodeVerifier", "upstreamProvider", "upstreamRecordRef", "upstreamState",
	}
	if !slices.Equal(sessionSecrets, expectedSessionSecrets) {
		t.Fatalf("Expected auth session secret fields %v, got %v", expectedSessionSecrets, sessionSecrets)
	}

	clients, _ := app.FindCollectionByNameOrId(core.CollectionNameOAuth2Clients)
	if !slices.Contains(core.SecretFieldNames(clients), "clientSecretHash") {
		t.Fatal("Expected clientSecretHash to be a secret field")
	}

	webhooks, _ := app.FindCollectionByNameOrId(core.CollectionNameWebhooks)
	if !slices.Contains(core.SecretFieldNames(webhooks), "secret") {
		t.Fatal("Expected the webhook secret to be a secret field")
	}
}
