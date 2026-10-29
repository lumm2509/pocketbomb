package core_test

import (
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/types"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

func TestLLMConfigValidate(t *testing.T) {
	restore := core.SetTestLLMEnvLookup(map[string]string{core.LLMEnvOpenAIAPIKey: "test"})
	defer restore()

	validProvider := core.LLMProviderConfig{Name: "p1", Provider: "openai", Enabled: true}

	scenarios := []struct {
		name           string
		config         core.LLMConfig
		expectedErrors []string
	}{
		{
			"zero value",
			core.LLMConfig{},
			[]string{},
		},
		{
			"valid config",
			core.LLMConfig{
				DefaultProvider: "p1",
				Providers: []core.LLMProviderConfig{
					validProvider,
					{Name: "local-llm", Provider: "openai-compatible", BaseURL: "http://localhost:1234/v1"},
				},
				Profiles: []core.LLMProfile{
					{
						Name:          "support_bot",
						Provider:      "openai", // env provider
						AllowedModels: []string{"a", "b"},
						MaxTokens:     10,
						Temperature:   types.Pointer(1.5),
						Quotas: core.LLMProfileQuotas{
							PerUser: core.LLMQuota{Requests: 10, Window: "hour"},
						},
					},
				},
				Logs: core.LLMLogsConfig{Enabled: true, MaxDays: 1},
			},
			[]string{},
		},
		{
			"invalid default provider",
			core.LLMConfig{DefaultProvider: "missing"},
			[]string{"defaultProvider"},
		},
		{
			"invalid providers",
			core.LLMConfig{
				Providers: []core.LLMProviderConfig{
					{Name: "invalid name", Provider: "missing", BaseURL: "invalid", Timeout: -1},
				},
			},
			[]string{"providers"},
		},
		{
			"duplicated providers",
			core.LLMConfig{Providers: []core.LLMProviderConfig{validProvider, validProvider}},
			[]string{"providers"},
		},
		{
			"openai-compatible without base url",
			core.LLMConfig{Providers: []core.LLMProviderConfig{{Name: "a", Provider: "openai-compatible"}}},
			[]string{"providers"},
		},
		{
			"duplicated profiles",
			core.LLMConfig{Profiles: []core.LLMProfile{{Name: "a"}, {Name: "a"}}},
			[]string{"profiles"},
		},
		{
			"invalid profile fields",
			core.LLMConfig{Profiles: []core.LLMProfile{{
				Name:          "",
				AllowedModels: []string{""},
				MaxTokens:     -1,
				Temperature:   types.Pointer(3.0),
				Quotas: core.LLMProfileQuotas{
					PerGuestIP: core.LLMQuota{Tokens: 10, Window: ""},
				},
			}}},
			[]string{"profiles"},
		},
		{
			"profile with unknown provider",
			core.LLMConfig{Profiles: []core.LLMProfile{{Name: "a", Provider: "missing"}}},
			[]string{"profiles"},
		},
		{
			"profile quotas without logs",
			core.LLMConfig{Profiles: []core.LLMProfile{{
				Name:   "a",
				Quotas: core.LLMProfileQuotas{PerUser: core.LLMQuota{Requests: 1, Window: "day"}},
			}}},
			[]string{"profiles"},
		},
		{
			"enabled logs without max days",
			core.LLMConfig{Logs: core.LLMLogsConfig{Enabled: true}},
			[]string{"logs"},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			result := s.config.Validate()

			tests.TestValidationErrors(t, result, s.expectedErrors)
		})
	}
}

func TestSettingsLLMProfileRuleValidation(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	scenarios := []struct {
		name        string
		rule        *string
		expectError bool
	}{
		{"nil", nil, false},
		{"empty", types.Pointer(""), false},
		{"valid", types.Pointer("@request.auth.id != '' && @request.body.model = 'a'"), false},
		{"plain field", types.Pointer("id != ''"), true},
		{"invalid", types.Pointer("@request.auth.id ~"), true},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			settings, err := app.Settings().Clone()
			if err != nil {
				t.Fatal(err)
			}

			settings.LLM.Profiles = []core.LLMProfile{{Name: "test", Rule: s.rule}}

			err = app.Validate(settings)

			hasErr := err != nil
			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}

			if hasErr {
				errs, _ := err.(validation.Errors)
				raw, _ := json.Marshal(errs)
				if !strings.Contains(string(raw), `"llm":{"profiles":{"0":{"rule":"Invalid rule.`) {
					t.Fatalf("Expected llm.profiles.0.rule error, got %s", raw)
				}
			}
		})
	}
}

func TestLLMConfigSecretsMerge(t *testing.T) {
	restore := core.SetTestLLMEnvLookup(nil)
	defer restore()

	settings := &core.Settings{}
	settings.LLM.Providers = []core.LLMProviderConfig{
		{Name: "a", Provider: "openai", APIKey: "key_a"},
		{Name: "b", Provider: "openai", APIKey: "key_b"},
		{Name: "c", Provider: "openai", APIKey: "key_c"},
	}

	// masked
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "key_") {
		t.Fatalf("Expected the api keys to be masked, got\n%s", raw)
	}
	if strings.Count(string(raw), `"hasApiKey":true`) != 3 {
		t.Fatalf("Expected 3 hasApiKey:true, got\n%s", raw)
	}

	// simulate a dashboard submit:
	// - reorder "a" and "b" (without keys)
	// - change the "c" key
	// - add new "d" provider without key
	// - "renamed" provider loses its key
	err = json.Unmarshal([]byte(`{"llm":{"providers":[
		{"name":"b","provider":"openai","envProviders":[]},
		{"name":"a","provider":"openai","hasApiKey":true},
		{"name":"c","provider":"openai","apiKey":"new_key_c"},
		{"name":"d","provider":"openai"}
	]}}`), settings)
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string]string{"b": "key_b", "a": "key_a", "c": "new_key_c", "d": ""}

	if len(settings.LLM.Providers) != len(expected) {
		t.Fatalf("Expected %d providers, got %d", len(expected), len(settings.LLM.Providers))
	}

	for _, p := range settings.LLM.Providers {
		if expected[p.Name] != p.APIKey {
			t.Fatalf("Expected provider %q key %q, got %q", p.Name, expected[p.Name], p.APIKey)
		}
	}

	// explicit empty key clears it and missing providers key preserves the existing providers
	err = json.Unmarshal([]byte(`{"llm":{"providers":[{"name":"a","provider":"openai","apiKey":""}]}}`), settings)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal([]byte(`{"llm":{"logs":{"maxDays":3}}}`), settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.LLM.Providers) != 1 || settings.LLM.Providers[0].APIKey != "" || settings.LLM.Logs.MaxDays != 3 {
		t.Fatalf("Unexpected providers %#v (logs %#v)", settings.LLM.Providers, settings.LLM.Logs)
	}

	// clone (aka. db export) preserves the keys
	settings.LLM.Providers[0].APIKey = "key_a"
	clone, err := settings.Clone()
	if err != nil {
		t.Fatal(err)
	}
	if clone.LLM.Providers[0].APIKey != "key_a" {
		t.Fatalf("Expected the cloned settings to have the api key, got %q", clone.LLM.Providers[0].APIKey)
	}
}
