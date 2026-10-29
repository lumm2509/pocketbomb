package core_test

import (
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestGraphQLConfigValidate(t *testing.T) {
	scenarios := []struct {
		name           string
		config         core.GraphQLConfig
		expectedErrors []string
	}{
		{
			"zero values",
			core.GraphQLConfig{},
			[]string{"maxDepth", "maxCost", "maxPageSize"},
		},
		{
			"out of range values",
			core.GraphQLConfig{MaxDepth: 51, MaxCost: 1000001, MaxPageSize: 501},
			[]string{"maxDepth", "maxCost", "maxPageSize"},
		},
		{
			"min values",
			core.GraphQLConfig{MaxDepth: 1, MaxCost: 1, MaxPageSize: 1},
			[]string{},
		},
		{
			"max values (disabled)",
			core.GraphQLConfig{Enabled: false, MaxDepth: 50, MaxCost: 1000000, MaxPageSize: 500},
			[]string{},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			tests.TestValidationErrors(t, s.config.Validate(), s.expectedErrors)
		})
	}
}

func TestGraphQLConfigDefaults(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	config := app.Settings().GraphQL

	if !config.Enabled || config.MaxDepth != 10 || config.MaxCost != 1000 || config.MaxPageSize != 250 {
		t.Fatalf("Unexpected default GraphQL settings %+v", config)
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Expected the default settings to be valid, got %v", err)
	}
}
