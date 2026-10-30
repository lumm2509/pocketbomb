package core

import (
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// StoreKeyGraphQLSchemaMigrationWriter is the app store key that is set when a migrations writer is bound to
// [App.OnGraphQLSchemaApplyRequest] (without it the dashboard GraphQL schema editor is read-only).
const StoreKeyGraphQLSchemaMigrationWriter = "@graphqlSchemaMigrationWriter"

// GraphQLConfig defines the GraphQL read API settings.
type GraphQLConfig struct {
	// Enabled enables the /api/graphql endpoint.
	Enabled bool `form:"enabled" json:"enabled"`

	// MaxDepth is the max selection depth of a single query (the introspection fields are not counted).
	MaxDepth int `form:"maxDepth" json:"maxDepth"`

	// MaxCost is the max static cost of a single query
	// (each returned object costs 1 and the lists multiply their children cost).
	MaxCost int `form:"maxCost" json:"maxCost"`

	// MaxPageSize is the max allowed connection "first" or "last" argument value.
	MaxPageSize int `form:"maxPageSize" json:"maxPageSize"`

	// Schema is the last applied schema of the dashboard GraphQL schema editor
	// (it is only the editor source; see POST /api/graphql/schema/apply).
	Schema string `form:"schema" json:"schema,omitempty"`
}

func newDefaultGraphQLConfig() GraphQLConfig {
	return GraphQLConfig{
		Enabled:     true,
		MaxDepth:    10,
		MaxCost:     1000,
		MaxPageSize: 250,
	}
}

// Validate makes GraphQLConfig validatable by implementing [validation.Validatable] interface.
func (c GraphQLConfig) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.MaxDepth, validation.Required, validation.Min(1), validation.Max(50)),
		validation.Field(&c.MaxCost, validation.Required, validation.Min(1), validation.Max(1000000)),
		validation.Field(&c.MaxPageSize, validation.Required, validation.Min(1), validation.Max(500)),
		validation.Field(&c.Schema, validation.Length(0, 1<<20)),
	)
}
