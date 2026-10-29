package apis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/gqlerrors"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/router"
)

const (
	// graphqlMaxQuerySize is the max allowed query document size (in bytes).
	graphqlMaxQuerySize = 32 << 10

	// graphqlTimeout is the max execution time of a single GraphQL request.
	graphqlTimeout = 10 * time.Second
)

// bindGraphQLApi registers the GraphQL read API endpoints.
//
// note: deny by default like the records API (the request must identify
// its client with an API key or an OAuth2 access token)
func bindGraphQLApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	sub := rg.Group("/graphql")
	sub.GET("", graphqlQuery).Bind(requireClientCredentials())
	sub.POST("", graphqlQuery).Bind(requireClientCredentials())
	sub.GET("/collections", graphqlCollections).Bind(RequirePermission(core.PermissionResourceCollections, core.PermissionLevelRead))
}

type graphqlPayload struct {
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName"`
}

func graphqlQuery(e *core.RequestEvent) error {
	if !e.App.Settings().GraphQL.Enabled {
		return e.NotFoundError("The GraphQL API is disabled.", nil)
	}

	payload, err := readGraphQLPayload(e)
	if err != nil {
		return writeGraphQLResponse(e, http.StatusBadRequest, graphqlErrorResponse(err.Error()))
	}

	event := new(core.GraphQLRequestEvent)
	event.RequestEvent = e
	event.Query = payload.Query
	event.Variables = payload.Variables
	event.OperationName = payload.OperationName

	return e.App.OnGraphQLRequest().Trigger(event, func(e *core.GraphQLRequestEvent) error {
		status, response := executeGraphQL(e.RequestEvent, e.Query, e.Variables, e.OperationName)

		return execAfterSuccessTx(true, e.App, func() error {
			return writeGraphQLResponse(e.RequestEvent, status, response)
		})
	})
}

func readGraphQLPayload(e *core.RequestEvent) (*graphqlPayload, error) {
	payload := &graphqlPayload{}

	if e.Request.Method == http.MethodGet {
		query := e.Request.URL.Query()
		payload.Query = query.Get("query")
		payload.OperationName = query.Get("operationName")
		if raw := query.Get("variables"); raw != "" {
			if err := json.Unmarshal([]byte(raw), &payload.Variables); err != nil {
				return nil, errors.New("Invalid variables JSON.")
			}
		}
	} else {
		if !strings.HasPrefix(e.Request.Header.Get("Content-Type"), "application/json") {
			return nil, errors.New("The request body must be application/json.")
		}

		if err := e.BindBody(payload); err != nil {
			return nil, errors.New("Invalid request body.")
		}
	}

	if strings.TrimSpace(payload.Query) == "" {
		return nil, errors.New("Missing query.")
	}

	return payload, nil
}

// writeGraphQLResponse writes the GraphQL response JSON (with sorted object keys).
func writeGraphQLResponse(e *core.RequestEvent, status int, response map[string]any) error {
	raw, err := json.Marshal(response)
	if err != nil {
		return e.InternalServerError("Failed to serialize the GraphQL response.", err)
	}

	return e.Blob(status, "application/json", raw)
}

// graphqlErrorResponse returns a GraphQL response of a request error
// (without data entry since the operation wasn't executed).
func graphqlErrorResponse(message string) map[string]any {
	return map[string]any{"errors": []map[string]any{{"message": message}}}
}

// executeGraphQL validates and executes the GraphQL query of the request actor
// and returns the response status and body.
//
// The query document must be parsable (otherwise 400) and the validation,
// limits and resolvers errors are returned as GraphQL errors (200).
func executeGraphQL(e *core.RequestEvent, query string, variables map[string]any, operationName string) (int, map[string]any) {
	if len(query) > graphqlMaxQuerySize {
		return http.StatusBadRequest, graphqlErrorResponse(fmt.Sprintf("The query exceeds the max size of %d bytes.", graphqlMaxQuerySize))
	}

	doc, err := parser.Parse(parser.ParseParams{
		Source: source.NewSource(&source.Source{Body: []byte(query), Name: "GraphQL request"}),
	})
	if err != nil {
		return http.StatusBadRequest, map[string]any{"errors": gqlerrors.FormatErrors(err)}
	}

	schema, err := graphqlSchemaFor(e.App)
	if err != nil {
		e.App.Logger().Error("Failed to build the GraphQL schema", "error", err)
		return http.StatusInternalServerError, graphqlErrorResponse("Failed to build the GraphQL schema.")
	}

	if result := graphql.ValidateDocument(&schema.schema, doc, nil); !result.IsValid {
		return http.StatusOK, map[string]any{"errors": result.Errors}
	}

	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok && op.Operation != ast.OperationTypeQuery {
			return http.StatusOK, graphqlErrorResponse("Only queries are supported.")
		}
	}

	config := e.App.Settings().GraphQL
	if err := schema.checkLimits(doc, operationName, variables, config.MaxDepth, config.MaxCost); err != nil {
		return http.StatusOK, graphqlErrorResponse(err.Error())
	}

	requestInfo, err := e.RequestInfo()
	if err != nil {
		return http.StatusBadRequest, graphqlErrorResponse("Invalid request.")
	}

	ctx, cancel := context.WithTimeout(e.Request.Context(), graphqlTimeout)
	defer cancel()

	req := &graphqlRequest{
		event:   e,
		info:    requestInfo,
		ctx:     ctx,
		schema:  schema,
		loaders: map[string]*graphqlRelationLoader{},
	}

	// note: the executor context is never canceled so that Execute always waits
	// for the resolvers (they stop on their own with the request ctx deadline)
	result := graphql.Execute(graphql.ExecuteParams{
		Schema:        schema.schema,
		AST:           doc,
		OperationName: operationName,
		Args:          variables,
		Context:       context.WithValue(context.WithoutCancel(ctx), graphqlRequestKey{}, req),
	})

	response := map[string]any{"data": result.Data}
	if len(result.Errors) > 0 {
		response["errors"] = result.Errors
	}

	return http.StatusOK, response
}

func graphqlCollections(e *core.RequestEvent) error {
	schema, err := graphqlSchemaFor(e.App)
	if err != nil {
		return e.InternalServerError("Failed to build the GraphQL schema.", err)
	}

	config := e.App.Settings().GraphQL

	return e.JSON(http.StatusOK, map[string]any{
		"enabled": config.Enabled,
		"limits": map[string]any{
			"maxDepth":     config.MaxDepth,
			"maxCost":      config.MaxCost,
			"maxPageSize":  config.MaxPageSize,
			"maxQuerySize": graphqlMaxQuerySize,
			"timeout":      int(graphqlTimeout / time.Second),
		},
		"collections": schema.report,
	})
}

// -------------------------------------------------------------------
// Limits
// -------------------------------------------------------------------

// checkLimits returns an error if the executed operation exceeds the max depth or the static cost
// (each returned record object costs 1 and the connections and multiple relations
// multiply their children cost by first/last or the relation max select; the introspection fields are free).
func (s *graphqlSchema) checkLimits(doc *ast.Document, operationName string, variables map[string]any, maxDepth int, maxCost int) error {
	w := &graphqlLimitsWalker{
		schema:    s,
		fragments: map[string]*ast.FragmentDefinition{},
		variables: variables,
	}

	var op *ast.OperationDefinition
	for _, def := range doc.Definitions {
		switch def := def.(type) {
		case *ast.FragmentDefinition:
			w.fragments[def.Name.Value] = def
		case *ast.OperationDefinition:
			if operationName == "" || (def.Name != nil && def.Name.Value == operationName) {
				op = def
			}
		}
	}

	if op == nil {
		return nil // the executor reports the missing operation
	}

	depth, cost := w.selectionSet(op.SelectionSet, s.schema.QueryType(), graphqlDefaultPageSize)

	if depth > maxDepth {
		return fmt.Errorf("The query exceeds the max depth of %d.", maxDepth)
	}

	if cost > maxCost {
		return fmt.Errorf("The query exceeds the max cost of %d (estimated cost %d).", maxCost, cost)
	}

	return nil
}

type graphqlLimitsWalker struct {
	schema    *graphqlSchema
	fragments map[string]*ast.FragmentDefinition
	variables map[string]any
}

func (w *graphqlLimitsWalker) selectionSet(set *ast.SelectionSet, parent graphql.Type, pageSize int) (int, int) {
	if set == nil {
		return 0, 0
	}

	var depth, cost int

	for _, sel := range set.Selections {
		switch sel := sel.(type) {
		case *ast.Field:
			name := sel.Name.Value
			if strings.HasPrefix(name, "__") {
				continue // introspection
			}

			fieldDef := graphqlFieldDef(parent, name)
			if fieldDef == nil {
				continue
			}

			named, _ := graphql.GetNamed(fieldDef.Type).(graphql.Type)
			if named == nil {
				continue
			}
			multiplier := 1
			childPageSize := pageSize
			own := 0

			if _, ok := w.schema.connections[named.Name()]; ok {
				own = 1
				childPageSize = w.pageSize(sel)
			} else if _, ok := w.schema.connections[parent.Name()]; ok && (name == "edges" || name == "nodes") {
				multiplier = pageSize
			} else if maxSelect, ok := w.schema.multiRelations[parent.Name()+"."+name]; ok {
				multiplier = max(1, maxSelect)
			}

			if _, ok := w.schema.typesByName[named.Name()]; ok || named.Name() == "Node" {
				own = 1
			}

			childDepth, childCost := w.selectionSet(sel.SelectionSet, named, childPageSize)

			depth = max(depth, childDepth+1)
			cost = graphqlSatAdd(cost, graphqlSatMul(multiplier, graphqlSatAdd(own, childCost)))
		case *ast.InlineFragment:
			t := parent
			if sel.TypeCondition != nil {
				if named := w.schema.schema.Type(sel.TypeCondition.Name.Value); named != nil {
					t = named
				}
			}

			childDepth, childCost := w.selectionSet(sel.SelectionSet, t, pageSize)
			depth = max(depth, childDepth)
			cost = graphqlSatAdd(cost, childCost)
		case *ast.FragmentSpread:
			frag := w.fragments[sel.Name.Value]
			if frag == nil {
				continue
			}

			t := parent
			if frag.TypeCondition != nil {
				if named := w.schema.schema.Type(frag.TypeCondition.Name.Value); named != nil {
					t = named
				}
			}

			childDepth, childCost := w.selectionSet(frag.SelectionSet, t, pageSize)
			depth = max(depth, childDepth)
			cost = graphqlSatAdd(cost, childCost)
		}
	}

	return depth, cost
}

// pageSize returns the first/last argument of a connection field (or the default page size).
func (w *graphqlLimitsWalker) pageSize(field *ast.Field) int {
	result := 0

	for _, arg := range field.Arguments {
		if arg.Name.Value != "first" && arg.Name.Value != "last" {
			continue
		}

		var n int
		switch v := arg.Value.(type) {
		case *ast.IntValue:
			n, _ = strconv.Atoi(v.Value)
		case *ast.Variable:
			switch raw := w.variables[v.Name.Value].(type) {
			case float64:
				n = int(raw)
			case int:
				n = raw
			}
		}

		result = max(result, n)
	}

	if result == 0 {
		hasArg := false
		for _, arg := range field.Arguments {
			hasArg = hasArg || arg.Name.Value == "first" || arg.Name.Value == "last"
		}
		if !hasArg {
			return graphqlDefaultPageSize
		}
	}

	return result
}

func graphqlFieldDef(parent graphql.Type, name string) *graphql.FieldDefinition {
	switch t := parent.(type) {
	case *graphql.Object:
		return t.Fields()[name]
	case *graphql.Interface:
		return t.Fields()[name]
	}

	return nil
}

func graphqlSatAdd(a, b int) int {
	if a > math.MaxInt32-b {
		return math.MaxInt32
	}
	return a + b
}

func graphqlSatMul(a, b int) int {
	if a != 0 && b > math.MaxInt32/a {
		return math.MaxInt32
	}
	return a * b
}
