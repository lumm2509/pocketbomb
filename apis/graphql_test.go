package apis_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

func gqlBody(query string) *strings.Reader {
	return strings.NewReader(`{"query":` + fmt.Sprintf("%q", query) + `}`)
}

func TestGraphQLApi(t *testing.T) {
	t.Parallel()

	demo2Id := gqlGlobalId("demo2", "llvuca81nly1qls")

	deepQuery := "{ gqlProducts(first: 1) { nodes { " + strings.Repeat("related { ", 9) + "id" + strings.Repeat(" }", 9) + " } } }"

	introspection := `{ __schema { queryType { name } types { name kind fields { name type { ...TypeRef } } } } }
		fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }`

	scenarios := []tests.ApiScenario{
		{
			Name:            "deny by default (no API key and no auth token)",
			Method:          http.MethodPost,
			URL:             "/api/graphql",
			Body:            gqlBody(`{ demo2s { totalCount } }`),
			ExpectedStatus:  401,
			ExpectedContent: []string{`"missing_client_credentials"`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "disabled",
			Method: http.MethodPost,
			URL:    "/api/graphql",
			Body:   gqlBody(`{ demo2s { totalCount } }`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().GraphQL.Enabled = false
			},
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "invalid json body",
			Method:          http.MethodPost,
			URL:             "/api/graphql",
			Body:            strings.NewReader(`{"query":`),
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"errors":[{"message":"Invalid request body."`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "missing query",
			Method:          http.MethodPost,
			URL:             "/api/graphql",
			Body:            strings.NewReader(`{"query":"  "}`),
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"message":"Missing query."`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:               "unparsable query",
			Method:             http.MethodPost,
			URL:                "/api/graphql",
			Body:               gqlBody(`{ demo2s { `),
			Headers:            tests.PublicAPIKeyHeaders(),
			ExpectedStatus:     400,
			ExpectedContent:    []string{`"errors":[{"message":"Syntax Error`},
			NotExpectedContent: []string{`"data"`},
			ExpectedEvents:     map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:            "query over the max size",
			Method:          http.MethodPost,
			URL:             "/api/graphql",
			Body:            gqlBody(`{ demo2s { totalCount } }` + strings.Repeat(" ", 32<<10)),
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"message":"The query exceeds the max size of 32768 bytes."`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:           "list query",
			Method:         http.MethodPost,
			URL:            "/api/graphql",
			Body:           gqlBody(`{ demo2s(sort: "title") { totalCount nodes { title active } } }`),
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"totalCount":3`,
				`"nodes":[{"active":false,"title":"test1"},{"active":true,"title":"test2"},{"active":true,"title":"test3"}]`,
			},
			NotExpectedContent: []string{`"errors"`},
			ExpectedEvents: map[string]int{
				"OnGraphQLRequest": 1,
				"OnRecordEnrich":   3,
			},
		},
		{
			Name:            "GET query with variables",
			Method:          http.MethodGet,
			URL:             "/api/graphql?query=" + url.QueryEscape(`query ($t: String) { demo2(title: $t) { title } }`) + "&variables=" + url.QueryEscape(`{"t":"test2"}`),
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`{"data":{"demo2":{"title":"test2"}}}`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1, "OnRecordEnrich": 1},
		},
		{
			Name:            "GET with invalid variables",
			Method:          http.MethodGet,
			URL:             "/api/graphql?query=" + url.QueryEscape(`{ demo2s { totalCount } }`) + "&variables=" + url.QueryEscape(`{`),
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"message":"Invalid variables JSON."`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:               "mutation",
			Method:             http.MethodPost,
			URL:                "/api/graphql",
			Body:               gqlBody(`mutation { demo2s { totalCount } }`),
			Headers:            tests.PublicAPIKeyHeaders(),
			ExpectedStatus:     200,
			ExpectedContent:    []string{`{"errors":[{"message":"Only queries are supported."}]}`},
			NotExpectedContent: []string{`"totalCount"`},
			ExpectedEvents:     map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:               "subscription",
			Method:             http.MethodPost,
			URL:                "/api/graphql",
			Body:               gqlBody(`subscription { demo2s { totalCount } }`),
			Headers:            tests.PublicAPIKeyHeaders(),
			ExpectedStatus:     200,
			ExpectedContent:    []string{`{"errors":[{"message":"Only queries are supported."}]}`},
			NotExpectedContent: []string{`"totalCount"`},
			ExpectedEvents:     map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:               "query document with a mutation operation",
			Method:             http.MethodPost,
			URL:                "/api/graphql",
			Body:               strings.NewReader(`{"query":"query A { demo2s { totalCount } } mutation B { demo2s { totalCount } }","operationName":"A"}`),
			Headers:            tests.PublicAPIKeyHeaders(),
			ExpectedStatus:     200,
			ExpectedContent:    []string{`{"errors":[{"message":"Only queries are supported."}]}`},
			NotExpectedContent: []string{`"totalCount"`},
			ExpectedEvents:     map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:   "max depth",
			Method: http.MethodPost,
			URL:    "/api/graphql",
			Body:   gqlBody(deepQuery),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				gqlFixtures(t, app)
			},
			Headers:            tests.PublicAPIKeyHeaders(),
			ExpectedStatus:     200,
			ExpectedContent:    []string{`"message":"The query exceeds the max depth of 10."`},
			NotExpectedContent: []string{`"data"`},
			ExpectedEvents:     map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:   "max depth (settings)",
			Method: http.MethodPost,
			URL:    "/api/graphql",
			Body:   gqlBody(`{ demo2s { nodes { title } } }`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().GraphQL.MaxDepth = 2
			},
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"message":"The query exceeds the max depth of 2."`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:   "max cost",
			Method: http.MethodPost,
			URL:    "/api/graphql",
			Body:   gqlBody(`{ gqlProducts(first: 250) { nodes { related { title } } } }`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				gqlFixtures(t, app)
			},
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"message":"The query exceeds the max cost of 1000 (estimated cost 1001)."`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:   "max cost with variables and fragments",
			Method: http.MethodPost,
			URL:    "/api/graphql",
			Body:   strings.NewReader(`{"query":"query ($n: Int) { gqlProducts(first: $n) { ...F } } fragment F on GqlProductConnection { edges { node { related { title } } } }","variables":{"n":250}}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				gqlFixtures(t, app)
			},
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"message":"The query exceeds the max cost of 1000 (estimated cost 1001)."`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:   "max cost (settings)",
			Method: http.MethodPost,
			URL:    "/api/graphql",
			Body:   gqlBody(`{ demo2s(first: 3) { nodes { title } } }`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().GraphQL.MaxCost = 3
			},
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"message":"The query exceeds the max cost of 3 (estimated cost 4)."`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:   "max page size (settings)",
			Method: http.MethodPost,
			URL:    "/api/graphql",
			Body:   gqlBody(`{ demo2s(first: 3) { nodes { title } } }`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().GraphQL.MaxPageSize = 2
			},
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"message":"The first and last arguments must be between 0 and 2."`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:           "introspection (not counted in the depth limit)",
			Method:         http.MethodPost,
			URL:            "/api/graphql",
			Body:           gqlBody(introspection),
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"queryType":{"name":"Query"}`,
				`"name":"Demo2Connection"`,
				`"name":"PageInfo"`,
				`"name":"Node"`,
			},
			NotExpectedContent: []string{
				`"errors"`,
				`"name":"Demo1"`, // no List/View API rule
				`"name":"password"`,
				`"name":"tokenKey"`,
			},
			ExpectedEvents: map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:            "node",
			Method:          http.MethodPost,
			URL:             "/api/graphql",
			Body:            gqlBody(`{ node(id: "` + demo2Id + `") { id __typename ... on Demo2 { title } } }`),
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`{"data":{"node":{"__typename":"Demo2","id":"` + demo2Id + `","title":"test1"}}}`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1, "OnRecordEnrich": 1},
		},
		{
			Name:               "node with invalid or not exposed ids",
			Method:             http.MethodPost,
			URL:                "/api/graphql",
			Body:               gqlBody(`{ a: node(id: "invalid") { id } b: node(id: "` + gqlGlobalId("demo1", "84nmscqy84lsi1t") + `") { id } c: node(id: "` + gqlGlobalId("demo2", "missing") + `") { id } }`),
			Headers:            tests.PublicAPIKeyHeaders(),
			ExpectedStatus:     200,
			ExpectedContent:    []string{`"a":null`, `"b":null`, `"c":null`},
			NotExpectedContent: []string{`"errors"`},
			ExpectedEvents:     map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:               "singular query by id and by unique field",
			Method:             http.MethodPost,
			URL:                "/api/graphql",
			Body:               gqlBody(`{ a: demo2(id: "` + demo2Id + `") { title } b: demo2(title: "test3") { title } c: demo2(title: "missing") { title } d: demo2(id: "` + gqlGlobalId("demo3", "llvuca81nly1qls") + `") { title } }`),
			Headers:            tests.PublicAPIKeyHeaders(),
			ExpectedStatus:     200,
			ExpectedContent:    []string{`"a":{"title":"test1"}`, `"b":{"title":"test3"}`, `"c":null`, `"d":null`},
			NotExpectedContent: []string{`"errors"`},
			ExpectedEvents:     map[string]int{"OnGraphQLRequest": 1, "OnRecordEnrich": 2},
		},
		{
			Name:            "singular query without or with multiple arguments",
			Method:          http.MethodPost,
			URL:             "/api/graphql",
			Body:            gqlBody(`{ a: demo2 { title } b: demo2(id: "` + demo2Id + `", title: "test1") { title } }`),
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"message":"Exactly one of the arguments id, title must be provided."`, `"a":null`, `"b":null`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:            "singular query of a collection without View rule access",
			Method:          http.MethodPost,
			URL:             "/api/graphql",
			Body:            gqlBody(`{ user(id: "` + gqlGlobalId("users", "4q1xlclmfloku33") + `") { username } }`),
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`{"data":{"user":null}}`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:           "forbidden list doesn't null the other root fields",
			Method:         http.MethodPost,
			URL:            "/api/graphql",
			Body:           gqlBody(`{ users { totalCount } demo2s { totalCount } }`),
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"data":{"demo2s":{"totalCount":3},"users":null}`,
				`"message":"Only superusers can perform this action."`,
				`"extensions":{"data":{},"status":403}`,
				`"path":["users"]`,
			},
			ExpectedEvents: map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:   "OnGraphQLRequest can modify the query",
			Method: http.MethodPost,
			URL:    "/api/graphql",
			Body:   gqlBody(`{ demo2s { totalCount } }`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnGraphQLRequest().BindFunc(func(e *core.GraphQLRequestEvent) error {
					e.Query = `query ($t: String) { demo2(title: $t) { title } }`
					e.Variables = map[string]any{"t": "test3"}
					return e.Next()
				})
			},
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`{"data":{"demo2":{"title":"test3"}}}`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1, "OnRecordEnrich": 1},
		},
		{
			Name:   "OnGraphQLRequest can short-circuit",
			Method: http.MethodPost,
			URL:    "/api/graphql",
			Body:   gqlBody(`{ demo2s { totalCount } }`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnGraphQLRequest().BindFunc(func(e *core.GraphQLRequestEvent) error {
					if !strings.Contains(e.Query, "demo2s") {
						t.Fatalf("Expected the submitted query, got %q", e.Query)
					}
					return e.JSON(http.StatusOK, map[string]any{"data": map[string]any{"custom": true}})
				})
			},
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`{"data":{"custom":true}}`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:   "OnRecordEnrich hooks are applied (incl. the relations)",
			Method: http.MethodPost,
			URL:    "/api/graphql",
			Body:   gqlBody(`{ demo2(title: "test1") { title active } users(sort: "username") { nodes { username rel { title active } } } }`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				users, _ := app.FindCollectionByNameOrId("users")
				users.ListRule = types.Pointer("")
				if err := app.Save(users); err != nil {
					t.Fatal(err)
				}

				app.OnRecordEnrich("demo2").BindFunc(func(e *core.RecordEnrichEvent) error {
					e.Record.Set("title", "enriched "+e.Record.GetString("title"))
					e.Record.Hide("active")
					return e.Next()
				})
			},
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"demo2":{"active":null,"title":"enriched test1"}`,
				`{"rel":{"active":null,"title":"enriched test1"},"username":"users75657"}`,
			},
			NotExpectedContent: []string{`"errors"`},
			ExpectedEvents: map[string]int{
				"OnGraphQLRequest": 1,
				"OnRecordEnrich":   1 + 3 + 2,
			},
		},
		{
			Name:            "timeout",
			Method:          http.MethodPost,
			URL:             "/api/graphql",
			Body:            gqlBody(`{ demo2s { totalCount } }`),
			Timeout:         time.Nanosecond,
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"message":"The request timed out."`, `"data":{"demo2s":null}`},
			ExpectedEvents:  map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:   "protected file url only with a file token",
			Method: http.MethodPost,
			URL:    "/api/graphql",
			Body:   gqlBody(`{ gqlProducts(first: 1, filter: "published = true", sort: "title") { nodes { image { filename url } docs { a: url b: url(token: "abc") } } } }`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				gqlFixtures(t, app)
			},
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"url":"http://localhost:8090/api/files/`,
				`"a":null`,
				`?token=abc"`,
			},
			NotExpectedContent: []string{`"errors"`},
			ExpectedEvents:     map[string]int{"OnGraphQLRequest": 1},
		},
		{
			Name:            "schema info (without collections read permission)",
			Method:          http.MethodGet,
			URL:             "/api/graphql/collections",
			Headers:         map[string]string{"Authorization": tests.AuthToken("users", "test@example.com")},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "schema info (Owner)",
			Method:         http.MethodGet,
			URL:            "/api/graphql/collections",
			Headers:        map[string]string{"Authorization": tests.AuthToken(core.CollectionNameSuperusers, "test@example.com")},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"enabled":true`,
				`"collectionName":"demo2","included":true,"typeName":"Demo2","singularField":"demo2","pluralField":"demo2s","uniqueArgs":["title"]`,
				`"collectionName":"demo1","included":false,"reason":"The collection has no List or View API rule (staff only)."`,
				`{"name":"","field":"password","reason":"hidden or secret field"}`,
			},
			NotExpectedContent: []string{`"collectionName":"_superusers"`},
			ExpectedEvents:     map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestGraphQLRateLimit(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	app.Settings().RateLimits.Enabled = true
	app.Settings().RateLimits.Rules = []core.RateLimitRule{
		{Label: "/api/graphql", MaxRequests: 2, Duration: 100},
	}

	_, key, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"X-PB-Public-Key": key}

	mux := oauth2Mux(t, app)

	for i, expected := range []int{200, 200, 429} {
		status, _ := gqlDo(t, mux, headers, `{ demo2s { totalCount } }`, nil)
		if status != expected {
			t.Fatalf("[%d] Expected status %d, got %d", i, expected, status)
		}
	}
}

// -------------------------------------------------------------------
// Relations batching benchmark
// -------------------------------------------------------------------

// gqlBenchFixtures creates public posts (author single relation, tags multiple relation),
// authors (team single relation), teams and tags collections.
func gqlBenchFixtures(t testing.TB, app core.App, totalPosts int) {
	t.Helper()

	newCollection := func(name string, fields ...core.Field) *core.Collection {
		c := core.NewBaseCollection(name)
		c.ListRule = types.Pointer("")
		c.ViewRule = types.Pointer("")
		c.Fields.Add(fields...)
		c.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true})
		if err := app.Save(c); err != nil {
			t.Fatal(err)
		}
		return c
	}

	newRecords := func(c *core.Collection, total int, data func(i int) map[string]any) []string {
		ids := make([]string, total)
		for i := range total {
			r := core.NewRecord(c)
			r.Load(data(i))
			if err := app.Save(r); err != nil {
				t.Fatal(err)
			}
			ids[i] = r.Id
		}
		return ids
	}

	teams := newCollection("gql_bench_teams", &core.TextField{Name: "name"})
	tags := newCollection("gql_bench_tags", &core.TextField{Name: "name"})
	authors := newCollection("gql_bench_authors",
		&core.TextField{Name: "name"},
		&core.RelationField{Name: "team", CollectionId: teams.Id, MaxSelect: 1},
	)
	posts := newCollection("gql_bench_posts",
		&core.TextField{Name: "title"},
		&core.RelationField{Name: "author", CollectionId: authors.Id, MaxSelect: 1},
		&core.RelationField{Name: "tags", CollectionId: tags.Id, MaxSelect: 2},
	)

	teamIds := newRecords(teams, 3, func(i int) map[string]any { return map[string]any{"name": fmt.Sprint("team ", i)} })
	tagIds := newRecords(tags, 5, func(i int) map[string]any { return map[string]any{"name": fmt.Sprint("tag ", i)} })
	authorIds := newRecords(authors, 10, func(i int) map[string]any {
		return map[string]any{"name": fmt.Sprint("author ", i), "team": teamIds[i%3]}
	})
	newRecords(posts, totalPosts, func(i int) map[string]any {
		return map[string]any{
			"title":  fmt.Sprint("post ", i),
			"author": authorIds[i%10],
			"tags":   []string{tagIds[i%5], tagIds[(i+1)%5]},
		}
	})
}

type gqlQueryCounter struct {
	db      *dbx.DB
	oldFunc dbx.QueryLogFunc
	count   atomic.Int64
}

// gqlCountQueries counts the executed SELECT queries of the app concurrent db until stop() is called.
func gqlCountQueries(app core.App) *gqlQueryCounter {
	db := app.ConcurrentDB().(*dbx.DB)

	c := &gqlQueryCounter{db: db, oldFunc: db.QueryLogFunc}
	db.QueryLogFunc = func(ctx context.Context, d time.Duration, query string, rows *sql.Rows, err error) {
		c.count.Add(1)
	}

	return c
}

func (c *gqlQueryCounter) stop() {
	c.db.QueryLogFunc = c.oldFunc
}

func (c *gqlQueryCounter) total() int {
	return int(c.count.Load())
}

// BenchmarkGraphQLRelations compares a list of 50 records with one relation level
// via GraphQL and via the REST API expand.
func BenchmarkGraphQLRelations(b *testing.B) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	gqlBenchFixtures(b, app, 50)

	_, key, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		b.Fatal(err)
	}
	headers := map[string]string{"X-PB-Public-Key": key}

	mux := oauth2Mux(b, app)

	// silence the dev mode SQL logs
	db := app.ConcurrentDB().(*dbx.DB)
	db.QueryLogFunc = nil

	b.Run("graphql", func(b *testing.B) {
		counter := gqlCountQueries(app)
		defer counter.stop()

		for b.Loop() {
			status, result := gqlDo(b, mux, headers, `{ gqlBenchPosts(first: 50) { nodes { id title author { id name } } } }`, nil)
			if status != 200 || gqlErrors(result) != nil {
				b.Fatalf("Unexpected response %d %v", status, result)
			}
		}

		b.ReportMetric(float64(counter.total())/float64(b.N), "queries/op")
	})

	b.Run("rest", func(b *testing.B) {
		counter := gqlCountQueries(app)
		defer counter.stop()

		for b.Loop() {
			status, result := restDo(b, mux, headers, "/api/collections/gql_bench_posts/records?perPage=50&skipTotal=1&sort=created,id&expand=author")
			if status != 200 || len(result["items"].([]any)) != 50 {
				b.Fatalf("Unexpected response %d %v", status, result)
			}
		}

		b.ReportMetric(float64(counter.total())/float64(b.N), "queries/op")
	})
}

func TestGraphQLSingularAccessCheckedBeforeTheId(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")

	// list only key ceiling
	_, key, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, core.Permissions{
		Collections: map[string][]string{demo2.Id: {core.PermissionActionList}},
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := oauth2Mux(t, app)

	for _, id := range []string{"invalid", gqlGlobalId("demo2", "missing"), gqlGlobalId("demo2", "llvuca81nly1qls")} {
		status, result := gqlDo(t, mux, map[string]string{"X-PB-Public-Key": key}, `query ($id: ID) { demo2(id: $id) { id } }`, map[string]any{"id": id})

		errs := gqlErrors(result)
		if status != 200 || len(errs) != 1 || gqlErrorStatus(errs[0]) != 403 {
			t.Fatalf("[%s] Expected a 403 GraphQL error, got %d %v", id, status, result)
		}
	}
}
