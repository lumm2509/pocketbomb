package apis_test

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/types"
)

// gqlPaginationFixtures creates:
//   - gql_items (base): title (duplicated), rank (duplicated), created
//   - gql_items_view (view): score and label with NULL values
func gqlPaginationFixtures(t testing.TB, app core.App) {
	t.Helper()

	items := core.NewBaseCollection("gql_items")
	items.ListRule = types.Pointer("")
	items.ViewRule = types.Pointer("")
	items.Fields.Add(
		&core.TextField{Name: "title"},
		&core.NumberField{Name: "rank"},
		&core.JSONField{Name: "data"},
		&core.AutodateField{Name: "created", OnCreate: true},
	)
	if err := app.Save(items); err != nil {
		t.Fatal(err)
	}

	for i := range 23 {
		r := core.NewRecord(items)
		r.Set("title", fmt.Sprintf("title %d", i%5))
		r.Set("rank", i%4)
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
	}

	view := core.NewViewCollection("gql_items_view")
	view.ListRule = types.Pointer("")
	view.ViewRule = types.Pointer("")
	view.ViewQuery = `SELECT id, title, created,
		CAST(CASE WHEN rank > 1 THEN rank ELSE NULL END AS NUMERIC) as score,
		CAST(CASE WHEN rank % 2 = 0 THEN title ELSE NULL END AS TEXT) as label
		FROM gql_items`
	if err := app.Save(view); err != nil {
		t.Fatal(err)
	}
}

func gqlExpectedOrder(t testing.TB, app core.App, table string, orderBy string) []string {
	t.Helper()

	ids := []string{}
	if err := app.DB().NewQuery("SELECT id FROM " + table + " ORDER BY " + orderBy).Column(&ids); err != nil {
		t.Fatal(err)
	}

	return ids
}

type gqlPage struct {
	ids             []string
	cursors         []string
	hasNextPage     bool
	hasPreviousPage bool
	startCursor     string
	endCursor       string
	errors          []map[string]any
}

func gqlFetchPage(t testing.TB, mux *oauth2TestMux, field string, args string) gqlPage {
	t.Helper()

	status, result := gqlDo(t, mux, tests.PublicAPIKeyHeaders(), "{ c: "+field+"("+args+") { edges { cursor node { id } } pageInfo { hasNextPage hasPreviousPage startCursor endCursor } } }", nil)
	if status != 200 {
		t.Fatalf("Expected 200, got %d %v", status, result)
	}

	page := gqlPage{errors: gqlErrors(result)}
	if page.errors != nil {
		return page
	}

	conn := result["data"].(map[string]any)["c"].(map[string]any)
	for _, raw := range conn["edges"].([]any) {
		edge := raw.(map[string]any)
		page.ids = append(page.ids, gqlRawId(t, edge["node"].(map[string]any)["id"]))
		page.cursors = append(page.cursors, edge["cursor"].(string))
	}

	info := conn["pageInfo"].(map[string]any)
	page.hasNextPage = info["hasNextPage"].(bool)
	page.hasPreviousPage = info["hasPreviousPage"].(bool)
	page.startCursor, _ = info["startCursor"].(string)
	page.endCursor, _ = info["endCursor"].(string)

	return page
}

func TestGraphQLPagination(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	gqlPaginationFixtures(t, app)

	mux := oauth2Mux(t, app)

	scenarios := []struct {
		name     string
		field    string
		table    string
		sort     string
		reverse  bool
		expected string // SQL ORDER BY
	}{
		{"default sort", "gqlItems", "gql_items", "", false, "created, id"},
		{"multi-field sort with duplicates", "gqlItems", "gql_items", "rank,-title", false, "rank, title DESC, id"},
		{"reversed multi-field sort", "gqlItems", "gql_items", "rank,-title", true, "rank DESC, title, id DESC"},
		{"explicit id sort", "gqlItems", "gql_items", "-id", false, "id DESC"},
		{"view with NULLs (desc)", "gqlItemsViews", "gql_items_view", "-score,label", false, "score DESC, label, id"},
		{"view with NULLs (asc)", "gqlItemsViews", "gql_items_view", "label,score", false, "label, score, id"},
		{"view with NULLs (reversed)", "gqlItemsViews", "gql_items_view", "label,-score", true, "label DESC, score, id DESC"},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			expected := gqlExpectedOrder(t, app, s.table, s.expected)

			baseArgs := fmt.Sprintf("sort: %q, reverse: %v", s.sort, s.reverse)

			// forward
			forward := []string{}
			after := ""
			for i := 0; ; i++ {
				args := baseArgs + ", first: 4"
				if after != "" {
					args += fmt.Sprintf(", after: %q", after)
				}

				page := gqlFetchPage(t, mux, s.field, args)
				if page.errors != nil {
					t.Fatalf("Unexpected errors %v", page.errors)
				}
				if page.hasPreviousPage != (i > 0) {
					t.Fatalf("[forward %d] Expected hasPreviousPage %v", i, i > 0)
				}
				if len(page.ids) > 0 && (page.startCursor != page.cursors[0] || page.endCursor != page.cursors[len(page.cursors)-1]) {
					t.Fatalf("[forward %d] Start/end cursors mismatch", i)
				}

				forward = append(forward, page.ids...)
				if !page.hasNextPage {
					break
				}
				after = page.endCursor
			}

			if !slices.Equal(forward, expected) {
				t.Fatalf("Forward order mismatch\nexpected %v\ngot      %v", expected, forward)
			}

			// backward
			backward := []string{}
			before := ""
			for i := 0; ; i++ {
				args := baseArgs + ", last: 5"
				if before != "" {
					args += fmt.Sprintf(", before: %q", before)
				}

				page := gqlFetchPage(t, mux, s.field, args)
				if page.errors != nil {
					t.Fatalf("Unexpected errors %v", page.errors)
				}
				if page.hasNextPage != (i > 0) {
					t.Fatalf("[backward %d] Expected hasNextPage %v", i, i > 0)
				}

				backward = append(page.ids, backward...)
				if !page.hasPreviousPage {
					break
				}
				before = page.startCursor
			}

			if !slices.Equal(backward, expected) {
				t.Fatalf("Backward order mismatch\nexpected %v\ngot      %v", expected, backward)
			}
		})
	}
}

func TestGraphQLPaginationErrors(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	gqlPaginationFixtures(t, app)

	mux := oauth2Mux(t, app)

	rankPage := gqlFetchPage(t, mux, "gqlItems", `sort: "rank", first: 2`)
	titlePage := gqlFetchPage(t, mux, "gqlItems", `sort: "title", first: 2`)
	viewPage := gqlFetchPage(t, mux, "gqlItemsViews", `sort: "title", first: 2`)

	tampered := []byte(rankPage.endCursor)
	tampered[3] ^= 1

	forged, _ := base64.RawURLEncoding.DecodeString(rankPage.endCursor)
	forgedCursor := base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(forged), `"v":[`, `"v":[{"x":1},`, 1)))

	scenarios := []struct {
		name     string
		args     string
		expected string
	}{
		{"first + last", `first: 1, last: 1`, "Passing both first and last is not supported."},
		{"first + before", fmt.Sprintf(`first: 1, before: %q`, rankPage.endCursor), "Use either first/after"},
		{"last + after", fmt.Sprintf(`last: 1, after: %q`, rankPage.endCursor), "Use either first/after"},
		{"negative first", `first: -1`, "must be between 0 and 250"},
		{"first over max page size", `first: 251`, "must be between 0 and 250"},
		{"tampered cursor", fmt.Sprintf(`sort: "rank", after: %q`, string(tampered)), "Invalid cursor"},
		{"forged cursor values", fmt.Sprintf(`sort: "rank", after: %q`, forgedCursor), "Invalid cursor"},
		{"cursor of another sort", fmt.Sprintf(`sort: "rank", after: %q`, titlePage.endCursor), "Invalid cursor"},
		{"cursor of another sort direction", fmt.Sprintf(`sort: "rank", reverse: true, after: %q`, rankPage.endCursor), "Invalid cursor"},
		{"cursor of another collection", fmt.Sprintf(`sort: "title", after: %q`, viewPage.endCursor), "Invalid cursor"},
		{"not base64 cursor", `after: "!!!"`, "Invalid cursor"},
		{"random sort", `sort: "@random"`, `Invalid sort field "@random"`},
		{"rowid sort", `sort: "@rowid"`, `Invalid sort field "@rowid"`},
		{"json field sort", `sort: "data"`, `Invalid sort field "data"`},
		{"unknown field sort", `sort: "missing"`, `Invalid sort field "missing"`},
		{"invalid filter (REST like error)", `filter: "missing = 1"`, "Something went wrong while processing your request."},
		{"superuser only filter fields", `filter: "@collection.gql_items.title = 'x'"`, "Only superusers can filter by @collection."},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			page := gqlFetchPage(t, mux, "gqlItems", s.args)
			if len(page.errors) != 1 {
				t.Fatalf("Expected 1 error, got %v", page.errors)
			}

			msg, _ := page.errors[0]["message"].(string)
			if !strings.Contains(msg, s.expected) {
				t.Fatalf("Expected error %q, got %q", s.expected, msg)
			}
			if strings.Contains(strings.ToLower(msg), "sql") || strings.Contains(msg, "SELECT") {
				t.Fatalf("The error must not leak SQL details: %q", msg)
			}
		})
	}

	t.Run("cursor of the same sort is accepted", func(t *testing.T) {
		page := gqlFetchPage(t, mux, "gqlItems", fmt.Sprintf(`sort: "rank", first: 2, after: %q`, rankPage.endCursor))
		if page.errors != nil || len(page.ids) != 2 {
			t.Fatalf("Expected 2 records without errors, got %v", page)
		}
	})

	t.Run("first: 0", func(t *testing.T) {
		page := gqlFetchPage(t, mux, "gqlItems", `first: 0`)
		if page.errors != nil || len(page.ids) != 0 || !page.hasNextPage {
			t.Fatalf("Expected empty page with next page, got %v", page)
		}
	})
}

func TestGraphQLRelationsBatching(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	gqlBenchFixtures(t, app, 60)

	_, key, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"X-PB-Public-Key": key}

	mux := oauth2Mux(t, app)

	query := func(first int) int {
		counter := gqlCountQueries(app)
		defer counter.stop()

		status, result := gqlDo(t, mux, headers, fmt.Sprintf(`{
			gqlBenchPosts(first: %d) { nodes { title author { name team { name } } tags { name } } }
		}`, first), nil)
		if status != 200 || gqlErrors(result) != nil {
			t.Fatalf("Unexpected response %d %v", status, result)
		}

		nodes := result["data"].(map[string]any)["gqlBenchPosts"].(map[string]any)["nodes"].([]any)
		if len(nodes) != first {
			t.Fatalf("Expected %d nodes, got %d", first, len(nodes))
		}
		for _, raw := range nodes {
			node := raw.(map[string]any)
			author, _ := node["author"].(map[string]any)
			if author == nil || author["team"] == nil || len(node["tags"].([]any)) != 2 {
				t.Fatalf("Missing relations in %v", node)
			}
		}

		return counter.total()
	}

	q5 := query(5)
	q50 := query(50)

	if q5 != q50 {
		t.Fatalf("Expected the same number of queries for 5 and 50 records (no N+1), got %d and %d", q5, q50)
	}
}

func TestGraphQLCursorOfNotVisibleSortValue(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, _ := app.FindCollectionByNameOrId("users")
	users.ListRule = types.Pointer("")
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	app.OnRecordEnrich("demo2").BindFunc(func(e *core.RecordEnrichEvent) error {
		e.Record.Hide("title")
		return e.Next()
	})

	_, key, err := tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
	if err != nil {
		t.Fatal(err)
	}
	guest := map[string]string{"X-PB-Public-Key": key}
	owner := map[string]string{"Authorization": mustOwnerToken(t, app)}

	mux := oauth2Mux(t, app)

	scenarios := []struct {
		name          string
		headers       map[string]string
		query         string
		expectedError string
	}{
		{"guest: email sort without cursors", guest, `{ users(sort: "email") { nodes { username } } }`, ""},
		{"guest: email sort with cursors", guest, `{ users(sort: "email") { edges { cursor } } }`, `Cursors are not available when sorting by the not visible field "email".`},
		{"guest: email sort with page info cursor", guest, `{ users(sort: "email") { pageInfo { endCursor } } }`, `Cursors are not available when sorting by the not visible field "email".`},
		{"owner: email sort with cursors (visible)", owner, `{ users(sort: "email") { edges { cursor } } }`, ""},
		{"enrich hidden field sort with cursors", guest, `{ demo2s(sort: "title") { edges { cursor } } }`, `Cursors are not available when sorting by the not visible field "title".`},
		{"enrich hidden field sort without cursors", guest, `{ demo2s(sort: "title") { nodes { id } } }`, ""},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			status, result := gqlDo(t, mux, s.headers, s.query, nil)
			errs := gqlErrors(result)

			if status != 200 {
				t.Fatalf("Expected 200, got %d", status)
			}

			if s.expectedError == "" {
				if errs != nil {
					t.Fatalf("Unexpected errors %v", errs)
				}
				return
			}

			if len(errs) == 0 || errs[0]["message"] != s.expectedError {
				t.Fatalf("Expected error %q, got %v", s.expectedError, result)
			}
			if strings.Contains(fmt.Sprint(result["data"]), "@example.com") {
				t.Fatalf("The response must not contain the hidden emails: %v", result["data"])
			}
		})
	}
}
