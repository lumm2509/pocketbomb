package apis_test

import (
	"encoding/json"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/types"
)

func gqlCreateCollection(t testing.TB, app core.App, name string, fields ...core.Field) *core.Collection {
	t.Helper()

	c := core.NewBaseCollection(name)
	c.ListRule = types.Pointer("")
	c.ViewRule = types.Pointer("")
	c.Fields.Add(fields...)
	if err := app.Save(c); err != nil {
		t.Fatal(err)
	}

	return c
}

// gqlSchemaReport returns the GraphQL collections report by collection name.
func gqlSchemaReport(t testing.TB, mux *oauth2TestMux, ownerToken string) map[string]map[string]any {
	t.Helper()

	status, result := restDo(t, mux, map[string]string{"Authorization": ownerToken}, "/api/graphql/collections")
	if status != 200 {
		t.Fatalf("Expected 200, got %d %v", status, result)
	}

	report := map[string]map[string]any{}
	for _, raw := range result["collections"].([]any) {
		info := raw.(map[string]any)
		report[info["collectionName"].(string)] = info
	}

	return report
}

// gqlQueryFields returns the root query field names.
func gqlQueryFields(t testing.TB, mux *oauth2TestMux) map[string]bool {
	t.Helper()

	status, result := gqlDo(t, mux, tests.PublicAPIKeyHeaders(), `{ __schema { queryType { fields { name } } } }`, nil)
	if status != 200 || gqlErrors(result) != nil {
		t.Fatalf("Unexpected response %d %v", status, result)
	}

	fields := map[string]bool{}
	for _, raw := range result["data"].(map[string]any)["__schema"].(map[string]any)["queryType"].(map[string]any)["fields"].([]any) {
		fields[raw.(map[string]any)["name"].(string)] = true
	}

	return fields
}

func TestGraphQLSchemaNaming(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	gqlCreateCollection(t, app, "blog_posts", &core.TextField{Name: "first_name"}, &core.TextField{Name: "Title"})
	gqlCreateCollection(t, app, "news")
	gqlCreateCollection(t, app, "people")
	gqlCreateCollection(t, app, "categories")

	// collisions
	gqlCreateCollection(t, app, "item")
	gqlCreateCollection(t, app, "items")
	gqlCreateCollection(t, app, "page_infos")
	gqlCreateCollection(t, app, "nodes")
	gqlCreateCollection(t, app, "box")
	gqlCreateCollection(t, app, "box_connection")
	gqlCreateCollection(t, app, "fields_clash",
		&core.TextField{Name: "first_name"},
		&core.TextField{Name: "firstName"},
		&core.TextField{Name: "_id"},
		&core.TextField{Name: "ok_field"},
	)
	gqlCreateCollection(t, app, "_1abc")

	mux := oauth2Mux(t, app)
	report := gqlSchemaReport(t, mux, mustOwnerToken(t, app))
	queryFields := gqlQueryFields(t, mux)

	t.Run("names", func(t *testing.T) {
		scenarios := []struct {
			collection string
			typeName   string
			singular   string
			plural     string
		}{
			{"blog_posts", "BlogPost", "blogPost", "blogPosts"},
			{"news", "News", "news", "newsList"},
			{"people", "Person", "person", "people"},
			{"categories", "Category", "category", "categories"},
			{"demo2", "Demo2", "demo2", "demo2s"},
		}

		for _, s := range scenarios {
			info := report[s.collection]
			if info["included"] != true || info["typeName"] != s.typeName || info["singularField"] != s.singular || info["pluralField"] != s.plural {
				t.Fatalf("Unexpected %s names %v", s.collection, info)
			}
			if !queryFields[s.singular] || !queryFields[s.plural] {
				t.Fatalf("Missing %s query fields", s.collection)
			}
		}
	})

	t.Run("collection collisions are skipped", func(t *testing.T) {
		scenarios := map[string]string{
			"item":           "GraphQL name collision with collection items.",
			"items":          "GraphQL name collision with collection item.",
			"page_infos":     "GraphQL name collision with reserved name PageInfo.",
			"nodes":          "GraphQL name collision with reserved name Node, reserved name node.",
			"box":            "GraphQL name collision with collection box_connection.",
			"box_connection": "GraphQL name collision with collection box.",
			"_1abc":          "The collection name can't be converted to a valid GraphQL name.",
		}

		for name, reason := range scenarios {
			info := report[name]
			if info["included"] != false || info["reason"] != reason {
				t.Fatalf("Expected %s to be skipped with %q, got %v", name, reason, info)
			}
		}

		for _, field := range []string{"item", "items", "pageInfo", "pageInfos", "box", "boxes", "boxConnection"} {
			if queryFields[field] {
				t.Fatalf("Didn't expect query field %q", field)
			}
		}

		if !queryFields["node"] {
			t.Fatal("Expected the node query field")
		}
	})

	t.Run("field names and collisions", func(t *testing.T) {
		fields := map[string]map[string]any{}
		for _, raw := range report["fields_clash"]["fields"].([]any) {
			f := raw.(map[string]any)
			fields[f["field"].(string)] = f
		}

		raw, _ := json.Marshal(fields)

		if fields["ok_field"]["name"] != "okField" || fields["ok_field"]["type"] != "String" {
			t.Fatalf("Unexpected ok_field mapping %s", raw)
		}
		for _, name := range []string{"first_name", "firstName"} {
			if fields[name]["reason"] != "GraphQL name collision (firstName)" {
				t.Fatalf("Expected %s collision, got %s", name, raw)
			}
		}
		if fields["_id"]["reason"] != "GraphQL name collision (id)" {
			t.Fatalf("Expected _id collision, got %s", raw)
		}

		status, result := gqlDo(t, mux, tests.PublicAPIKeyHeaders(), `{ __type(name: "BlogPost") { fields { name } } }`, nil)
		if status != 200 || gqlErrors(result) != nil {
			t.Fatalf("Unexpected response %v", result)
		}
		typeRaw, _ := json.Marshal(result)
		if string(typeRaw) != `{"data":{"__type":{"fields":[{"name":"firstName"},{"name":"id"},{"name":"title"}]}}}` {
			t.Fatalf("Unexpected BlogPost fields %s", typeRaw)
		}
	})
}

func TestGraphQLSchemaRebuild(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	mux := oauth2Mux(t, app)

	if gqlQueryFields(t, mux)["widgets"] {
		t.Fatal("Didn't expect widgets before create")
	}

	// create
	staffOnly := core.NewBaseCollection("staff_only")
	staffOnly.Fields.Add(&core.TextField{Name: "title"})
	if err := app.Save(staffOnly); err != nil {
		t.Fatal(err)
	}

	widgets := gqlCreateCollection(t, app, "widgets",
		&core.TextField{Name: "title"},
		&core.RelationField{Name: "owner", CollectionId: staffOnly.Id, MaxSelect: 1},
	)

	owner := core.NewRecord(staffOnly)
	owner.Set("title", "owner")
	if err := app.Save(owner); err != nil {
		t.Fatal(err)
	}
	w := core.NewRecord(widgets)
	w.Set("title", "w1")
	w.Set("owner", owner.Id)
	if err := app.Save(w); err != nil {
		t.Fatal(err)
	}

	if !gqlQueryFields(t, mux)["widgets"] {
		t.Fatal("Expected widgets after create")
	}

	// relation to a collection that is not in the schema (staff only) -> raw id
	status, result := gqlDo(t, mux, tests.PublicAPIKeyHeaders(), `{ widgets { nodes { title owner } } }`, nil)
	raw, _ := json.Marshal(result)
	if status != 200 || string(raw) != `{"data":{"widgets":{"nodes":[{"owner":"`+owner.Id+`","title":"w1"}]}}}` {
		t.Fatalf("Unexpected response %d %s", status, raw)
	}

	// update (new field + unique index)
	widgets.Fields.Add(&core.TextField{Name: "handle"})
	widgets.AddIndex("idx_widgets_handle", true, "handle", "")
	if err := app.Save(widgets); err != nil {
		t.Fatal(err)
	}
	status, result = gqlDo(t, mux, tests.PublicAPIKeyHeaders(), `{ widget(handle: "x") { handle } }`, nil)
	raw, _ = json.Marshal(result)
	if status != 200 || string(raw) != `{"data":{"widget":null}}` {
		t.Fatalf("Unexpected response after update %d %s", status, raw)
	}

	// once the staff only collection is exposed the relation field changes to its type
	staffOnly.ViewRule = types.Pointer("")
	if err := app.Save(staffOnly); err != nil {
		t.Fatal(err)
	}
	status, result = gqlDo(t, mux, tests.PublicAPIKeyHeaders(), `{ widgets { nodes { owner { title } } } }`, nil)
	raw, _ = json.Marshal(result)
	if status != 200 || string(raw) != `{"data":{"widgets":{"nodes":[{"owner":{"title":"owner"}}]}}}` {
		t.Fatalf("Unexpected response after the related collection update %d %s", status, raw)
	}

	// update (staff only)
	widgets.ListRule = nil
	widgets.ViewRule = nil
	if err := app.Save(widgets); err != nil {
		t.Fatal(err)
	}
	if gqlQueryFields(t, mux)["widgets"] {
		t.Fatal("Didn't expect widgets after the rules update")
	}

	// delete
	if err := app.Delete(staffOnly); err == nil {
		t.Fatal("Expected the referenced collection delete to fail")
	}
	if err := app.Delete(widgets); err != nil {
		t.Fatal(err)
	}
	if err := app.Delete(staffOnly); err != nil {
		t.Fatal(err)
	}
	if fields := gqlQueryFields(t, mux); fields["widgets"] || fields["staffOnly"] {
		t.Fatal("Didn't expect the deleted collections")
	}
}
