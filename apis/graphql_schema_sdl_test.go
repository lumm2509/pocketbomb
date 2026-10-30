package apis_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/plugins/migratecmd"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/hook"
)

var hookFailAfterNext = hook.Handler[*core.GraphQLSchemaApplyRequestEvent]{
	Id: "testFailAfterNext",
	Func: func(e *core.GraphQLSchemaApplyRequestEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		return e.BadRequestError("the writer failed", nil)
	},
}

type sdlPlan struct {
	Changes []struct {
		Collection string `json:"collection"`
		Action     string `json:"action"`
		Fields     []struct {
			Name        string `json:"name"`
			Action      string `json:"action"`
			Type        string `json:"type"`
			Destructive bool   `json:"destructive"`
		} `json:"fields"`
		Details     []string `json:"details"`
		Destructive bool     `json:"destructive"`
	} `json:"changes"`
	Warnings []string `json:"warnings"`
	Errors   []struct {
		Line    int    `json:"line"`
		Column  int    `json:"column"`
		Message string `json:"message"`
	} `json:"errors"`
	PlanHash string `json:"planHash"`
	CanApply bool   `json:"canApply"`
}

func sdlApp(t testing.TB, automigrate bool) (*tests.TestApp, string) {
	t.Helper()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Cleanup)

	dir := t.TempDir()
	if automigrate {
		migratecmd.MustRegister(app, nil, migratecmd.Config{Automigrate: true, Dir: dir, TemplateLang: migratecmd.TemplateLangJS})
	}

	return app, dir
}

func sdlPost(t testing.TB, app core.App, path string, token string, payload map[string]any) (int, string) {
	t.Helper()

	raw, _ := json.Marshal(payload)

	return appApi(t, app, http.MethodPost, path, token, string(raw))
}

func sdlMustPlan(t testing.TB, app core.App, token string, schema string) *sdlPlan {
	t.Helper()

	status, body := sdlPost(t, app, "/api/graphql/schema/plan", token, map[string]any{"schema": schema})
	if status != http.StatusOK {
		t.Fatalf("Unexpected plan response %d %s", status, body)
	}

	plan := &sdlPlan{}
	if err := json.Unmarshal([]byte(body), plan); err != nil {
		t.Fatal(err)
	}

	return plan
}

func sdlDerived(t testing.TB, app core.App, token string) string {
	t.Helper()

	status, body := appApi(t, app, http.MethodGet, "/api/graphql/schema", token, "")
	if status != http.StatusOK {
		t.Fatalf("Unexpected response %d %s", status, body)
	}

	data := struct {
		Schema string `json:"schema"`
		Source string `json:"source"`
	}{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		t.Fatal(err)
	}

	return data.Schema
}

// apply plans and applies the schema expecting a success.
func sdlMustApply(t testing.TB, app core.App, token string, schema string, allowDestructive bool) *sdlPlan {
	t.Helper()

	plan := sdlMustPlan(t, app, token, schema)
	if len(plan.Errors) > 0 {
		t.Fatalf("Unexpected plan errors %v\n%s", plan.Errors, schema)
	}

	status, body := sdlPost(t, app, "/api/graphql/schema/apply", token, map[string]any{
		"schema":           schema,
		"planHash":         plan.PlanHash,
		"allowDestructive": allowDestructive,
	})
	if status != http.StatusOK {
		t.Fatalf("Unexpected apply response %d %s\n%s", status, body, schema)
	}

	return plan
}

// sdlStateHash returns the plan hash of the provided schema without the plan validation.
func sdlStateHash(t testing.TB, app core.App, schema string) string {
	t.Helper()

	collections, err := app.FindAllCollections()
	if err != nil {
		t.Fatal(err)
	}

	h := sha256.New()
	h.Write([]byte(schema))
	h.Write([]byte{0})
	for _, c := range collections {
		if !c.System {
			raw, _ := json.Marshal(c)
			h.Write(raw)
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

func TestGraphQLSchemaRoundTrip(t *testing.T) {
	t.Parallel()

	app, _ := sdlApp(t, false)
	token := mustOwnerToken(t, app)

	schema := sdlDerived(t, app, token)

	plan := sdlMustPlan(t, app, token, schema)
	if len(plan.Errors) > 0 {
		t.Fatalf("Unexpected errors %v\n%s", plan.Errors, schema)
	}
	if len(plan.Changes) > 0 {
		raw, _ := json.MarshalIndent(plan.Changes, "", " ")
		t.Fatalf("Expected an empty plan, got %s\n%s", raw, schema)
	}

	// every managed fixture collection is described and no system or view collection is
	collections, err := app.FindAllCollections()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range collections {
		described := strings.Contains(schema, `"`+c.Name+`"`) || regexp.MustCompile(`(?i)type `+strings.TrimRight(strings.ReplaceAll(c.Name, "_", ""), "s")).MatchString(schema)
		if !c.System && !c.IsView() && !described {
			t.Fatalf("Missing collection %q in\n%s", c.Name, schema)
		}
		if c.System && strings.Contains(schema, "type "+strings.TrimPrefix(c.Name, "_")) {
			t.Fatalf("Unexpected system collection %q in\n%s", c.Name, schema)
		}
	}
}

func TestGraphQLSchemaParserMatrix(t *testing.T) {
	t.Parallel()

	app, _ := sdlApp(t, true)
	token := mustOwnerToken(t, app)

	base := sdlDerived(t, app, token)

	scenarios := []struct {
		name          string
		schema        string
		expectedError string
		line          int
	}{
		{"syntax", "type {", "Syntax Error", 1},
		{"unsupported definition", "input A { a: String }", "Only type, enum", 1},
		{"unknown directive", "type Sdl1 {\n  a: String @nope\n}", "Unknown directive", 2},
		{"unknown field arg", "type Sdl1 {\n  a: Boolean @field(min: 1)\n}", "not supported", 2},
		{"unknown type", "type Sdl1 {\n  a: Nope\n}", "Unknown type", 2},
		{"bad list", "type Sdl1 {\n  a: [String!]\n}", "can't be a list", 2},
		{"unknown collection arg", "type Sdl1 @collection(nope: 1) {\n  a: String\n}", "Unknown @collection argument", 1},
		{"unknown rules arg", "type Sdl1 @rules(nope: \"\") {\n  a: String\n}", "Unknown @rules argument", 1},
		{"invalid collection type", "type Sdl1 @collection(type: view) {\n  a: String\n}", "Invalid collection type", 1},
		{"system collection", "type Sdl1 @collection(name: \"_superusers\") {\n  a: String\n}", "system collection", 1},
		{"underscore collection", "type Sdl1 @collection(name: \"_other\") {\n  a: String\n}", "system collection", 1},
		{"view collection", "type Sdl1 @collection(name: \"view1\") {\n  a: String\n}", "view collection", 1},
		{"type change", "type Sdl1 @collection(name: \"demo1\", type: auth) {\n  a: String\n}", "can't be changed", 1},
		{"same collection", "type A1 @collection(name: \"x1\") {\n  a: String\n}\ntype A2 @collection(name: \"x1\") {\n  a: String\n}", "same collection", 4},
		{"duplicated field", "type Sdl1 {\n  a: String\n  b: Int @field(name: \"a\")\n}", "Duplicated field", 3},
		{"system field", "type Sdl1 @collection(name: \"users\", type: auth) {\n  email: Email\n}", "system field", 2},
		{"relation without target", "type Sdl1 {\n  a: ID @relation\n}", "Unknown collection", 2},
		{"default on number", "type Sdl1 {\n  a: Float @default(value: 1)\n}", "@default is supported only", 2},
		{"auth rule on base", "type Sdl1 @rules(auth: \"\") {\n  a: String\n}", "only for the auth", 1},
		{"index without fields", "type Sdl1 @index(name: \"idx\") {\n  a: String\n}", "@index requires", 1},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			plan := sdlMustPlan(t, app, token, s.schema)
			if len(plan.Errors) == 0 {
				t.Fatalf("Expected an error, got %+v", plan)
			}
			if plan.PlanHash != "" {
				t.Fatalf("Expected no plan hash, got %q", plan.PlanHash)
			}
			if !strings.Contains(plan.Errors[0].Message, s.expectedError) || plan.Errors[0].Line != s.line {
				t.Fatalf("Unexpected error %+v", plan.Errors)
			}
		})
	}

	t.Run("every scalar and directive", func(t *testing.T) {
		schema := base + `
enum SdlAllStatus {
  draft
  published
}

type SdlAll @collection(name: "sdl_all") @rules(list: "", view: "@request.auth.id != ''") @index(name: "idx_sdl_all_multi", fields: ["str DESC", "num"], where: "str != ''") {
  id: ID!
  str: String! @field(min: 1, max: 10, pattern: "^[a-z]+$", help: "h", presentable: true) @unique
  fallback: String @default(value: "a.b")
  num: Float @field(min: 0.5, max: 10)
  intNum: Int
  flag: Boolean
  created: DateTime @field(onCreate: true)
  updated: DateTime @field(onCreate: true, onUpdate: true)
  at: DateTime! @field(min: "2020-01-01 00:00:00.000Z")
  data: JSON @field(maxSize: 100)
  mail: Email @field(onlyDomains: ["example.com"])
  link: URL @field(exceptDomains: ["example.org"])
  content: Editor @field(maxSize: 200, convertURLs: true)
  doc: File @field(maxSize: 10, mimeTypes: ["image/png"], thumbs: ["10x10"], protected: true)
  docs: [File!] @field(max: 3)
  point: GeoPoint @hidden
  status: SdlAllStatus!
  statuses: [SdlAllStatus!]! @field(max: 1)
  label: String @field(type: "select", values: ["a b", "c"])
  owner: ID @relation(onCollection: "_superusers", cascadeDelete: true)
  self: SdlAll
  many: [SdlAll!] @relation(cascadeDelete: true) @field(min: 1, max: 5)
  camelName: String @field(name: "customName")
}
`
		plan := sdlMustApply(t, app, token, schema, false)
		if len(plan.Changes) != 1 || plan.Changes[0].Collection != "sdl_all" || plan.Changes[0].Action != "create" {
			t.Fatalf("Unexpected changes %+v", plan.Changes)
		}
	})
}

func TestGraphQLSchemaApplyMatrix(t *testing.T) {
	t.Parallel()

	app, _ := sdlApp(t, true)
	token := mustOwnerToken(t, app)

	created := "\ntype SdlPost @collection(name: \"sdl_posts\") @rules(list: \"\") {\n  title: String! @unique\n  author: SdlAuthor\n  body: String\n}\n\n" +
		"type SdlAuthor @collection(name: \"sdl_authors\") {\n  name: String\n  posts: [SdlPost!]\n}\n"

	base := sdlDerived(t, app, token)

	t.Run("create circular collections", func(t *testing.T) {
		plan := sdlMustApply(t, app, token, base+created, false)
		if len(plan.Changes) != 2 || !slices.ContainsFunc(plan.Warnings, func(w string) bool {
			return strings.Contains(w, "sdl_authors") && strings.Contains(w, "not in the GraphQL API")
		}) {
			t.Fatalf("Unexpected plan %+v", plan)
		}

		posts, err := app.FindCollectionByNameOrId("sdl_posts")
		if err != nil {
			t.Fatal(err)
		}
		if posts.GetIndex("idx_sdl_posts_title") == "" || posts.ViewRule != nil || *posts.ListRule != "" {
			t.Fatalf("Unexpected collection %+v", posts)
		}

		if app.Settings().GraphQL.Schema != base+created {
			t.Fatalf("The schema wasn't stored: %q", app.Settings().GraphQL.Schema)
		}

		// the stored schema is returned and it is empty plan
		status, body := appApi(t, app, http.MethodGet, "/api/graphql/schema", token, "")
		if status != http.StatusOK || !strings.Contains(body, `"source":"stored"`) || !strings.Contains(body, `"canApply":true`) {
			t.Fatalf("Unexpected response %d %s", status, body)
		}
		if plan := sdlMustPlan(t, app, token, base+created); len(plan.Changes) != 0 || len(plan.Errors) != 0 {
			t.Fatalf("Expected an empty plan, got %+v", plan)
		}
	})

	t.Run("stale plan", func(t *testing.T) {
		schema := base + strings.Replace(created, "body: String", "body: String\n  extra: Int", 1)
		plan := sdlMustPlan(t, app, token, schema)

		// a collection change after the plan
		if err := app.Save(core.NewBaseCollection("sdl_concurrent")); err != nil {
			t.Fatal(err)
		}
		defer func() {
			c, _ := app.FindCollectionByNameOrId("sdl_concurrent")
			_ = app.Delete(c)
		}()

		status, body := sdlPost(t, app, "/api/graphql/schema/apply", token, map[string]any{"schema": schema, "planHash": plan.PlanHash})
		if status != http.StatusConflict {
			t.Fatalf("Expected 409, got %d %s", status, body)
		}

		status, _ = sdlPost(t, app, "/api/graphql/schema/apply", token, map[string]any{"schema": schema, "planHash": "x"})
		if status != http.StatusConflict {
			t.Fatalf("Expected 409, got %d", status)
		}

		if c, _ := app.FindCollectionByNameOrId("sdl_posts"); c.Fields.GetByName("extra") != nil {
			t.Fatal("Expected no change")
		}
	})

	t.Run("destructive guard", func(t *testing.T) {
		// body removed and author type changed + the authors collection removed
		schema := base + "\ntype SdlPost @collection(name: \"sdl_posts\") @rules(list: \"\") {\n  title: String! @unique\n  author: String\n}\n"

		plan := sdlMustPlan(t, app, token, schema)
		if len(plan.Errors) > 0 || len(plan.Changes) != 2 {
			t.Fatalf("Unexpected plan %+v", plan)
		}
		for _, c := range plan.Changes {
			if !c.Destructive {
				t.Fatalf("Expected a destructive change, got %+v", c)
			}
		}

		status, body := sdlPost(t, app, "/api/graphql/schema/apply", token, map[string]any{"schema": schema, "planHash": plan.PlanHash})
		if status != http.StatusBadRequest {
			t.Fatalf("Expected 400, got %d %s", status, body)
		}
		if c, err := app.FindCollectionByNameOrId("sdl_authors"); err != nil || c == nil {
			t.Fatal("Expected the collection to be kept")
		}

		status, body = sdlPost(t, app, "/api/graphql/schema/apply", token, map[string]any{"schema": schema, "planHash": plan.PlanHash, "allowDestructive": true})
		if status != http.StatusOK {
			t.Fatalf("Expected 200, got %d %s", status, body)
		}

		if _, err := app.FindCollectionByNameOrId("sdl_authors"); err == nil {
			t.Fatal("Expected the collection to be removed")
		}

		posts, _ := app.FindCollectionByNameOrId("sdl_posts")
		if posts.Fields.GetByName("body") != nil || posts.Fields.GetByName("author").Type() != core.FieldTypeText {
			t.Fatalf("Unexpected fields %+v", posts.Fields)
		}
	})

	t.Run("rollback on invalid rule", func(t *testing.T) {
		stored := app.Settings().GraphQL.Schema
		schema := base + "\ntype SdlBroken @collection(name: \"sdl_broken\") @rules(list: \"missing_field = 1\") {\n  a: String\n}\n"

		plan := sdlMustPlan(t, app, token, schema)
		if len(plan.Errors) == 0 || plan.PlanHash != "" || plan.Errors[0].Line != 0 {
			t.Fatalf("Expected a plan validation error, got %+v", plan)
		}
		if _, err := app.FindCollectionByNameOrId("sdl_broken"); err == nil {
			t.Fatal("The plan must not change anything")
		}
		if _, err := app.FindCachedCollectionByNameOrId("sdl_broken"); err == nil {
			t.Fatal("The plan must not change the cached collections")
		}

		// the apply path of the same invalid rule (e.g. something else changed after a valid plan)
		status, body := sdlPost(t, app, "/api/graphql/schema/apply", token, map[string]any{"schema": schema, "planHash": sdlStateHash(t, app, schema)})
		if status != http.StatusBadRequest {
			t.Fatalf("Expected 400, got %d %s", status, body)
		}
		if _, err := app.FindCollectionByNameOrId("sdl_broken"); err == nil {
			t.Fatal("Expected the changes to be rolled back")
		}
		if _, err := app.FindCachedCollectionByNameOrId("sdl_broken"); err == nil {
			t.Fatal("Expected the cached collections to be reloaded")
		}
		if app.Settings().GraphQL.Schema != stored {
			t.Fatal("Expected the stored schema to be kept")
		}
	})

	t.Run("migration writer failure rolls back", func(t *testing.T) {
		app.OnGraphQLSchemaApplyRequest().Bind(&hookFailAfterNext)
		defer app.OnGraphQLSchemaApplyRequest().Unbind(hookFailAfterNext.Id)

		schema := base + "\ntype SdlFail @collection(name: \"sdl_fail\") {\n  a: String\n}\n"
		plan := sdlMustPlan(t, app, token, schema)

		status, body := sdlPost(t, app, "/api/graphql/schema/apply", token, map[string]any{"schema": schema, "planHash": plan.PlanHash})
		if status != http.StatusBadRequest {
			t.Fatalf("Expected 400, got %d %s", status, body)
		}
		if _, err := app.FindCollectionByNameOrId("sdl_fail"); err == nil {
			t.Fatal("Expected the changes to be rolled back")
		}
		if _, err := app.FindCachedCollectionByNameOrId("sdl_fail"); err == nil {
			t.Fatal("Expected the cached collections to be reloaded")
		}
	})
}

func TestGraphQLSchemaDrifted(t *testing.T) {
	t.Parallel()

	app, _ := sdlApp(t, true)
	token := mustOwnerToken(t, app)

	get := func(query string) (string, bool, string) {
		t.Helper()

		status, body := appApi(t, app, http.MethodGet, "/api/graphql/schema"+query, token, "")
		if status != http.StatusOK {
			t.Fatalf("Unexpected response %d %s", status, body)
		}

		data := struct {
			Schema  string `json:"schema"`
			Source  string `json:"source"`
			Drifted bool   `json:"drifted"`
		}{}
		if err := json.Unmarshal([]byte(body), &data); err != nil {
			t.Fatal(err)
		}

		return data.Source, data.Drifted, data.Schema
	}

	if source, drifted, _ := get(""); source != "derived" || drifted {
		t.Fatalf("Unexpected state without a stored schema: %s %v", source, drifted)
	}

	_, _, base := get("")
	stored := base + "\ntype SdlDrift @collection(name: \"sdl_drift\") {\n  a: String\n}\n"
	sdlMustApply(t, app, token, stored, false)

	if source, drifted, schema := get(""); source != "stored" || drifted || schema != stored {
		t.Fatalf("Unexpected state after the apply: %s %v", source, drifted)
	}

	// a change outside of the editor
	c, err := app.FindCollectionByNameOrId("sdl_drift")
	if err != nil {
		t.Fatal(err)
	}
	c.Fields.Add(&core.TextField{Name: "outside"})
	if err := app.Save(c); err != nil {
		t.Fatal(err)
	}

	source, drifted, schema := get("")
	if source != "stored" || !drifted || schema != stored {
		t.Fatalf("Expected a drifted stored schema, got %s %v", source, drifted)
	}

	// regenerate: the current collections (and nothing was applied)
	source, drifted, schema = get("?source=derived")
	if source != "derived" || drifted || !strings.Contains(schema, "outside") {
		t.Fatalf("Unexpected derived schema: %s %v\n%s", source, drifted, schema)
	}
	if app.Settings().GraphQL.Schema != stored {
		t.Fatal("Expected the stored schema to be kept")
	}
	if plan := sdlMustPlan(t, app, token, schema); len(plan.Changes) != 0 {
		t.Fatalf("Expected an empty plan, got %+v", plan.Changes)
	}
}

func TestGraphQLSchemaWithoutMigrationWriter(t *testing.T) {
	t.Parallel()

	app, _ := sdlApp(t, false)
	token := mustOwnerToken(t, app)

	schema := sdlDerived(t, app, token) + "\ntype SdlNo @collection(name: \"sdl_no\") {\n  a: String\n}\n"

	plan := sdlMustPlan(t, app, token, schema)
	if plan.CanApply || plan.PlanHash == "" {
		t.Fatalf("Unexpected plan %+v", plan)
	}

	status, body := appApi(t, app, http.MethodGet, "/api/graphql/schema", token, "")
	if status != http.StatusOK || !strings.Contains(body, `"canApply":false`) || !strings.Contains(body, `"source":"derived"`) {
		t.Fatalf("Unexpected response %d %s", status, body)
	}

	status, body = sdlPost(t, app, "/api/graphql/schema/apply", token, map[string]any{"schema": schema, "planHash": plan.PlanHash})
	if status != http.StatusConflict || !strings.Contains(body, "migrations") {
		t.Fatalf("Expected 409, got %d %s", status, body)
	}
	if _, err := app.FindCollectionByNameOrId("sdl_no"); err == nil {
		t.Fatal("Expected nothing to be changed")
	}
	if app.Settings().GraphQL.Schema != "" {
		t.Fatal("Expected no stored schema")
	}
}

func TestGraphQLSchemaRBAC(t *testing.T) {
	t.Parallel()

	app, _ := sdlApp(t, true)

	// a staff with everything assignable (the collections write is Owner only)
	extCreateStaff(t, app, "sdl-staff@example.com", core.Permissions{System: map[string]string{
		core.PermissionResourceCollections: core.PermissionLevelRead,
		core.PermissionResourceSettings:    core.PermissionLevelRead,
	}})
	_, staffToken := extStaffSession(t, app, "sdl-staff@example.com")

	customer, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	_, customerToken := ownSessionToken(t, app, customer)

	for _, s := range []struct {
		name   string
		token  string
		status int
	}{
		{"guest", "", http.StatusUnauthorized},
		{"customer", customerToken, http.StatusForbidden},
		{"limited staff", staffToken, http.StatusForbidden},
	} {
		t.Run(s.name, func(t *testing.T) {
			if status, _ := appApi(t, app, http.MethodGet, "/api/graphql/schema", s.token, ""); status != s.status {
				t.Fatalf("GET: expected %d, got %d", s.status, status)
			}
			if status, _ := sdlPost(t, app, "/api/graphql/schema/plan", s.token, map[string]any{"schema": ""}); status != s.status {
				t.Fatalf("plan: expected %d, got %d", s.status, status)
			}
			if status, _ := sdlPost(t, app, "/api/graphql/schema/apply", s.token, map[string]any{"schema": ""}); status != s.status {
				t.Fatalf("apply: expected %d, got %d", s.status, status)
			}
		})
	}

	// the settings readers see the stored schema
	token := mustOwnerToken(t, app)
	schema := sdlDerived(t, app, token)
	sdlMustApply(t, app, token, schema, false)
	if status, body := appApi(t, app, http.MethodGet, "/api/settings", staffToken, ""); status != http.StatusOK || !strings.Contains(body, `"schema":`) {
		t.Fatalf("Unexpected settings response %d %s", status, body)
	}
}
