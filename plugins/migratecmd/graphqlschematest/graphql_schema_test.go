// Package graphqlschematest runs the generated GraphQL schema migrations in
// its own test binary (the JS migrations are registered in the global migrations list).
package graphqlschematest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	_ "github.com/lumm2509/pocketbomb/migrations"
	"github.com/lumm2509/pocketbomb/plugins/jsvm"
	"github.com/lumm2509/pocketbomb/plugins/migratecmd"
	"github.com/lumm2509/pocketbomb/tests"
)

func api(t *testing.T, app core.App, method string, path string, token string, payload any) (int, map[string]any) {
	t.Helper()

	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	data := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &data)

	return rec.Code, data
}

func apply(t *testing.T, app core.App, token string, schema string, allowDestructive bool) {
	t.Helper()

	status, plan := api(t, app, http.MethodPost, "/api/graphql/schema/plan", token, map[string]any{"schema": schema})
	if status != http.StatusOK {
		t.Fatalf("Unexpected plan status %d %v", status, plan)
	}
	if errs, _ := plan["errors"].([]any); len(errs) > 0 {
		t.Fatalf("Unexpected plan errors %v", errs)
	}

	status, result := api(t, app, http.MethodPost, "/api/graphql/schema/apply", token, map[string]any{
		"schema":           schema,
		"planHash":         plan["planHash"],
		"allowDestructive": allowDestructive,
	})
	if status != http.StatusOK {
		t.Fatalf("Unexpected apply status %d %v", status, result)
	}
}

func snapshot(t *testing.T, app core.App) string {
	t.Helper()

	all, err := app.FindAllCollections()
	if err != nil {
		t.Fatal(err)
	}

	return snapshotOf(all)
}

func snapshotOf(all []*core.Collection) string {
	result := map[string]any{}
	for _, c := range all {
		if c.System || !strings.HasPrefix(c.Name, "sdl_") {
			continue
		}

		raw, _ := json.Marshal(c)
		data := map[string]any{}
		_ = json.Unmarshal(raw, &data)
		delete(data, "created")
		delete(data, "updated")
		fields, _ := data["fields"].([]any)
		slices.SortFunc(fields, func(a, b any) int {
			return strings.Compare(a.(map[string]any)["name"].(string), b.(map[string]any)["name"].(string))
		})
		result[c.Name] = data
	}

	raw, _ := json.MarshalIndent(result, "", " ")

	return string(raw)
}

func derived(t *testing.T, app core.App, token string) string {
	t.Helper()

	status, data := api(t, app, http.MethodGet, "/api/graphql/schema", token, nil)
	if status != http.StatusOK {
		t.Fatalf("Unexpected status %d %v", status, data)
	}

	return data["schema"].(string)
}

const schemaV1 = `
type SdlA @collection(name: "sdl_as") @rules(list: "") {
  title: String! @unique
  b: SdlB
}

type SdlB @collection(name: "sdl_bs") {
  a: [SdlA!]
  status: SdlBStatus
}

enum SdlBStatus {
  one
  two
}
`

const schemaV2 = `
type SdlA @collection(name: "sdl_as") @rules(list: "", view: "") {
  title: String! @unique
  extra: Int
}
`

const goRunnerSource = `package main

import (
	"encoding/json/v2"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/lumm2509/pocketbomb/core"
	_ "github.com/lumm2509/pocketbomb/migrations"
	_ "%s/migrations"
)

func main() {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: os.Args[1]})
	if err := app.Bootstrap(); err != nil {
		log.Fatal(err)
	}

	if err := app.RunAllMigrations(); err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 2 {
		total, _ := strconv.Atoi(os.Args[2])
		if _, err := core.NewMigrationsRunner(app, core.AppMigrations).Down(total); err != nil {
			log.Fatal(err)
		}
	}

	all, err := app.FindAllCollections()
	if err != nil {
		log.Fatal(err)
	}

	raw, err := json.Marshal(all)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(raw))
}
`

// note: it must stay first because the JS test registers its migrations in the global list.
//
// The generated migrations are compiled with a small program inside of this module.
func TestGeneratedGoMigrationRunsOnFreshDB(t *testing.T) {
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	moduleDir, err := os.MkdirTemp(".", "_gomigration")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(moduleDir) })

	dir := filepath.Join(moduleDir, "migrations")
	migratecmd.MustRegister(app, nil, migratecmd.Config{Automigrate: true, Dir: dir, TemplateLang: migratecmd.TemplateLangGo})

	owner, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := tests.NewSessionAuthToken(app, owner)
	if err != nil {
		t.Fatal(err)
	}

	base := derived(t, app, authToken)
	apply(t, app, authToken, base+schemaV1, false)
	apply(t, app, authToken, base+schemaV2, true)

	files, _ := filepath.Glob(filepath.Join(dir, "*_graphql_schema.go"))
	if len(files) != 2 {
		t.Fatalf("Expected 2 migrations, got %v", files)
	}

	pkg := "github.com/lumm2509/pocketbomb/plugins/migratecmd/graphqlschematest/" + filepath.Base(moduleDir)
	mainFile := filepath.Join(moduleDir, "main.go")
	if err := os.WriteFile(mainFile, []byte(fmt.Sprintf(goRunnerSource, pkg)), 0644); err != nil {
		t.Fatal(err)
	}

	binary := filepath.Join(t.TempDir(), "runner")
	if out, err := exec.Command("go", "build", "-o", binary, mainFile).CombinedOutput(); err != nil {
		t.Fatalf("The generated migrations don't compile: %v\n%s", err, out)
	}

	run := func(args ...string) string {
		t.Helper()

		out, err := exec.Command(binary, args...).Output()
		if err != nil {
			t.Fatalf("The generated migrations failed: %v", err)
		}

		collections := []*core.Collection{}
		if err := json.Unmarshal(out, &collections); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}

		return snapshotOf(collections)
	}

	dataDir := t.TempDir()

	expected := snapshot(t, app)
	if !strings.Contains(expected, `"sdl_as"`) || strings.Contains(expected, `"sdl_bs"`) {
		t.Fatalf("Unexpected collections %s", expected)
	}

	if got := run(dataDir); got != expected {
		t.Fatalf("Expected the same collections\n%s\n\ngot\n%s", expected, got)
	}

	if got := run(dataDir, "2"); got != "{}" {
		t.Fatalf("Expected no sdl collections after the down migrations, got\n%s", got)
	}
}

func TestGeneratedJSMigrationRunsOnFreshDB(t *testing.T) {
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	dir := t.TempDir()
	migratecmd.MustRegister(app, nil, migratecmd.Config{Automigrate: true, Dir: dir, TemplateLang: migratecmd.TemplateLangJS})

	owner, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := tests.NewSessionAuthToken(app, owner)
	if err != nil {
		t.Fatal(err)
	}

	base := derived(t, app, authToken)

	apply(t, app, authToken, base+schemaV1, false)

	files, _ := filepath.Glob(filepath.Join(dir, "*_graphql_schema.js"))
	if len(files) != 1 {
		t.Fatalf("Expected ONE migration, got %v", files)
	}

	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "importCollections") || !strings.Contains(string(raw), `"sdl_as"`) || !strings.Contains(string(raw), `"sdl_bs"`) {
		t.Fatalf("Unexpected migration\n%s", raw)
	}

	var applied int
	err = app.DB().NewQuery("SELECT count(*) FROM _migrations WHERE file = {:file}").
		Bind(map[string]any{"file": filepath.Base(files[0])}).
		Row(&applied)
	if err != nil || applied != 1 {
		t.Fatalf("Expected the migration to be marked as applied, got %d %v", applied, err)
	}

	// update + delete
	apply(t, app, authToken, base+schemaV2, true)

	files, _ = filepath.Glob(filepath.Join(dir, "*_graphql_schema.js"))
	if len(files) != 2 {
		t.Fatalf("Expected 2 migrations, got %v", files)
	}

	expected := snapshot(t, app)
	if !strings.Contains(expected, `"sdl_as"`) || strings.Contains(expected, `"sdl_bs"`) {
		t.Fatalf("Unexpected collections %s", expected)
	}

	fresh := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := fresh.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	defer fresh.ResetBootstrapState()

	jsvm.MustRegister(fresh, jsvm.Config{MigrationsDir: dir, HooksDir: t.TempDir()})

	if err := fresh.RunAllMigrations(); err != nil {
		t.Fatal(err)
	}

	if got := snapshot(t, fresh); got != expected {
		t.Fatalf("Expected the same collections\n%s\n\ngot\n%s", expected, got)
	}

	// down
	if _, err := core.NewMigrationsRunner(fresh, core.AppMigrations).Down(2); err != nil {
		t.Fatal(err)
	}
	if got := snapshot(t, fresh); got != "{}" {
		t.Fatalf("Expected no sdl collections after the down migrations, got\n%s", got)
	}
}
