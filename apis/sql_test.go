package apis_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/tests"
)

func TestSQLRun(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodPost,
			URL:             "/api/sql",
			Body:            strings.NewReader(`{"query":"select 1"}`),
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "regular user",
			Method: http.MethodPost,
			URL:    "/api/sql",
			Body:   strings.NewReader(`{"query":"select 1"}`),
			Headers: map[string]string{
				// users, test2@example.com
				"Authorization": tests.AuthToken("users", "test2@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superuser",
			Method: http.MethodPost,
			URL:    "/api/sql",
			Body:   strings.NewReader(`{"query":"select 1"}`),
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"execTime":`,
				`"affectedRows":0`,
				`"columns":[{"name":"1","type":"","nullable":true}]`,
				`"rows":[["1"]]`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "empty query",
			Method: http.MethodPost,
			URL:    "/api/sql",
			Body:   strings.NewReader(`{"query":""}`),
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"query":{`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "invalid query",
			Method: http.MethodPost,
			URL:    "/api/sql",
			Body:   strings.NewReader(`{"query":"invalid"}`),
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{}`,
				`Raw error:`,
				`SQL logic error`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "query with length above the limit",
			Method: http.MethodPost,
			URL:    "/api/sql",
			Body:   strings.NewReader(`{"query":"` + strings.Repeat("a", 5001) + `"}`),
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"query":{`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "query with length equal to the limit",
			Method: http.MethodPost,
			URL:    "/api/sql",
			Body:   strings.NewReader(`{"query":"select '` + strings.Repeat("a", 4985) + `' as id"}`),
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"execTime":`,
				`"affectedRows":0`,
				`"columns":[{"name":"id","type":"","nullable":true}]`,
				`"rows":[["aaa`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "single write query",
			Method: http.MethodPost,
			URL:    "/api/sql",
			Body:   strings.NewReader(`{"query":"create table test_sql_table(id int primary key)"}`),
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if !app.HasTable("test_sql_table") {
					t.Fatalf("Missing expected new %q table", "test_sql_table")
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"execTime":`,
				// note: the DDL statements don't reset the connection changes counter
				// (the auth token placeholder resolution inserts the test auth sessions)
				`"affectedRows":`,
				`"columns":[]`,
				`"rows":[]`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "multiple write queries",
			Method: http.MethodPost,
			URL:    "/api/sql",
			Body:   strings.NewReader(`{"query":"create table test_sql_table(id int primary key);insert into test_sql_table(id)VALUES(1)"}`),
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				var total int
				err := app.DB().NewQuery("select count(*) from test_sql_table").Row(&total)
				if err != nil {
					t.Fatal(err)
				}

				if total != 1 {
					t.Fatalf("Expected exactly 1 row, found: %d", total)
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"execTime":`,
				`"affectedRows":1`,
				`"columns":[]`,
				`"rows":[]`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "multiple write queries (transaction rollback)",
			Method: http.MethodPost,
			URL:    "/api/sql",
			Body:   strings.NewReader(`{"query":"create table test_sql_table(id int primary key);insert into test_sql_table(id)VALUES(1);invalid"}`),
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if app.HasTable("test_sql_table") {
					t.Fatalf("Expected table %q to not be created", "test_sql_table")
				}
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{}`,
				`Raw error:`,
				`SQL logic error`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "multiple read queries",
			Method: http.MethodPost,
			URL:    "/api/sql",
			Body:   strings.NewReader(`{"query":"select 1;select 2"}`),
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"execTime":`,
				`"affectedRows":0`,
				// only the result of the last query should be returned
				`"columns":[{"name":"2","type":"","nullable":true}]`,
				`"rows":[["2"]]`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}
