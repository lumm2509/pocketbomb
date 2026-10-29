package apis_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/spf13/cast"
)

func TestCronsList(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodGet,
			URL:             "/api/crons",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as regular user",
			Method: http.MethodGet,
			URL:    "/api/crons",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as superuser (empty list)",
			Method: http.MethodGet,
			URL:    "/api/crons",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Cron().RemoveAll()
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{`[]`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as superuser",
			Method: http.MethodGet,
			URL:    "/api/crons",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`{"id":"__pbLogsCleanup__","expression":"0 */6 * * *"}`,
				`{"id":"__pbDBOptimize__","expression":"0 0 * * *"}`,
				`{"id":"__pbOTPCleanup__","expression":"0 * * * *"}`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestCronsRun(t *testing.T) {
	t.Parallel()

	beforeTestFunc := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		app.Cron().Add("test", "* * * * *", func() {
			app.Store().Set("testJobCalls", cast.ToInt(app.Store().Get("testJobCalls"))+1)
		})
		app.Cron().Stop()
	}

	expectedCalls := func(expected int) func(t testing.TB, app *tests.TestApp, res *http.Response) {
		return func(t testing.TB, app *tests.TestApp, res *http.Response) {
			time.Sleep(50 * time.Millisecond)

			total := cast.ToInt(app.Store().Get("testJobCalls"))
			if total != expected {
				t.Fatalf("Expected total testJobCalls %d, got %d", expected, total)
			}
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodPost,
			URL:             "/api/crons/test",
			BeforeTestFunc:  beforeTestFunc,
			AfterTestFunc:   expectedCalls(0),
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as regular user",
			Method: http.MethodPost,
			URL:    "/api/crons/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc:  beforeTestFunc,
			AfterTestFunc:   expectedCalls(0),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as superuser (missing job)",
			Method: http.MethodPost,
			URL:    "/api/crons/missing",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc:  beforeTestFunc,
			AfterTestFunc:   expectedCalls(0),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authorized as superuser (existing job)",
			Method: http.MethodPost,
			URL:    "/api/crons/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: beforeTestFunc,
			AfterTestFunc:  expectedCalls(1),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}
