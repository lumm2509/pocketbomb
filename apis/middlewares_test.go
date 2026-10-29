package apis_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/hook"
)

func TestPanicRecover(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "panic from route",
			Method: http.MethodGet,
			URL:    "/my/test",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test", func(e *core.RequestEvent) error {
					panic("123")
				})
			},
			ExpectedStatus:  500,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "panic from middleware",
			Method: http.MethodGet,
			URL:    "/my/test",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test", func(e *core.RequestEvent) error {
					return e.String(http.StatusOK, "test")
				}).BindFunc(func(e *core.RequestEvent) error {
					panic(123)
				})
			},
			ExpectedStatus:  500,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRequireGuestOnly(t *testing.T) {
	t.Parallel()

	beforeTestFunc := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		e.Router.GET("/my/test", func(e *core.RequestEvent) error {
			return e.String(200, "test123")
		}).Bind(apis.RequireGuestOnly())
	}

	scenarios := []tests.ApiScenario{
		{
			Name:   "valid regular user token",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc:  beforeTestFunc,
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "valid superuser auth token",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc:  beforeTestFunc,
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "expired/invalid token",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.ExpiredAuthToken("users", "test@example.com"),
			},
			BeforeTestFunc:  beforeTestFunc,
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "guest",
			Method:          http.MethodGet,
			URL:             "/my/test",
			BeforeTestFunc:  beforeTestFunc,
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRequireAuth(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "guest",
			Method: http.MethodGet,
			URL:    "/my/test",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireAuth())
			},
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "expired token",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.ExpiredAuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireAuth())
			},
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "invalid token",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.RecordToken(core.TokenTypeFile, "_superusers", "test@example.com", false),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireAuth())
			},
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "valid record auth token with no collection restrictions",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				// regular user
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireAuth())
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
		},
		{
			Name:   "valid record static auth token",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				// regular user
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireAuth())
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
		},
		{
			Name:   "valid record auth token with collection not in the restricted list",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				// superuser
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireAuth("users", "demo1"))
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "valid record auth token with collection in the restricted list",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				// superuser
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireAuth("users", core.CollectionNameSuperusers))
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
		},
		{
			Name:   "valid record auth token with Bearer case-insensitive prefix",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				// regular user
				"Authorization": "BeArEr " + tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireAuth())
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRequirePermission(t *testing.T) {
	t.Parallel()

	route := func(handler *hook.Handler[*core.RequestEvent]) func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		return func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			logsReader, err := tests.CreateRole(app, "logs reader", core.Permissions{
				System: map[string]string{core.PermissionResourceLogs: core.PermissionLevelRead},
			})
			if err != nil {
				t.Fatal(err)
			}

			if _, err := tests.CreateStaff(app, "limited@example.com", logsReader.Id); err != nil {
				t.Fatal(err)
			}

			if _, err := tests.CreateStaff(app, "none@example.com"); err != nil {
				t.Fatal(err)
			}

			e.Router.GET("/my/test", func(e *core.RequestEvent) error {
				return e.String(200, "test123")
			}).Bind(handler)
		}
	}

	logsRead := apis.RequirePermission(core.PermissionResourceLogs, core.PermissionLevelRead)
	logsWrite := apis.RequirePermission(core.PermissionResourceLogs, core.PermissionLevelWrite)
	sql := apis.RequirePermission(core.PermissionResourceSQL, core.PermissionLevelWrite)
	multi := apis.RequirePermission(core.PermissionResourceLogs, core.PermissionLevelRead, core.PermissionResourceSettings, core.PermissionLevelRead)

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodGet,
			URL:             "/my/test",
			BeforeTestFunc:  route(logsRead),
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "expired/invalid token",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.ExpiredAuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc:  route(logsRead),
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "regular user (customer) auth token",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc:  route(logsRead),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "Owner",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc:  route(logsWrite),
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
		},
		{
			Name:   "Owner (sql)",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc:  route(sql),
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
		},
		{
			Name:   "staff with the required level",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "limited@example.com"),
			},
			BeforeTestFunc:  route(logsRead),
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
		},
		{
			Name:   "staff with lower level",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "limited@example.com"),
			},
			BeforeTestFunc:  route(logsWrite),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "staff with only one of the multiple required permissions",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "limited@example.com"),
			},
			BeforeTestFunc:  route(multi),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "staff (not Owner) for sql",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "limited@example.com"),
			},
			BeforeTestFunc:  route(sql),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "staff without permissions",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "none@example.com"),
			},
			BeforeTestFunc:  route(logsRead),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRequireSuperuserOrOwnerAuth(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "guest",
			Method: http.MethodGet,
			URL:    "/my/test/4q1xlclmfloku33",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{id}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSuperuserOrOwnerAuth(""))
			},
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "expired/invalid token",
			Method: http.MethodGet,
			URL:    "/my/test/4q1xlclmfloku33",
			Headers: map[string]string{
				"Authorization": tests.ExpiredAuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{id}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSuperuserOrOwnerAuth(""))
			},
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "valid record auth token (different user)",
			Method: http.MethodGet,
			URL:    "/my/test/oap640cot4yru2s",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{id}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSuperuserOrOwnerAuth(""))
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "valid record auth token (owner)",
			Method: http.MethodGet,
			URL:    "/my/test/4q1xlclmfloku33",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{id}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSuperuserOrOwnerAuth(""))
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
		},
		{
			Name:   "valid record auth token (owner + non-matching custom owner param)",
			Method: http.MethodGet,
			URL:    "/my/test/4q1xlclmfloku33",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{id}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSuperuserOrOwnerAuth("test"))
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "valid record auth token (owner + matching custom owner param)",
			Method: http.MethodGet,
			URL:    "/my/test/4q1xlclmfloku33",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{test}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSuperuserOrOwnerAuth("test"))
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
		},
		{
			Name:   "valid superuser auth token",
			Method: http.MethodGet,
			URL:    "/my/test/4q1xlclmfloku33",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{id}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSuperuserOrOwnerAuth(""))
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRequireSameCollectionContextAuth(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "guest",
			Method: http.MethodGet,
			URL:    "/my/test/_pb_users_auth_",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{collection}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSameCollectionContextAuth(""))
			},
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "expired/invalid token",
			Method: http.MethodGet,
			URL:    "/my/test/_pb_users_auth_",
			Headers: map[string]string{
				"Authorization": tests.ExpiredAuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{collection}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSameCollectionContextAuth(""))
			},
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "valid record auth token (different collection)",
			Method: http.MethodGet,
			URL:    "/my/test/clients",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{collection}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSameCollectionContextAuth(""))
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "valid record auth token (same collection)",
			Method: http.MethodGet,
			URL:    "/my/test/_pb_users_auth_",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{collection}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSameCollectionContextAuth(""))
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
		},
		{
			Name:   "valid record auth token (non-matching/missing collection param)",
			Method: http.MethodGet,
			URL:    "/my/test/_pb_users_auth_",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{id}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSuperuserOrOwnerAuth(""))
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "valid record auth token (matching custom collection param)",
			Method: http.MethodGet,
			URL:    "/my/test/_pb_users_auth_",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{test}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSuperuserOrOwnerAuth("test"))
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superuser no exception check",
			Method: http.MethodGet,
			URL:    "/my/test/_pb_users_auth_",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				e.Router.GET("/my/test/{collection}", func(e *core.RequestEvent) error {
					return e.String(200, "test123")
				}).Bind(apis.RequireSameCollectionContextAuth(""))
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestSuperuserIPsWhitelist(t *testing.T) {
	t.Parallel()

	setupWhitelist := func(superuserIPs ...string) func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		return func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			// allow loading a mock IP from the test scenario
			app.Settings().TrustedProxy = core.TrustedProxyConfig{
				Headers: []string{"x-test-ip"},
			}

			app.Settings().SuperuserIPs = superuserIPs

			err := app.Save(app.Settings())
			if err != nil {
				t.Fatal(err)
			}

			e.Router.GET("/my/test", func(e *core.RequestEvent) error {
				return e.String(200, "test123")
			})
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest with non-matching IP",
			Method:          http.MethodGet,
			URL:             "/my/test",
			Headers:         map[string]string{"x-test-ip": "127.0.0.1"},
			BeforeTestFunc:  setupWhitelist("0.0.0.0"),
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "regular user with non-matching IP",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"x-test-ip":     "127.0.0.1",
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc:  setupWhitelist("0.0.0.0"),
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superuser with non-matching IP",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"x-test-ip":     "127.0.0.1",
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc:  setupWhitelist("0.0.0.0"),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superuser with matching IP",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"x-test-ip":     "127.0.0.1",
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc:  setupWhitelist("0.0.0.0", "127.0.0.1"),
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superuser with no whitelisted IPs",
			Method: http.MethodGet,
			URL:    "/my/test",
			Headers: map[string]string{
				"x-test-ip":     "127.0.0.1",
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc:  setupWhitelist(),
			ExpectedStatus:  200,
			ExpectedContent: []string{"test123"},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestOAuth2AttackForgedSessionClaims(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)

	client := oauth2FindClient(t, app, "app")
	user := oauth2FindRecord(t, app, "users", "test@example.com")
	other := oauth2FindRecord(t, app, "users", "test2@example.com")

	_, userSession := oauth2AccessToken(t, app, client, user, []string{"openid"})
	_, otherSession := oauth2AccessToken(t, app, client, other, []string{"openid"})

	sign := func(record *core.Record, claims map[string]any) string {
		base := map[string]any{
			core.TokenClaimType:            core.TokenTypeAuth,
			core.TokenClaimId:              record.Id,
			core.TokenClaimCollectionId:    record.Collection().Id,
			core.TokenClaimOAuth2ClientId:  "app",
			core.TokenClaimOAuth2Scope:     "openid",
			core.TokenClaimOAuth2SessionId: userSession.Id,
		}
		for k, v := range claims {
			if v == nil {
				delete(base, k)
			} else {
				base[k] = v
			}
		}
		token, err := security.NewJWT(base, record.TokenKey()+record.Collection().AuthToken.Secret, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	// sanity check (correctly signed with the matching session)
	if _, err := app.FindAuthRecordByToken(sign(user, nil), core.TokenTypeAuth); err != nil {
		t.Fatalf("Expected the well formed token to be valid, got %v", err)
	}

	for name, token := range map[string]string{
		"missing sid":               sign(user, map[string]any{core.TokenClaimOAuth2SessionId: nil}),
		"sid of another record":     sign(user, map[string]any{core.TokenClaimOAuth2SessionId: otherSession.Id}),
		"sid of another session id": sign(other, map[string]any{core.TokenClaimOAuth2SessionId: userSession.Id}),
		"another client id":         sign(user, map[string]any{core.TokenClaimOAuth2ClientId: "3p"}),
		"missing client id":         sign(user, map[string]any{core.TokenClaimOAuth2ClientId: nil}),
		"non string sid":            sign(user, map[string]any{core.TokenClaimOAuth2SessionId: 123}),
	} {
		if _, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth); err == nil {
			t.Fatalf("%s: expected the token to be rejected", name)
		}
	}

	// a root SSO session id as sid
	_, root := oauth2StubSSO(t, app, user, types.NowDateTime())
	if _, err := app.FindAuthRecordByToken(sign(user, map[string]any{core.TokenClaimOAuth2SessionId: root.Id}), core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the root session sid to be rejected")
	}

	// the id_token (RS/ES256) is never accepted as access token
	idToken, err := user.NewOIDCIdToken(core.OIDCIdTokenOptions{
		Issuer:  oauth2TestIssuer,
		Client:  client,
		Session: userSession,
		ExtraClaims: map[string]any{
			core.TokenClaimType:           core.TokenTypeAuth,
			core.TokenClaimId:             user.Id,
			core.TokenClaimCollectionId:   user.Collection().Id,
			core.TokenClaimOAuth2ClientId: "app",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindAuthRecordByToken(idToken, core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the id_token to be rejected as access token")
	}

	// installer token is never accepted as auth token
	su := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
	installerToken, _ := su.NewInstallerToken(time.Minute)
	if _, err := app.FindAuthRecordByToken(installerToken, core.TokenTypeAuth); err == nil {
		t.Fatal("Expected the installer token to be rejected as auth token")
	}
	if _, err := app.FindAuthRecordByToken(installerToken); err == nil {
		// a type-less lookup must still verify with the installer key (and it is an installer token)
		if claims, _ := security.ParseUnverifiedJWT(installerToken); claims["type"] == core.TokenTypeAuth {
			t.Fatal("Unexpected auth type installer token")
		}
	}
}

// RBAC actors of the matrix tests.
const (
	actorGuest              = "guest"
	actorCustomer           = "customer (default role)"
	actorCustomerRestricted = "customer (restricted role)"
	actorOwner              = "staff Owner"
	actorStaffLimited       = "staff limited"
	actorStaffNone          = "staff without roles"
	actorStaffWebhooks      = "staff webhooks"
	actorThirdParty         = "third-party token"
	actorImpersonated       = "impersonated customer"

	// API keys (phase K; the keys only identify the client and restrict, they never grant)
	actorGuestKey         = "guest + public key"
	actorGuestReadKey     = "guest + read-only public key"
	actorCustomerKey      = "customer + same client read-only key"
	actorCustomerOtherKey = "customer + other client key"
)

var rbacActors = []string{
	actorGuest,
	actorCustomer,
	actorCustomerRestricted,
	actorOwner,
	actorStaffLimited,
	actorStaffNone,
	actorStaffWebhooks,
	actorThirdParty,
	actorImpersonated,
	actorGuestKey,
	actorGuestReadKey,
	actorCustomerKey,
	actorCustomerOtherKey,
}

// rbacMatrixSetup creates the matrix actor and returns its auth token and public API key
// (the staff members, sessions and keys only for the provided actor):
//   - customer: users test@example.com with the default Customer role
//   - customer restricted: users test2@example.com with only demo2 list/view
//   - Owner: _superusers test@example.com
//   - staff limited: demo1 list, demo2 list/view, logs read and sessions read
//   - staff without roles
//   - staff webhooks: demo2 list/view and webhooks write (W1: subscriptions only to the viewable topics)
//   - third-party token: users test@example.com with "openid read_demo2" scopes
//   - impersonated: users test@example.com impersonated by the Owner (pb_dashboard client)
//   - guest + public key: a key of the pb_test_users client with all the collections actions
//   - guest + read-only public key: a key of the pb_test_users client with only list/view
//   - customer + same client read-only key: the customer token (pb_test_users) + the read-only key
//   - customer + other client key: the customer token + an all actions key of another client
func rbacMatrixSetup(t testing.TB, app *tests.TestApp, forActor string) (map[string]string, map[string]string) {
	t.Helper()

	demo1, err := app.FindCollectionByNameOrId("demo1")
	if err != nil {
		t.Fatal(err)
	}

	demo2, err := app.FindCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}

	limitedRole, err := tests.CreateRole(app, "Limited staff", core.Permissions{
		Collections: map[string][]string{
			demo1.Id: {core.PermissionActionList},
			demo2.Id: {core.PermissionActionList, core.PermissionActionView},
		},
		System: map[string]string{
			core.PermissionResourceLogs:     core.PermissionLevelRead,
			core.PermissionResourceSessions: core.PermissionLevelRead,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	webhooksRole, err := tests.CreateRole(app, "Webhooks staff", core.Permissions{
		Collections: map[string][]string{
			demo2.Id: {core.PermissionActionList, core.PermissionActionView},
		},
		System: map[string]string{
			core.PermissionResourceWebhooks: core.PermissionLevelWrite,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	restrictedRole, err := tests.CreateRole(app, "Restricted customer", core.Permissions{
		Collections: map[string][]string{
			demo2.Id: {core.PermissionActionList, core.PermissionActionView},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	staff := map[string]*core.Record{}
	for actor, s := range map[string]struct {
		email string
		roles []string
	}{
		actorStaffLimited:  {"limited@example.com", []string{limitedRole.Id}},
		actorStaffNone:     {"none@example.com", nil},
		actorStaffWebhooks: {"webhooks@example.com", []string{webhooksRole.Id}},
	} {
		if actor != forActor {
			continue
		}

		staff[actor], err = tests.CreateStaff(app, s.email, s.roles...)
		if err != nil {
			t.Fatal(err)
		}
	}

	customer := oauth2FindRecord(t, app, "users", "test@example.com")

	restricted := oauth2FindRecord(t, app, "users", "test2@example.com")
	if err := tests.AssignRoles(app, restricted, restrictedRole.Id); err != nil {
		t.Fatal(err)
	}

	owner := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")

	// note: only the provided actor tokens are created (the sessions and tokens are the slowest part of the setup)
	tokens := map[string]string{actorGuest: ""}

	actorRecords := map[string]*core.Record{
		actorCustomer:           customer,
		actorCustomerRestricted: restricted,
		actorOwner:              owner,
		actorCustomerKey:        customer,
		actorCustomerOtherKey:   customer,
	}
	for actor, record := range staff {
		actorRecords[actor] = record
	}

	if record, ok := actorRecords[forActor]; ok {
		token, err := tests.NewSessionAuthToken(app, record)
		if err != nil {
			t.Fatal(err)
		}
		tokens[forActor] = token
	}

	oauth2PrepareIssuer(t, app, "users")

	// third-party
	if forActor == actorThirdParty {
		thirdParty := oauth2StubClient(t, app, "users", "rbac3p", func(c *core.OAuth2Client) {
			c.SetScopes([]string{"openid", "email", "read_demo2", "write_demo2", "read_users"})
		})
		tokens[actorThirdParty], _ = oauth2AccessToken(t, app, thirdParty, customer, []string{"openid", "read_demo2"})
	}

	// impersonated
	if forActor == actorImpersonated {
		dashboard, err := app.FindOAuth2ClientByClientId(core.OAuth2DashboardClientId)
		if err != nil {
			t.Fatal(err)
		}
		ownerSession, err := tests.CreateAuthSession(app, owner)
		if err != nil {
			t.Fatal(err)
		}
		session, err := app.CreateAuthSession(customer, dashboard, core.AuthSessionOptions{
			Scopes:              []string{"openid"},
			Impersonator:        owner.Id,
			ImpersonatorSession: ownerSession.Id,
			AuthMethods:         []core.AuthSessionMethod{{Method: core.AuthSessionMethodImpersonation, Time: types.NowDateTime()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		tokens[actorImpersonated], err = session.NewAccessToken()
		if err != nil {
			t.Fatal(err)
		}
	}

	// API keys
	keys := map[string]string{}
	readOnly := core.Permissions{Collections: map[string][]string{
		core.PermissionAllCollections: {core.PermissionActionList, core.PermissionActionView},
	}}
	switch forActor {
	case actorGuestKey:
		_, keys[forActor], err = tests.NewAPIKey(app, "users", core.APIKeyKindPublic, tests.AllCollectionsActions)
	case actorGuestReadKey:
		_, keys[forActor], err = tests.NewAPIKey(app, "users", core.APIKeyKindPublic, readOnly)
	case actorCustomerKey:
		_, keys[forActor], err = tests.NewAPIKey(app, "users", core.APIKeyKindPublic, readOnly)
	case actorCustomerOtherKey:
		other := oauth2StubClient(t, app, "users", "rbacother")
		_, keys[forActor], err = tests.NewClientAPIKey(app, other, core.APIKeyKindPublic, tests.AllCollectionsActions)
	}
	if err != nil {
		t.Fatal(err)
	}

	return tokens, keys
}

type rbacMatrixRow struct {
	name        string
	method      string
	url         string
	body        string
	contentType string

	// actorTokenField sends the actor token as form field (e.g. the token exchange actor_token)
	// instead of the Authorization header.
	actorTokenField string

	expected map[string]int
	content  map[string][]string
}

// all returns an expected statuses map with the same status for all actors
// (overwritten with the provided actor specific statuses).
func all(status int, overrides map[string]int) map[string]int {
	result := make(map[string]int, len(rbacActors))
	for _, a := range rbacActors {
		result[a] = status
	}
	for k, v := range overrides {
		result[k] = v
	}
	return result
}

func TestRBACMatrix(t *testing.T) {
	t.Parallel()

	rows := []rbacMatrixRow{
		// regular collection with public rules (demo2)
		{
			name:   "list public demo2 records",
			method: http.MethodGet,
			url:    "/api/collections/demo2/records",
			expected: all(200, map[string]int{
				actorStaffNone:        403,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
		},
		{
			name:   "create public demo2 record",
			method: http.MethodPost,
			url:    "/api/collections/demo2/records",
			body:   `{"title":"rbac"}`,
			expected: all(200, map[string]int{
				actorCustomerRestricted: 403,
				actorStaffLimited:       403,
				actorStaffNone:          403,
				actorStaffWebhooks:      403,
				actorThirdParty:         403, // only read_demo2 scope

				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
				actorGuestReadKey:     403, // the key ceiling
				actorCustomerKey:      403, // the key ceiling
			}),
		},
		{
			name:   "delete public demo2 record",
			method: http.MethodDelete,
			url:    "/api/collections/demo2/records/0yxhwia2amd8gec",
			expected: all(204, map[string]int{
				actorCustomerRestricted: 403,
				actorStaffLimited:       403,
				actorStaffNone:          403,
				actorStaffWebhooks:      403,
				actorThirdParty:         403,
				actorGuest:              401, // deny by default (no client credentials)
				actorCustomerOtherKey:   401, // the token and the key clients mismatch
				actorGuestReadKey:       403, // the key ceiling
				actorCustomerKey:        403, // the key ceiling
			}),
		},
		// regular collection with nil (superusers only) rules (demo1)
		{
			name:   "list superusers only demo1 records",
			method: http.MethodGet,
			url:    "/api/collections/demo1/records",
			expected: all(403, map[string]int{
				actorOwner:        200,
				actorStaffLimited: 200, // list permission => bypass

				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
		},
		{
			name:   "view superusers only demo1 record",
			method: http.MethodGet,
			url:    "/api/collections/demo1/records/84nmscqy84lsi1t",
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
		},
		// auth collection (users: list nil, view "id = @request.auth.id")
		{
			name:   "list users",
			method: http.MethodGet,
			url:    "/api/collections/users/records",
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
		},
		{
			name:   "view own users record",
			method: http.MethodGet,
			url:    "/api/collections/users/records/4q1xlclmfloku33",
			expected: all(403, map[string]int{
				actorCustomer:         200,
				actorOwner:            200,
				actorImpersonated:     200,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
				actorGuestKey:         404, // rule
				actorGuestReadKey:     404, // rule
				actorCustomerKey:      200,
			}),
		},
		// system collections
		{
			name:   "list _superusers (staff)",
			method: http.MethodGet,
			url:    "/api/collections/_superusers/records",
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
		},
		{
			name:   "list _externalAuths (sessions; own records via rules)",
			method: http.MethodGet,
			url:    "/api/collections/_externalAuths/records",
			expected: all(200, map[string]int{
				actorThirdParty:       403,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
			content: map[string][]string{
				actorOwner:        {`"totalItems":4`},
				actorStaffLimited: {`"totalItems":4`}, // sessions read => bypass
				actorStaffNone:    {`"totalItems":0`},
				actorGuestKey:     {`"totalItems":0`},
				actorGuestReadKey: {`"totalItems":0`},
			},
		},
		{
			name:   "list _roles",
			method: http.MethodGet,
			url:    "/api/collections/_roles/records",
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
		},
		{
			name:   "list _roleAssignments",
			method: http.MethodGet,
			url:    "/api/collections/_roleAssignments/records",
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
		},
		// batch
		{
			name:   "batch create demo2 record",
			method: http.MethodPost,
			url:    "/api/batch",
			body:   `{"requests":[{"method":"POST","url":"/api/collections/demo2/records","body":{"title":"rbac"}}]}`,
			expected: all(200, map[string]int{
				actorCustomerRestricted: 400,
				actorStaffLimited:       400,
				actorStaffNone:          400,
				actorStaffWebhooks:      400,
				actorThirdParty:         400,
				actorGuest:              401, // deny by default (no client credentials)
				actorCustomerOtherKey:   401, // the token and the key clients mismatch
				actorGuestReadKey:       400, // the key ceiling
				actorCustomerKey:        400, // the key ceiling
			}),
		},
		// system APIs
		{
			name:     "collections list",
			method:   http.MethodGet,
			url:      "/api/collections",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200, actorStaffLimited: 200, actorStaffWebhooks: 200}),
			content: map[string][]string{
				actorOwner: {`"totalItems":25`},
				// demo1, demo2 + the sessions mapped system collections (5)
				actorStaffLimited: {`"totalItems":7`, `"name":"demo1"`, `"name":"demo2"`, `"name":"_externalAuths"`},
			},
		},
		{
			name:     "collection view (not allowed for limited staff)",
			method:   http.MethodGet,
			url:      "/api/collections/demo3",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200}),
		},
		{
			name:     "collection view (allowed for limited staff)",
			method:   http.MethodGet,
			url:      "/api/collections/demo2",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200, actorStaffLimited: 200, actorStaffWebhooks: 200}),
		},
		{
			name:     "collection create",
			method:   http.MethodPost,
			url:      "/api/collections",
			body:     `{"name":"rbac_new","type":"base"}`,
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200}),
		},
		{
			name:     "settings",
			method:   http.MethodGet,
			url:      "/api/settings",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200}),
		},
		{
			name:     "logs list",
			method:   http.MethodGet,
			url:      "/api/logs",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200, actorStaffLimited: 200}),
		},
		{
			name:     "logs truncate",
			method:   http.MethodDelete,
			url:      "/api/logs",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 204}),
		},
		{
			name:     "backups",
			method:   http.MethodGet,
			url:      "/api/backups",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200}),
		},
		{
			name:     "crons",
			method:   http.MethodGet,
			url:      "/api/crons",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200}),
		},
		{
			name:     "webhooks topics",
			method:   http.MethodGet,
			url:      "/api/webhooks/topics",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200, actorStaffWebhooks: 200}),
		},
		// W1: subscriptions only to the topics of the viewable collections
		{
			name:   "webhook subscription create (viewable collection topic)",
			method: http.MethodPost,
			url:    "/api/collections/_webhooks/records",
			body:   `{"name":"w","uri":"https://example.com/hook","topics":["demo2.create"]}`,
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorStaffWebhooks:    200,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
			content: map[string][]string{
				actorOwner:         {`"actorRef":""`},
				actorStaffWebhooks: {`"actorRef":"pbc_3142635823:`},
			},
		},
		{
			name:   "webhook subscription create (not viewable collection topic)",
			method: http.MethodPost,
			url:    "/api/collections/_webhooks/records",
			body:   `{"name":"w","uri":"https://example.com/hook","topics":["demo1.create"]}`,
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorStaffWebhooks:    400,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
			content: map[string][]string{
				actorStaffWebhooks: {`"validation_webhook_topic_forbidden"`},
			},
		},
		{
			name:   "webhook subscription create (wildcard topic)",
			method: http.MethodPost,
			url:    "/api/collections/_webhooks/records",
			body:   `{"name":"w","uri":"https://example.com/hook","topics":["*.create"]}`,
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorStaffWebhooks:    400,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
			content: map[string][]string{
				actorStaffWebhooks: {`"validation_webhook_topic_wildcard_forbidden"`},
			},
		},
		// W2: the subscription filter can reference only the accessible fields and collections
		{
			name:   "webhook subscription create (filter with the own fields)",
			method: http.MethodPost,
			url:    "/api/collections/_webhooks/records",
			body:   `{"name":"w","uri":"https://example.com/hook","topics":["demo2.create"],"filter":"title != ''"}`,
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorStaffWebhooks:    200,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
		},
		{
			name:   "webhook subscription create (filter with a not viewable @collection)",
			method: http.MethodPost,
			url:    "/api/collections/_webhooks/records",
			body:   `{"name":"w","uri":"https://example.com/hook","topics":["demo2.create"],"filter":"@collection.users.email != ''"}`,
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorStaffWebhooks:    400,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
			content: map[string][]string{
				actorStaffWebhooks: {`"validation_webhook_filter_forbidden"`},
			},
		},
		{
			name:   "webhook subscription create (filter with a system @collection secret field)",
			method: http.MethodPost,
			url:    "/api/collections/_webhooks/records",
			body:   `{"name":"w","uri":"https://example.com/hook","topics":["demo2.create"],"filter":"@collection._superusers.tokenKey != ''"}`,
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorStaffWebhooks:    400,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
			content: map[string][]string{
				actorStaffWebhooks: {`"validation_webhook_filter_forbidden"`},
			},
		},
		{
			name:   "webhook subscription create (custom topic)",
			method: http.MethodPost,
			url:    "/api/collections/_webhooks/records",
			body:   `{"name":"w","uri":"https://example.com/hook","topics":["orders.paid"]}`,
			expected: all(403, map[string]int{
				actorOwner:            200,
				actorStaffWebhooks:    200,
				actorGuest:            401, // deny by default (no client credentials)
				actorCustomerOtherKey: 401, // the token and the key clients mismatch
			}),
		},
		{
			name:     "webhook deliveries list",
			method:   http.MethodGet,
			url:      "/api/webhooks/deliveries",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200, actorStaffWebhooks: 200}),
		},
		{
			name:     "webhook deliveries stats",
			method:   http.MethodGet,
			url:      "/api/webhooks/deliveries/stats",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200, actorStaffWebhooks: 200}),
		},
		{
			name:     "llm providers",
			method:   http.MethodGet,
			url:      "/api/llm/providers",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200}),
		},
		{
			name:     "oauth2 clients secret",
			method:   http.MethodPost,
			url:      "/api/oauth2/clients/missing/rotate-secret",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 404}),
		},
		{
			name:     "roles list",
			method:   http.MethodGet,
			url:      "/api/roles",
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200}),
		},
		{
			name:     "sql (Owner only)",
			method:   http.MethodPost,
			url:      "/api/sql",
			body:     `{"query":"select 1 as a"}`,
			expected: all(403, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401, actorOwner: 200}),
		},
		{
			name:     "permissions me",
			method:   http.MethodGet,
			url:      "/api/permissions/me",
			expected: all(200, map[string]int{actorGuest: 401, actorGuestKey: 401, actorGuestReadKey: 401, actorCustomerOtherKey: 401}),
			content: map[string][]string{
				actorOwner:              {`"owner":true`, `"kind":"staff"`, `"roles":["Owner"]`},
				actorStaffLimited:       {`"owner":false`, `"kind":"staff"`, `"roles":["Limited staff"]`, `"logs":"read"`},
				actorCustomer:           {`"kind":"customer"`, `"roles":["Customer"]`},
				actorCustomerRestricted: {`"roles":["Restricted customer"]`},
				actorThirdParty:         {`"thirdParty":true`, `"scopes":["read_demo2"]`},
			},
		},
		// impersonation (token exchange; the actor_token is the actor token)
		{
			name:            "impersonate",
			method:          http.MethodPost,
			url:             "/oauth2/users/token",
			contentType:     "application/x-www-form-urlencoded",
			body:            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=pb_dashboard&subject_token=oap640cot4yru2s&subject_token_type=urn%3Apocketbase%3Aparams%3Aoauth%3Atoken-type%3Arecord_id&actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
			actorTokenField: "actor_token",
			expected:        all(400, map[string]int{actorOwner: 200}),
		},
	}

	for _, row := range rows {
		for _, actor := range rbacActors {
			expectedStatus, ok := row.expected[actor]
			if !ok {
				t.Fatalf("[%s] missing expected status for %q", row.name, actor)
			}

			headers := map[string]string{}
			if row.contentType != "" {
				headers["Content-Type"] = row.contentType
			}

			body := &strings.Builder{}

			scenario := tests.ApiScenario{
				Name:            row.name + " / " + actor,
				Method:          row.method,
				URL:             row.url,
				Headers:         headers,
				ExpectedStatus:  expectedStatus,
				ExpectedContent: row.content[actor],
				BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
					tokens, keys := rbacMatrixSetup(t, app, actor)

					token := tokens[actor]

					if key := keys[actor]; key != "" {
						headers[apis.APIKeyPublicHeader] = key
					}

					body.WriteString(row.body)
					if row.actorTokenField != "" {
						body.WriteString("&" + row.actorTokenField + "=" + url.QueryEscape(token))
					} else if token != "" {
						headers["Authorization"] = token
					}
				},
			}

			// the body is written in the BeforeTestFunc (after the tokens are generated)
			if row.body != "" || row.actorTokenField != "" {
				scenario.Body = &lazyReader{builder: body}
			}

			if len(row.content[actor]) == 0 {
				switch {
				case expectedStatus == 204:
					// empty body
				case expectedStatus >= 400 && row.actorTokenField != "":
					scenario.ExpectedContent = []string{`"error"`}
				case expectedStatus >= 400:
					scenario.ExpectedContent = []string{`"status"`}
				default:
					scenario.NotExpectedContent = []string{`"status":4`, `"status":5`}
				}
			}

			scenario.Test(t)
		}
	}
}

// lazyReader reads the builder content on the first Read call.
type lazyReader struct {
	builder *strings.Builder
	reader  *strings.Reader
}

func (r *lazyReader) Read(p []byte) (int, error) {
	if r.reader == nil {
		r.reader = strings.NewReader(r.builder.String())
	}
	return r.reader.Read(p)
}

func rbacThirdPartyToken(t *testing.T, app *tests.TestApp, scopes ...string) string {
	t.Helper()

	client := oauth2FindClient(t, app, "3p")
	client.SetScopes(append([]string{"openid"}, scopes...))
	if err := app.Save(client); err != nil {
		t.Fatal(err)
	}

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	token, _ := oauth2AccessToken(t, app, client, user, append([]string{"openid"}, scopes...))

	return token
}

func TestRBACAttackCustomerDefaultRoleSystemPermissions(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)
	b := newOAuth2Browser(t, app)

	// a (misconfigured) customer role with system permissions never grants them to non-staff
	role, err := tests.CreateRole(app, "customer_with_system", core.Permissions{
		Collections: map[string][]string{"*": {"list", "view"}},
		System: map[string]string{
			core.PermissionResourceLogs:     core.PermissionLevelWrite,
			core.PermissionResourceRoles:    core.PermissionLevelWrite,
			core.PermissionResourceSessions: core.PermissionLevelWrite,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	users, _ := app.FindCollectionByNameOrId("users")
	users.DefaultRoles = []string{role.Id}
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	token, err := tests.NewSessionAuthToken(app, user)
	if err != nil {
		t.Fatal(err)
	}

	for _, u := range []string{"/api/logs", "/api/roles", "/api/collections/_authSessions/records", "/api/collections/_roleAssignments/records"} {
		res, body := b.do(http.MethodGet, u, "", map[string]string{"Authorization": token})
		if res.StatusCode == http.StatusOK && !strings.Contains(body, `"items":[]`) {
			t.Fatalf("%s: expected no system access, got %d %s", u, res.StatusCode, body)
		}
	}

	// and the customer can't assign itself roles
	res, _ := b.do(http.MethodPost, "/api/collections/_roleAssignments/records", `{"collectionRef":"`+users.Id+`","recordRef":"`+user.Id+`","role":"`+role.Id+`"}`, map[string]string{
		"Content-Type":  "application/json",
		"Authorization": token,
	})
	if res.StatusCode == http.StatusOK {
		t.Fatal("Expected the self role assignment to be rejected")
	}
}

func TestSidlessAuthTokenIsRejectedByTheAPIs(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	superuser := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")

	sign := func(record *core.Record, claims jwt.MapClaims) string {
		base := jwt.MapClaims{
			core.TokenClaimType:         core.TokenTypeAuth,
			core.TokenClaimId:           record.Id,
			core.TokenClaimCollectionId: record.Collection().Id,
			"refreshable":               true,
		}
		for k, v := range claims {
			base[k] = v
		}
		token, err := security.NewJWT(base, record.TokenKey()+record.Collection().AuthToken.Secret, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	b := newOAuth2Browser(t, app)

	// authenticated actor API (401 without valid auth)
	res, body := b.do(http.MethodPost, "/api/collections/users/request-verification", "", map[string]string{"Authorization": sign(user, nil)})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for the sid-less user token, got %d %s", res.StatusCode, body)
	}

	// superuser only API
	for name, token := range map[string]string{
		"sid-less":            sign(superuser, nil),
		"sid-less with cid":   sign(superuser, jwt.MapClaims{core.TokenClaimOAuth2ClientId: core.OAuth2DashboardClientId}),
		"unknown sid":         sign(superuser, jwt.MapClaims{core.TokenClaimOAuth2SessionId: "missing", core.TokenClaimOAuth2ClientId: core.OAuth2DashboardClientId}),
		"installer token":     installerToken(t, app),
		"installer as Bearer": "Bearer " + installerToken(t, app),
	} {
		res, body := b.do(http.MethodGet, "/api/collections/_superusers/records", "", map[string]string{"Authorization": token})
		if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden {
			t.Fatalf("[%s] Expected 401/403, got %d %s", name, res.StatusCode, body)
		}
	}

	// the same superuser with a real session-backed token
	valid, err := tests.NewSessionAuthToken(app, superuser)
	if err != nil {
		t.Fatal(err)
	}
	res, body = b.do(http.MethodGet, "/api/collections/_superusers/records", "", map[string]string{"Authorization": valid})
	b.expectStatus(res, body, http.StatusOK)
}

func TestOAuth2TokenGuard(t *testing.T) {
	t.Parallel()

	type guardScenario struct {
		name            string
		method          string
		url             string
		body            string
		superuser       bool // use a superuser (staff issuer) third-party OAuth2 token (saved without validation)
		regularToken    bool // use a first-party client auth token (not restricted)
		expectedStatus  int
		expectedContent []string
		after           func(t testing.TB, app *tests.TestApp, res *http.Response, token string)
	}

	// note: the third-party restrictions are enforced by the RBAC model
	// (role permissions ∩ collection scopes; system permissions denied)
	// and by the guard (restricted routes and auth fields)
	forbidden := []string{`"status":403`}

	scenarios := []guardScenario{
		{
			name:           "request-email-change with first-party token (not restricted)",
			method:         http.MethodPost,
			url:            "/api/collections/users/request-email-change",
			body:           `{"newEmail":"new@example.com"}`,
			regularToken:   true,
			expectedStatus: 204,
		},
		// restricted routes
		{
			name:            "request-email-change",
			method:          http.MethodPost,
			url:             "/api/collections/users/request-email-change",
			body:            `{"newEmail":"new@example.com"}`,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "webhooks topics (superuser OAuth2 token)",
			method:          http.MethodGet,
			url:             "/api/webhooks/topics",
			superuser:       true,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "webhook secret reveal (superuser OAuth2 token)",
			method:          http.MethodGet,
			url:             "/api/webhooks/subscriptions/missing/secret",
			superuser:       true,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "webhook deliveries (superuser OAuth2 token)",
			method:          http.MethodGet,
			url:             "/api/webhooks/deliveries",
			superuser:       true,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "list _webhooks (superuser OAuth2 token)",
			method:          http.MethodGet,
			url:             "/api/collections/_webhooks/records",
			superuser:       true,
			expectedStatus:  403,
			expectedContent: forbidden,
		},

		// restricted collections
		{
			name:            "list _externalAuths",
			method:          http.MethodGet,
			url:             "/api/collections/_externalAuths/records",
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "list _externalAuths with regular token (not restricted)",
			method:          http.MethodGet,
			url:             "/api/collections/_externalAuths/records",
			regularToken:    true,
			expectedStatus:  200,
			expectedContent: []string{`"totalItems":2`},
		},
		{
			name:            "view own _externalAuths record",
			method:          http.MethodGet,
			url:             "/api/collections/_externalAuths/records/clmflokuq1xl341",
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "delete own _externalAuths record",
			method:          http.MethodDelete,
			url:             "/api/collections/_externalAuths/records/clmflokuq1xl341",
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "list _otps",
			method:          http.MethodGet,
			url:             "/api/collections/_otps/records",
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "generate client secret (superuser OAuth2 token)",
			method:          http.MethodPost,
			url:             "/api/oauth2/clients/missing/rotate-secret",
			superuser:       true,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "rotate signing key (superuser OAuth2 token)",
			method:          http.MethodPost,
			url:             "/api/oauth2/users/keys/rotate",
			superuser:       true,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "list _oauth2Clients (superuser OAuth2 token)",
			method:          http.MethodGet,
			url:             "/api/collections/_oauth2Clients/records",
			superuser:       true,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "create _oauth2Clients (superuser OAuth2 token)",
			method:          http.MethodPost,
			url:             "/api/collections/_oauth2Clients/records",
			body:            `{"name":"test"}`,
			superuser:       true,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "list _oauth2Consents",
			method:          http.MethodGet,
			url:             "/api/collections/_oauth2Consents/records",
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "list _authSessions (superuser OAuth2 token)",
			method:          http.MethodGet,
			url:             "/api/collections/_authSessions/records",
			superuser:       true,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "realtime subscription to a restricted collection",
			method:          http.MethodPost,
			url:             "/api/realtime",
			body:            `{"clientId":"missing","subscriptions":["users/4q1xlclmfloku33","_externalAuths/clmflokuq1xl341"]}`,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "realtime subscription to a non-restricted collection",
			method:          http.MethodPost,
			url:             "/api/realtime",
			body:            `{"clientId":"missing","subscriptions":["users/4q1xlclmfloku33"]}`,
			expectedStatus:  404, // missing client
			expectedContent: []string{`"data":{}`},
		},

		// restricted auth fields
		{
			name:            "update own non-restricted field",
			method:          http.MethodPatch,
			url:             "/api/collections/users/records/4q1xlclmfloku33",
			body:            `{"name":"new_name"}`,
			expectedStatus:  200,
			expectedContent: []string{`"name":"new_name"`},
		},
		{
			name:            "update own email",
			method:          http.MethodPatch,
			url:             "/api/collections/users/records/4q1xlclmfloku33",
			body:            `{"email":"new@example.com"}`,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "update own password",
			method:          http.MethodPatch,
			url:             "/api/collections/users/records/4q1xlclmfloku33",
			body:            `{"oldPassword":"1234567890","password":"1234567890new","passwordConfirm":"1234567890new"}`,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "update own emailVisibility",
			method:          http.MethodPatch,
			url:             "/api/collections/users/records/4q1xlclmfloku33",
			body:            `{"emailVisibility":true}`,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "update own emailVisibility with the same value",
			method:          http.MethodPatch,
			url:             "/api/collections/users/records/4q1xlclmfloku33",
			body:            `{"emailVisibility":false}`,
			expectedStatus:  200,
			expectedContent: []string{`"id":"4q1xlclmfloku33"`},
		},
		{
			name:            "update own verified",
			method:          http.MethodPatch,
			url:             "/api/collections/users/records/4q1xlclmfloku33",
			body:            `{"verified":true}`,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "update another user email (superuser OAuth2 token)",
			method:          http.MethodPatch,
			url:             "/api/collections/users/records/oap640cot4yru2s",
			body:            `{"email":"new@example.com"}`,
			superuser:       true,
			expectedStatus:  403,
			expectedContent: forbidden,
		},
		{
			name:            "batch update own email",
			method:          http.MethodPost,
			url:             "/api/batch",
			body:            `{"requests":[{"method":"PATCH","url":"/api/collections/users/records/4q1xlclmfloku33","body":{"email":"new@example.com"}}]}`,
			expectedStatus:  400,
			expectedContent: []string{`"status":403`, "OAuth2 access tokens are not allowed"},
			after: func(t testing.TB, app *tests.TestApp, res *http.Response, token string) {
				user, err := app.FindRecordById("users", "4q1xlclmfloku33")
				if err != nil {
					t.Fatal(err)
				}
				if user.Email() != "test@example.com" {
					t.Fatalf("Expected the email to remain unchanged, got %q", user.Email())
				}
			},
		},
		{
			name:            "batch create _externalAuths",
			method:          http.MethodPost,
			url:             "/api/batch",
			body:            `{"requests":[{"method":"POST","url":"/api/collections/_externalAuths/records","body":{"provider":"github"}}]}`,
			expectedStatus:  400,
			expectedContent: []string{`"status":403`},
		},
	}

	for _, s := range scenarios {
		headers := map[string]string{}
		var token string

		scenario := tests.ApiScenario{
			Name:            s.name,
			Method:          s.method,
			URL:             s.url,
			Body:            strings.NewReader(s.body),
			Headers:         headers,
			ExpectedStatus:  s.expectedStatus,
			ExpectedContent: s.expectedContent,
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				switch {
				case s.regularToken:
					var err error
					token, err = tests.NewSessionAuthToken(app, oauth2FindRecord(t, app, "users", "test@example.com"))
					if err != nil {
						t.Fatal(err)
					}
				case s.superuser:
					oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers)
					// note: the superusers issuer allows only first-party clients so the
					// third-party one is saved without validation (aka. defense in depth)
					client := core.NewOAuth2Client(app)
					client.SetName("staff 3p")
					client.SetClientId("staff3p")
					client.SetType(core.OAuth2ClientTypePublic)
					superusersCol, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
					client.SetCollectionRef(superusersCol.Id)
					client.SetRedirectURIs([]string{oauth2TestRedirectURI})
					client.SetScopes([]string{"openid"})
					if err := app.SaveNoValidate(client); err != nil {
						t.Fatal(err)
					}
					superuser, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
					if err != nil {
						t.Fatal(err)
					}
					token, _ = oauth2AccessToken(t, app, client, superuser, []string{"openid"})
				default:
					oauth2PrepareIssuer(t, app, "users")
					client := oauth2StubClient(t, app, "users", "app")
					// grant the users collection scopes so that the auth fields guard is reached
					client.SetScopes(append(client.Scopes(), "read_users", "write_users"))
					if err := app.Save(client); err != nil {
						t.Fatal(err)
					}
					token, _ = oauth2AccessToken(t, app, client, oauth2FindRecord(t, app, "users", "test@example.com"), []string{"openid", "email", "read_users", "write_users"})
				}

				headers["Authorization"] = token
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if s.after != nil {
					s.after(t, app, res, token)
				}
			},
		}

		scenario.Test(t)
	}
}

func TestLoadAuthTokenWithSessionTokens(t *testing.T) {
	t.Parallel()

	type scenario struct {
		name   string
		modify func(t testing.TB, app *tests.TestApp, session *core.AuthSession)
		status int
	}

	scenarios := []scenario{
		{name: "active session", status: 200},
		{
			name: "ended session",
			modify: func(t testing.TB, app *tests.TestApp, session *core.AuthSession) {
				_ = session.End()
				if err := app.Save(session); err != nil {
					t.Fatal(err)
				}
			},
			status: 401,
		},
		{
			name: "expired session",
			modify: func(t testing.TB, app *tests.TestApp, session *core.AuthSession) {
				session.SetExpiresAt(types.NowDateTime().Add(-time.Second))
				if err := app.Save(session); err != nil {
					t.Fatal(err)
				}
			},
			status: 401,
		},
		{
			name: "disabled client",
			modify: func(t testing.TB, app *tests.TestApp, session *core.AuthSession) {
				client := oauth2FindClient(t, app, "app")
				client.SetDisabled(true)
				if err := app.Save(client); err != nil {
					t.Fatal(err)
				}
			},
			status: 401,
		},
		{
			name: "deleted client",
			modify: func(t testing.TB, app *tests.TestApp, session *core.AuthSession) {
				if err := app.Delete(oauth2FindClient(t, app, "app")); err != nil {
					t.Fatal(err)
				}
			},
			status: 401,
		},
		{
			name: "password change",
			modify: func(t testing.TB, app *tests.TestApp, session *core.AuthSession) {
				user := oauth2FindRecord(t, app, "users", "test@example.com")
				user.SetPassword("new_password_123")
				if err := app.Save(user); err != nil {
					t.Fatal(err)
				}
			},
			status: 401,
		},
		{
			name: "ended root (non offline_access child)",
			modify: func(t testing.TB, app *tests.TestApp, session *core.AuthSession) {
				_, root := oauth2StubSSO(t, app, oauth2FindRecord(t, app, "users", "test@example.com"), types.NowDateTime())
				session.SetParent(root.Id)
				if err := app.Save(session); err != nil {
					t.Fatal(err)
				}
				_ = root.End()
				if err := app.Save(root); err != nil {
					t.Fatal(err)
				}
			},
			status: 401,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app, _ := tests.NewTestApp()
			defer app.Cleanup()

			oauth2AuthorizeSetup(t, app)

			user := oauth2FindRecord(t, app, "users", "test@example.com")
			token, session := oauth2AccessToken(t, app, oauth2FindClient(t, app, "app"), user, []string{"openid"})

			if s.modify != nil {
				s.modify(t, app, session)
			}

			// the users view rule is "id = @request.auth.id"; a rejected token makes the request
			// anonymous and therefore it is denied by default (401 missing_client_credentials)
			b := newOAuth2Browser(t, app)
			res, body := b.do(http.MethodGet, "/api/collections/users/records/"+user.Id, "", map[string]string{"Authorization": token})
			b.expectStatus(res, body, s.status)
			if s.status == 401 && !strings.Contains(body, "missing_client_credentials") {
				t.Fatalf("Expected missing_client_credentials error, got %s", body)
			}
		})
	}
}
