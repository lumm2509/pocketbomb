package apis_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/pocketbase/dbx"
)

func TestRecordCrudSuperuserList(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodGet,
			URL:             "/api/collections/" + core.CollectionNameSuperusers + "/records",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "non-superusers auth",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameSuperusers + "/records",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superusers auth",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameSuperusers + "/records",
			Headers: map[string]string{
				// _superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":4`,
				`"items":[{`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       4,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudSuperuserView(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodGet,
			URL:             "/api/collections/" + core.CollectionNameSuperusers + "/records/sywbhecnh46rhm0",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "non-superusers auth",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameSuperusers + "/records/sywbhecnh46rhm0",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superusers auth",
			Method: http.MethodGet,
			URL:    "/api/collections/" + core.CollectionNameSuperusers + "/records/sywbhecnh46rhm0",
			Headers: map[string]string{
				// _superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"sywbhecnh46rhm0"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudSuperuserDelete(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodDelete,
			URL:             "/api/collections/" + core.CollectionNameSuperusers + "/records/sbmbsdb40jyxf7h",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "non-superusers auth",
			Method: http.MethodDelete,
			URL:    "/api/collections/" + core.CollectionNameSuperusers + "/records/sbmbsdb40jyxf7h",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superusers auth",
			Method: http.MethodDelete,
			URL:    "/api/collections/" + core.CollectionNameSuperusers + "/records/sbmbsdb40jyxf7h",
			Headers: map[string]string{
				// _superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordDeleteRequest":      1,
				"OnModelDelete":              5, // + 3 AuthOrigins + 1 Owner role assignment
				"OnModelDeleteExecute":       5,
				"OnModelAfterDeleteSuccess":  5,
				"OnRecordDelete":             5,
				"OnRecordDeleteExecute":      5,
				"OnRecordAfterDeleteSuccess": 5,
			},
		},
		{
			Name:   "delete the last superuser",
			Method: http.MethodDelete,
			URL:    "/api/collections/" + core.CollectionNameSuperusers + "/records/sywbhecnh46rhm0",
			Headers: map[string]string{
				// _superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				// delete all other superusers
				superusers, err := app.FindAllRecords(core.CollectionNameSuperusers, dbx.Not(dbx.HashExp{"id": "sywbhecnh46rhm0"}))
				if err != nil {
					t.Fatal(err)
				}
				for _, superuser := range superusers {
					if err = app.Delete(superuser); err != nil {
						t.Fatal(err)
					}
				}
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordDeleteRequest":    1,
				"OnModelDelete":            1,
				"OnModelAfterDeleteError":  1,
				"OnRecordDelete":           1,
				"OnRecordAfterDeleteError": 1,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudSuperuserCreate(t *testing.T) {
	t.Parallel()

	body := func() *strings.Reader {
		return strings.NewReader(`{
			"email":           "test_new@example.com",
			"password":        "1234567890",
			"passwordConfirm": "1234567890",
			"verified":        false
		}`)
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodPost,
			URL:             "/api/collections/" + core.CollectionNameSuperusers + "/records",
			Headers:         tests.PublicAPIKeyHeaders(),
			Body:            body(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "non-superusers auth",
			Method: http.MethodPost,
			URL:    "/api/collections/" + core.CollectionNameSuperusers + "/records",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			Body:            body(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superusers auth",
			Method: http.MethodPost,
			URL:    "/api/collections/" + core.CollectionNameSuperusers + "/records",
			Headers: map[string]string{
				// _superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			Body: body(),
			ExpectedContent: []string{
				`"collectionName":"_superusers"`,
				`"email":"test_new@example.com"`,
				`"verified":true`,
			},
			ExpectedStatus: 200,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnRecordEnrich":             1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnModelValidate":            1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnRecordValidate":           1,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudSuperuserUpdate(t *testing.T) {
	t.Parallel()

	body := func() *strings.Reader {
		return strings.NewReader(`{
			"email":    "test_new@example.com",
			"verified": true
		}`)
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodPatch,
			URL:             "/api/collections/" + core.CollectionNameSuperusers + "/records/sywbhecnh46rhm0",
			Headers:         tests.PublicAPIKeyHeaders(),
			Body:            body(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "non-superusers auth",
			Method: http.MethodPatch,
			URL:    "/api/collections/" + core.CollectionNameSuperusers + "/records/sywbhecnh46rhm0",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			Body:            body(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superusers auth",
			Method: http.MethodPatch,
			URL:    "/api/collections/" + core.CollectionNameSuperusers + "/records/sywbhecnh46rhm0",
			Headers: map[string]string{
				// _superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			Body: body(),
			ExpectedContent: []string{
				`"collectionName":"_superusers"`,
				`"id":"sywbhecnh46rhm0"`,
				`"email":"test_new@example.com"`,
				`"verified":true`,
			},
			ExpectedStatus: 200,
			// note: the email change refreshes the tokenKey which ends
			// the actor auth sessions (aka. +2 updates for the root and child session)
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnRecordEnrich":             1,
				"OnModelUpdate":              3,
				"OnModelUpdateExecute":       3,
				"OnModelAfterUpdateSuccess":  3,
				"OnModelValidate":            3,
				"OnRecordUpdate":             3,
				"OnRecordUpdateExecute":      3,
				"OnRecordAfterUpdateSuccess": 3,
				"OnRecordValidate":           3,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}
