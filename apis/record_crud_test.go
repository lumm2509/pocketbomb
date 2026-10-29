package apis_test

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/types"
)

func TestRecordCrudList(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "missing collection",
			Method:          http.MethodGet,
			URL:             "/api/collections/missing/records",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "unauthenticated trying to access nil rule collection (aka. need superuser auth)",
			Method:          http.MethodGet,
			URL:             "/api/collections/demo1/records",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authenticated record trying to access nil rule collection (aka. need superuser auth)",
			Method: http.MethodGet,
			URL:    "/api/collections/demo1/records",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "public collection but with superuser only filter param (aka. @collection, @request, etc.)",
			Method:          http.MethodGet,
			URL:             "/api/collections/demo2/records?filter=%40collection.demo2.title='test1'",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "public collection but with superuser only sort param (aka. @collection, @request, etc.)",
			Method:          http.MethodGet,
			URL:             "/api/collections/demo2/records?sort=@request.auth.title",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "public collection but with ENCODED superuser only filter/sort (aka. @collection)",
			Method:          http.MethodGet,
			URL:             "/api/collections/demo2/records?filter=%40collection.demo2.title%3D%27test1%27",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "public collection",
			Method:         http.MethodGet,
			URL:            "/api/collections/demo2/records",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":3`,
				`"items":[{`,
				`"id":"0yxhwia2amd8gec"`,
				`"id":"achvryl401bhse3"`,
				`"id":"llvuca81nly1qls"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       3,
			},
		},
		{
			Name:           "public collection (using the collection id)",
			Method:         http.MethodGet,
			URL:            "/api/collections/sz5l5z67tg7gku0/records",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":3`,
				`"items":[{`,
				`"id":"0yxhwia2amd8gec"`,
				`"id":"achvryl401bhse3"`,
				`"id":"llvuca81nly1qls"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       3,
			},
		},
		{
			Name:   "authorized as superuser trying to access nil rule collection (aka. need superuser auth)",
			Method: http.MethodGet,
			URL:    "/api/collections/demo1/records",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":3`,
				`"items":[{`,
				`"id":"al1h9ijdeojtsjy"`,
				`"id":"84nmscqy84lsi1t"`,
				`"id":"imy661ixudk5izi"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       3,
			},
		},
		{
			Name:   "valid query params",
			Method: http.MethodGet,
			URL:    "/api/collections/demo1/records?filter=text~'test'&sort=-bool",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalItems":2`,
				`"items":[{`,
				`"id":"al1h9ijdeojtsjy"`,
				`"id":"84nmscqy84lsi1t"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       2,
			},
		},
		{
			Name:   "invalid filter",
			Method: http.MethodGet,
			URL:    "/api/collections/demo1/records?filter=invalid~'test'",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "expand relations",
			Method: http.MethodGet,
			URL:    "/api/collections/demo1/records?expand=rel_one,rel_many.rel,missing&perPage=2&sort=created",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":2`,
				`"totalPages":2`,
				`"totalItems":3`,
				`"items":[{`,
				`"collectionName":"demo1"`,
				`"id":"84nmscqy84lsi1t"`,
				`"id":"al1h9ijdeojtsjy"`,
				`"expand":{`,
				`"rel_one":""`,
				`"rel_one":{"`,
				`"rel_many":[{`,
				`"rel":{`,
				`"rel":""`,
				`"json":[1,2,3]`,
				`"select_many":["optionB","optionC"]`,
				`"select_many":["optionB"]`,
				// subrel items
				`"id":"0yxhwia2amd8gec"`,
				`"id":"llvuca81nly1qls"`,
				// email visibility should be ignored for superusers even in expanded rels
				`"email":"test@example.com"`,
				`"email":"test2@example.com"`,
				`"email":"test3@example.com"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       8,
			},
		},
		{
			Name:   "authenticated record model that DOESN'T match the collection list rule",
			Method: http.MethodGet,
			URL:    "/api/collections/demo3/records",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalItems":0`,
				`"items":[]`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
			},
		},
		{
			Name:   "authenticated record that matches the collection list rule",
			Method: http.MethodGet,
			URL:    "/api/collections/demo3/records",
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": tests.AuthToken("clients", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":4`,
				`"items":[{`,
				`"id":"1tmknxy2868d869"`,
				`"id":"lcl9d87w22ml6jy"`,
				`"id":"7nwo8tuiatetxdm"`,
				`"id":"mk5fmymtx4wsprk"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       4,
			},
		},
		{
			Name:   "authenticated regular record that matches the collection list rule with hidden field",
			Method: http.MethodGet,
			URL:    "/api/collections/demo3/records",
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": tests.AuthToken("clients", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				col, err := app.FindCollectionByNameOrId("demo3")
				if err != nil {
					t.Fatal(err)
				}

				// mock hidden field
				col.Fields.GetByName("title").SetHidden(true)

				col.ListRule = types.Pointer("title ~ 'test'")

				if err = app.Save(col); err != nil {
					t.Fatal(err)
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":4`,
				`"items":[{`,
				`"id":"1tmknxy2868d869"`,
				`"id":"lcl9d87w22ml6jy"`,
				`"id":"7nwo8tuiatetxdm"`,
				`"id":"mk5fmymtx4wsprk"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       4,
			},
		},
		{
			Name:   "authenticated regular record filtering with a hidden field",
			Method: http.MethodGet,
			URL:    "/api/collections/demo3/records?filter=title~'test'",
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": tests.AuthToken("clients", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				col, err := app.FindCollectionByNameOrId("demo3")
				if err != nil {
					t.Fatal(err)
				}

				// mock hidden field
				col.Fields.GetByName("title").SetHidden(true)

				if err = app.Save(col); err != nil {
					t.Fatal(err)
				}
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superuser filtering with a hidden field",
			Method: http.MethodGet,
			URL:    "/api/collections/demo3/records?filter=title~'test'",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				col, err := app.FindCollectionByNameOrId("demo3")
				if err != nil {
					t.Fatal(err)
				}

				// mock hidden field
				col.Fields.GetByName("title").SetHidden(true)

				if err = app.Save(col); err != nil {
					t.Fatal(err)
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":4`,
				`"items":[{`,
				`"id":"1tmknxy2868d869"`,
				`"id":"lcl9d87w22ml6jy"`,
				`"id":"7nwo8tuiatetxdm"`,
				`"id":"mk5fmymtx4wsprk"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       4,
			},
		},
		{
			Name:           ":rule modifer",
			Method:         http.MethodGet,
			URL:            "/api/collections/demo5/records",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":1`,
				`"items":[{`,
				`"id":"qjeql998mtp1azp"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       1,
			},
		},
		{
			Name:           "multi-match - at least one of (guest - non-satisfied relation filter API rule)",
			Method:         http.MethodGet,
			URL:            "/api/collections/demo4/records?filter=" + url.QueryEscape("rel_many_no_cascade_required.files:length?=2"),
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":0`,
				`"totalItems":0`,
				`"items":[]`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       0,
			},
		},
		{
			Name:   "multi-match - at least one of (clients)",
			Method: http.MethodGet,
			URL:    "/api/collections/demo4/records?filter=" + url.QueryEscape("rel_many_no_cascade_required.files:length?=2"),
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": tests.AuthToken("clients", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":1`,
				`"items":[{`,
				`"id":"qzaqccwrmva4o1n"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       1,
			},
		},
		{
			Name:   "multi-match - all (clients)",
			Method: http.MethodGet,
			URL:    "/api/collections/demo4/records?filter=" + url.QueryEscape("rel_many_no_cascade_required.files:length=2"),
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": tests.AuthToken("clients", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":0`,
				`"totalItems":0`,
				`"items":[]`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
			},
		},
		{
			Name:   "OnRecordsListRequest tx body write check",
			Method: http.MethodGet,
			URL:    "/api/collections/demo4/records",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnRecordsListRequest().BindFunc(func(e *core.RecordsListRequestEvent) error {
					original := e.App
					return e.App.RunInTransaction(func(txApp core.App) error {
						e.App = txApp
						defer func() { e.App = original }()

						if err := e.Next(); err != nil {
							return err
						}

						return e.BadRequestError("TX_ERROR", nil)
					})
				})
			},
			ExpectedStatus:  400,
			ExpectedEvents:  map[string]int{"OnRecordsListRequest": 1},
			ExpectedContent: []string{"TX_ERROR"},
		},

		// auth collection
		// -----------------------------------------------------------
		{
			Name:           "check email visibility as guest",
			Method:         http.MethodGet,
			URL:            "/api/collections/nologin/records",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":3`,
				`"items":[{`,
				`"id":"phhq3wr65cap535"`,
				`"id":"dc49k6jgejn40h3"`,
				`"id":"oos036e9xvqeexy"`,
				`"email":"test2@example.com"`,
				`"emailVisibility":true`,
				`"emailVisibility":false`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
				`"email":"test@example.com"`,
				`"email":"test3@example.com"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       3,
			},
		},
		{
			Name:   "check email visibility as any authenticated record",
			Method: http.MethodGet,
			URL:    "/api/collections/nologin/records",
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": tests.AuthToken("clients", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":3`,
				`"items":[{`,
				`"id":"phhq3wr65cap535"`,
				`"id":"dc49k6jgejn40h3"`,
				`"id":"oos036e9xvqeexy"`,
				`"email":"test2@example.com"`,
				`"emailVisibility":true`,
				`"emailVisibility":false`,
			},
			NotExpectedContent: []string{
				`"tokenKey":"`,
				`"password":""`,
				`"email":"test@example.com"`,
				`"email":"test3@example.com"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       3,
			},
		},
		{
			Name:   "check email visibility as manage auth record",
			Method: http.MethodGet,
			URL:    "/api/collections/nologin/records",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":3`,
				`"items":[{`,
				`"id":"phhq3wr65cap535"`,
				`"id":"dc49k6jgejn40h3"`,
				`"id":"oos036e9xvqeexy"`,
				`"email":"test@example.com"`,
				`"email":"test2@example.com"`,
				`"email":"test3@example.com"`,
				`"emailVisibility":true`,
				`"emailVisibility":false`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       3,
			},
		},
		{
			Name:   "check email visibility as superuser",
			Method: http.MethodGet,
			URL:    "/api/collections/nologin/records",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":3`,
				`"items":[{`,
				`"id":"phhq3wr65cap535"`,
				`"id":"dc49k6jgejn40h3"`,
				`"id":"oos036e9xvqeexy"`,
				`"email":"test@example.com"`,
				`"email":"test2@example.com"`,
				`"email":"test3@example.com"`,
				`"emailVisibility":true`,
				`"emailVisibility":false`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       3,
			},
		},
		{
			Name:   "check self email visibility resolver",
			Method: http.MethodGet,
			URL:    "/api/collections/nologin/records",
			Headers: map[string]string{
				// nologin, test@example.com
				"Authorization": tests.AuthToken("nologin", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":3`,
				`"items":[{`,
				`"id":"phhq3wr65cap535"`,
				`"id":"dc49k6jgejn40h3"`,
				`"id":"oos036e9xvqeexy"`,
				`"email":"test2@example.com"`,
				`"email":"test@example.com"`,
				`"emailVisibility":true`,
				`"emailVisibility":false`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
				`"email":"test3@example.com"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       3,
			},
		},

		// view collection
		// -----------------------------------------------------------
		{
			Name:           "public view records",
			Method:         http.MethodGet,
			URL:            "/api/collections/view2/records?filter=state=false",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":2`,
				`"items":[{`,
				`"id":"al1h9ijdeojtsjy"`,
				`"id":"imy661ixudk5izi"`,
			},
			NotExpectedContent: []string{
				`"created"`,
				`"updated"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       2,
			},
		},
		{
			Name:           "guest that doesn't match the view collection list rule",
			Method:         http.MethodGet,
			URL:            "/api/collections/view1/records",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":0`,
				`"totalItems":0`,
				`"items":[]`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
			},
		},
		{
			Name:   "authenticated record that matches the view collection list rule",
			Method: http.MethodGet,
			URL:    "/api/collections/view1/records",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":1`,
				`"items":[{`,
				`"id":"84nmscqy84lsi1t"`,
				`"bool":true`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       1,
			},
		},
		{
			Name:           "view collection with numeric ids",
			Method:         http.MethodGet,
			URL:            "/api/collections/numeric_id_view/records",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalPages":1`,
				`"totalItems":2`,
				`"items":[{`,
				`"id":"1"`,
				`"id":"2"`,
			},
			ExpectedEvents: map[string]int{
				"*":                    0,
				"OnRecordsListRequest": 1,
				"OnRecordEnrich":       2,
			},
		},

		// rate limit checks
		// -----------------------------------------------------------
		{
			Name:    "RateLimit rule - view2:list",
			Method:  http.MethodGet,
			URL:     "/api/collections/view2/records",
			Headers: tests.PublicAPIKeyHeaders(),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 100, Label: "*:list"},
					{MaxRequests: 0, Label: "view2:list"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:    "RateLimit rule - *:list",
			Method:  http.MethodGet,
			URL:     "/api/collections/view2/records",
			Headers: tests.PublicAPIKeyHeaders(),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 0, Label: "*:list"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudView(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "missing collection",
			Method:          http.MethodGet,
			URL:             "/api/collections/missing/records/0yxhwia2amd8gec",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "missing record",
			Method:          http.MethodGet,
			URL:             "/api/collections/demo2/records/missing",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "unauthenticated trying to access nil rule collection (aka. need superuser auth)",
			Method:          http.MethodGet,
			URL:             "/api/collections/demo1/records/imy661ixudk5izi",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authenticated record trying to access nil rule collection (aka. need superuser auth)",
			Method: http.MethodGet,
			URL:    "/api/collections/demo1/records/imy661ixudk5izi",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authenticated record that doesn't match the collection view rule",
			Method: http.MethodGet,
			URL:    "/api/collections/users/records/bgs820n361vj1qd",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "public collection view",
			Method:         http.MethodGet,
			URL:            "/api/collections/demo2/records/0yxhwia2amd8gec",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"0yxhwia2amd8gec"`,
				`"collectionName":"demo2"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
		{
			Name:           "public collection view (using the collection id)",
			Method:         http.MethodGet,
			URL:            "/api/collections/sz5l5z67tg7gku0/records/0yxhwia2amd8gec",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"0yxhwia2amd8gec"`,
				`"collectionName":"demo2"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
		{
			Name:   "authorized as superuser trying to access nil rule collection view (aka. need superuser auth)",
			Method: http.MethodGet,
			URL:    "/api/collections/demo1/records/imy661ixudk5izi",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"imy661ixudk5izi"`,
				`"collectionName":"demo1"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
		{
			Name:   "authenticated record that does match the collection view rule",
			Method: http.MethodGet,
			URL:    "/api/collections/users/records/4q1xlclmfloku33",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"4q1xlclmfloku33"`,
				`"collectionName":"users"`,
				// owners can always view their email
				`"emailVisibility":false`,
				`"email":"test@example.com"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
		{
			Name:   "expand relations",
			Method: http.MethodGet,
			URL:    "/api/collections/demo1/records/al1h9ijdeojtsjy?expand=rel_one,rel_many.rel,missing&perPage=2&sort=created",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"al1h9ijdeojtsjy"`,
				`"collectionName":"demo1"`,
				`"rel_many":[{`,
				`"rel_one":{`,
				`"collectionName":"users"`,
				`"id":"bgs820n361vj1qd"`,
				`"expand":{"rel":{`,
				`"id":"0yxhwia2amd8gec"`,
				`"collectionName":"demo2"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      7,
			},
		},
		{
			Name:   "OnRecordViewRequest tx body write check",
			Method: http.MethodGet,
			URL:    "/api/collections/demo1/records/al1h9ijdeojtsjy",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnRecordViewRequest().BindFunc(func(e *core.RecordRequestEvent) error {
					original := e.App
					return e.App.RunInTransaction(func(txApp core.App) error {
						e.App = txApp
						defer func() { e.App = original }()

						if err := e.Next(); err != nil {
							return err
						}

						return e.BadRequestError("TX_ERROR", nil)
					})
				})
			},
			ExpectedStatus:  400,
			ExpectedEvents:  map[string]int{"OnRecordViewRequest": 1},
			ExpectedContent: []string{"TX_ERROR"},
		},

		// auth collection
		// -----------------------------------------------------------
		{
			Name:           "check email visibility as guest",
			Method:         http.MethodGet,
			URL:            "/api/collections/nologin/records/oos036e9xvqeexy",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"oos036e9xvqeexy"`,
				`"emailVisibility":false`,
				`"verified":true`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
				`"email":"test3@example.com"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
		{
			Name:   "check email visibility as any authenticated record",
			Method: http.MethodGet,
			URL:    "/api/collections/nologin/records/oos036e9xvqeexy",
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": tests.AuthToken("clients", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"oos036e9xvqeexy"`,
				`"emailVisibility":false`,
				`"verified":true`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
				`"email":"test3@example.com"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
		{
			Name:   "check email visibility as manage auth record",
			Method: http.MethodGet,
			URL:    "/api/collections/nologin/records/oos036e9xvqeexy",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"oos036e9xvqeexy"`,
				`"emailVisibility":false`,
				`"email":"test3@example.com"`,
				`"verified":true`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
		{
			Name:   "check email visibility as superuser",
			Method: http.MethodGet,
			URL:    "/api/collections/nologin/records/oos036e9xvqeexy",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"oos036e9xvqeexy"`,
				`"emailVisibility":false`,
				`"email":"test3@example.com"`,
				`"verified":true`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
		{
			Name:   "check self email visibility resolver",
			Method: http.MethodGet,
			URL:    "/api/collections/nologin/records/dc49k6jgejn40h3",
			Headers: map[string]string{
				// nologin, test@example.com
				"Authorization": tests.AuthToken("nologin", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"dc49k6jgejn40h3"`,
				`"email":"test@example.com"`,
				`"emailVisibility":false`,
				`"verified":false`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},

		// view collection
		// -----------------------------------------------------------
		{
			Name:           "public view record",
			Method:         http.MethodGet,
			URL:            "/api/collections/view2/records/84nmscqy84lsi1t",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"84nmscqy84lsi1t"`,
				`"state":true`,
				`"file_many":["`,
				`"rel_many":["`,
			},
			NotExpectedContent: []string{
				`"created"`,
				`"updated"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
		{
			Name:            "guest that doesn't match the view collection view rule",
			Method:          http.MethodGet,
			URL:             "/api/collections/view1/records/84nmscqy84lsi1t",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authenticated record that matches the view collection view rule",
			Method: http.MethodGet,
			URL:    "/api/collections/view1/records/84nmscqy84lsi1t",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"84nmscqy84lsi1t"`,
				`"bool":true`,
				`"text":"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},
		{
			Name:           "view record with numeric id",
			Method:         http.MethodGet,
			URL:            "/api/collections/numeric_id_view/records/1",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"1"`,
			},
			ExpectedEvents: map[string]int{
				"*":                   0,
				"OnRecordViewRequest": 1,
				"OnRecordEnrich":      1,
			},
		},

		// rate limit checks
		// -----------------------------------------------------------
		{
			Name:    "RateLimit rule - numeric_id_view:view",
			Method:  http.MethodGet,
			URL:     "/api/collections/numeric_id_view/records/1",
			Headers: tests.PublicAPIKeyHeaders(),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 100, Label: "*:view"},
					{MaxRequests: 0, Label: "numeric_id_view:view"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:    "RateLimit rule - *:view",
			Method:  http.MethodGet,
			URL:     "/api/collections/numeric_id_view/records/1",
			Headers: tests.PublicAPIKeyHeaders(),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 0, Label: "*:view"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudDelete(t *testing.T) {
	t.Parallel()

	ensureDeletedFiles := func(app *tests.TestApp, collectionId string, recordId string) {
		storageDir := filepath.Join(app.DataDir(), "storage", collectionId, recordId)

		entries, _ := os.ReadDir(storageDir)
		if len(entries) != 0 {
			t.Errorf("Expected empty/deleted dir, found: %d\n%v", len(entries), entries)
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "missing collection",
			Method:          http.MethodDelete,
			URL:             "/api/collections/missing/records/0yxhwia2amd8gec",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "missing record",
			Method:          http.MethodDelete,
			URL:             "/api/collections/demo2/records/missing",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "unauthenticated trying to delete nil rule collection (aka. need superuser auth)",
			Method:          http.MethodDelete,
			URL:             "/api/collections/demo1/records/imy661ixudk5izi",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authenticated record trying to delete nil rule collection (aka. need superuser auth)",
			Method: http.MethodDelete,
			URL:    "/api/collections/demo1/records/imy661ixudk5izi",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "authenticated record that doesn't match the collection delete rule",
			Method: http.MethodDelete,
			URL:    "/api/collections/users/records/bgs820n361vj1qd",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "trying to delete a view collection record",
			Method:          http.MethodDelete,
			URL:             "/api/collections/view1/records/imy661ixudk5izi",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "public collection record delete",
			Method:         http.MethodDelete,
			URL:            "/api/collections/nologin/records/dc49k6jgejn40h3",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordDeleteRequest":      1,
				"OnModelDelete":              1,
				"OnModelDeleteExecute":       1,
				"OnModelAfterDeleteSuccess":  1,
				"OnRecordDelete":             1,
				"OnRecordDeleteExecute":      1,
				"OnRecordAfterDeleteSuccess": 1,
			},
		},
		{
			Name:           "public collection record delete (using the collection id as identifier)",
			Method:         http.MethodDelete,
			URL:            "/api/collections/kpv709sk2lqbqk8/records/dc49k6jgejn40h3",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordDeleteRequest":      1,
				"OnModelDelete":              1,
				"OnModelDeleteExecute":       1,
				"OnModelAfterDeleteSuccess":  1,
				"OnRecordDelete":             1,
				"OnRecordDeleteExecute":      1,
				"OnRecordAfterDeleteSuccess": 1,
			},
		},
		{
			Name:   "authorized as superuser trying to delete nil rule collection view (aka. need superuser auth)",
			Method: http.MethodDelete,
			URL:    "/api/collections/clients/records/o1y0dd0spd786md",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordDeleteRequest":      1,
				"OnModelDelete":              1,
				"OnModelDeleteExecute":       1,
				"OnModelAfterDeleteSuccess":  1,
				"OnRecordDelete":             1,
				"OnRecordDeleteExecute":      1,
				"OnRecordAfterDeleteSuccess": 1,
			},
		},
		{
			Name:   "OnRecordDeleteRequest tx body write check",
			Method: http.MethodDelete,
			URL:    "/api/collections/clients/records/o1y0dd0spd786md",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnRecordDeleteRequest().BindFunc(func(e *core.RecordRequestEvent) error {
					original := e.App
					return e.App.RunInTransaction(func(txApp core.App) error {
						e.App = txApp
						defer func() { e.App = original }()

						if err := e.Next(); err != nil {
							return err
						}

						return e.BadRequestError("TX_ERROR", nil)
					})
				})
			},
			ExpectedStatus:  400,
			ExpectedEvents:  map[string]int{"OnRecordDeleteRequest": 1},
			ExpectedContent: []string{"TX_ERROR"},
		},
		{
			Name:   "authenticated record that match the collection delete rule",
			Method: http.MethodDelete,
			URL:    "/api/collections/users/records/4q1xlclmfloku33",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			Delay:          100 * time.Millisecond,
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordDeleteRequest":      1,
				"OnModelDelete":              5, // +2 for the externalAuths and +2 for the actor root and child auth sessions
				"OnModelDeleteExecute":       5,
				"OnModelAfterDeleteSuccess":  5,
				"OnRecordDelete":             5,
				"OnRecordDeleteExecute":      5,
				"OnRecordAfterDeleteSuccess": 5,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnRecordUpdateExecute":      1,
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				ensureDeletedFiles(app, "_pb_users_auth_", "4q1xlclmfloku33")

				// check if all the external auths records were deleted
				collection, _ := app.FindCollectionByNameOrId("users")
				record := core.NewRecord(collection)
				record.Set("id", "4q1xlclmfloku33")
				externalAuths, err := app.FindAllExternalAuthsByRecord(record)
				if err != nil {
					t.Errorf("Failed to fetch external auths: %v", err)
				}
				if len(externalAuths) > 0 {
					t.Errorf("Expected the linked external auths to be deleted, got %d", len(externalAuths))
				}
			},
		},
		{
			Name:            "@request :isset (rule failure check)",
			Method:          http.MethodDelete,
			URL:             "/api/collections/demo5/records/la4y2w4o98acwuj",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "@request :isset (rule pass check)",
			Method:         http.MethodDelete,
			URL:            "/api/collections/demo5/records/la4y2w4o98acwuj?test=1",
			Headers:        tests.PublicAPIKeyHeaders(),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordDeleteRequest":      1,
				"OnModelDelete":              1,
				"OnModelDeleteExecute":       1,
				"OnModelAfterDeleteSuccess":  1,
				"OnRecordDelete":             1,
				"OnRecordDeleteExecute":      1,
				"OnRecordAfterDeleteSuccess": 1,
			},
		},

		// cascade delete checks
		// -----------------------------------------------------------
		{
			Name:   "trying to delete a record while being part of a non-cascade required relation",
			Method: http.MethodDelete,
			URL:    "/api/collections/demo3/records/7nwo8tuiatetxdm",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordDeleteRequest":    1,
				"OnModelDelete":            2, // the record itself + rel_one_cascade of test1 record
				"OnModelDeleteExecute":     2,
				"OnModelAfterDeleteError":  2,
				"OnRecordDelete":           2,
				"OnRecordDeleteExecute":    2,
				"OnRecordAfterDeleteError": 2,
				"OnModelUpdate":            2, // self_rel_many update of test1 record + rel_one_cascade demo4 cascaded in demo5
				"OnModelUpdateExecute":     2,
				"OnModelAfterUpdateError":  2,
				"OnRecordUpdate":           2,
				"OnRecordUpdateExecute":    2,
				"OnRecordAfterUpdateError": 2,
			},
		},
		{
			Name:   "delete a record with non-cascade references",
			Method: http.MethodDelete,
			URL:    "/api/collections/demo3/records/1tmknxy2868d869",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordDeleteRequest":      1,
				"OnModelDelete":              1,
				"OnModelDeleteExecute":       1,
				"OnModelAfterDeleteSuccess":  1,
				"OnRecordDelete":             1,
				"OnRecordDeleteExecute":      1,
				"OnRecordAfterDeleteSuccess": 1,
				"OnModelUpdate":              2,
				"OnModelUpdateExecute":       2,
				"OnModelAfterUpdateSuccess":  2,
				"OnRecordUpdate":             2,
				"OnRecordUpdateExecute":      2,
				"OnRecordAfterUpdateSuccess": 2,
			},
		},
		{
			Name:   "delete a record with cascade references",
			Method: http.MethodDelete,
			URL:    "/api/collections/users/records/oap640cot4yru2s",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			Delay:          100 * time.Millisecond,
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordDeleteRequest":      1,
				"OnModelDelete":              2,
				"OnModelDeleteExecute":       2,
				"OnModelAfterDeleteSuccess":  2,
				"OnRecordDelete":             2,
				"OnRecordDeleteExecute":      2,
				"OnRecordAfterDeleteSuccess": 2,
				"OnModelUpdate":              2,
				"OnModelUpdateExecute":       2,
				"OnModelAfterUpdateSuccess":  2,
				"OnRecordUpdate":             2,
				"OnRecordUpdateExecute":      2,
				"OnRecordAfterUpdateSuccess": 2,
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				recId := "84nmscqy84lsi1t"
				rec, _ := app.FindRecordById("demo1", recId, nil)
				if rec != nil {
					t.Errorf("Expected record %s to be cascade deleted", recId)
				}
				ensureDeletedFiles(app, "wsmn24bux7wo113", recId)
				ensureDeletedFiles(app, "_pb_users_auth_", "oap640cot4yru2s")
			},
		},

		// rate limit checks
		// -----------------------------------------------------------
		{
			Name:    "RateLimit rule - demo5:delete",
			Method:  http.MethodDelete,
			URL:     "/api/collections/demo5/records/la4y2w4o98acwuj?test=1",
			Headers: tests.PublicAPIKeyHeaders(),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 100, Label: "*:delete"},
					{MaxRequests: 0, Label: "demo5:delete"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:    "RateLimit rule - *:delete",
			Method:  http.MethodDelete,
			URL:     "/api/collections/demo5/records/la4y2w4o98acwuj?test=1",
			Headers: tests.PublicAPIKeyHeaders(),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 0, Label: "*:delete"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudCreate(t *testing.T) {
	t.Parallel()

	formData, mp, err := tests.MockMultipartData(map[string]string{
		"title": "title_test",
	}, "files")
	if err != nil {
		t.Fatal(err)
	}

	formData2, mp2, err2 := tests.MockMultipartData(map[string]string{
		router.JSONPayloadKey: `{"title": "title_test2", "testPayload": 123}`,
	}, "files")
	if err2 != nil {
		t.Fatal(err2)
	}

	formData3, mp3, err3 := tests.MockMultipartData(map[string]string{
		router.JSONPayloadKey: `{"title": "title_test3", "testPayload": 123}`,
	}, "files")
	if err3 != nil {
		t.Fatal(err3)
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "missing collection",
			Method:          http.MethodPost,
			URL:             "/api/collections/missing/records",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "guest trying to access nil-rule collection",
			Method:          http.MethodPost,
			URL:             "/api/collections/demo1/records",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "auth record trying to access nil-rule collection",
			Method: http.MethodPost,
			URL:    "/api/collections/demo1/records",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "trying to create a new view collection record",
			Method:          http.MethodPost,
			URL:             "/api/collections/view1/records",
			Headers:         tests.PublicAPIKeyHeaders(),
			Body:            strings.NewReader(`{"text":"new"}`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "submit invalid body",
			Method:          http.MethodPost,
			URL:             "/api/collections/demo2/records",
			Headers:         tests.PublicAPIKeyHeaders(),
			Body:            strings.NewReader(`{"`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "submit nil body",
			Method:         http.MethodPost,
			URL:            "/api/collections/demo2/records",
			Headers:        tests.PublicAPIKeyHeaders(),
			Body:           nil,
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"title":{"code":"validation_required"`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordCreateRequest":    1,
				"OnModelCreate":            1,
				"OnModelValidate":          1,
				"OnModelAfterCreateError":  1,
				"OnRecordCreate":           1,
				"OnRecordValidate":         1,
				"OnRecordAfterCreateError": 1,
			},
		},
		{
			Name:           "submit empty json body",
			Method:         http.MethodPost,
			URL:            "/api/collections/nologin/records",
			Headers:        tests.PublicAPIKeyHeaders(),
			Body:           strings.NewReader(`{}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"password":{"code":"validation_required"`,
				`"passwordConfirm":{"code":"validation_required"`,
			},
			ExpectedEvents: map[string]int{
				"*":                     0,
				"OnRecordCreateRequest": 1,
			},
		},
		{
			Name:           "guest submit in public collection",
			Method:         http.MethodPost,
			URL:            "/api/collections/demo2/records",
			Headers:        tests.PublicAPIKeyHeaders(),
			Body:           strings.NewReader(`{"title":"new"}`),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":`,
				`"title":"new"`,
				`"active":false`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:            "guest trying to submit in restricted collection",
			Method:          http.MethodPost,
			URL:             "/api/collections/demo3/records",
			Headers:         tests.PublicAPIKeyHeaders(),
			Body:            strings.NewReader(`{"title":"test123"}`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "auth record submit in restricted collection (rule failure check)",
			Method: http.MethodPost,
			URL:    "/api/collections/demo3/records",
			Body:   strings.NewReader(`{"title":"test123"}`),
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "auth record submit in restricted collection (rule pass check) + expand relations",
			Method: http.MethodPost,
			URL:    "/api/collections/demo4/records?expand=missing,rel_one_no_cascade,rel_many_no_cascade_required",
			Body: strings.NewReader(`{
				"title":"test123",
				"rel_one_no_cascade":"mk5fmymtx4wsprk",
				"rel_one_no_cascade_required":"7nwo8tuiatetxdm",
				"rel_one_cascade":"mk5fmymtx4wsprk",
				"rel_many_no_cascade":"mk5fmymtx4wsprk",
				"rel_many_no_cascade_required":["7nwo8tuiatetxdm","lcl9d87w22ml6jy"],
				"rel_many_cascade":"lcl9d87w22ml6jy"
			}`),
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":`,
				`"title":"test123"`,
				`"expand":{}`, // empty expand even because of the query param
				`"rel_one_no_cascade":"mk5fmymtx4wsprk"`,
				`"rel_one_no_cascade_required":"7nwo8tuiatetxdm"`,
				`"rel_one_cascade":"mk5fmymtx4wsprk"`,
				`"rel_many_no_cascade":["mk5fmymtx4wsprk"]`,
				`"rel_many_no_cascade_required":["7nwo8tuiatetxdm","lcl9d87w22ml6jy"]`,
				`"rel_many_cascade":["lcl9d87w22ml6jy"]`,
			},
			NotExpectedContent: []string{
				// the users auth records don't have access to view the demo3 expands
				`"missing"`,
				`"id":"mk5fmymtx4wsprk"`,
				`"id":"7nwo8tuiatetxdm"`,
				`"id":"lcl9d87w22ml6jy"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "superuser submit in restricted collection (rule skip check) + expand relations",
			Method: http.MethodPost,
			URL:    "/api/collections/demo4/records?expand=missing,rel_one_no_cascade,rel_many_no_cascade_required",
			Body: strings.NewReader(`{
				"title":"test123",
				"rel_one_no_cascade":"mk5fmymtx4wsprk",
				"rel_one_no_cascade_required":"7nwo8tuiatetxdm",
				"rel_one_cascade":"mk5fmymtx4wsprk",
				"rel_many_no_cascade":"mk5fmymtx4wsprk",
				"rel_many_no_cascade_required":["7nwo8tuiatetxdm","lcl9d87w22ml6jy"],
				"rel_many_cascade":"lcl9d87w22ml6jy"
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":`,
				`"title":"test123"`,
				`"rel_one_no_cascade":"mk5fmymtx4wsprk"`,
				`"rel_one_no_cascade_required":"7nwo8tuiatetxdm"`,
				`"rel_one_cascade":"mk5fmymtx4wsprk"`,
				`"rel_many_no_cascade":["mk5fmymtx4wsprk"]`,
				`"rel_many_no_cascade_required":["7nwo8tuiatetxdm","lcl9d87w22ml6jy"]`,
				`"rel_many_cascade":["lcl9d87w22ml6jy"]`,
				`"expand":{`,
				`"id":"mk5fmymtx4wsprk"`,
				`"id":"7nwo8tuiatetxdm"`,
				`"id":"lcl9d87w22ml6jy"`,
			},
			NotExpectedContent: []string{
				`"missing"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             4,
			},
		},
		{
			Name:   "superuser submit via multipart form data",
			Method: http.MethodPost,
			URL:    "/api/collections/demo3/records",
			Body:   formData,
			Headers: map[string]string{
				"Content-Type":  mp.FormDataContentType(),
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"`,
				`"title":"title_test"`,
				`"files":["`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "submit via multipart form data with @jsonPayload key and unsatisfied @request.body rule",
			Method: http.MethodPost,
			URL:    "/api/collections/demo3/records",
			Body:   formData2,
			Headers: map[string]string{
				"X-PB-Public-Key": tests.PublicAPIKey(),
				"Content-Type":    mp2.FormDataContentType(),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				collection, err := app.FindCollectionByNameOrId("demo3")
				if err != nil {
					t.Fatalf("failed to find demo3 collection: %v", err)
				}
				collection.CreateRule = types.Pointer("@request.body.testPayload != 123")
				if err := app.Save(collection); err != nil {
					t.Fatalf("failed to update demo3 collection create rule: %v", err)
				}
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "submit via multipart form data with @jsonPayload key and satisfied @request.body rule",
			Method: http.MethodPost,
			URL:    "/api/collections/demo3/records",
			Body:   formData3,
			Headers: map[string]string{
				"X-PB-Public-Key": tests.PublicAPIKey(),
				"Content-Type":    mp3.FormDataContentType(),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				collection, err := app.FindCollectionByNameOrId("demo3")
				if err != nil {
					t.Fatalf("failed to find demo3 collection: %v", err)
				}
				collection.CreateRule = types.Pointer("@request.body.testPayload = 123")
				if err := app.Save(collection); err != nil {
					t.Fatalf("failed to update demo3 collection create rule: %v", err)
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"`,
				`"title":"title_test3"`,
				`"files":["`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:    "unique field error check",
			Method:  http.MethodPost,
			URL:     "/api/collections/demo2/records",
			Headers: tests.PublicAPIKeyHeaders(),
			Body: strings.NewReader(`{
				"title":"test2"
			}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"title":{`,
				`"code":"validation_not_unique"`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordCreateRequest":    1,
				"OnModelCreate":            1,
				"OnModelCreateExecute":     1,
				"OnModelAfterCreateError":  1,
				"OnModelValidate":          1,
				"OnRecordCreate":           1,
				"OnRecordCreateExecute":    1,
				"OnRecordAfterCreateError": 1,
				"OnRecordValidate":         1,
			},
		},
		{
			Name:   "OnRecordCreateRequest tx body write check",
			Method: http.MethodPost,
			URL:    "/api/collections/demo2/records",
			Body:   strings.NewReader(`{"title":"new"}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnRecordCreateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
					original := e.App
					return e.App.RunInTransaction(func(txApp core.App) error {
						e.App = txApp
						defer func() { e.App = original }()

						if err := e.Next(); err != nil {
							return err
						}

						return e.BadRequestError("TX_ERROR", nil)
					})
				})
			},
			ExpectedStatus:  400,
			ExpectedEvents:  map[string]int{"OnRecordCreateRequest": 1},
			ExpectedContent: []string{"TX_ERROR"},
		},

		// ID checks
		// -----------------------------------------------------------
		{
			Name:   "invalid custom insertion id (less than 15 chars)",
			Method: http.MethodPost,
			URL:    "/api/collections/demo3/records",
			Body: strings.NewReader(`{
				"id": "12345678901234",
				"title": "test"
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"id":{"code":"validation_min_text_constraint"`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordCreateRequest":    1,
				"OnModelCreate":            1,
				"OnModelValidate":          1,
				"OnModelAfterCreateError":  1,
				"OnRecordCreate":           1,
				"OnRecordValidate":         1,
				"OnRecordAfterCreateError": 1,
			},
		},
		{
			Name:   "invalid custom insertion id (more than 15 chars)",
			Method: http.MethodPost,
			URL:    "/api/collections/demo3/records",
			Body: strings.NewReader(`{
				"id": "1234567890123456",
				"title": "test"
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"id":{"code":"validation_max_text_constraint"`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordCreateRequest":    1,
				"OnModelCreate":            1,
				"OnModelValidate":          1,
				"OnModelAfterCreateError":  1,
				"OnRecordCreate":           1,
				"OnRecordValidate":         1,
				"OnRecordAfterCreateError": 1,
			},
		},
		{
			Name:   "valid custom insertion id (exactly 15 chars)",
			Method: http.MethodPost,
			URL:    "/api/collections/demo3/records",
			Body: strings.NewReader(`{
				"id": "123456789012345",
				"title": "test"
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"123456789012345"`,
				`"title":"test"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "valid custom insertion id existing in another non-auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/demo3/records",
			Body: strings.NewReader(`{
				"id": "0yxhwia2amd8gec",
				"title": "test"
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"0yxhwia2amd8gec"`,
				`"title":"test"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "valid custom insertion auth id duplicating in another auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/users/records",
			Body: strings.NewReader(`{
				"id":"o1y0dd0spd786md",
				"title":"test",
				"password":"1234567890",
				"passwordConfirm":"1234567890"
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"id":{"code":"validation_invalid_auth_id"`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordCreateRequest":    1,
				"OnModelCreate":            1,
				"OnModelCreateExecute":     1, // unique constraints are handled on db level
				"OnModelAfterCreateError":  1,
				"OnRecordCreate":           1,
				"OnRecordCreateExecute":    1,
				"OnRecordAfterCreateError": 1,
				"OnModelValidate":          1,
				"OnRecordValidate":         1,
			},
		},

		// check whether if @request.body modifer fields are properly resolved
		// -----------------------------------------------------------
		{
			Name:    "@request.body.field with compute modifers (rule failure check)",
			Method:  http.MethodPost,
			URL:     "/api/collections/demo5/records",
			Headers: tests.PublicAPIKeyHeaders(),
			Body: strings.NewReader(`{
				"total+":4,
				"total-":2
			}`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:    "@request.body.field with compute modifers (rule pass check)",
			Method:  http.MethodPost,
			URL:     "/api/collections/demo5/records",
			Headers: tests.PublicAPIKeyHeaders(),
			Body: strings.NewReader(`{
				"total+":4,
				"total-":1
			}`),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"`,
				`"collectionName":"demo5"`,
				`"total":3`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},

		// auth records
		// -----------------------------------------------------------
		{
			Name:   "auth record with invalid form data",
			Method: http.MethodPost,
			URL:    "/api/collections/users/records",
			Body: strings.NewReader(`{
				"password":"1234567",
				"passwordConfirm":"1234560",
				"email":"invalid",
				"username":"Users75657"
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"passwordConfirm":{"code":"validation_values_mismatch"`,
			},
			NotExpectedContent: []string{
				// record fields are not checked if the base auth form fields have errors
				`"rel":`,
				`"email":`,
			},
			ExpectedEvents: map[string]int{
				"*":                     0,
				"OnRecordCreateRequest": 1,
			},
		},
		{
			Name:   "auth record with valid form data but invalid record fields",
			Method: http.MethodPost,
			URL:    "/api/collections/users/records",
			Body: strings.NewReader(`{
				"password":"1234567",
				"passwordConfirm":"1234567",
				"rel":"invalid"
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"rel":{"code":`,
				`"password":{"code":`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordCreateRequest":    1,
				"OnModelCreate":            1,
				"OnModelValidate":          1,
				"OnModelAfterCreateError":  1,
				"OnRecordCreate":           1,
				"OnRecordValidate":         1,
				"OnRecordAfterCreateError": 1,
			},
		},
		{
			Name:    "auth record with valid data and explicitly verified state by guest",
			Method:  http.MethodPost,
			URL:     "/api/collections/users/records",
			Headers: tests.PublicAPIKeyHeaders(),
			Body: strings.NewReader(`{
				"password":"12345678",
				"passwordConfirm":"12345678",
				"verified":true
			}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"verified":{"code":`,
			},
			ExpectedEvents: map[string]int{
				"*":                     0,
				"OnRecordCreateRequest": 1,
				// no validation hooks because it should fail before save by the form auth fields validator
			},
		},
		{
			Name:   "auth record with valid data and explicitly verified state by random user",
			Method: http.MethodPost,
			URL:    "/api/collections/users/records",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			Body: strings.NewReader(`{
				"password":"12345678",
				"passwordConfirm":"12345678",
				"emailVisibility":true,
				"verified":true
			}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"verified":{"code":`,
			},
			NotExpectedContent: []string{
				`"emailVisibility":{"code":`,
			},
			ExpectedEvents: map[string]int{
				"*":                     0,
				"OnRecordCreateRequest": 1,
				// no validation hooks because it should fail before save by the form auth fields validator
			},
		},
		{
			Name:   "auth record with valid data by superuser",
			Method: http.MethodPost,
			URL:    "/api/collections/users/records",
			Body: strings.NewReader(`{
				"id":"o1o1y0pd78686mq",
				"username":"test.valid",
				"email":"new@example.com",
				"password":"12345678",
				"passwordConfirm":"12345678",
				"rel":"achvryl401bhse3",
				"emailVisibility":true,
				"verified":true
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"o1o1y0pd78686mq"`,
				`"username":"test.valid"`,
				`"email":"new@example.com"`,
				`"rel":"achvryl401bhse3"`,
				`"emailVisibility":true`,
				`"verified":true`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
				`"passwordConfirm"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "auth record with valid data by auth record with manage access",
			Method: http.MethodPost,
			URL:    "/api/collections/nologin/records",
			Body: strings.NewReader(`{
				"email":"new@example.com",
				"password":"12345678",
				"passwordConfirm":"12345678",
				"name":"test_name",
				"emailVisibility":true,
				"verified":true
			}`),
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"`,
				`"username":"`,
				`"email":"new@example.com"`,
				`"name":"test_name"`,
				`"emailVisibility":true`,
				`"verified":true`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
				`"passwordConfirm"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},

		// ensure that hidden fields cannot be set by non-superusers
		// -----------------------------------------------------------
		{
			Name:   "create with hidden field as regular user",
			Method: http.MethodPost,
			URL:    "/api/collections/demo3/records",
			Body: strings.NewReader(`{
				"id": "abcde1234567890",
				"title": "test_create"
			}`),
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": tests.AuthToken("clients", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				col, err := app.FindCollectionByNameOrId("demo3")
				if err != nil {
					t.Fatal(err)
				}

				// mock hidden field
				col.Fields.GetByName("title").SetHidden(true)

				if err = app.Save(col); err != nil {
					t.Fatal(err)
				}
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				record, err := app.FindRecordById("demo3", "abcde1234567890")
				if err != nil {
					t.Fatal(err)
				}

				// ensure that the title wasn't saved
				if v := record.GetString("title"); v != "" {
					t.Fatalf("Expected empty title, got %q", v)
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"abcde1234567890"`,
			},
			NotExpectedContent: []string{
				`"title"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "create with hidden field as superuser",
			Method: http.MethodPost,
			URL:    "/api/collections/demo3/records",
			Body: strings.NewReader(`{
				"id": "abcde1234567890",
				"title": "test_create"
			}`),
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				col, err := app.FindCollectionByNameOrId("demo3")
				if err != nil {
					t.Fatal(err)
				}

				// mock hidden field
				col.Fields.GetByName("title").SetHidden(true)

				if err = app.Save(col); err != nil {
					t.Fatal(err)
				}
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				record, err := app.FindRecordById("demo3", "abcde1234567890")
				if err != nil {
					t.Fatal(err)
				}

				// ensure that the title was saved
				if v := record.GetString("title"); v != "test_create" {
					t.Fatalf("Expected title %q, got %q", "test_create", v)
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"abcde1234567890"`,
				`"title":"test_create"`,
			},
			NotExpectedContent: []string{},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordCreateRequest":      1,
				"OnModelCreate":              1,
				"OnModelCreateExecute":       1,
				"OnModelAfterCreateSuccess":  1,
				"OnRecordCreate":             1,
				"OnRecordCreateExecute":      1,
				"OnRecordAfterCreateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},

		// rate limit checks
		// -----------------------------------------------------------
		{
			Name:    "RateLimit rule - demo2:create",
			Method:  http.MethodPost,
			URL:     "/api/collections/demo2/records",
			Headers: tests.PublicAPIKeyHeaders(),
			Body:    strings.NewReader(`{"title":"new"}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 100, Label: "*:create"},
					{MaxRequests: 0, Label: "demo2:create"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:    "RateLimit rule - *:create",
			Method:  http.MethodPost,
			URL:     "/api/collections/demo2/records",
			Headers: tests.PublicAPIKeyHeaders(),
			Body:    strings.NewReader(`{"title":"new"}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 0, Label: "*:create"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},

		// dynamic body limit checks
		// -----------------------------------------------------------
		{
			Name:    "body > collection BodyLimit",
			Method:  http.MethodPost,
			URL:     "/api/collections/demo1/records",
			Headers: tests.PublicAPIKeyHeaders(),
			// the exact body doesn't matter as long as it returns 413
			Body: bytes.NewReader(make([]byte, apis.DefaultMaxBodySize+5+20+2+1)),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				collection, err := app.FindCollectionByNameOrId("demo1")
				if err != nil {
					t.Fatal(err)
				}

				// adjust field sizes for the test
				// ---
				fileOneField := collection.Fields.GetByName("file_one").(*core.FileField)
				fileOneField.MaxSize = 5

				fileManyField := collection.Fields.GetByName("file_many").(*core.FileField)
				fileManyField.MaxSize = 10
				fileManyField.MaxSelect = 2

				jsonField := collection.Fields.GetByName("json").(*core.JSONField)
				jsonField.MaxSize = 2

				err = app.Save(collection)
				if err != nil {
					t.Fatal(err)
				}
			},
			ExpectedStatus:  413,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:    "body <= collection BodyLimit",
			Method:  http.MethodPost,
			URL:     "/api/collections/demo1/records",
			Headers: tests.PublicAPIKeyHeaders(),
			// the exact body doesn't matter as long as it doesn't return 413
			Body: bytes.NewReader(make([]byte, apis.DefaultMaxBodySize+5+20+2)),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				collection, err := app.FindCollectionByNameOrId("demo1")
				if err != nil {
					t.Fatal(err)
				}

				// adjust field sizes for the test
				// ---
				fileOneField := collection.Fields.GetByName("file_one").(*core.FileField)
				fileOneField.MaxSize = 5

				fileManyField := collection.Fields.GetByName("file_many").(*core.FileField)
				fileManyField.MaxSize = 10
				fileManyField.MaxSelect = 2

				jsonField := collection.Fields.GetByName("json").(*core.JSONField)
				jsonField.MaxSize = 2

				err = app.Save(collection)
				if err != nil {
					t.Fatal(err)
				}
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRecordCrudUpdate(t *testing.T) {
	t.Parallel()

	formData, mp, err := tests.MockMultipartData(map[string]string{
		"title": "title_test",
	}, "files")
	if err != nil {
		t.Fatal(err)
	}

	formData2, mp2, err2 := tests.MockMultipartData(map[string]string{
		router.JSONPayloadKey: `{"title": "title_test2", "testPayload": 123}`,
	}, "files")
	if err2 != nil {
		t.Fatal(err2)
	}

	formData3, mp3, err3 := tests.MockMultipartData(map[string]string{
		router.JSONPayloadKey: `{"title": "title_test3", "testPayload": 123, "files":"300_JdfBOieXAW.png"}`,
	}, "files")
	if err3 != nil {
		t.Fatal(err3)
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "missing collection",
			Method:          http.MethodPatch,
			URL:             "/api/collections/missing/records/0yxhwia2amd8gec",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "guest trying to access nil-rule collection record",
			Method:          http.MethodPatch,
			URL:             "/api/collections/demo1/records/imy661ixudk5izi",
			Headers:         tests.PublicAPIKeyHeaders(),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "auth record trying to access nil-rule collection",
			Method: http.MethodPatch,
			URL:    "/api/collections/demo1/records/imy661ixudk5izi",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "trying to update a view collection record",
			Method:          http.MethodPatch,
			URL:             "/api/collections/view1/records/imy661ixudk5izi",
			Headers:         tests.PublicAPIKeyHeaders(),
			Body:            strings.NewReader(`{"text":"new"}`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "submit invalid body",
			Method:          http.MethodPatch,
			URL:             "/api/collections/demo2/records/0yxhwia2amd8gec",
			Headers:         tests.PublicAPIKeyHeaders(),
			Body:            strings.NewReader(`{"`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "submit nil body (aka. no fields change)",
			Method:         http.MethodPatch,
			URL:            "/api/collections/demo2/records/0yxhwia2amd8gec",
			Headers:        tests.PublicAPIKeyHeaders(),
			Body:           nil,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"collectionName":"demo2"`,
				`"id":"0yxhwia2amd8gec"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:           "submit empty body (aka. no fields change)",
			Method:         http.MethodPatch,
			URL:            "/api/collections/demo2/records/0yxhwia2amd8gec",
			Headers:        tests.PublicAPIKeyHeaders(),
			Body:           strings.NewReader(`{}`),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"collectionName":"demo2"`,
				`"id":"0yxhwia2amd8gec"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:           "trigger field validation",
			Method:         http.MethodPatch,
			URL:            "/api/collections/demo2/records/0yxhwia2amd8gec",
			Headers:        tests.PublicAPIKeyHeaders(),
			Body:           strings.NewReader(`{"title":"a"}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`data":{`,
				`"title":{"code":"validation_min_text_constraint"`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordUpdateRequest":    1,
				"OnModelUpdate":            1,
				"OnModelValidate":          1,
				"OnModelAfterUpdateError":  1,
				"OnRecordUpdate":           1,
				"OnRecordValidate":         1,
				"OnRecordAfterUpdateError": 1,
			},
		},
		{
			Name:           "guest submit in public collection",
			Method:         http.MethodPatch,
			URL:            "/api/collections/demo2/records/0yxhwia2amd8gec",
			Headers:        tests.PublicAPIKeyHeaders(),
			Body:           strings.NewReader(`{"title":"new"}`),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"0yxhwia2amd8gec"`,
				`"title":"new"`,
				`"active":true`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:            "guest trying to submit in restricted collection",
			Method:          http.MethodPatch,
			URL:             "/api/collections/demo3/records/mk5fmymtx4wsprk",
			Headers:         tests.PublicAPIKeyHeaders(),
			Body:            strings.NewReader(`{"title":"new"}`),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "auth record submit in restricted collection (rule failure check)",
			Method: http.MethodPatch,
			URL:    "/api/collections/demo3/records/mk5fmymtx4wsprk",
			Body:   strings.NewReader(`{"title":"new"}`),
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "auth record submit in restricted collection (rule pass check) + expand relations",
			Method: http.MethodPatch,
			URL:    "/api/collections/demo4/records/i9naidtvr6qsgb4?expand=missing,rel_one_no_cascade,rel_many_no_cascade_required",
			Body: strings.NewReader(`{
				"title":"test123",
				"rel_one_no_cascade":"mk5fmymtx4wsprk",
				"rel_one_no_cascade_required":"7nwo8tuiatetxdm",
				"rel_one_cascade":"mk5fmymtx4wsprk",
				"rel_many_no_cascade":"mk5fmymtx4wsprk",
				"rel_many_no_cascade_required":["7nwo8tuiatetxdm","lcl9d87w22ml6jy"],
				"rel_many_cascade":"lcl9d87w22ml6jy"
			}`),
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"i9naidtvr6qsgb4"`,
				`"title":"test123"`,
				`"expand":{}`, // empty expand even because of the query param
				`"rel_one_no_cascade":"mk5fmymtx4wsprk"`,
				`"rel_one_no_cascade_required":"7nwo8tuiatetxdm"`,
				`"rel_one_cascade":"mk5fmymtx4wsprk"`,
				`"rel_many_no_cascade":["mk5fmymtx4wsprk"]`,
				`"rel_many_no_cascade_required":["7nwo8tuiatetxdm","lcl9d87w22ml6jy"]`,
				`"rel_many_cascade":["lcl9d87w22ml6jy"]`,
			},
			NotExpectedContent: []string{
				// the users auth records don't have access to view the demo3 expands
				`"missing"`,
				`"id":"mk5fmymtx4wsprk"`,
				`"id":"7nwo8tuiatetxdm"`,
				`"id":"lcl9d87w22ml6jy"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "superuser submit in restricted collection (rule skip check) + expand relations",
			Method: http.MethodPatch,
			URL:    "/api/collections/demo4/records/i9naidtvr6qsgb4?expand=missing,rel_one_no_cascade,rel_many_no_cascade_required",
			Body: strings.NewReader(`{
				"title":"test123",
				"rel_one_no_cascade":"mk5fmymtx4wsprk",
				"rel_one_no_cascade_required":"7nwo8tuiatetxdm",
				"rel_one_cascade":"mk5fmymtx4wsprk",
				"rel_many_no_cascade":"mk5fmymtx4wsprk",
				"rel_many_no_cascade_required":["7nwo8tuiatetxdm","lcl9d87w22ml6jy"],
				"rel_many_cascade":"lcl9d87w22ml6jy"
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"i9naidtvr6qsgb4"`,
				`"title":"test123"`,
				`"rel_one_no_cascade":"mk5fmymtx4wsprk"`,
				`"rel_one_no_cascade_required":"7nwo8tuiatetxdm"`,
				`"rel_one_cascade":"mk5fmymtx4wsprk"`,
				`"rel_many_no_cascade":["mk5fmymtx4wsprk"]`,
				`"rel_many_no_cascade_required":["7nwo8tuiatetxdm","lcl9d87w22ml6jy"]`,
				`"rel_many_cascade":["lcl9d87w22ml6jy"]`,
				`"expand":{`,
				`"id":"mk5fmymtx4wsprk"`,
				`"id":"7nwo8tuiatetxdm"`,
				`"id":"lcl9d87w22ml6jy"`,
			},
			NotExpectedContent: []string{
				`"missing"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             4,
			},
		},
		{
			Name:   "superuser submit via multipart form data",
			Method: http.MethodPatch,
			URL:    "/api/collections/demo3/records/mk5fmymtx4wsprk",
			Body:   formData,
			Headers: map[string]string{
				"Content-Type":  mp.FormDataContentType(),
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"mk5fmymtx4wsprk"`,
				`"title":"title_test"`,
				`"files":["`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "submit via multipart form data with @jsonPayload key and unsatisfied @request.body rule",
			Method: http.MethodPatch,
			URL:    "/api/collections/demo3/records/mk5fmymtx4wsprk",
			Body:   formData2,
			Headers: map[string]string{
				"X-PB-Public-Key": tests.PublicAPIKey(),
				"Content-Type":    mp2.FormDataContentType(),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				collection, err := app.FindCollectionByNameOrId("demo3")
				if err != nil {
					t.Fatalf("failed to find demo3 collection: %v", err)
				}
				collection.UpdateRule = types.Pointer("@request.body.testPayload != 123")
				if err := app.Save(collection); err != nil {
					t.Fatalf("failed to update demo3 collection update rule: %v", err)
				}
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "submit via multipart form data with @jsonPayload key and satisfied @request.body rule",
			Method: http.MethodPatch,
			URL:    "/api/collections/demo3/records/mk5fmymtx4wsprk",
			Body:   formData3,
			Headers: map[string]string{
				"X-PB-Public-Key": tests.PublicAPIKey(),
				"Content-Type":    mp3.FormDataContentType(),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				collection, err := app.FindCollectionByNameOrId("demo3")
				if err != nil {
					t.Fatalf("failed to find demo3 collection: %v", err)
				}
				collection.UpdateRule = types.Pointer("@request.body.testPayload = 123")
				if err := app.Save(collection); err != nil {
					t.Fatalf("failed to update demo3 collection update rule: %v", err)
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"mk5fmymtx4wsprk"`,
				`"title":"title_test3"`,
				`"files":["`,
				`"300_JdfBOieXAW.png"`,
				`"tmpfile_`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "OnRecordUpdateRequest tx body write check",
			Method: http.MethodPatch,
			URL:    "/api/collections/demo2/records/0yxhwia2amd8gec",
			Body:   strings.NewReader(`{"title":"new"}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnRecordUpdateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
					original := e.App
					return e.App.RunInTransaction(func(txApp core.App) error {
						e.App = txApp
						defer func() { e.App = original }()

						if err := e.Next(); err != nil {
							return err
						}

						return e.BadRequestError("TX_ERROR", nil)
					})
				})
			},
			ExpectedStatus:  400,
			ExpectedEvents:  map[string]int{"OnRecordUpdateRequest": 1},
			ExpectedContent: []string{"TX_ERROR"},
		},
		{
			Name:   "try to change the id of an existing record",
			Method: http.MethodPatch,
			URL:    "/api/collections/demo3/records/mk5fmymtx4wsprk",
			Body: strings.NewReader(`{
				"id": "mk5fmymtx4wspra"
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"id":{"code":"validation_pk_change"`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordUpdateRequest":    1,
				"OnModelUpdate":            1,
				"OnModelValidate":          1,
				"OnModelAfterUpdateError":  1,
				"OnRecordUpdate":           1,
				"OnRecordValidate":         1,
				"OnRecordAfterUpdateError": 1,
			},
		},
		{
			Name:    "unique field error check",
			Method:  http.MethodPatch,
			URL:     "/api/collections/demo2/records/llvuca81nly1qls",
			Headers: tests.PublicAPIKeyHeaders(),
			Body: strings.NewReader(`{
				"title":"test2"
			}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"title":{`,
				`"code":"validation_not_unique"`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordUpdateRequest":    1,
				"OnModelUpdate":            1,
				"OnModelUpdateExecute":     1,
				"OnModelAfterUpdateError":  1,
				"OnRecordUpdate":           1,
				"OnRecordUpdateExecute":    1,
				"OnRecordAfterUpdateError": 1,
				"OnModelValidate":          1,
				"OnRecordValidate":         1,
			},
		},

		// check whether if @request.body modifer fields are properly resolved
		// -----------------------------------------------------------
		{
			Name:    "@request.body.field with compute modifers (rule failure check)",
			Method:  http.MethodPatch,
			URL:     "/api/collections/demo5/records/la4y2w4o98acwuj",
			Headers: tests.PublicAPIKeyHeaders(),
			Body: strings.NewReader(`{
				"total+":3,
				"total-":1
			}`),
			ExpectedStatus: 404,
			ExpectedContent: []string{
				`"data":{}`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:    "@request.body.field with compute modifers (rule pass check)",
			Method:  http.MethodPatch,
			URL:     "/api/collections/demo5/records/la4y2w4o98acwuj",
			Headers: tests.PublicAPIKeyHeaders(),
			Body: strings.NewReader(`{
				"total+":2,
				"total-":1
			}`),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"la4y2w4o98acwuj"`,
				`"collectionName":"demo5"`,
				`"total":3`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},

		// auth records
		// -----------------------------------------------------------
		{
			Name:   "auth record with invalid form data",
			Method: http.MethodPatch,
			URL:    "/api/collections/users/records/bgs820n361vj1qd",
			Body: strings.NewReader(`{
				"password":"",
				"passwordConfirm":"1234560",
				"email":"invalid",
				"verified":false
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"passwordConfirm":{`,
				`"password":{`,
			},
			NotExpectedContent: []string{
				// record fields are not checked if the base auth form fields have errors
				`"email":`,
				"verified", // superusers are allowed to change the verified state
			},
			ExpectedEvents: map[string]int{
				"*":                     0,
				"OnRecordUpdateRequest": 1,
			},
		},
		{
			Name:   "auth record with valid form data but invalid record fields",
			Method: http.MethodPatch,
			URL:    "/api/collections/users/records/bgs820n361vj1qd",
			Body: strings.NewReader(`{
				"password":"1234567",
				"passwordConfirm":"1234567",
				"rel":"invalid"
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"rel":{"code":`,
				`"password":{"code":`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRecordUpdateRequest":    1,
				"OnModelUpdate":            1,
				"OnModelValidate":          1,
				"OnModelAfterUpdateError":  1,
				"OnRecordUpdate":           1,
				"OnRecordValidate":         1,
				"OnRecordAfterUpdateError": 1,
			},
		},
		{
			Name:    "try to change account managing fields by guest",
			Method:  http.MethodPatch,
			URL:     "/api/collections/nologin/records/phhq3wr65cap535",
			Headers: tests.PublicAPIKeyHeaders(),
			Body: strings.NewReader(`{
				"password":"12345678",
				"passwordConfirm":"12345678",
				"emailVisibility":true,
				"verified":true
			}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"verified":{"code":`,
				`"oldPassword":{"code":`,
			},
			NotExpectedContent: []string{
				`"emailVisibility":{"code":`,
			},
			ExpectedEvents: map[string]int{
				"*":                     0,
				"OnRecordUpdateRequest": 1,
			},
		},
		{
			Name:   "try to change account managing fields by auth record (owner)",
			Method: http.MethodPatch,
			URL:    "/api/collections/users/records/4q1xlclmfloku33",
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			Body: strings.NewReader(`{
				"password":"12345678",
				"passwordConfirm":"12345678",
				"emailVisibility":true,
				"verified":true
			}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"verified":{"code":`,
				`"oldPassword":{"code":`,
			},
			NotExpectedContent: []string{
				`"emailVisibility":{"code":`,
			},
			ExpectedEvents: map[string]int{
				"*":                     0,
				"OnRecordUpdateRequest": 1,
			},
		},
		{
			Name:   "try to unset/downgrade email and verified fields (owner)",
			Method: http.MethodPatch,
			URL:    "/api/collections/users/records/oap640cot4yru2s",
			Headers: map[string]string{
				// users, test2@example.com
				"Authorization": tests.AuthToken("users", "test2@example.com"),
			},
			Body: strings.NewReader(`{
				"email":"",
				"verified":false
			}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"email":{"code":`,
				`"verified":{"code":`,
			},
			ExpectedEvents: map[string]int{
				"*":                     0,
				"OnRecordUpdateRequest": 1,
			},
		},
		{
			Name:   "try to change account managing fields by auth record with managing rights",
			Method: http.MethodPatch,
			URL:    "/api/collections/nologin/records/phhq3wr65cap535",
			Body: strings.NewReader(`{
				"email":"new@example.com",
				"password":"12345678",
				"passwordConfirm":"12345678",
				"name":"test_name",
				"emailVisibility":true,
				"verified":true
			}`),
			Headers: map[string]string{
				// users, test@example.com
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"email":"new@example.com"`,
				`"name":"test_name"`,
				`"emailVisibility":true`,
				`"verified":true`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
				`"passwordConfirm"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				record, _ := app.FindRecordById("nologin", "phhq3wr65cap535")
				if !record.ValidatePassword("12345678") {
					t.Fatal("Password update failed.")
				}
			},
		},
		{
			Name:   "update auth record with valid data by superuser",
			Method: http.MethodPatch,
			URL:    "/api/collections/users/records/oap640cot4yru2s",
			Body: strings.NewReader(`{
				"username":"test.valid",
				"email":"new@example.com",
				"password":"12345678",
				"passwordConfirm":"12345678",
				"rel":"achvryl401bhse3",
				"emailVisibility":true,
				"verified":false
			}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"username":"test.valid"`,
				`"email":"new@example.com"`,
				`"rel":"achvryl401bhse3"`,
				`"emailVisibility":true`,
				`"verified":false`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				record, _ := app.FindRecordById("users", "oap640cot4yru2s")
				if !record.ValidatePassword("12345678") {
					t.Fatal("Password update failed.")
				}
			},
		},
		{
			Name:    "update auth record with valid data by guest (empty update filter + auth origins check)",
			Method:  http.MethodPatch,
			URL:     "/api/collections/nologin/records/dc49k6jgejn40h3",
			Headers: tests.PublicAPIKeyHeaders(),
			Body: strings.NewReader(`{
				"username":"test_new",
				"emailVisibility":true,
				"name":"test"
			}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				nologin, err := app.FindCollectionByNameOrId("nologin")
				if err != nil {
					t.Fatal(err)
				}

				// add dummy auth origins for the record
				for i := 0; i < 3; i++ {
					d := core.NewAuthOrigin(app)
					d.SetCollectionRef(nologin.Id)
					d.SetRecordRef("dc49k6jgejn40h3")
					d.SetFingerprint("abc_" + strconv.Itoa(i))
					if err = app.Save(d); err != nil {
						t.Fatalf("Failed to save dummy auth origin %d: %v", i, err)
					}
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"username":"test_new"`,
				`"email":"test@example.com"`, // the email should be visible since we updated the emailVisibility
				`"emailVisibility":true`,
				`"verified":false`,
				`"name":"test"`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
				`"passwordConfirm"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				record, _ := app.FindRecordById("nologin", "dc49k6jgejn40h3")

				// the dummy auth origins should NOT have been removed since we didn't change the password
				devices, err := app.FindAllAuthOriginsByRecord(record)
				if err != nil {
					t.Fatalf("Failed to retrieve dummy auth origins: %v", err)
				}
				if len(devices) != 3 {
					t.Fatalf("Expected %d auth origins, got %d", 3, len(devices))
				}
			},
		},
		{
			Name:    "success password change with oldPassword (+authOrigins reset check)",
			Method:  http.MethodPatch,
			URL:     "/api/collections/nologin/records/dc49k6jgejn40h3",
			Headers: tests.PublicAPIKeyHeaders(),
			Body: strings.NewReader(`{
				"password":"123456789",
				"passwordConfirm":"123456789",
				"oldPassword":"1234567890"
			}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				nologin, err := app.FindCollectionByNameOrId("nologin")
				if err != nil {
					t.Fatal(err)
				}

				// add dummy auth origins for the record
				for i := 0; i < 3; i++ {
					d := core.NewAuthOrigin(app)
					d.SetCollectionRef(nologin.Id)
					d.SetRecordRef("dc49k6jgejn40h3")
					d.SetFingerprint("abc_" + strconv.Itoa(i))
					if err = app.Save(d); err != nil {
						t.Fatalf("Failed to save dummy auth origin %d: %v", i, err)
					}
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"dc49k6jgejn40h3"`,
			},
			NotExpectedContent: []string{
				`"tokenKey"`,
				`"password"`,
				`"passwordConfirm"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
				// auth origins
				"OnModelDelete":              3,
				"OnModelDeleteExecute":       3,
				"OnModelAfterDeleteSuccess":  3,
				"OnRecordDelete":             3,
				"OnRecordDeleteExecute":      3,
				"OnRecordAfterDeleteSuccess": 3,
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				record, _ := app.FindRecordById("nologin", "dc49k6jgejn40h3")
				if !record.ValidatePassword("123456789") {
					t.Fatal("Password update failed.")
				}

				// the dummy auth origins should have been removed
				devices, err := app.FindAllAuthOriginsByRecord(record)
				if err != nil {
					t.Fatalf("Failed to retrieve dummy auth origins: %v", err)
				}
				if len(devices) > 0 {
					t.Fatalf("Expected auth origins to be removed, got %d", len(devices))
				}
			},
		},

		// ensure that hidden fields cannot be set by non-superusers
		// -----------------------------------------------------------
		{
			Name:   "update with hidden field as regular user",
			Method: http.MethodPatch,
			URL:    "/api/collections/demo3/records/1tmknxy2868d869",
			Body: strings.NewReader(`{
				"title": "test_update"
			}`),
			Headers: map[string]string{
				// clients, test@example.com
				"Authorization": tests.AuthToken("clients", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				col, err := app.FindCollectionByNameOrId("demo3")
				if err != nil {
					t.Fatal(err)
				}

				// mock hidden field
				col.Fields.GetByName("title").SetHidden(true)

				if err = app.Save(col); err != nil {
					t.Fatal(err)
				}
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				record, err := app.FindRecordById("demo3", "1tmknxy2868d869")
				if err != nil {
					t.Fatal(err)
				}

				// ensure that the title wasn't saved
				if v := record.GetString("title"); v != "test1" {
					t.Fatalf("Expected no title change, got %q", v)
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"1tmknxy2868d869"`,
			},
			NotExpectedContent: []string{
				`"title"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},
		{
			Name:   "update with hidden field as superuser",
			Method: http.MethodPatch,
			URL:    "/api/collections/demo3/records/1tmknxy2868d869",
			Body: strings.NewReader(`{
				"title": "test_update"
			}`),
			Headers: map[string]string{
				// superusers, test@example.com
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				col, err := app.FindCollectionByNameOrId("demo3")
				if err != nil {
					t.Fatal(err)
				}

				// mock hidden field
				col.Fields.GetByName("title").SetHidden(true)

				if err = app.Save(col); err != nil {
					t.Fatal(err)
				}
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				record, err := app.FindRecordById("demo3", "1tmknxy2868d869")
				if err != nil {
					t.Fatal(err)
				}

				// ensure that the title has been updated
				if v := record.GetString("title"); v != "test_update" {
					t.Fatalf("Expected title %q, got %q", "test_update", v)
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"1tmknxy2868d869"`,
				`"title":"test_update"`,
			},
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRecordUpdateRequest":      1,
				"OnModelUpdate":              1,
				"OnModelUpdateExecute":       1,
				"OnModelAfterUpdateSuccess":  1,
				"OnRecordUpdate":             1,
				"OnRecordUpdateExecute":      1,
				"OnRecordAfterUpdateSuccess": 1,
				"OnModelValidate":            1,
				"OnRecordValidate":           1,
				"OnRecordEnrich":             1,
			},
		},

		// rate limit checks
		// -----------------------------------------------------------
		{
			Name:    "RateLimit rule - demo2:update",
			Method:  http.MethodPatch,
			URL:     "/api/collections/demo2/records/0yxhwia2amd8gec",
			Headers: tests.PublicAPIKeyHeaders(),
			Body:    strings.NewReader(`{"title":"new"}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 100, Label: "*:update"},
					{MaxRequests: 0, Label: "demo2:update"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:    "RateLimit rule - *:update",
			Method:  http.MethodPatch,
			URL:     "/api/collections/demo2/records/0yxhwia2amd8gec",
			Headers: tests.PublicAPIKeyHeaders(),
			Body:    strings.NewReader(`{"title":"new"}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 0, Label: "*:update"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},

		// dynamic body limit checks
		// -----------------------------------------------------------
		{
			Name:    "body > collection BodyLimit",
			Method:  http.MethodPatch,
			URL:     "/api/collections/demo1/records/imy661ixudk5izi",
			Headers: tests.PublicAPIKeyHeaders(),
			// the exact body doesn't matter as long as it returns 413
			Body: bytes.NewReader(make([]byte, apis.DefaultMaxBodySize+5+20+2+1)),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				collection, err := app.FindCollectionByNameOrId("demo1")
				if err != nil {
					t.Fatal(err)
				}

				// adjust field sizes for the test
				// ---
				fileOneField := collection.Fields.GetByName("file_one").(*core.FileField)
				fileOneField.MaxSize = 5

				fileManyField := collection.Fields.GetByName("file_many").(*core.FileField)
				fileManyField.MaxSize = 10
				fileManyField.MaxSelect = 2

				jsonField := collection.Fields.GetByName("json").(*core.JSONField)
				jsonField.MaxSize = 2

				err = app.Save(collection)
				if err != nil {
					t.Fatal(err)
				}
			},
			ExpectedStatus:  413,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:    "body <= collection BodyLimit",
			Method:  http.MethodPatch,
			URL:     "/api/collections/demo1/records/imy661ixudk5izi",
			Headers: tests.PublicAPIKeyHeaders(),
			// the exact body doesn't matter as long as it doesn't return 413
			Body: bytes.NewReader(make([]byte, apis.DefaultMaxBodySize+5+20+2)),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				collection, err := app.FindCollectionByNameOrId("demo1")
				if err != nil {
					t.Fatal(err)
				}

				// adjust field sizes for the test
				// ---
				fileOneField := collection.Fields.GetByName("file_one").(*core.FileField)
				fileOneField.MaxSize = 5

				fileManyField := collection.Fields.GetByName("file_many").(*core.FileField)
				fileManyField.MaxSize = 10
				fileManyField.MaxSelect = 2

				jsonField := collection.Fields.GetByName("json").(*core.JSONField)
				jsonField.MaxSize = 2

				err = app.Save(collection)
				if err != nil {
					t.Fatal(err)
				}
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRBACAttackThirdPartyExpandAndFilterJoins(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)
	b := newOAuth2Browser(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	user.Set("rel", "0yxhwia2amd8gec")
	if err := app.Save(user); err != nil {
		t.Fatal(err)
	}

	onlyUsers := rbacThirdPartyToken(t, app, "read_users")

	// expand into a collection that is not in the token scopes
	res, body := b.do(http.MethodGet, "/api/collections/users/records/"+user.Id+"?expand=rel", "", map[string]string{"Authorization": onlyUsers})
	if res.StatusCode != http.StatusOK || strings.Contains(body, `"expand"`) {
		t.Fatalf("Expected the record without expand, got %d %s", res.StatusCode, body)
	}

	// client filter/sort joins into a not scoped collection
	onlyDemo4 := rbacThirdPartyToken(t, app, "read_demo4")
	for _, query := range []string{
		"filter=" + url.QueryEscape(`@collection.demo2.title != ""`),
		"filter=" + url.QueryEscape(`rel_one_cascade.id != ""`),
		"sort=rel_one_cascade.created",
		"filter=" + url.QueryEscape(`@collection._superusers.email != ""`),
		"filter=" + url.QueryEscape(`@collection._authSessions.id != ""`),
	} {
		res, body = b.do(http.MethodGet, "/api/collections/demo4/records?"+query, "", map[string]string{"Authorization": onlyDemo4})
		if res.StatusCode != http.StatusBadRequest && res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: expected 400/403, got %d %s", query, res.StatusCode, body)
		}
	}

	// sanity check
	res, body = b.do(http.MethodGet, "/api/collections/demo4/records", "", map[string]string{"Authorization": onlyDemo4})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected the scoped list to work, got %d %s", res.StatusCode, body)
	}

	// with the related scope the expand works
	both := rbacThirdPartyToken(t, app, "read_users", "read_demo2")
	res, body = b.do(http.MethodGet, "/api/collections/users/records/"+user.Id+"?expand=rel", "", map[string]string{"Authorization": both})
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"expand"`) {
		t.Fatalf("Expected the expanded record, got %d %s", res.StatusCode, body)
	}

	// a not scoped collection is denied entirely
	res, _ = b.do(http.MethodGet, "/api/collections/demo2/records", "", map[string]string{"Authorization": onlyUsers})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 for a not scoped collection, got %d", res.StatusCode)
	}
}

func TestRBACAttackStaffSecretFields(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)
	b := newOAuth2Browser(t, app)

	users, _ := app.FindCollectionByNameOrId("users")

	role, err := tests.CreateRole(app, "users_support", core.Permissions{
		Collections: map[string][]string{users.Id: {"list", "view", "update"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	staff, err := tests.CreateStaff(app, "support@example.com", role.Id)
	if err != nil {
		t.Fatal(err)
	}
	token, err := tests.NewSessionAuthToken(app, staff)
	if err != nil {
		t.Fatal(err)
	}

	// filter/sort on the secret fields (tokenKey oracle)
	for _, query := range []string{
		"filter=" + url.QueryEscape(`tokenKey ~ "a"`),
		"filter=" + url.QueryEscape(`password ~ "$2a"`),
		"sort=tokenKey",
		"sort=-password",
		"filter=" + url.QueryEscape(`@collection._superusers.tokenKey ~ "a"`),
		"filter=" + url.QueryEscape(`@collection._otps.password != ""`),
	} {
		res, body := b.do(http.MethodGet, "/api/collections/users/records?"+query, "", map[string]string{"Authorization": token})
		if res.StatusCode != http.StatusBadRequest && res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: expected 400/403, got %d %s", query, res.StatusCode, body)
		}
	}

	// the secrets are never exported (incl. via the fields param)
	res, body := b.do(http.MethodGet, "/api/collections/users/records?fields=id,tokenKey,password,email", "", map[string]string{"Authorization": token})
	if res.StatusCode != http.StatusOK || strings.Contains(body, "tokenKey") || strings.Contains(body, `"password"`) {
		t.Fatalf("Expected the secrets not to be exported, got %d %s", res.StatusCode, body)
	}
	if !strings.Contains(body, "test@example.com") {
		t.Fatalf("Expected the staff to see the hidden email field, got %s", body)
	}

	// and can't be set (e.g. to forge tokens for the record)
	user := oauth2FindRecord(t, app, "users", "test@example.com")
	res, _ = b.do(http.MethodPatch, "/api/collections/users/records/"+user.Id, `{"tokenKey":"attacker_known_token_key_0123456789_0123456789"}`, map[string]string{
		"Content-Type":  "application/json",
		"Authorization": token,
	})
	user = oauth2FindRecord(t, app, "users", "test@example.com")
	if user.TokenKey() == "attacker_known_token_key_0123456789_0123456789" {
		t.Fatalf("Expected the tokenKey not to be settable by non-Owners (%d)", res.StatusCode)
	}
}

func TestRBACAttackScopeCollisions(t *testing.T) {
	t.Parallel()

	t.Run("custom scope with reserved prefix", func(t *testing.T) {
		app := oauth2AttackApp(t)

		users, _ := app.FindCollectionByNameOrId("users")
		for _, scope := range []string{"write_orders", "read_settings", "write_demo1", "system:read_settings", "system:write_logs", "system:custom"} {
			users.OAuth2Server.Scopes = []string{scope}
			if err := app.Save(users); err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("%s: expected reserved scope validation error, got %v", scope, err)
			}
		}
	})

	t.Run("collection renamed to a system resource name", func(t *testing.T) {
		app := oauth2AttackApp(t)

		demo2, _ := app.FindCollectionByNameOrId("demo2")
		demo2.Name = "settings"
		if err := app.Save(demo2); err != nil {
			t.Fatal(err)
		}

		token := rbacThirdPartyToken(t, app, "read_settings", "write_settings")
		b := newOAuth2Browser(t, app)

		// the collection scope must never grant the system resource
		for _, u := range []string{"/api/settings", "/api/collections", "/api/logs"} {
			res, _ := b.do(http.MethodGet, u, "", map[string]string{"Authorization": token})
			if res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s: expected 401/403, got %d", u, res.StatusCode)
			}
		}

		// the regular collection is accessible
		res, body := b.do(http.MethodGet, "/api/collections/settings/records", "", map[string]string{"Authorization": token})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected the renamed collection to be accessible, got %d %s", res.StatusCode, body)
		}
	})

	t.Run("view collections have no write scope", func(t *testing.T) {
		app := oauth2AttackApp(t)

		users, _ := app.FindCollectionByNameOrId("users")
		allowed := core.OAuth2AllowedScopes(app, users)
		for _, s := range allowed {
			if s == "write_view1" || strings.HasPrefix(s, "read__") || strings.HasPrefix(s, "write__") {
				t.Fatalf("Unexpected allowed scope %q", s)
			}
		}
	})
}

func TestRecordsListWithOAuth2ScopeRule(t *testing.T) {
	t.Parallel()

	setup := func(t testing.TB, app *tests.TestApp) {
		oauth2AuthorizeSetup(t, app)

		demo, err := app.FindCollectionByNameOrId("demo2")
		if err != nil {
			t.Fatal(err)
		}
		demo.ListRule = types.Pointer("@request.auth.id != '' && (@request.oauth2.clientId = '' || @request.oauth2.scopes:each ?= 'posts:read')")
		if err := app.Save(demo); err != nil {
			t.Fatal(err)
		}

		// allow the demo2 collection scope for the third-party client
		client := oauth2FindClient(t, app, "3p")
		client.SetScopes(append(client.Scopes(), "read_demo2"))
		if err := app.Save(client); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("third-party token without the collection scope (RBAC deny by default)", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()
		setup(t, app)

		token, _ := oauth2AccessToken(t, app, oauth2FindClient(t, app, "3p"), oauth2FindRecord(t, app, "users", "test@example.com"), []string{"openid", "posts:read"})

		b := newOAuth2Browser(t, app)
		res, body := b.do(http.MethodGet, "/api/collections/demo2/records", "", map[string]string{"Authorization": token})
		b.expectStatus(res, body, http.StatusForbidden)
	})

	t.Run("third-party token with the collection scope but without the rule scope", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()
		setup(t, app)

		token, _ := oauth2AccessToken(t, app, oauth2FindClient(t, app, "3p"), oauth2FindRecord(t, app, "users", "test@example.com"), []string{"openid", "read_demo2"})

		b := newOAuth2Browser(t, app)
		res, body := b.do(http.MethodGet, "/api/collections/demo2/records", "", map[string]string{"Authorization": token})
		b.expectStatus(res, body, http.StatusOK)
		if !strings.Contains(body, `"totalItems":0`) {
			t.Fatalf("Expected no items, got %s", body)
		}
	})

	t.Run("third-party token with the collection and the rule scopes", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()
		setup(t, app)

		token, _ := oauth2AccessToken(t, app, oauth2FindClient(t, app, "3p"), oauth2FindRecord(t, app, "users", "test@example.com"), []string{"openid", "posts:read", "read_demo2"})

		b := newOAuth2Browser(t, app)
		res, body := b.do(http.MethodGet, "/api/collections/demo2/records", "", map[string]string{"Authorization": token})
		b.expectStatus(res, body, http.StatusOK)
		if strings.Contains(body, `"totalItems":0`) {
			t.Fatalf("Expected items, got %s", body)
		}
	})
}

func TestOAuth2ConsentsListRule(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	user2 := oauth2FindRecord(t, app, "users", "test2@example.com")

	if _, err := app.SaveOAuth2Consent(user, oauth2FindClient(t, app, "3p"), []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.SaveOAuth2Consent(user2, oauth2FindClient(t, app, "3p"), []string{"openid"}); err != nil {
		t.Fatal(err)
	}

	b := newOAuth2Browser(t, app)

	// a first-party client token lists only its own consents
	legacy, err := tests.NewSessionAuthToken(app, user)
	if err != nil {
		t.Fatal(err)
	}
	res, body := b.do(http.MethodGet, "/api/collections/_oauth2Consents/records", "", map[string]string{"Authorization": legacy})
	b.expectStatus(res, body, http.StatusOK)
	if !strings.Contains(body, `"totalItems":1`) || !strings.Contains(body, user.Id) {
		t.Fatalf("Expected only the own consent, got %s", body)
	}

	// third-party OAuth2 access tokens can't manage the authorized apps
	token, _ := oauth2AccessToken(t, app, oauth2FindClient(t, app, "3p"), user, []string{"openid"})
	res, body = b.do(http.MethodGet, "/api/collections/_oauth2Consents/records", "", map[string]string{"Authorization": token})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d %s", res.StatusCode, body)
	}

	// the auth sessions are superusers only
	res, body = b.do(http.MethodGet, "/api/collections/_authSessions/records", "", map[string]string{"Authorization": legacy})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 for the auth sessions, got %d %s", res.StatusCode, body)
	}

	res, body = b.do(http.MethodGet, "/api/collections/_authSessions/records", "", map[string]string{"Authorization": oauth2TestSuperuserToken})
	b.expectStatus(res, body, http.StatusOK)
	for _, hidden := range []string{"handleHash", "bindingHash", "refreshTokenHash", "ssoSecretHash"} {
		if strings.Contains(body, hidden) {
			t.Fatalf("Expected hidden %q field even for superusers", hidden)
		}
	}
}
