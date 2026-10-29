package apis_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/webhooks"
	"github.com/pocketbase/dbx"
)

var (
	webhooksTestUserToken      = tests.AuthToken("users", "test@example.com")
	webhooksTestSuperuserToken = tests.AuthToken("_superusers", "test@example.com")

	webhooksTestId     = "whtest000000001"
	webhooksTestSecret = "test_secret_1234567890"
)

// webhooksTestSetup creates a test receiver (it fails with 500 if the
// request path ends with "/fail") and a "whtest000000001" subscription
// to the demo2 records and the "orders.*" custom topics.
func webhooksTestSetup(t testing.TB, app *tests.TestApp, path string) *httptest.Server {
	// stop the background dispatcher started on serve so that the
	// deliveries could be processed deterministically with ProcessDue
	if err := app.Webhooks().Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := webhooks.Verify(r, webhooksTestSecret); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/fail") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("oops"))
			return
		}
		w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	app.Settings().Webhooks.AllowPrivateTargets = true
	app.Settings().Webhooks.MaxAttempts = 1

	w := core.NewWebhook(app)
	w.Id = webhooksTestId
	w.SetName("test")
	w.SetURI(srv.URL + path)
	w.SetSecret(webhooksTestSecret)
	w.SetTopics([]string{"demo2.*", "orders.*"})
	w.SetActive(true)
	if err := app.Save(w); err != nil {
		t.Fatal(err)
	}

	return srv
}

// webhooksTestSeedDeliveries creates 1 success, 1 failed and 1 pending deliveries.
func webhooksTestSeedDeliveries(t testing.TB, app *tests.TestApp) map[string]string {
	ctx := context.Background()

	ids := map[string]string{}

	// success
	if err := app.Webhooks().Trigger(ctx, "orders.paid", map[string]any{"n": 1}); err != nil {
		t.Fatal(err)
	}
	app.Webhooks().ProcessDue(ctx, 10)

	// failed
	w, _ := app.FindWebhookById(webhooksTestId)
	uri := w.URI()
	w.SetURI(uri + "/fail")
	app.Save(w)
	if err := app.Webhooks().Trigger(ctx, "orders.refunded", map[string]any{"n": 2}); err != nil {
		t.Fatal(err)
	}
	app.Webhooks().ProcessDue(ctx, 10)
	w.SetURI(uri)
	app.Save(w)

	// pending (not due yet so that it couldn't be processed by the background dispatcher started on serve)
	if err := app.Webhooks().Trigger(ctx, "orders.created", map[string]any{"n": 3}); err != nil {
		t.Fatal(err)
	}
	_, err := app.AuxNonconcurrentDB().Update(
		core.WebhookDeliveriesTableName,
		dbx.Params{"nextAttemptAt": "2999-01-01 00:00:00.000Z"},
		dbx.HashExp{"topic": "orders.created"},
	).Execute()
	if err != nil {
		t.Fatal(err)
	}

	rows := []*core.WebhookDelivery{}
	app.WebhookDeliveryQuery().All(&rows)
	for _, r := range rows {
		ids[r.Status] = r.Id
	}

	if len(ids) != 3 {
		t.Fatalf("Expected 3 seeded deliveries with different statuses, got %v", ids)
	}

	return ids
}

func TestWebhooksTopics(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodGet,
			URL:             "/api/webhooks/topics",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "regular user",
			Method:          http.MethodGet,
			URL:             "/api/webhooks/topics",
			Headers:         map[string]string{"Authorization": webhooksTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:    "superuser",
			Method:  http.MethodGet,
			URL:     "/api/webhooks/topics",
			Headers: map[string]string{"Authorization": webhooksTestSuperuserToken},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Webhooks().RegisterTopic("orders.paid", "Order paid")
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"collections":[`,
				`{"topic":"sz5l5z67tg7gku0.create","label":"demo2.create"}`,
				`{"topic":"_pb_users_auth_.auth","label":"users.auth"}`,
				`"wildcards":[`,
				`{"topic":"*.*","label":"*.*"`,
				// note: the application lifecycle topics are always registered
				`"custom":[{"topic":"application.installed","label":"application.installed",`,
				`{"topic":"application.scopes_update","label":"application.scopes_update",`,
				`{"topic":"application.uninstalled","label":"application.uninstalled",`,
				`{"topic":"orders.paid","label":"orders.paid","description":"Order paid"}]`,
			},
			NotExpectedContent: []string{
				`"name":"_otps"`,
				`"name":"_webhooks"`,
				`"label":"demo2.auth"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestWebhooksSecret(t *testing.T) {
	t.Parallel()

	setup := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		webhooksTestSetup(t, app, "")
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "reveal as guest",
			Method:          http.MethodGet,
			URL:             "/api/webhooks/subscriptions/" + webhooksTestId + "/secret",
			BeforeTestFunc:  setup,
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:            "reveal as regular user",
			Method:          http.MethodGet,
			URL:             "/api/webhooks/subscriptions/" + webhooksTestId + "/secret",
			Headers:         map[string]string{"Authorization": webhooksTestUserToken},
			BeforeTestFunc:  setup,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:            "reveal missing",
			Method:          http.MethodGet,
			URL:             "/api/webhooks/subscriptions/missing/secret",
			Headers:         map[string]string{"Authorization": webhooksTestSuperuserToken},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:           "reveal as superuser",
			Method:         http.MethodGet,
			URL:            "/api/webhooks/subscriptions/" + webhooksTestId + "/secret",
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"` + webhooksTestId + `"`,
				`"secret":"` + webhooksTestSecret + `"`,
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if v := res.Header.Get("Cache-Control"); v != "no-store" {
					t.Fatalf("Expected no-store Cache-Control, got %q", v)
				}
			},
		},
		{
			Name:            "rotate as regular user",
			Method:          http.MethodPost,
			URL:             "/api/webhooks/subscriptions/" + webhooksTestId + "/rotate-secret",
			Headers:         map[string]string{"Authorization": webhooksTestUserToken},
			BeforeTestFunc:  setup,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:           "rotate as superuser",
			Method:         http.MethodPost,
			URL:            "/api/webhooks/subscriptions/" + webhooksTestId + "/rotate-secret",
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"` + webhooksTestId + `"`,
				`"secret":"`,
			},
			NotExpectedContent: []string{webhooksTestSecret},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				body := struct {
					Secret string `json:"secret"`
				}{}
				raw, _ := io.ReadAll(res.Body)
				json.Unmarshal(raw, &body)

				w, err := app.FindWebhookById(webhooksTestId)
				if err != nil {
					t.Fatal(err)
				}
				if len(body.Secret) != 40 || w.Secret() != body.Secret {
					t.Fatalf("Expected the new 40 chars secret to be stored, got %q vs %q", body.Secret, w.Secret())
				}
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestWebhooksRecordsApi(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "list as regular user",
			Method: http.MethodGet,
			URL:    "/api/collections/_webhooks/records",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				webhooksTestSetup(t, app, "")
			},
			Headers:         map[string]string{"Authorization": webhooksTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:   "view as superuser (secret is never exposed)",
			Method: http.MethodGet,
			URL:    "/api/collections/_webhooks/records/" + webhooksTestId,
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				webhooksTestSetup(t, app, "")
			},
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"` + webhooksTestId + `"`,
				`"hasSecret":true`,
				`"topics":["sz5l5z67tg7gku0.*","orders.*"]`,
				`"topicNames":["demo2.*","orders.*"]`,
				`"apiVersion":"` + core.WebhooksApiVersion + `"`,
			},
			NotExpectedContent: []string{
				`"secret":`,
				webhooksTestSecret,
			},
		},
		{
			Name:   "create as superuser (topics normalization + validation)",
			Method: http.MethodPost,
			URL:    "/api/collections/_webhooks/records",
			Body: strings.NewReader(`{
				"name":"new",
				"uri":"https://example.com/hook",
				"topics":["demo2.create","users.auth","orders.paid"],
				"filter":"id != ''",
				"active":true
			}`),
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"topics":["sz5l5z67tg7gku0.create","_pb_users_auth_.auth","orders.paid"]`,
				`"topicNames":["demo2.create","users.auth","orders.paid"]`,
				`"hasSecret":true`,
			},
			NotExpectedContent: []string{`"secret":`},
		},
		{
			Name:   "create as superuser (invalid)",
			Method: http.MethodPost,
			URL:    "/api/collections/_webhooks/records",
			Body: strings.NewReader(`{
				"name":"new",
				"uri":"https://example.com/hook",
				"topics":["demo2.auth","_otps.create"]
			}`),
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"topics":{`,
				`"0":{"code":"validation_invalid_webhook_topic_op"`,
				`"1":{"code":"validation_webhook_topic_collection_denied"`,
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestWebhooksTest(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "regular user",
			Method: http.MethodPost,
			URL:    "/api/webhooks/subscriptions/" + webhooksTestId + "/test",
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				webhooksTestSetup(t, app, "")
			},
			Headers:         map[string]string{"Authorization": webhooksTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:            "missing subscription",
			Method:          http.MethodPost,
			URL:             "/api/webhooks/subscriptions/missing/test",
			Headers:         map[string]string{"Authorization": webhooksTestSuperuserToken},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:   "invalid topic",
			Method: http.MethodPost,
			URL:    "/api/webhooks/subscriptions/" + webhooksTestId + "/test",
			Body:   strings.NewReader(`{"topic":"users.create"}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				webhooksTestSetup(t, app, "")
			},
			Headers:         map[string]string{"Authorization": webhooksTestSuperuserToken},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"message":"Invalid webhook topic`},
		},
		{
			Name:   "successful test send",
			Method: http.MethodPost,
			URL:    "/api/webhooks/subscriptions/" + webhooksTestId + "/test",
			Body:   strings.NewReader(`{"topic":"demo2.update"}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				webhooksTestSetup(t, app, "")
			},
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"webhook":"` + webhooksTestId + `"`,
				`"test":true`,
				`"status":"success"`,
				`"attempts":1`,
				`"responseStatus":200`,
				`"responseBody":"ok"`,
				`"topic":"sz5l5z67tg7gku0.update"`,
				`"topicName":"demo2.update"`,
				`"X-Pb-Test":"true"`,
				`\"changedFields\":[]`,
			},
			NotExpectedContent: []string{`"leaseToken"`},
		},
		{
			Name:   "failed test send",
			Method: http.MethodPost,
			URL:    "/api/webhooks/subscriptions/" + webhooksTestId + "/test",
			Body:   strings.NewReader(`{"topic":"orders.paid"}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				webhooksTestSetup(t, app, "/fail")
			},
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"test":true`,
				`"status":"failed"`,
				`"responseStatus":500`,
				`"responseBody":"oops"`,
				`"topicName":"orders.paid"`,
				`"nextAttemptAt":""`,
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestWebhookDeliveriesList(t *testing.T) {
	t.Parallel()

	setup := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		webhooksTestSetup(t, app, "")
		webhooksTestSeedDeliveries(t, app)
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "guest",
			Method:          http.MethodGet,
			URL:             "/api/webhooks/deliveries",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:            "regular user",
			Method:          http.MethodGet,
			URL:             "/api/webhooks/deliveries",
			Headers:         map[string]string{"Authorization": webhooksTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:           "superuser",
			Method:         http.MethodGet,
			URL:            "/api/webhooks/deliveries?sort=-created",
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"totalItems":3`,
				`"status":"success"`,
				`"status":"failed"`,
				`"status":"pending"`,
				`"topicName":"orders.paid"`,
			},
			NotExpectedContent: []string{`"leaseToken"`},
		},
		{
			Name:           "superuser with filter",
			Method:         http.MethodGet,
			URL:            "/api/webhooks/deliveries?filter=" + encodeQuery("status='failed' && topic='orders.refunded' && webhook='"+webhooksTestId+"' && created > '2000-01-01'"),
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"totalItems":1`,
				`"status":"failed"`,
				`"responseStatus":500`,
			},
		},
		{
			Name:            "superuser with invalid filter",
			Method:          http.MethodGet,
			URL:             "/api/webhooks/deliveries?filter=" + encodeQuery("leaseToken != ''"),
			Headers:         map[string]string{"Authorization": webhooksTestSuperuserToken},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func encodeQuery(v string) string {
	return strings.NewReplacer(" ", "%20", "'", "%27", "&", "%26", "=", "%3D", ">", "%3E", "!", "%21").Replace(v)
}

func TestWebhookDeliveriesViewStatsRedeliverTruncate(t *testing.T) {
	t.Parallel()

	var ids map[string]string

	setup := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		webhooksTestSetup(t, app, "")
		ids = webhooksTestSeedDeliveries(t, app)
	}

	// view
	// ---
	(&tests.ApiScenario{
		Name:            "view missing",
		Method:          http.MethodGet,
		URL:             "/api/webhooks/deliveries/missing",
		Headers:         map[string]string{"Authorization": webhooksTestSuperuserToken},
		ExpectedStatus:  404,
		ExpectedContent: []string{`"data":{}`},
	}).Test(t)

	t.Run("view existing", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()
		setup(t, app, nil)

		(&tests.ApiScenario{
			Name:           "view existing",
			Method:         http.MethodGet,
			URL:            "/api/webhooks/deliveries/" + ids["failed"],
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			TestAppFactory: func(t testing.TB) *tests.TestApp { return app },
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"` + ids["failed"] + `"`,
				`"status":"failed"`,
				`"payload":{"n":2}`,
				`"requestBody":"{\"n\":2}"`,
				`"responseBody":"oops"`,
				`"topicName":"orders.refunded"`,
			},
			DisableTestAppCleanup: true,
		}).Test(t)
	})

	// stats
	// ---
	scenarios := []tests.ApiScenario{
		{
			Name:            "stats as regular user",
			Method:          http.MethodGet,
			URL:             "/api/webhooks/deliveries/stats",
			Headers:         map[string]string{"Authorization": webhooksTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:            "stats with invalid params",
			Method:          http.MethodGet,
			URL:             "/api/webhooks/deliveries/stats?interval=week&groupBy=user",
			Headers:         map[string]string{"Authorization": webhooksTestSuperuserToken},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"interval":{`, `"groupBy":{`},
		},
		{
			Name:           "stats grouped by status",
			Method:         http.MethodGet,
			URL:            "/api/webhooks/deliveries/stats?interval=day&groupBy=status",
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"group":"failed","total":1,"success":0,"failed":1`,
				`"group":"pending","total":1`,
				`"group":"success","total":1,"success":1`,
			},
		},
		{
			Name:           "stats with filter",
			Method:         http.MethodGet,
			URL:            "/api/webhooks/deliveries/stats?filter=" + encodeQuery("topic='orders.paid'"),
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"group":"","total":1,"success":1`,
			},
			NotExpectedContent: []string{`"failed":1`},
		},
		{
			Name:            "truncate as regular user",
			Method:          http.MethodDelete,
			URL:             "/api/webhooks/deliveries",
			Headers:         map[string]string{"Authorization": webhooksTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
		},
		{
			Name:           "truncate as superuser (keeps the queued ones)",
			Method:         http.MethodDelete,
			URL:            "/api/webhooks/deliveries",
			Headers:        map[string]string{"Authorization": webhooksTestSuperuserToken},
			BeforeTestFunc: setup,
			ExpectedStatus: 204,
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				rows := []*core.WebhookDelivery{}
				app.WebhookDeliveryQuery().All(&rows)
				if len(rows) != 1 || rows[0].Status != core.WebhookDeliveryStatusPending {
					t.Fatalf("Expected only the pending delivery to remain, got %d", len(rows))
				}
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}

	// redeliver
	// ---
	redeliver := func(t *testing.T, status string, expectedStatus int, expectedContent []string, after func(t testing.TB, app *tests.TestApp)) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()
		setup(t, app, nil)

		(&tests.ApiScenario{
			Name:            "redeliver " + status,
			Method:          http.MethodPost,
			URL:             "/api/webhooks/deliveries/" + ids[status] + "/redeliver",
			Headers:         map[string]string{"Authorization": webhooksTestSuperuserToken},
			TestAppFactory:  func(t testing.TB) *tests.TestApp { return app },
			ExpectedStatus:  expectedStatus,
			ExpectedContent: expectedContent,
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if after != nil {
					after(t, app)
				}
			},
			DisableTestAppCleanup: true,
		}).Test(t)
	}

	t.Run("redeliver failed", func(t *testing.T) {
		redeliver(t, "failed", 200, []string{
			`"status":"success"`,
			`"attempts":1`,
			`"payload":{"n":2}`,
			`"topicName":"orders.refunded"`,
		}, func(t testing.TB, app *tests.TestApp) {
			original, _ := app.FindWebhookDeliveryById(ids["failed"])

			rows := []*core.WebhookDelivery{}
			app.WebhookDeliveryQuery().AndWhere(dbx.HashExp{"redeliveryOf": original.Id}).All(&rows)
			if len(rows) != 1 || rows[0].EventId != original.EventId || rows[0].Id == original.Id {
				t.Fatalf("Expected a new delivery with the same event id, got %v", rows)
			}
			if original.Status != core.WebhookDeliveryStatusFailed {
				t.Fatalf("Expected the original delivery to remain failed, got %q", original.Status)
			}
		})
	})

	t.Run("redeliver pending", func(t *testing.T) {
		redeliver(t, "pending", 400, []string{`"data":{}`}, nil)
	})

	(&tests.ApiScenario{
		Name:            "redeliver missing",
		Method:          http.MethodPost,
		URL:             "/api/webhooks/deliveries/missing/redeliver",
		Headers:         map[string]string{"Authorization": webhooksTestSuperuserToken},
		ExpectedStatus:  404,
		ExpectedContent: []string{`"data":{}`},
	}).Test(t)

	(&tests.ApiScenario{
		Name:            "redeliver as regular user",
		Method:          http.MethodPost,
		URL:             "/api/webhooks/deliveries/missing/redeliver",
		Headers:         map[string]string{"Authorization": webhooksTestUserToken},
		ExpectedStatus:  403,
		ExpectedContent: []string{`"data":{}`},
	}).Test(t)
}

// webhookActorStaff creates a staff member with webhooks write and the provided collections permissions.
func webhookActorStaff(t testing.TB, app core.App, email string, collections map[string][]string) (*core.Record, *core.Role, string) {
	t.Helper()

	role, err := tests.CreateRole(app, "hooks "+email, core.Permissions{
		Collections: collections,
		System:      map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
	})
	if err != nil {
		t.Fatal(err)
	}

	staff, err := tests.CreateStaff(app, email, role.Id)
	if err != nil {
		t.Fatal(err)
	}

	token, err := tests.NewSessionAuthToken(app, staff)
	if err != nil {
		t.Fatal(err)
	}

	return staff, role, token
}

func webhookDeliveriesCount(t testing.TB, app core.App, webhookId string) int {
	t.Helper()

	app.Webhooks().FlushEvents()

	var total int
	err := app.WebhookDeliveryQuery().Select("count(*)").AndWhere(dbx.HashExp{"webhook": webhookId}).Row(&total)
	if err != nil {
		t.Fatal(err)
	}

	return total
}

func webhookSaveRecord(t testing.TB, app core.App, collection string, title string) {
	t.Helper()

	c, err := app.FindCollectionByNameOrId(collection)
	if err != nil {
		t.Fatal(err)
	}

	r := core.NewRecord(c)
	r.Set("title", title)
	if err := app.Save(r); err != nil {
		t.Fatal(err)
	}
}

func webhookCreateViaApi(t testing.TB, app core.App, token string, topics string, extra string) (int, map[string]any) {
	t.Helper()

	status, body := appApi(t, app, http.MethodPost, "/api/collections/_webhooks/records", token,
		`{"name":"w1","uri":"https://example.com/hook","active":true,"topics":`+topics+extra+`}`)

	data := map[string]any{}
	_ = json.Unmarshal([]byte(body), &data)

	return status, data
}

func TestWebhooksActorSubscribeCoverage(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	demo3, _ := app.FindCollectionByNameOrId("demo3")

	staff, _, staffToken := webhookActorStaff(t, app, "hooks@example.com", map[string][]string{
		demo2.Id: {"list"}, // no view
		demo3.Id: {"view"},
	})
	_, _, wildcardToken := webhookActorStaff(t, app, "hooks-all@example.com", map[string][]string{
		core.PermissionAllCollections: {"view"},
	})
	ownerToken := mustOwnerToken(t, app)

	scenarios := []struct {
		name     string
		token    string
		topics   string
		status   int
		contains string
	}{
		{"not viewable collection", staffToken, `["demo2.create"]`, 400, `"validation_webhook_topic_forbidden"`},
		{"one not viewable collection", staffToken, `["demo3.create","demo2.update"]`, 400, `"1":{"code":"validation_webhook_topic_forbidden"`},
		{"wildcard without all collections view", staffToken, `["*.create"]`, 400, `"validation_webhook_topic_wildcard_forbidden"`},
		{"viewable collection", staffToken, `["demo3.create"]`, 200, `"topics":["`},
		{"custom topic", staffToken, `["orders.paid"]`, 200, `"orders.paid"`},
		{"wildcard with all collections view", wildcardToken, `["*.create"]`, 200, `"*.create"`},
		{"Owner any collection", ownerToken, `["users.update","*.delete"]`, 200, `"actorRef":""`},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			status, body := appApi(t, app, http.MethodPost, "/api/collections/_webhooks/records", s.token,
				`{"name":"w1","uri":"https://example.com/hook","topics":`+s.topics+`,"actorRef":"forged:value"}`)
			if status != s.status || !strings.Contains(body, s.contains) {
				t.Fatalf("Expected %d with %s, got %d %s", s.status, s.contains, status, body)
			}
			if strings.Contains(body, "forged:value") {
				t.Fatal("The actorRef must never be set from the request body")
			}
		})
	}

	// the actorRef of a staff subscription is the staff member
	status, data := webhookCreateViaApi(t, app, staffToken, `["demo3.create"]`, `,"actorRef":""`)
	if status != 200 || data["actorRef"] != core.WebhookActorRef(staff) {
		t.Fatalf("Expected the staff actorRef, got %d %v", status, data)
	}
	staffHookId := data["id"].(string)

	// an Owner subscription with topics the staff can't view can't be changed (no hijacking)
	_, ownerHook := webhookCreateViaApi(t, app, ownerToken, `["users.update"]`, "")
	ownerHookId := ownerHook["id"].(string)
	for _, body := range []string{`{"name":"renamed"}`, `{"topics":["demo3.create"]}`, `{"uri":"https://evil.example.com"}`} {
		if status, res := appApi(t, app, http.MethodPatch, "/api/collections/_webhooks/records/"+ownerHookId, staffToken, body); status != 403 {
			t.Fatalf("Expected the Owner subscription change %s to be rejected, got %d %s", body, status, res)
		}
	}

	// the Owner changing the staff subscription topics resets the actor (Owner = no dispatch checks)
	status, res := appApi(t, app, http.MethodPatch, "/api/collections/_webhooks/records/"+staffHookId, ownerToken, `{"topics":["demo2.create"]}`)
	if status != 200 || !strings.Contains(res, `"actorRef":""`) {
		t.Fatalf("Expected the Owner topics change to clear the actor, got %d %s", status, res)
	}

	// a non topics change keeps the actor
	status, data = webhookCreateViaApi(t, app, staffToken, `["demo3.update"]`, "")
	if status != 200 {
		t.Fatalf("Expected 200, got %d", status)
	}
	status, res = appApi(t, app, http.MethodPatch, "/api/collections/_webhooks/records/"+data["id"].(string), ownerToken, `{"name":"renamed by owner","actorRef":""}`)
	if status != 200 || !strings.Contains(res, `"actorRef":"`+core.WebhookActorRef(staff)+`"`) {
		t.Fatalf("Expected the actorRef to be kept on a non topics change, got %d %s", status, res)
	}

	// any non-Owner change sets the request actor (e.g. a changed URI must not
	// keep receiving the events with the previous Owner/no-checks access)
	_, ownerViewable := webhookCreateViaApi(t, app, ownerToken, `["demo3.delete"]`, "")
	ownerViewableId := ownerViewable["id"].(string)
	if ownerViewable["actorRef"] != "" {
		t.Fatalf("Expected an empty Owner actorRef, got %v", ownerViewable["actorRef"])
	}
	status, res = appApi(t, app, http.MethodPatch, "/api/collections/_webhooks/records/"+ownerViewableId, staffToken, `{"uri":"https://staff.example.com/hook","actorRef":""}`)
	if status != 200 || !strings.Contains(res, `"actorRef":"`+core.WebhookActorRef(staff)+`"`) {
		t.Fatalf("Expected the staff URI change to set the staff actorRef, got %d %s", status, res)
	}

	// the same for a secret rotation
	_, ownerViewable2 := webhookCreateViaApi(t, app, ownerToken, `["demo3.delete"]`, "")
	ownerViewable2Id := ownerViewable2["id"].(string)
	if status, res := appApi(t, app, http.MethodPost, "/api/webhooks/subscriptions/"+ownerViewable2Id+"/rotate-secret", staffToken, ""); status != 200 {
		t.Fatalf("Expected the covered secret rotation to be allowed, got %d %s", status, res)
	}
	if hook, _ := app.FindWebhookById(ownerViewable2Id); hook.ActorRef() != core.WebhookActorRef(staff) {
		t.Fatalf("Expected the staff secret rotation to set the staff actorRef, got %q", hook.ActorRef())
	}
	// (the Owner secret rotation keeps the actor)
	if status, _ := appApi(t, app, http.MethodPost, "/api/webhooks/subscriptions/"+ownerViewable2Id+"/rotate-secret", ownerToken, ""); status != 200 {
		t.Fatalf("Expected the Owner secret rotation to be allowed, got %d", status)
	}
	if hook, _ := app.FindWebhookById(ownerViewable2Id); hook.ActorRef() != core.WebhookActorRef(staff) {
		t.Fatalf("Expected the Owner secret rotation to keep the actorRef, got %q", hook.ActorRef())
	}

	// the covered subscription secret could be revealed by the staff member
	if status, res := appApi(t, app, http.MethodGet, "/api/webhooks/subscriptions/"+ownerViewable2Id+"/secret", staffToken, ""); status != 200 || !strings.Contains(res, `"secret":"`) {
		t.Fatalf("Expected the covered secret reveal to be allowed, got %d %s", status, res)
	}

	// the own subscription whose topics were changed by the Owner to not viewable ones is no longer accessible
	if status, _ := appApi(t, app, http.MethodGet, "/api/webhooks/subscriptions/"+staffHookId+"/secret", staffToken, ""); status != 403 {
		t.Fatalf("Expected the no longer covered secret reveal to be rejected, got %d", status)
	}
	if status, _ := appApi(t, app, http.MethodPatch, "/api/collections/_webhooks/records/"+staffHookId, staffToken, `{"topics":["demo3.create"]}`); status != 403 {
		t.Fatalf("Expected the no longer covered subscription change to be rejected, got %d", status)
	}

	// the secret, test and rotate endpoints require the topics view permission
	for _, s := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/secret"},
		{http.MethodPost, "/rotate-secret"},
		{http.MethodPost, "/test"},
	} {
		if status, res := appApi(t, app, s.method, "/api/webhooks/subscriptions/"+ownerHookId+s.path, staffToken, `{}`); status != 403 {
			t.Fatalf("Expected %s %s 403, got %d %s", s.method, s.path, status, res)
		}
	}
	if status, _ := appApi(t, app, http.MethodGet, "/api/webhooks/subscriptions/"+staffHookId+"/secret", ownerToken, ""); status != 200 {
		t.Fatalf("Expected the Owner to access any secret, got %d", status)
	}

	// delete is allowed with webhooks write (consistent with the other resources)
	if status, _ := appApi(t, app, http.MethodDelete, "/api/collections/_webhooks/records/"+ownerHookId, staffToken, ""); status != 204 {
		t.Fatalf("Expected the delete to be allowed, got %d", status)
	}
}

func TestWebhooksActorDispatchNarrowing(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo3, _ := app.FindCollectionByNameOrId("demo3")

	staff, role, staffToken := webhookActorStaff(t, app, "narrow@example.com", map[string][]string{demo3.Id: {"view"}})

	status, data := webhookCreateViaApi(t, app, staffToken, `["demo3.create"]`, "")
	if status != 200 {
		t.Fatalf("Expected 200, got %d %v", status, data)
	}
	hookId := data["id"].(string)

	webhookSaveRecord(t, app, "demo3", "first")
	if n := webhookDeliveriesCount(t, app, hookId); n != 1 {
		t.Fatalf("Expected 1 delivery, got %d", n)
	}

	// narrowing the role stops the deliveries immediately
	role.SetPermissions(core.Permissions{
		Collections: map[string][]string{demo3.Id: {"list"}},
		System:      map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
	})
	if err := app.Save(role); err != nil {
		t.Fatal(err)
	}
	webhookSaveRecord(t, app, "demo3", "second")
	if n := webhookDeliveriesCount(t, app, hookId); n != 1 {
		t.Fatalf("Expected no new delivery after the role narrowing, got %d", n)
	}

	// restored
	role.SetPermissions(core.Permissions{
		Collections: map[string][]string{demo3.Id: {"view"}},
		System:      map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
	})
	if err := app.Save(role); err != nil {
		t.Fatal(err)
	}
	webhookSaveRecord(t, app, "demo3", "third")
	if n := webhookDeliveriesCount(t, app, hookId); n != 2 {
		t.Fatalf("Expected a new delivery after restoring the role, got %d", n)
	}

	// deleted actor => nothing
	if err := app.Delete(staff); err != nil {
		t.Fatal(err)
	}
	webhookSaveRecord(t, app, "demo3", "fourth")
	if n := webhookDeliveriesCount(t, app, hookId); n != 2 {
		t.Fatalf("Expected no new delivery after the actor delete, got %d", n)
	}
}

func TestWebhooksActorApplication(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	demo3, _ := app.FindCollectionByNameOrId("demo3")

	installed := appInstall(t, app, "hooks-app", core.Permissions{
		Collections: map[string][]string{demo3.Id: {"list", "view"}, demo2.Id: {"list"}},
		System:      map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
	})
	token := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

	for _, s := range []struct {
		topics string
		status int
	}{
		{`["demo2.create"]`, 400}, // only list granted
		{`["*.create"]`, 400},     // never for the applications
		{`["users.update"]`, 400}, // not granted
		{`["demo3.create"]`, 200},
	} {
		status, data := webhookCreateViaApi(t, app, token, s.topics, "")
		if status != s.status {
			t.Fatalf("[%s] Expected %d, got %d %v", s.topics, s.status, status, data)
		}
	}

	// a narrowed token scope is also applied on subscribe
	narrowed := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "read_demo2 system:write_webhooks")
	if status, data := webhookCreateViaApi(t, app, narrowed, `["demo3.update"]`, ""); status != 400 {
		t.Fatalf("Expected the not scoped topic to be rejected, got %d %v", status, data)
	}

	hooks, _ := app.FindAllRecords(core.CollectionNameWebhooks, dbx.HashExp{"actorRef": core.WebhookActorRef(installed.Installation.Record)})
	if len(hooks) != 1 {
		t.Fatalf("Expected 1 application subscription, got %d", len(hooks))
	}
	hookId := hooks[0].Id

	webhookSaveRecord(t, app, "demo3", "app first")
	if n := webhookDeliveriesCount(t, app, hookId); n != 1 {
		t.Fatalf("Expected 1 delivery, got %d", n)
	}

	// grant narrowing applies at dispatch time (grant only, no token scopes)
	installation, _ := app.FindApplicationInstallationById(installed.Installation.Id)
	installation.SetPermissions(core.Permissions{
		Collections: map[string][]string{demo3.Id: {"list"}},
		System:      map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
	})
	if err := app.Save(installation); err != nil {
		t.Fatal(err)
	}
	webhookSaveRecord(t, app, "demo3", "app second")
	if n := webhookDeliveriesCount(t, app, hookId); n != 1 {
		t.Fatalf("Expected no new delivery after the grant narrowing, got %d", n)
	}

	// uninstall removes the application subscriptions
	if err := app.Delete(installation); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindWebhookById(hookId); err == nil {
		t.Fatal("Expected the application subscription to be deleted on uninstall")
	}
}

func TestWebhooksActorDeliveriesAccess(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo3, _ := app.FindCollectionByNameOrId("demo3")

	_, _, staffToken := webhookActorStaff(t, app, "reader@example.com", map[string][]string{demo3.Id: {"view"}})
	ownerToken := mustOwnerToken(t, app)

	visible := core.NewWebhook(app)
	visible.SetName("visible")
	visible.SetURI("https://example.com/visible")
	visible.SetTopics([]string{"demo3.create"})
	visible.SetActive(true)
	if err := app.Save(visible); err != nil {
		t.Fatal(err)
	}

	hidden := core.NewWebhook(app)
	hidden.SetName("hidden")
	hidden.SetURI("https://example.com/hidden")
	hidden.SetTopics([]string{"demo3.create", "users.update"})
	hidden.SetActive(true)
	if err := app.Save(hidden); err != nil {
		t.Fatal(err)
	}

	// a subscription whose previous topic was not viewable
	changed := core.NewWebhook(app)
	changed.SetName("changed")
	changed.SetURI("https://example.com/changed")
	changed.SetTopics([]string{"demo2.create"})
	changed.SetActive(true)
	if err := app.Save(changed); err != nil {
		t.Fatal(err)
	}
	webhookSaveRecord(t, app, "demo2", "previous topic")
	if webhookDeliveriesCount(t, app, changed.Id) != 1 {
		t.Fatal("Expected 1 demo2.create delivery")
	}
	changed.SetTopics([]string{"demo3.update"})
	if err := app.Save(changed); err != nil {
		t.Fatal(err)
	}

	webhookSaveRecord(t, app, "demo3", "deliveries")
	if webhookDeliveriesCount(t, app, visible.Id) != 1 || webhookDeliveriesCount(t, app, hidden.Id) != 1 {
		t.Fatal("Expected 1 delivery per subscription")
	}

	findDelivery := func(webhookId string) string {
		var id string
		if err := app.WebhookDeliveryQuery().Select("id").AndWhere(dbx.HashExp{"webhook": webhookId}).Row(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	visibleDelivery := findDelivery(visible.Id)
	hiddenDelivery := findDelivery(hidden.Id)
	previousTopicDelivery := findDelivery(changed.Id)

	// list (with pagination totals)
	status, body := appApi(t, app, http.MethodGet, "/api/webhooks/deliveries?perPage=1", staffToken, "")
	if status != 200 || !strings.Contains(body, `"totalItems":1`) || !strings.Contains(body, visibleDelivery) ||
		strings.Contains(body, hiddenDelivery) || strings.Contains(body, previousTopicDelivery) {
		t.Fatalf("Expected only the visible delivery, got %d %s", status, body)
	}
	status, body = appApi(t, app, http.MethodGet, "/api/webhooks/deliveries", ownerToken, "")
	if status != 200 || !strings.Contains(body, `"totalItems":3`) {
		t.Fatalf("Expected the Owner to see all deliveries, got %d %s", status, body)
	}

	// view
	if status, _ := appApi(t, app, http.MethodGet, "/api/webhooks/deliveries/"+hiddenDelivery, staffToken, ""); status != 404 {
		t.Fatalf("Expected the hidden delivery to be 404, got %d", status)
	}
	if status, _ := appApi(t, app, http.MethodGet, "/api/webhooks/deliveries/"+visibleDelivery, staffToken, ""); status != 200 {
		t.Fatalf("Expected the visible delivery to be 200, got %d", status)
	}
	if status, _ := appApi(t, app, http.MethodGet, "/api/webhooks/deliveries/"+previousTopicDelivery, staffToken, ""); status != 404 {
		t.Fatalf("Expected the previous not viewable topic delivery to be 404, got %d", status)
	}
	if status, _ := appApi(t, app, http.MethodGet, "/api/webhooks/deliveries/"+hiddenDelivery, ownerToken, ""); status != 200 {
		t.Fatalf("Expected the Owner to view any delivery, got %d", status)
	}

	// redeliver
	if status, _ := appApi(t, app, http.MethodPost, "/api/webhooks/deliveries/"+hiddenDelivery+"/redeliver", staffToken, ""); status != 404 {
		t.Fatalf("Expected the hidden delivery redeliver to be 404, got %d", status)
	}

	// stats
	status, body = appApi(t, app, http.MethodGet, "/api/webhooks/deliveries/stats", staffToken, "")
	if status != 200 || !strings.Contains(body, `"total":1`) {
		t.Fatalf("Expected the stats of the visible deliveries only, got %d %s", status, body)
	}
	status, body = appApi(t, app, http.MethodGet, "/api/webhooks/deliveries/stats?filter="+strings.ReplaceAll("status!=''", "'", "%27"), staffToken, "")
	if status != 200 || !strings.Contains(body, `"total":1`) {
		t.Fatalf("Expected the filtered stats of the visible deliveries only, got %d %s", status, body)
	}

	// truncate deletes only the accessible completed deliveries
	_, err := app.AuxNonconcurrentDB().Update(
		core.WebhookDeliveriesTableName,
		dbx.Params{"status": core.WebhookDeliveryStatusSuccess},
		nil,
	).Execute()
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := appApi(t, app, http.MethodDelete, "/api/webhooks/deliveries", staffToken, ""); status != 204 {
		t.Fatalf("Expected the truncate to be allowed, got %d", status)
	}
	if webhookDeliveriesCount(t, app, visible.Id) != 0 || webhookDeliveriesCount(t, app, hidden.Id) != 1 || webhookDeliveriesCount(t, app, changed.Id) != 1 {
		t.Fatal("Expected only the visible delivery to be deleted by the staff truncate")
	}
	if status, _ := appApi(t, app, http.MethodDelete, "/api/webhooks/deliveries", ownerToken, ""); status != 204 {
		t.Fatalf("Expected the Owner truncate to be allowed, got %d", status)
	}
	if webhookDeliveriesCount(t, app, hidden.Id) != 0 || webhookDeliveriesCount(t, app, changed.Id) != 0 {
		t.Fatal("Expected the Owner truncate to delete all completed deliveries")
	}
}

func TestWebhooksPayloadExcludesSecretFields(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// a system collection with a not hidden secret field
	c := core.NewBaseCollection("_w1secrets")
	c.System = true
	c.Fields.Add(&core.TextField{Name: "title"}, &core.TextField{Name: "apiSecret"})
	if err := app.Save(c); err != nil {
		t.Fatal(err)
	}

	hook := core.NewWebhook(app)
	hook.SetName("secrets")
	hook.SetURI("https://example.com/secrets")
	hook.SetTopics([]string{"_w1secrets.create"})
	hook.SetActive(true)
	if err := app.Save(hook); err != nil {
		t.Fatal(err)
	}

	r := core.NewRecord(c)
	r.Set("title", "visible")
	r.Set("apiSecret", "top-secret-value")
	if err := app.Save(r); err != nil {
		t.Fatal(err)
	}

	app.Webhooks().FlushEvents()

	var payload string
	if err := app.WebhookDeliveryQuery().Select("payload").AndWhere(dbx.HashExp{"webhook": hook.Id}).Row(&payload); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(payload, `"title":"visible"`) || strings.Contains(payload, "top-secret-value") || strings.Contains(payload, "apiSecret") {
		t.Fatalf("Expected the secret field to be excluded, got %s", payload)
	}

	// the synthetic test events too
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	app.Settings().Webhooks.AllowPrivateTargets = true
	hook.SetURI(srv.URL)
	if err := app.Save(hook); err != nil {
		t.Fatal(err)
	}

	delivery, err := app.Webhooks().SendTest(context.Background(), hook, "_w1secrets.create")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(delivery.Payload), `"title":""`) || strings.Contains(string(delivery.Payload), "apiSecret") {
		t.Fatalf("Expected the secret field to be excluded from the test payload, got %s", delivery.Payload)
	}
}

func TestWebhooksActorFilterAccess(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, _ := app.FindCollectionByNameOrId("users")
	demo2, _ := app.FindCollectionByNameOrId("demo2")
	demo3, _ := app.FindCollectionByNameOrId("demo3")

	_, _, staffToken := webhookActorStaff(t, app, "filter@example.com", map[string][]string{
		users.Id: {"view"},
		demo2.Id: {"list"}, // no view
		demo3.Id: {"view"},
	})
	ownerToken := mustOwnerToken(t, app)

	installed := appInstall(t, app, "filter-app", core.Permissions{
		Collections: map[string][]string{users.Id: {"view"}, demo3.Id: {"view"}},
		System:      map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
	})
	appToken := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")

	scenarios := []struct {
		name   string
		topics string
		filter string
		status map[string]int // token => status
	}{
		{"secret field (tokenKey)", `["users.update"]`, `tokenKey ~ 'a'`, map[string]int{staffToken: 400, appToken: 400, ownerToken: 200}},
		{"secret field (password)", `["users.update"]`, `password != ''`, map[string]int{staffToken: 400, appToken: 400, ownerToken: 200}},
		{"@collection not viewable", `["demo3.create"]`, `@collection.demo2.title = 'x'`, map[string]int{staffToken: 400, appToken: 400, ownerToken: 200}},
		{"@collection system", `["demo3.create"]`, `@collection._superusers.email ~ 'a'`, map[string]int{staffToken: 400, appToken: 400, ownerToken: 200}},
		{"@collection secret field of a viewable collection", `["demo3.create"]`, `@collection.users.tokenKey ~ 'a'`, map[string]int{staffToken: 400, appToken: 400, ownerToken: 200}},
		{"relation into a not viewable collection", `["users.update"]`, `rel.title != ''`, map[string]int{staffToken: 400, appToken: 400, ownerToken: 200}},
		{"back-relation from a not viewable collection", `["demo3.create"]`, `demo4_via_rel_one_cascade.title != ''`, map[string]int{staffToken: 400, appToken: 400, ownerToken: 200}},
		{"own fields", `["demo3.create"]`, `title != ''`, map[string]int{staffToken: 200, appToken: 200, ownerToken: 200}},
		{"@collection viewable", `["demo3.create"]`, `@collection.users.email ~ 'a'`, map[string]int{staffToken: 200, appToken: 200, ownerToken: 200}},
	}

	for _, s := range scenarios {
		for token, expected := range s.status {
			t.Run(s.name, func(t *testing.T) {
				filter, _ := json.Marshal(s.filter)
				status, data := webhookCreateViaApi(t, app, token, s.topics, `,"filter":`+string(filter))
				if status != expected {
					t.Fatalf("Expected %d, got %d %v", expected, status, data)
				}
				if expected == 400 {
					raw, _ := json.Marshal(data)
					if !strings.Contains(string(raw), `"filter":{"code":"validation_webhook_filter_forbidden"`) {
						t.Fatalf("Expected the filter field error, got %s", raw)
					}
				}
			})
		}
	}

	// an Owner subscription with a filter the staff member can't use is not accessible (no adoption/oracle)
	status, ownerHook := webhookCreateViaApi(t, app, ownerToken, `["demo3.create"]`, `,"filter":"@collection.demo2.title != ''"`)
	if status != 200 {
		t.Fatalf("Expected 200, got %d %v", status, ownerHook)
	}
	ownerHookId := ownerHook["id"].(string)
	if status, _ := appApi(t, app, http.MethodPatch, "/api/collections/_webhooks/records/"+ownerHookId, staffToken, `{"name":"adopted"}`); status != 403 {
		t.Fatalf("Expected the change of a subscription with a not allowed filter to be rejected, got %d", status)
	}
	if status, _ := appApi(t, app, http.MethodGet, "/api/webhooks/subscriptions/"+ownerHookId+"/secret", staffToken, ""); status != 403 {
		t.Fatalf("Expected the secret reveal of a subscription with a not allowed filter to be rejected, got %d", status)
	}
	webhookSaveRecord(t, app, "demo3", "owner filter")
	if webhookDeliveriesCount(t, app, ownerHookId) != 1 {
		t.Fatal("Expected the Owner filter to be evaluated without restrictions")
	}
	status, body := appApi(t, app, http.MethodGet, "/api/webhooks/deliveries", staffToken, "")
	if status != 200 || strings.Contains(body, ownerHookId) {
		t.Fatalf("Expected the deliveries of a subscription with a not allowed filter to be hidden, got %d %s", status, body)
	}
}

func TestWebhooksActorFilterDispatchNarrowing(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, _ := app.FindCollectionByNameOrId("users")
	demo3, _ := app.FindCollectionByNameOrId("demo3")

	_, role, staffToken := webhookActorStaff(t, app, "filter-narrow@example.com", map[string][]string{
		users.Id: {"view"},
		demo3.Id: {"view"},
	})

	status, data := webhookCreateViaApi(t, app, staffToken, `["demo3.create"]`, `,"filter":"@collection.users.email != ''"`)
	if status != 200 {
		t.Fatalf("Expected 200, got %d %v", status, data)
	}
	hookId := data["id"].(string)

	webhookSaveRecord(t, app, "demo3", "first")
	if n := webhookDeliveriesCount(t, app, hookId); n != 1 {
		t.Fatalf("Expected 1 delivery, got %d", n)
	}

	// narrowing the role (the topic collection is still viewable but the filter join is not) skips the events
	role.SetPermissions(core.Permissions{
		Collections: map[string][]string{demo3.Id: {"view"}},
		System:      map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
	})
	if err := app.Save(role); err != nil {
		t.Fatal(err)
	}
	webhookSaveRecord(t, app, "demo3", "second")
	if n := webhookDeliveriesCount(t, app, hookId); n != 1 {
		t.Fatalf("Expected no new delivery after the role narrowing, got %d", n)
	}

	// application: grant narrowing
	installed := appInstall(t, app, "filter-narrow-app", core.Permissions{
		Collections: map[string][]string{users.Id: {"view"}, demo3.Id: {"view"}},
		System:      map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
	})
	token := appToken(t, app, installed.Client.ClientId(), installed.ClientSecret, "")
	status, data = webhookCreateViaApi(t, app, token, `["demo3.create"]`, `,"filter":"@collection.users.email != ''"`)
	if status != 200 {
		t.Fatalf("Expected 200, got %d %v", status, data)
	}
	appHookId := data["id"].(string)

	webhookSaveRecord(t, app, "demo3", "app first")
	if n := webhookDeliveriesCount(t, app, appHookId); n != 1 {
		t.Fatalf("Expected 1 application delivery, got %d", n)
	}

	installation, _ := app.FindApplicationInstallationById(installed.Installation.Id)
	installation.SetPermissions(core.Permissions{
		Collections: map[string][]string{demo3.Id: {"view"}},
		System:      map[string]string{core.PermissionResourceWebhooks: core.PermissionLevelWrite},
	})
	if err := app.Save(installation); err != nil {
		t.Fatal(err)
	}
	webhookSaveRecord(t, app, "demo3", "app second")
	if n := webhookDeliveriesCount(t, app, appHookId); n != 1 {
		t.Fatalf("Expected no new application delivery after the grant narrowing, got %d", n)
	}
}
