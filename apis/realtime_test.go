package apis_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/subscriptions"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

func TestRealtimeConnect(t *testing.T) {
	scenarios := []tests.ApiScenario{
		{
			Method:         http.MethodGet,
			URL:            "/api/realtime",
			Timeout:        100 * time.Millisecond,
			Headers:        map[string]string{"x-test-ip": "127.0.0.2"},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`id:`,
				`event:PB_CONNECT`,
				`data:{"clientId":`,
			},
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRealtimeConnectRequest": 1,
				"OnRealtimeMessageSend":    1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().TrustedProxy.Headers = []string{"x-test-ip"}

				app.OnRealtimeConnectRequest().BindFunc(func(e *core.RealtimeConnectRequestEvent) error {
					if ip, _ := e.Client.Get(apis.RealtimeClientIPKey).(string); ip != "127.0.0.2" {
						t.Fatalf("Expected IP %q, got %q", "127.0.0.2", ip)
					}

					return e.Next()
				})
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if len(app.SubscriptionsBroker().Clients()) != 0 {
					t.Errorf("Expected the subscribers to be removed after connection close, found %d", len(app.SubscriptionsBroker().Clients()))
				}
			},
		},
		{
			Name:           "PB_CONNECT interrupt",
			Method:         http.MethodGet,
			URL:            "/api/realtime",
			Timeout:        100 * time.Millisecond,
			ExpectedStatus: 200,
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRealtimeConnectRequest": 1,
				"OnRealtimeMessageSend":    1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnRealtimeMessageSend().BindFunc(func(e *core.RealtimeMessageEvent) error {
					if e.Message.Name == "PB_CONNECT" {
						return errors.New("PB_CONNECT error")
					}
					return e.Next()
				})
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if len(app.SubscriptionsBroker().Clients()) != 0 {
					t.Errorf("Expected the subscribers to be removed after connection close, found %d", len(app.SubscriptionsBroker().Clients()))
				}
			},
		},
		{
			Name:           "Skipping/ignoring messages",
			Method:         http.MethodGet,
			URL:            "/api/realtime",
			Timeout:        100 * time.Millisecond,
			ExpectedStatus: 200,
			ExpectedEvents: map[string]int{
				"*":                        0,
				"OnRealtimeConnectRequest": 1,
				"OnRealtimeMessageSend":    1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnRealtimeMessageSend().BindFunc(func(e *core.RealtimeMessageEvent) error {
					return nil
				})
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if len(app.SubscriptionsBroker().Clients()) != 0 {
					t.Errorf("Expected the subscribers to be removed after connection close, found %d", len(app.SubscriptionsBroker().Clients()))
				}
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRealtimeSubscribe(t *testing.T) {
	client := subscriptions.NewDefaultClient()

	resetClient := func() {
		client.Unsubscribe()
		client.Unset(apis.RealtimeClientAuthKey)
		client.Unset(apis.RealtimeClientIPKey)
	}

	validSubscriptionsLimit := make([]string, 1000)
	for i := 0; i < len(validSubscriptionsLimit); i++ {
		validSubscriptionsLimit[i] = fmt.Sprintf(`"%d"`, i)
	}
	invalidSubscriptionsLimit := make([]string, 1001)
	for i := 0; i < len(invalidSubscriptionsLimit); i++ {
		invalidSubscriptionsLimit[i] = fmt.Sprintf(`"%d"`, i)
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "missing client",
			Method:          http.MethodPost,
			URL:             "/api/realtime",
			Body:            strings.NewReader(`{"clientId":"missing","subscriptions":["test1", "test2"]}`),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "empty data",
			Method:         http.MethodPost,
			URL:            "/api/realtime",
			Body:           strings.NewReader(`{}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"clientId":{"code":"validation_required`,
			},
			NotExpectedContent: []string{
				`"subscriptions"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "existing client with invalid subscriptions limit",
			Method: http.MethodPost,
			URL:    "/api/realtime",
			Body: strings.NewReader(`{
				"clientId": "` + client.Id() + `",
				"subscriptions": [` + strings.Join(invalidSubscriptionsLimit, ",") + `]
			}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				resetClient()
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"subscriptions":{"code":"validation_length_too_long"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:   "existing client with valid subscriptions limit",
			Method: http.MethodPost,
			URL:    "/api/realtime",
			Body: strings.NewReader(`{
				"clientId": "` + client.Id() + `",
				"subscriptions": [` + strings.Join(validSubscriptionsLimit, ",") + `]
			}`),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRealtimeSubscribeRequest": 1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				client.Subscribe("test0") // should be replaced
				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if len(client.Subscriptions()) != len(validSubscriptionsLimit) {
					t.Errorf("Expected %d subscriptions, got %d", len(validSubscriptionsLimit), len(client.Subscriptions()))
				}
				if client.HasSubscription("test0") {
					t.Errorf("Expected old subscriptions to be replaced")
				}
				resetClient()
			},
		},
		{
			Name:   "existing client with invalid topic length",
			Method: http.MethodPost,
			URL:    "/api/realtime",
			Body: strings.NewReader(`{
				"clientId": "` + client.Id() + `",
				"subscriptions": ["abc", "` + strings.Repeat("a", 2501) + `"]
			}`),
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				resetClient()
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"data":{`,
				`"subscriptions":{"1":{"code":"validation_length_too_long"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:            "existing client with different IP",
			Method:          http.MethodPost,
			URL:             "/api/realtime",
			Body:            strings.NewReader(`{"clientId":"` + client.Id() + `","subscriptions":["test"]}`),
			Headers:         map[string]string{"x-test-ip": "127.0.0.2"},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().TrustedProxy.Headers = []string{"x-test-ip"}

				client.Set(apis.RealtimeClientIPKey, "127.0.0.1")

				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				resetClient()
			},
		},
		{
			Name:   "existing client with valid topic length",
			Method: http.MethodPost,
			URL:    "/api/realtime",
			Body: strings.NewReader(`{
				"clientId": "` + client.Id() + `",
				"subscriptions": ["abc", "` + strings.Repeat("a", 2500) + `"]
			}`),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRealtimeSubscribeRequest": 1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				client.Subscribe("test0")
				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if len(client.Subscriptions()) != 2 {
					t.Errorf("Expected %d subscriptions, got %d", 2, len(client.Subscriptions()))
				}
				if client.HasSubscription("test0") {
					t.Errorf("Expected old subscriptions to be replaced")
				}
				resetClient()
			},
		},
		{
			Name:           "existing client - empty subscriptions",
			Method:         http.MethodPost,
			URL:            "/api/realtime",
			Body:           strings.NewReader(`{"clientId":"` + client.Id() + `","subscriptions":[]}`),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRealtimeSubscribeRequest": 1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				client.Subscribe("test0")
				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if len(client.Subscriptions()) != 0 {
					t.Errorf("Expected no subscriptions, got %d", len(client.Subscriptions()))
				}
				resetClient()
			},
		},
		{
			Name:           "existing client - 2 new subscriptions",
			Method:         http.MethodPost,
			URL:            "/api/realtime",
			Body:           strings.NewReader(`{"clientId":"` + client.Id() + `","subscriptions":["test1", "test2"]}`),
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRealtimeSubscribeRequest": 1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				client.Subscribe("test0")
				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				expectedSubs := []string{"test1", "test2"}
				if len(expectedSubs) != len(client.Subscriptions()) {
					t.Errorf("Expected subscriptions %v, got %v", expectedSubs, client.Subscriptions())
				}

				for _, s := range expectedSubs {
					if !client.HasSubscription(s) {
						t.Errorf("Cannot find %q subscription in %v", s, client.Subscriptions())
					}
				}
				resetClient()
			},
		},
		{
			Name:   "existing client - guest -> authorized superuser",
			Method: http.MethodPost,
			URL:    "/api/realtime",
			Body:   strings.NewReader(`{"clientId":"` + client.Id() + `","subscriptions":["test1", "test2"]}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRealtimeSubscribeRequest": 1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				authRecord, _ := client.Get(apis.RealtimeClientAuthKey).(*core.Record)
				if authRecord == nil || !authRecord.IsSuperuser() {
					t.Errorf("Expected superuser auth record, got %v", authRecord)
				}
				resetClient()
			},
		},
		{
			Name:   "existing client - guest -> authorized regular auth record",
			Method: http.MethodPost,
			URL:    "/api/realtime",
			Body:   strings.NewReader(`{"clientId":"` + client.Id() + `","subscriptions":["test1", "test2"]}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRealtimeSubscribeRequest": 1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				authRecord, _ := client.Get(apis.RealtimeClientAuthKey).(*core.Record)
				if authRecord == nil {
					t.Errorf("Expected regular user auth record, got %v", authRecord)
				}
				resetClient()
			},
		},
		{
			Name:   "existing client - same auth",
			Method: http.MethodPost,
			URL:    "/api/realtime",
			Body:   strings.NewReader(`{"clientId":"` + client.Id() + `","subscriptions":["test1", "test2"]}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                          0,
				"OnRealtimeSubscribeRequest": 1,
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				// the same user as the auth token
				user, err := app.FindAuthRecordByEmail("users", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}

				client.Set(apis.RealtimeClientAuthKey, user)

				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				authRecord, _ := client.Get(apis.RealtimeClientAuthKey).(*core.Record)
				if authRecord == nil {
					t.Errorf("Expected auth record model, got nil")
				}
				resetClient()
			},
		},
		{
			Name:   "existing client - mismatched auth",
			Method: http.MethodPost,
			URL:    "/api/realtime",
			Body:   strings.NewReader(`{"clientId":"` + client.Id() + `","subscriptions":["test1", "test2"]}`),
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test2@example.com")
				if err != nil {
					t.Fatal(err)
				}

				client.Set(apis.RealtimeClientAuthKey, user)

				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				authRecord, _ := client.Get(apis.RealtimeClientAuthKey).(*core.Record)
				if authRecord == nil {
					t.Errorf("Expected auth record model, got nil")
				}
				resetClient()
			},
		},
		{
			Name:            "existing client - unauthorized client",
			Method:          http.MethodPost,
			URL:             "/api/realtime",
			Body:            strings.NewReader(`{"clientId":"` + client.Id() + `","subscriptions":["test1", "test2"]}`),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				user, err := app.FindAuthRecordByEmail("users", "test2@example.com")
				if err != nil {
					t.Fatal(err)
				}

				client.Set(apis.RealtimeClientAuthKey, user)

				app.SubscriptionsBroker().Register(client)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				authRecord, _ := client.Get(apis.RealtimeClientAuthKey).(*core.Record)
				if authRecord == nil {
					t.Errorf("Expected auth record model, got nil")
				}
				resetClient()
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestRealtimeAuthRecordDeleteEvent(t *testing.T) {
	testApp, _ := tests.NewTestApp()
	defer testApp.Cleanup()

	// init realtime handlers
	_, err := apis.NewRouter(testApp)
	if err != nil {
		t.Fatal(err)
	}

	authRecord1, err := testApp.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	authRecord2, err := testApp.FindAuthRecordByEmail("users", "test2@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client1 := subscriptions.NewDefaultClient()
	client1.Set(apis.RealtimeClientAuthKey, authRecord1)
	testApp.SubscriptionsBroker().Register(client1)

	client2 := subscriptions.NewDefaultClient()
	client2.Set(apis.RealtimeClientAuthKey, authRecord1)
	testApp.SubscriptionsBroker().Register(client2)

	client3 := subscriptions.NewDefaultClient()
	client3.Set(apis.RealtimeClientAuthKey, authRecord2)
	testApp.SubscriptionsBroker().Register(client3)

	// mock delete event
	e := new(core.ModelEvent)
	e.App = testApp
	e.Type = core.ModelEventTypeDelete
	e.Context = context.Background()
	e.Model = authRecord1

	err = testApp.OnModelAfterDeleteSuccess().Trigger(e)
	if err != nil {
		t.Fatal(err)
	}

	if total := len(testApp.SubscriptionsBroker().Clients()); total != 3 {
		t.Fatalf("Expected %d subscription clients, found %d", 3, total)
	}

	if auth := client1.Get(apis.RealtimeClientAuthKey); auth != nil {
		t.Fatalf("[client1] Expected the auth state to be unset, found %#v", auth)
	}

	if auth := client2.Get(apis.RealtimeClientAuthKey); auth != nil {
		t.Fatalf("[client2] Expected the auth state to be unset, found %#v", auth)
	}

	if auth := client3.Get(apis.RealtimeClientAuthKey); auth == nil || auth.(*core.Record).Id != authRecord2.Id {
		t.Fatalf("[client3] Expected the auth state to be left unchanged, found %#v", auth)
	}
}

func TestRealtimeAuthRecordUpdateEvent(t *testing.T) {
	testApp, _ := tests.NewTestApp()
	defer testApp.Cleanup()

	// init realtime handlers
	_, err := apis.NewRouter(testApp)
	if err != nil {
		t.Fatal(err)
	}

	authRecord1, err := testApp.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client := subscriptions.NewDefaultClient()
	client.Set(apis.RealtimeClientAuthKey, authRecord1)
	testApp.SubscriptionsBroker().Register(client)

	// refetch the authRecord and change its name
	authRecord2, err := testApp.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	newName := "test_new_name"
	authRecord2.Set("name", newName)

	err = testApp.Save(authRecord2)
	if err != nil {
		t.Fatal(err)
	}

	clientAuthRecord, _ := client.Get(apis.RealtimeClientAuthKey).(*core.Record)
	if clientAuthRecord.Get("name") != newName {
		t.Fatalf("Expected authRecord with email %q, got %q", newName, clientAuthRecord.Email())
	}
}

func TestRealtimeRecordHiddenFields(t *testing.T) {
	t.Parallel()

	testApp, _ := tests.NewTestApp()
	defer testApp.Cleanup()

	// init realtime handlers
	_, err := apis.NewRouter(testApp)
	if err != nil {
		t.Fatal(err)
	}

	// create temp collection with hidden fields
	testCollection := core.NewBaseCollection("test_realtime")
	testCollection.ListRule = types.Pointer("@request.auth.id != ''")
	testCollection.Fields.Add(
		&core.TextField{Name: "public"},
		&core.TextField{Name: "hidden", Hidden: true},
	)
	if err := testApp.Save(testCollection); err != nil {
		t.Fatal(err)
	}

	testSubscription := testCollection.Name + "/*"

	// register guest subscriber
	guestClient := subscriptions.NewDefaultClient()
	guestClient.Subscribe(testSubscription)
	testApp.SubscriptionsBroker().Register(guestClient)

	// register regular user subscriber
	regular, err := testApp.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	regularClient := subscriptions.NewDefaultClient()
	regularClient.Set(apis.RealtimeClientAuthKey, regular)
	regularClient.Subscribe(testSubscription)
	testApp.SubscriptionsBroker().Register(regularClient)

	// register superuser subscriber
	superuser, err := testApp.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	superuserClient := subscriptions.NewDefaultClient()
	superuserClient.Set(apis.RealtimeClientAuthKey, superuser)
	superuserClient.Subscribe(testSubscription)
	testApp.SubscriptionsBroker().Register(superuserClient)

	enrichCalls := map[string]int{}
	testApp.OnRecordEnrich(testCollection.Name).BindFunc(func(e *core.RecordEnrichEvent) error {
		var id string
		if e.RequestInfo.Auth != nil {
			id = e.RequestInfo.Auth.Id
		}
		enrichCalls[id]++
		return e.Next()
	})

	timeout := time.After(3 * time.Second)
	done := make(chan struct{})

	// collect first received messages
	var regularMessageData, superuserMessageData string
	go func() {
		regularMessageData = string((<-regularClient.Channel()).Data)
		superuserMessageData = string((<-superuserClient.Channel()).Data)
		done <- struct{}{}
	}()

	// broadcast create message
	testRecord := core.NewRecord(testCollection)
	testRecord.Set("public", "test1")
	testRecord.Set("hidden", "test2")
	if err := testApp.Save(testRecord); err != nil {
		t.Fatal(err)
	}

	// wait for the events
	select {
	case <-timeout:
		t.Fatal("realtime test messages timeout")
	case <-done:
		// ready
	}

	if total := len(enrichCalls); total != 2 {
		t.Fatalf("Expected %d enrich hook calls, got %d", 2, total)
	}

	if total := enrichCalls[regular.Id]; total != 1 {
		t.Fatalf("Expected exactly 1 regular user enrich hook call, got %d", total)
	}

	if total := enrichCalls[superuser.Id]; total != 1 {
		t.Fatalf("Expected exactly 1 superuser enrich hook call, got %d", total)
	}

	// validate messages content
	scenarios := map[string]bool{
		"regular message public field should exist":     strings.Contains(regularMessageData, `"public":`),
		"regular message hidden field should NOT exist": !strings.Contains(regularMessageData, `"hidden":`),
		"superuser message public field should exist":   strings.Contains(superuserMessageData, `"public":`),
		"superuser message hidden field should exist":   strings.Contains(superuserMessageData, `"hidden":`),
	}
	for name, valid := range scenarios {
		t.Run(name, func(t *testing.T) {
			if !valid {
				t.Fatal("Invalid realtime message expectation")
			}
		})
	}
}

func TestRealtimeAuthRecordUnsetOnTokenKeyRefresh(t *testing.T) {
	testApp, _ := tests.NewTestApp()
	defer testApp.Cleanup()

	// init realtime handlers
	_, err := apis.NewRouter(testApp)
	if err != nil {
		t.Fatal(err)
	}

	authRecord1, err := testApp.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client := subscriptions.NewDefaultClient()
	client.Set(apis.RealtimeClientAuthKey, authRecord1)
	testApp.SubscriptionsBroker().Register(client)

	// refetch the authRecord and refresh its tokenKey
	authRecord2, err := testApp.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	authRecord2.RefreshTokenKey()

	err = testApp.Save(authRecord2)
	if err != nil {
		t.Fatal(err)
	}

	clientAuthRecord, _ := client.Get(apis.RealtimeClientAuthKey).(*core.Record)
	if clientAuthRecord != nil {
		t.Fatalf("Expected authRecord to be unset, got %q", clientAuthRecord.Email())
	}
}

func TestRealtimeAuthRecordUnsetOnCollectionSecretChange(t *testing.T) {
	testApp, _ := tests.NewTestApp()
	defer testApp.Cleanup()

	// init realtime handlers
	_, err := apis.NewRouter(testApp)
	if err != nil {
		t.Fatal(err)
	}

	usersCollection, err := testApp.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	clientsCollection, err := testApp.FindCollectionByNameOrId("clients")
	if err != nil {
		t.Fatal(err)
	}

	authRecord1, err := testApp.FindAuthRecordByEmail(usersCollection, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	client1 := subscriptions.NewDefaultClient()
	client1.Set(apis.RealtimeClientAuthKey, authRecord1)

	authRecord2, err := testApp.FindAuthRecordByEmail(usersCollection, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	client2 := subscriptions.NewDefaultClient()
	client2.Set(apis.RealtimeClientAuthKey, authRecord2)

	authRecord3, err := testApp.FindAuthRecordByEmail(clientsCollection, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	client3 := subscriptions.NewDefaultClient()
	client3.Set(apis.RealtimeClientAuthKey, authRecord3)

	clientMocks := map[*core.Record]subscriptions.Client{
		authRecord1: client1,
		authRecord2: client2,
		authRecord3: client3,
	}
	for _, client := range clientMocks {
		testApp.SubscriptionsBroker().Register(client)
	}

	// change the secret of the users collection (should trigger unset)
	usersCollection.AuthToken.Secret = strings.Repeat("a", 30)
	err = testApp.Save(usersCollection)
	if err != nil {
		t.Fatal(err)
	}

	// change something else of the clients collection (shouldn't trigger unset)
	clientsCollection.ListRule = nil
	err = testApp.Save(clientsCollection)
	if err != nil {
		t.Fatal(err)
	}

	expectations := map[*core.Record]bool{
		// record -> unset
		authRecord1: true,
		authRecord2: true,
		authRecord3: false,
	}
	for record, expectedUnset := range expectations {
		clientAuthRecord, _ := clientMocks[record].Get(apis.RealtimeClientAuthKey).(*core.Record)
		unset := clientAuthRecord == nil
		if unset != expectedUnset {
			t.Fatalf("Expected unset state %v, got %v (%v)", expectedUnset, unset, clientAuthRecord)
		}
	}
}

func TestRealtimeAuthRecordUnsetOnCollectionDelete(t *testing.T) {
	testApp, _ := tests.NewTestApp()
	defer testApp.Cleanup()

	// init realtime handlers
	_, err := apis.NewRouter(testApp)
	if err != nil {
		t.Fatal(err)
	}

	usersCollection, err := testApp.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	clientsCollection, err := testApp.FindCollectionByNameOrId("clients")
	if err != nil {
		t.Fatal(err)
	}

	authRecord1, err := testApp.FindAuthRecordByEmail(usersCollection, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	client1 := subscriptions.NewDefaultClient()
	client1.Set(apis.RealtimeClientAuthKey, authRecord1)

	authRecord2, err := testApp.FindAuthRecordByEmail(usersCollection, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	client2 := subscriptions.NewDefaultClient()
	client2.Set(apis.RealtimeClientAuthKey, authRecord2)

	authRecord3, err := testApp.FindAuthRecordByEmail(clientsCollection, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	client3 := subscriptions.NewDefaultClient()
	client3.Set(apis.RealtimeClientAuthKey, authRecord3)

	clientMocks := map[*core.Record]subscriptions.Client{
		authRecord1: client1,
		authRecord2: client2,
		authRecord3: client3,
	}
	for _, client := range clientMocks {
		testApp.SubscriptionsBroker().Register(client)
	}

	// mock users collection delete event to avoid triggering constraints check
	e := new(core.ModelEvent)
	e.App = testApp
	e.Type = core.ModelEventTypeDelete
	e.Context = context.Background()
	e.Model = usersCollection

	err = testApp.OnModelAfterDeleteSuccess().Trigger(e)
	if err != nil {
		t.Fatal(err)
	}

	expectations := map[*core.Record]bool{
		// record -> unset
		authRecord1: true,
		authRecord2: true,
		authRecord3: false,
	}
	for record, expectedUnset := range expectations {
		clientAuthRecord, _ := clientMocks[record].Get(apis.RealtimeClientAuthKey).(*core.Record)
		unset := clientAuthRecord == nil
		if unset != expectedUnset {
			t.Fatalf("Expected unset state %v, got %v (%v)", expectedUnset, unset, clientAuthRecord)
		}
	}
}

// Custom auth record model struct
// -------------------------------------------------------------------
var _ core.Model = (*CustomUser)(nil)

type CustomUser struct {
	core.BaseModel

	Email string `db:"email" json:"email"`
}

func (m *CustomUser) TableName() string {
	return "users"
}

func findCustomUserByEmail(app core.App, email string) (*CustomUser, error) {
	model := &CustomUser{}

	err := app.ModelQuery(model).
		AndWhere(dbx.HashExp{"email": email}).
		Limit(1).
		One(model)

	if err != nil {
		return nil, err
	}

	return model, nil
}

func TestRealtimeCustomAuthModelDeleteEvent(t *testing.T) {
	testApp, _ := tests.NewTestApp()
	defer testApp.Cleanup()

	// init realtime handlers
	_, err := apis.NewRouter(testApp)
	if err != nil {
		t.Fatal(err)
	}

	authRecord1, err := testApp.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	authRecord2, err := testApp.FindAuthRecordByEmail("users", "test2@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client1 := subscriptions.NewDefaultClient()
	client1.Set(apis.RealtimeClientAuthKey, authRecord1)
	testApp.SubscriptionsBroker().Register(client1)

	client2 := subscriptions.NewDefaultClient()
	client2.Set(apis.RealtimeClientAuthKey, authRecord1)
	testApp.SubscriptionsBroker().Register(client2)

	client3 := subscriptions.NewDefaultClient()
	client3.Set(apis.RealtimeClientAuthKey, authRecord2)
	testApp.SubscriptionsBroker().Register(client3)

	// refetch the authRecord as CustomUser
	customUser, err := findCustomUserByEmail(testApp, authRecord1.Email())
	if err != nil {
		t.Fatal(err)
	}

	// delete the custom user (should unset the client auth record)
	if err := testApp.Delete(customUser); err != nil {
		t.Fatal(err)
	}

	if total := len(testApp.SubscriptionsBroker().Clients()); total != 3 {
		t.Fatalf("Expected %d subscription clients, found %d", 3, total)
	}

	if auth := client1.Get(apis.RealtimeClientAuthKey); auth != nil {
		t.Fatalf("[client1] Expected the auth state to be unset, found %#v", auth)
	}

	if auth := client2.Get(apis.RealtimeClientAuthKey); auth != nil {
		t.Fatalf("[client2] Expected the auth state to be unset, found %#v", auth)
	}

	if auth := client3.Get(apis.RealtimeClientAuthKey); auth == nil || auth.(*core.Record).Id != authRecord2.Id {
		t.Fatalf("[client3] Expected the auth state to be left unchanged, found %#v", auth)
	}
}

func TestRealtimeCustomAuthModelUpdateEvent(t *testing.T) {
	testApp, _ := tests.NewTestApp()
	defer testApp.Cleanup()

	// init realtime handlers
	_, err := apis.NewRouter(testApp)
	if err != nil {
		t.Fatal(err)
	}

	authRecord, err := testApp.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	client := subscriptions.NewDefaultClient()
	client.Set(apis.RealtimeClientAuthKey, authRecord)
	testApp.SubscriptionsBroker().Register(client)

	// refetch the authRecord as CustomUser
	customUser, err := findCustomUserByEmail(testApp, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// change its email
	customUser.Email = "new@example.com"
	if err := testApp.Save(customUser); err != nil {
		t.Fatal(err)
	}

	clientAuthRecord, _ := client.Get(apis.RealtimeClientAuthKey).(*core.Record)
	if clientAuthRecord.Email() != customUser.Email {
		t.Fatalf("Expected authRecord with email %q, got %q", customUser.Email, clientAuthRecord.Email())
	}
}

// -------------------------------------------------------------------

var _ core.Model = (*CustomModelResolve)(nil)

type CustomModelResolve struct {
	core.BaseModel
	tableName string

	Created string `db:"created"`
}

func (m *CustomModelResolve) TableName() string {
	return m.tableName
}

func TestRealtimeRecordResolve(t *testing.T) {
	t.Parallel()

	const testCollectionName = "realtime_test_collection"

	testRecordId := core.GenerateDefaultRandomId()

	client0 := subscriptions.NewDefaultClient()
	client0.Subscribe(testCollectionName + "/*")
	client0.Discard()
	// ---
	client1 := subscriptions.NewDefaultClient()
	client1.Subscribe(testCollectionName + "/*")
	// ---
	client2 := subscriptions.NewDefaultClient()
	client2.Subscribe(testCollectionName + "/" + testRecordId)
	// ---
	client3 := subscriptions.NewDefaultClient()
	client3.Subscribe("demo1/*")

	scenarios := []struct {
		name     string
		op       func(testApp core.App) error
		expected map[string][]string // clientId -> [events]
	}{
		{
			"core.Record",
			func(testApp core.App) error {
				c, err := testApp.FindCollectionByNameOrId(testCollectionName)
				if err != nil {
					return err
				}

				r := core.NewRecord(c)
				r.Id = testRecordId

				// create
				err = testApp.Save(r)
				if err != nil {
					return err
				}

				// update
				err = testApp.Save(r)
				if err != nil {
					return err
				}

				// delete
				err = testApp.Delete(r)
				if err != nil {
					return err
				}

				return nil
			},
			map[string][]string{
				client1.Id(): {"create", "update", "delete"},
				client2.Id(): {"create", "update", "delete"},
			},
		},
		{
			"core.RecordProxy",
			func(testApp core.App) error {
				c, err := testApp.FindCollectionByNameOrId(testCollectionName)
				if err != nil {
					return err
				}

				r := core.NewRecord(c)

				proxy := &struct {
					core.BaseRecordProxy
				}{}
				proxy.SetProxyRecord(r)
				proxy.Id = testRecordId

				// create
				err = testApp.Save(proxy)
				if err != nil {
					return err
				}

				// update
				err = testApp.Save(proxy)
				if err != nil {
					return err
				}

				// delete
				err = testApp.Delete(proxy)
				if err != nil {
					return err
				}

				return nil
			},
			map[string][]string{
				client1.Id(): {"create", "update", "delete"},
				client2.Id(): {"create", "update", "delete"},
			},
		},
		{
			"custom model struct",
			func(testApp core.App) error {
				m := &CustomModelResolve{tableName: testCollectionName}
				m.Id = testRecordId

				// create
				err := testApp.Save(m)
				if err != nil {
					return err
				}

				// update
				m.Created = "123"
				err = testApp.Save(m)
				if err != nil {
					return err
				}

				// delete
				err = testApp.Delete(m)
				if err != nil {
					return err
				}

				return nil
			},
			map[string][]string{
				client1.Id(): {"create", "update", "delete"},
				client2.Id(): {"create", "update", "delete"},
			},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			testApp, _ := tests.NewTestApp()
			defer testApp.Cleanup()

			// init realtime handlers
			apis.NewRouter(testApp)

			// create new test collection with public read access
			testCollection := core.NewBaseCollection(testCollectionName)
			testCollection.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true, OnUpdate: true})
			testCollection.ListRule = types.Pointer("")
			testCollection.ViewRule = types.Pointer("")
			err := testApp.Save(testCollection)
			if err != nil {
				t.Fatal(err)
			}

			testApp.SubscriptionsBroker().Register(client0)
			testApp.SubscriptionsBroker().Register(client1)
			testApp.SubscriptionsBroker().Register(client2)
			testApp.SubscriptionsBroker().Register(client3)

			var wg sync.WaitGroup

			var notifications = map[string][]string{}

			var mu sync.Mutex
			notify := func(clientId string, eventData []byte) {
				data := struct {
					Action string `json:"action"`
				}{}
				_ = json.Unmarshal(eventData, &data)

				mu.Lock()
				defer mu.Unlock()

				if notifications[clientId] == nil {
					notifications[clientId] = []string{}
				}
				notifications[clientId] = append(notifications[clientId], data.Action)
			}

			wg.Add(1)
			go func() {
				defer wg.Done()

				timeout := time.After(250 * time.Millisecond)

				for {
					select {
					case e, ok := <-client0.Channel():
						if ok {
							notify(client0.Id(), e.Data)
						}
					case e, ok := <-client1.Channel():
						if ok {
							notify(client1.Id(), e.Data)
						}
					case e, ok := <-client2.Channel():
						if ok {
							notify(client2.Id(), e.Data)
						}
					case e, ok := <-client3.Channel():
						if ok {
							notify(client3.Id(), e.Data)
						}
					case <-timeout:
						return
					}
				}
			}()

			err = s.op(testApp)
			if err != nil {
				t.Fatal(err)
			}

			wg.Wait()

			if len(s.expected) != len(notifications) {
				t.Fatalf("Expected %d notified clients, got %d:\n%v", len(s.expected), len(notifications), notifications)
			}

			for id, events := range s.expected {
				if len(events) != len(notifications[id]) {
					t.Fatalf("[%s] Expected %d events, got %d:\n%v\n%v", id, len(events), len(notifications[id]), s.expected, notifications)
				}
				for _, event := range events {
					if !slices.Contains(notifications[id], event) {
						t.Fatalf("[%s] Missing expected event %q in %v", id, event, notifications[id])
					}
				}
			}
		})
	}
}

func TestRBACRealtimeStaffNoSecretFields(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	if _, err := apis.NewRouter(app); err != nil {
		t.Fatal(err)
	}

	_, _, staff := rbacAuditSetup(t, app)
	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")

	staffClient := subscriptions.NewDefaultClient()
	staffClient.Set(apis.RealtimeClientAuthKey, staff)
	staffClient.Subscribe(core.CollectionNameSuperusers + "/*")
	app.SubscriptionsBroker().Register(staffClient)

	ownerClient := subscriptions.NewDefaultClient()
	ownerClient.Set(apis.RealtimeClientAuthKey, owner)
	ownerClient.Subscribe(core.CollectionNameSuperusers + "/*")
	app.SubscriptionsBroker().Register(ownerClient)

	var staffMsg, ownerMsg string
	wg := sync.WaitGroup{}
	wg.Go(func() {
		select {
		case m := <-staffClient.Channel():
			staffMsg = string(m.Data)
		case <-time.After(1500 * time.Millisecond):
		}
	})
	wg.Go(func() {
		select {
		case m := <-ownerClient.Channel():
			ownerMsg = string(m.Data)
		case <-time.After(1500 * time.Millisecond):
		}
	})

	target, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test2@example.com")
	target.SetEmail("test2_new@example.com")
	if err := app.Save(target); err != nil {
		t.Fatal(err)
	}

	wg.Wait()

	if staffMsg == "" || strings.Contains(staffMsg, `"tokenKey"`) || strings.Contains(staffMsg, target.TokenKey()) {
		t.Fatalf("Expected a staff message without tokenKey, got %q", staffMsg)
	}

	// note: the tokenKey is never exported (not even for the Owners) but the Owner still receives the event
	if !strings.Contains(ownerMsg, "test2_new@example.com") {
		t.Fatalf("Expected the Owner message, got %q", ownerMsg)
	}
}

func TestRBACRealtime(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// init realtime handlers
	if _, err := apis.NewRouter(app); err != nil {
		t.Fatal(err)
	}

	collection := core.NewBaseCollection("rbac_rt")
	collection.ListRule = types.Pointer("")
	collection.ViewRule = types.Pointer("")
	collection.Fields.Add(
		&core.TextField{Name: "public"},
		&core.TextField{Name: "hidden", Hidden: true},
	)
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}

	viewRole, err := tests.CreateRole(app, "rt viewer", core.Permissions{
		Collections: map[string][]string{collection.Id: {"list", "view"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	otherRole, err := tests.CreateRole(app, "rt other", core.Permissions{
		Collections: map[string][]string{collection.Id: {"create"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	limited, _ := tests.CreateStaff(app, "limited@example.com", viewRole.Id)
	none, _ := tests.CreateStaff(app, "none@example.com")
	customer, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	restricted, _ := app.FindAuthRecordByEmail("users", "test2@example.com")
	if err := tests.AssignRoles(app, restricted, otherRole.Id); err != nil {
		t.Fatal(err)
	}

	type sub struct {
		name           string
		auth           *core.Record
		oauth2         *core.RequestInfoOAuth2
		expectMessage  bool
		expectedHidden bool
	}

	subs := []*sub{
		{name: "guest", expectMessage: true},
		{name: "Owner", auth: owner, expectMessage: true, expectedHidden: true},
		{name: "staff with view permission", auth: limited, expectMessage: true, expectedHidden: true},
		{name: "staff without roles", auth: none},
		{name: "customer default role", auth: customer, expectMessage: true},
		{name: "customer without view permission", auth: restricted},
		{name: "third-party without scope", auth: customer, oauth2: &core.RequestInfoOAuth2{ClientId: "3p", Scopes: []string{"openid"}}},
		{name: "third-party with scope", auth: customer, oauth2: &core.RequestInfoOAuth2{ClientId: "3p", Scopes: []string{"read_rbac_rt"}}, expectMessage: true},
		{name: "first-party token", auth: customer, oauth2: &core.RequestInfoOAuth2{ClientId: "1p", FirstParty: true}, expectMessage: true},
	}

	clients := make([]subscriptions.Client, len(subs))
	for i, s := range subs {
		c := subscriptions.NewDefaultClient()
		if s.auth != nil {
			c.Set(apis.RealtimeClientAuthKey, s.auth)
		}
		if s.oauth2 != nil {
			c.Set(apis.RealtimeClientOAuth2Key, *s.oauth2)
		}
		c.Subscribe(collection.Name + "/*")
		app.SubscriptionsBroker().Register(c)
		clients[i] = c
	}

	messages := make([]string, len(subs))
	wg := sync.WaitGroup{}
	for i, c := range clients {
		wg.Go(func() {
			select {
			case msg := <-c.Channel():
				messages[i] = string(msg.Data)
			case <-time.After(1500 * time.Millisecond):
			}
		})
	}

	record := core.NewRecord(collection)
	record.Set("public", "public_value")
	record.Set("hidden", "hidden_value")
	if err := app.Save(record); err != nil {
		t.Fatal(err)
	}

	wg.Wait()

	for i, s := range subs {
		got := messages[i] != ""
		if got != s.expectMessage {
			t.Errorf("[%s] Expected message %v, got %q", s.name, s.expectMessage, messages[i])
			continue
		}
		if got && strings.Contains(messages[i], "hidden_value") != s.expectedHidden {
			t.Errorf("[%s] Expected hidden field visibility %v, got %q", s.name, s.expectedHidden, messages[i])
		}
	}
}

// W2: the realtime client-side filter can't reference the secret fields (even if not hidden) for the non-Owners.
func TestRBACRealtimeFilterSecretFields(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// init realtime handlers
	if _, err := apis.NewRouter(app); err != nil {
		t.Fatal(err)
	}

	collection := core.NewBaseCollection("rbac_rt_secret")
	collection.ListRule = types.Pointer("")
	collection.ViewRule = types.Pointer("")
	collection.Fields.Add(
		&core.TextField{Name: "title"},
		&core.PasswordField{Name: "pin", Hidden: false, Cost: 4}, // min bcrypt cost (test only)
	)
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}

	viewRole, err := tests.CreateRole(app, "rt secret viewer", core.Permissions{
		Collections: map[string][]string{collection.Id: {"list", "view"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	staff, err := tests.CreateStaff(app, "rt-secret@example.com", viewRole.Id)
	if err != nil {
		t.Fatal(err)
	}

	subs := []struct {
		name          string
		auth          *core.Record
		filter        string
		expectMessage bool
	}{
		{"Owner secret field filter", owner, "pin != ''", true},
		{"staff secret field filter", staff, "pin != ''", false},
		{"staff regular field filter", staff, "title != ''", true},
	}

	clients := make([]subscriptions.Client, len(subs))
	for i, s := range subs {
		c := subscriptions.NewDefaultClient()
		c.Set(apis.RealtimeClientAuthKey, s.auth)
		c.Subscribe(collection.Name + `/*?options={"query":{"filter":"` + s.filter + `"}}`)
		app.SubscriptionsBroker().Register(c)
		clients[i] = c
	}

	record := core.NewRecord(collection)
	record.Set("title", "test")
	record.Set("pin", "1234567890")
	if err := app.Save(record); err != nil {
		t.Fatal(err)
	}

	// note: the messages are sent in the background with unbuffered channels
	// (the wait starts after the save so that it doesn't include the password hashing)
	messages := make([]string, len(subs))
	wg := sync.WaitGroup{}
	for i, c := range clients {
		wg.Go(func() {
			select {
			case msg := <-c.Channel():
				messages[i] = string(msg.Data)
			case <-time.After(1500 * time.Millisecond):
			}
		})
	}

	wg.Wait()

	for i, s := range subs {
		if got := messages[i] != ""; got != s.expectMessage {
			t.Errorf("[%s] Expected message %v, got %q", s.name, s.expectMessage, messages[i])
		}
	}
}
