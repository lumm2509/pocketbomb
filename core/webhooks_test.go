package core_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/webhooks"
	"github.com/pocketbase/dbx"
)

// webhookReceiver is a test webhook receiver that verifies the signatures.
type webhookReceiver struct {
	*httptest.Server

	mu       sync.Mutex
	secret   string
	requests []*receivedWebhook
	status   func(n int) int // response status of the n-th (1-based) request
}

type receivedWebhook struct {
	header http.Header
	body   []byte
	valid  bool
}

func newWebhookReceiver(secret string) *webhookReceiver {
	r := &webhookReceiver{secret: secret}

	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		secret := r.secret
		r.mu.Unlock()

		body, err := webhooks.Verify(req, secret)
		if err != nil {
			body, _ = io.ReadAll(req.Body)
		}

		r.mu.Lock()
		r.requests = append(r.requests, &receivedWebhook{header: req.Header.Clone(), body: body, valid: err == nil})
		n := len(r.requests)
		statusFn := r.status
		r.mu.Unlock()

		status := http.StatusOK
		if err != nil {
			status = http.StatusUnauthorized
		} else if statusFn != nil {
			status = statusFn(n)
		}

		w.WriteHeader(status)
		w.Write([]byte(`{"received":true}`))
	}))

	return r
}

func (r *webhookReceiver) received() []*receivedWebhook {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.requests)
}

func newWebhooksTestApp(t testing.TB) *tests.TestApp {
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}

	// allow the local httptest receivers
	app.Settings().Webhooks.AllowPrivateTargets = true

	return app
}

func createTestWebhook(t testing.TB, app core.App, uri string, topics []string, modify func(w *core.Webhook)) *core.Webhook {
	w := core.NewWebhook(app)
	w.SetName("test")
	w.SetURI(uri)
	w.SetTopics(topics)
	w.SetActive(true)
	if modify != nil {
		modify(w)
	}

	if err := app.Save(w); err != nil {
		t.Fatalf("Failed to save webhook: %v", err)
	}

	return w
}

func findTestDeliveries(t testing.TB, app core.App, webhookId string) []*core.WebhookDelivery {
	result := []*core.WebhookDelivery{}

	err := app.WebhookDeliveryQuery().
		AndWhere(dbx.HashExp{"webhook": webhookId}).
		OrderBy("created ASC", "rowid ASC").
		All(&result)
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func saveTestRecord(t testing.TB, app core.App, collection string, data map[string]any) *core.Record {
	c, err := app.FindCollectionByNameOrId(collection)
	if err != nil {
		t.Fatal(err)
	}

	// demo2.title is required to be unique and with min 2 chars
	if title, ok := data["title"].(string); ok && c.Name == "demo2" {
		data["title"] = title + "-" + security.PseudorandomString(6)
	}

	r := core.NewRecord(c)
	r.Load(data)
	if err := app.Save(r); err != nil {
		t.Fatal(err)
	}

	return r
}

// -------------------------------------------------------------------

func TestWebhookValidation(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	scenarios := []struct {
		name         string
		modify       func(w *core.Webhook)
		expectedErrs []string
	}{
		{
			// note: the base fields validators run before the custom ones
			"empty uri",
			func(w *core.Webhook) {
				w.SetURI("")
				w.SetTopics(nil)
			},
			[]string{"uri"},
		},
		{
			"empty topics",
			func(w *core.Webhook) {
				w.SetTopics(nil)
			},
			[]string{"topics"},
		},
		{
			"invalid uri and api version",
			func(w *core.Webhook) {
				w.SetURI("ftp://example.com")
				w.SetApiVersion("1999-01")
			},
			[]string{"uri", "apiVersion"},
		},
		{
			"relative uri",
			func(w *core.Webhook) {
				w.SetURI("/test")
			},
			[]string{"uri"},
		},
		{
			"invalid topics",
			func(w *core.Webhook) {
				w.SetTopics([]string{"demo2.create", "demo2.auth", "_otps.create"})
			},
			[]string{"topics"},
		},
		{
			"too short secret",
			func(w *core.Webhook) {
				w.SetSecret("abc")
			},
			[]string{"secret"},
		},
		{
			"invalid filter",
			func(w *core.Webhook) {
				w.SetFilter("missing = 1")
			},
			[]string{"filter"},
		},
		{
			"filter with custom topics only",
			func(w *core.Webhook) {
				w.SetTopics([]string{"orders.paid"})
				w.SetFilter("id != ''")
			},
			[]string{"filter"},
		},
		{
			"invalid fields",
			func(w *core.Webhook) {
				w.SetFields([]string{"id", "title:unknown"})
			},
			[]string{"fields"},
		},
		{
			"missing client",
			func(w *core.Webhook) {
				w.SetClient("missing")
			},
			[]string{"client"},
		},
		{
			"valid",
			func(w *core.Webhook) {
				w.SetTopics([]string{"demo2.create", "demo2.create", "*.delete", "orders.paid"})
				w.SetFilter("title != 'skip'")
				w.SetFields([]string{"id", "title:excerpt(10)"})
			},
			nil,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			w := core.NewWebhook(app)
			w.SetName("test")
			w.SetURI("https://example.com/hook")
			w.SetTopics([]string{"demo2.create"})
			s.modify(w)

			err := app.Validate(w)

			var errs map[string]error
			if err != nil {
				raw, _ := json.Marshal(err)
				json.Unmarshal(raw, &errs)
			}

			for _, k := range s.expectedErrs {
				if !strings.Contains(errString(err), `"`+k+`"`) {
					t.Errorf("Missing expected error key %q in %v", k, errString(err))
				}
			}

			if len(s.expectedErrs) == 0 && err != nil {
				t.Fatalf("Expected no errors, got %v", err)
			}
		})
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	raw, _ := json.Marshal(err)
	return string(raw)
}

func TestWebhookSaveDefaults(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")

	w := createTestWebhook(t, app, "https://example.com", []string{"demo2.create", "demo2.create"}, func(w *core.Webhook) {
		w.SetFailureCount(5)
		w.SetDisabledReason("old")
	})

	if len(w.Secret()) < 40 {
		t.Fatalf("Expected auto generated secret, got %q", w.Secret())
	}
	if w.ApiVersion() != core.WebhooksApiVersion {
		t.Fatalf("Expected default api version, got %q", w.ApiVersion())
	}
	if !slices.Equal(w.Topics(), []string{demo2.Id + ".create"}) {
		t.Fatalf("Expected normalized deduplicated topics, got %v", w.Topics())
	}
	if w.FailureCount() != 0 || w.DisabledReason() != "" {
		t.Fatalf("Expected reset failures state on activation, got %d %q", w.FailureCount(), w.DisabledReason())
	}

	// the secret should be hidden in the public export
	if _, ok := w.PublicExport()["secret"]; ok {
		t.Fatal("Expected the secret to be hidden")
	}
}

func TestTriggerWebhookErrors(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	ctx := context.Background()

	if err := app.Webhooks().Trigger(ctx, "demo2.paid", nil); !errors.Is(err, core.ErrWebhookInvalidTopic) {
		t.Fatalf("Expected collection clash error, got %v", err)
	}
	if err := app.Webhooks().Trigger(ctx, "orders", nil); !errors.Is(err, core.ErrWebhookInvalidTopic) {
		t.Fatalf("Expected invalid topic error, got %v", err)
	}
	if err := app.Webhooks().Trigger(ctx, "orders.*", nil); !errors.Is(err, core.ErrWebhookInvalidTopic) {
		t.Fatalf("Expected invalid topic error for wildcard, got %v", err)
	}
	if err := app.Webhooks().Trigger(ctx, "orders.paid", []byte("{invalid")); err == nil {
		t.Fatal("Expected invalid JSON payload error")
	}
	if err := app.Webhooks().Trigger(ctx, "orders.paid", nil); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// register
	if err := app.Webhooks().RegisterTopic("demo2.x", ""); err == nil {
		t.Fatal("Expected clash error")
	}
	if err := app.Webhooks().RegisterTopic("orders.paid", "Order paid"); err != nil {
		t.Fatal(err)
	}

	topics, err := app.Webhooks().Topics()
	if err != nil {
		t.Fatal(err)
	}
	// note: the application lifecycle topics are registered on bootstrap
	customTopics := map[string]string{}
	for _, c := range topics.Custom {
		customTopics[c.Topic] = c.Description
	}
	if len(customTopics) != 4 || customTopics["orders.paid"] != "Order paid" ||
		customTopics[core.ApplicationEventInstalled] == "" ||
		customTopics[core.ApplicationEventUninstalled] == "" ||
		customTopics[core.ApplicationEventScopesUpdate] == "" {
		t.Fatalf("Unexpected custom topics %v", topics.Custom)
	}
	for _, c := range topics.Collections {
		if c.Name == core.CollectionNameOTPs || c.Name == core.CollectionNameWebhooks {
			t.Fatalf("Denied collection %q should not be listed", c.Name)
		}
		if c.Name == "users" && len(c.Topics) != 6 {
			t.Fatalf("Expected 6 users topics, got %v", c.Topics)
		}
		if c.Name == "demo2" && len(c.Topics) != 4 {
			t.Fatalf("Expected 4 demo2 topics, got %v", c.Topics)
		}
	}
}

func TestWebhookDisabledGlobally(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	w := createTestWebhook(t, app, "https://example.com", []string{"*.*", "orders.*"}, nil)

	app.Settings().Webhooks.Enabled = false

	saveTestRecord(t, app, "demo2", map[string]any{"title": "a"})
	app.Webhooks().Trigger(context.Background(), "orders.paid", nil)
	app.Webhooks().FlushEvents()

	if n := len(findTestDeliveries(t, app, w.Id)); n != 0 {
		t.Fatalf("Expected no deliveries, got %d", n)
	}
}

func TestWebhookFilter(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	w := createTestWebhook(t, app, "https://example.com", []string{"demo2.*"}, func(w *core.Webhook) {
		w.SetFilter("title ~ 'match' && active = true")
	})

	saveTestRecord(t, app, "demo2", map[string]any{"title": "match1", "active": true})
	saveTestRecord(t, app, "demo2", map[string]any{"title": "match2", "active": false})
	saveTestRecord(t, app, "demo2", map[string]any{"title": "other", "active": true})
	r := saveTestRecord(t, app, "demo2", map[string]any{"title": "match_deleted", "active": true})

	// the filter should be evaluated against the last record state even after delete
	if err := app.Delete(r); err != nil {
		t.Fatal(err)
	}

	app.Webhooks().FlushEvents()

	deliveries := findTestDeliveries(t, app, w.Id)

	var titles []string
	for _, d := range deliveries {
		var payload struct {
			Action string         `json:"action"`
			Record map[string]any `json:"record"`
		}
		if err := json.Unmarshal(d.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		title := payload.Record["title"].(string)
		titles = append(titles, payload.Action+":"+title[:strings.LastIndex(title, "-")])
	}

	expected := []string{"create:match1", "create:match_deleted", "delete:match_deleted"}
	if !slices.Equal(titles, expected) {
		t.Fatalf("Expected %v, got %v", expected, titles)
	}
}

func TestWebhookFilterWithRelations(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	// demo1.rel_one -> demo1 (self) / check that joins against the actual tables work
	demo1, _ := app.FindCollectionByNameOrId("demo1")
	relField, _ := demo1.Fields.GetByName("rel_one").(*core.RelationField)
	if relField == nil {
		t.Skip("missing demo1.rel_one relation")
	}

	related, err := app.FindFirstRecordByFilter(relField.CollectionId, "id != ''")
	if err != nil {
		t.Fatal(err)
	}

	w := createTestWebhook(t, app, "https://example.com", []string{"demo1.create"}, func(w *core.Webhook) {
		w.SetFilter("rel_one.id = '" + related.Id + "'")
	})

	record := core.NewRecord(demo1)
	record.Set("rel_one", related.Id)
	if err := app.SaveNoValidate(record); err != nil {
		t.Fatal(err)
	}

	record2 := core.NewRecord(demo1)
	if err := app.SaveNoValidate(record2); err != nil {
		t.Fatal(err)
	}

	app.Webhooks().FlushEvents()

	deliveries := findTestDeliveries(t, app, w.Id)
	if len(deliveries) != 1 || !strings.Contains(string(deliveries[0].Payload), record.Id) {
		t.Fatalf("Expected 1 delivery for record %s, got %v", record.Id, deliveries)
	}
}

func TestWebhookPayload(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	users, _ := app.FindCollectionByNameOrId("users")

	full := createTestWebhook(t, app, "https://example.com/1", []string{"users.update"}, nil)
	projected := createTestWebhook(t, app, "https://example.com/2", []string{"users.update"}, func(w *core.Webhook) {
		w.SetFields([]string{"id", "email", "name"})
	})

	user, err := app.FindAuthRecordByEmail(users, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	user.Set("emailVisibility", !user.GetBool("emailVisibility"))
	user.Set("name", "new name")
	user.SetPassword("1234567890new")
	if err := app.Save(user); err != nil {
		t.Fatal(err)
	}

	app.Webhooks().FlushEvents()

	type payloadType struct {
		Action         string         `json:"action"`
		CollectionId   string         `json:"collectionId"`
		CollectionName string         `json:"collectionName"`
		Record         map[string]any `json:"record"`
		ChangedFields  []string       `json:"changedFields"`
	}

	// full payload
	deliveries := findTestDeliveries(t, app, full.Id)
	if len(deliveries) != 1 {
		t.Fatalf("Expected 1 delivery, got %d", len(deliveries))
	}

	var p payloadType
	if err := json.Unmarshal(deliveries[0].Payload, &p); err != nil {
		t.Fatal(err)
	}

	if p.Action != "update" || p.CollectionId != users.Id || p.CollectionName != "users" {
		t.Fatalf("Unexpected payload envelope %#v", p)
	}
	for _, hidden := range []string{"password", "tokenKey"} {
		if _, ok := p.Record[hidden]; ok {
			t.Fatalf("The hidden field %q should not be in the payload", hidden)
		}
	}
	if p.Record["email"] != "test@example.com" {
		t.Fatalf("Expected the email to be included regardless of its visibility, got %v", p.Record["email"])
	}
	if p.Record["name"] != "new name" {
		t.Fatalf("Expected the new name, got %v", p.Record["name"])
	}
	slices.Sort(p.ChangedFields)
	expectedChanged := []string{"emailVisibility", "name", "updated"}
	if !slices.Equal(p.ChangedFields, expectedChanged) {
		t.Fatalf("Expected changed fields %v, got %v", expectedChanged, p.ChangedFields)
	}

	// projected payload
	deliveries = findTestDeliveries(t, app, projected.Id)
	if len(deliveries) != 1 {
		t.Fatalf("Expected 1 projected delivery, got %d", len(deliveries))
	}
	p = payloadType{}
	json.Unmarshal(deliveries[0].Payload, &p)
	keys := make([]string, 0, len(p.Record))
	for k := range p.Record {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"email", "id", "name"}) {
		t.Fatalf("Expected projected record keys, got %v", keys)
	}
}

func TestWebhookAuthAndVerifiedTopics(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	users, _ := app.FindCollectionByNameOrId("users")

	w := createTestWebhook(t, app, "https://example.com", []string{"users.verified", "users.auth"}, nil)

	user := core.NewRecord(users)
	user.SetEmail("new_verified@example.com")
	user.SetPassword("1234567890")
	user.SetVerified(false)
	user.RefreshTokenKey()
	if err := app.Save(user); err != nil {
		t.Fatal(err)
	}

	// regular update without verified change
	user.Set("name", "abc")
	app.Save(user)

	user, _ = app.FindRecordById(users, user.Id)
	user.SetVerified(true)
	if err := app.Save(user); err != nil {
		t.Fatal(err)
	}

	// auth event (triggered on auth session completion)
	session := core.NewAuthSession(app)
	session.SetAuthMethods([]core.AuthSessionMethod{
		{Method: core.AuthSessionMethodPassword},
		{Method: core.AuthSessionMethodOTP},
	})
	event := new(core.AuthSessionCompleteRequestEvent)
	event.RequestEvent = &core.RequestEvent{App: app}
	event.Collection = users
	event.Record = user
	event.Session = session
	if err := app.OnAuthSessionCompleteRequest().Trigger(event, func(e *core.AuthSessionCompleteRequestEvent) error { return nil }); err != nil {
		t.Fatal(err)
	}

	// rejected completion should be ignored
	app.OnAuthSessionCompleteRequest().Trigger(event, func(e *core.AuthSessionCompleteRequestEvent) error { return errors.New("rejected") })

	app.Webhooks().FlushEvents()

	deliveries := findTestDeliveries(t, app, w.Id)
	if len(deliveries) != 2 {
		t.Fatalf("Expected 2 deliveries, got %d", len(deliveries))
	}

	if deliveries[0].Topic != users.Id+".verified" {
		t.Fatalf("Expected verified topic, got %q", deliveries[0].Topic)
	}

	if deliveries[1].Topic != users.Id+".auth" || !strings.Contains(string(deliveries[1].Payload), `"authMethod":"otp"`) {
		t.Fatalf("Expected auth topic with otp method, got %q %s", deliveries[1].Topic, deliveries[1].Payload)
	}
}

func TestWebhookCollectionRenameAndDelete(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	demo2 := core.NewBaseCollection("wh_test")
	demo2.Fields.Add(&core.TextField{Name: "title"})
	if err := app.Save(demo2); err != nil {
		t.Fatal(err)
	}

	w := createTestWebhook(t, app, "https://example.com", []string{"wh_test.create"}, nil)
	w2 := createTestWebhook(t, app, "https://example.com", []string{"wh_test.delete", "orders.paid"}, nil)

	demo2.Name = "demo2_renamed"
	if err := app.Save(demo2); err != nil {
		t.Fatal(err)
	}

	saveTestRecord(t, app, "demo2_renamed", map[string]any{"title": "renamed"})
	app.Webhooks().FlushEvents()

	deliveries := findTestDeliveries(t, app, w.Id)
	if len(deliveries) != 1 {
		t.Fatalf("Expected the subscription to still match after rename, got %d deliveries", len(deliveries))
	}

	if v := core.RenderWebhookTopic(app, deliveries[0].Topic); v != "demo2_renamed.create" {
		t.Fatalf("Expected the renamed topic, got %q", v)
	}

	// delete the collection
	if err := app.Delete(demo2); err != nil {
		t.Fatal(err)
	}

	w, _ = app.FindWebhookById(w.Id)
	if len(w.Topics()) != 0 || w.Active() || w.DisabledReason() == "" {
		t.Fatalf("Expected the subscription to be deactivated without topics, got %v %v %q", w.Topics(), w.Active(), w.DisabledReason())
	}

	w2, _ = app.FindWebhookById(w2.Id)
	if !slices.Equal(w2.Topics(), []string{"orders.paid"}) || !w2.Active() {
		t.Fatalf("Expected only the custom topic to remain, got %v %v", w2.Topics(), w2.Active())
	}
}

func TestWebhookClientScopes(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	users, _ := app.FindCollectionByNameOrId("users")
	users.OAuth2Server.Scopes = []string{"demo2:read", "webhooks:*"}
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	client := core.NewOAuth2Client(app)
	client.SetName("test")
	client.SetClientId("webhooks_test")
	client.SetType(core.OAuth2ClientTypePublic)
	client.SetCollectionRef(users.Id)
	client.SetRedirectURIs([]string{"https://example.com/cb"})
	client.SetScopes([]string{"demo2:read"})
	if err := app.Save(client); err != nil {
		t.Fatal(err)
	}

	// missing scopes
	invalid := core.NewWebhook(app)
	invalid.SetName("test")
	invalid.SetURI("https://example.com")
	invalid.SetTopics([]string{"demo2.create", "users.create", "*.delete", "orders.paid"})
	invalid.SetClient(client.Id)
	err := app.Validate(invalid)
	if err == nil {
		t.Fatal("Expected scopes validation error")
	}
	for _, k := range []string{`"1"`, `"2"`, `"3"`} {
		if !strings.Contains(errString(err), k) {
			t.Fatalf("Expected topics error %s, got %s", k, errString(err))
		}
	}
	if strings.Contains(errString(err), `"0"`) {
		t.Fatalf("Expected no error for the allowed demo2 topic, got %s", errString(err))
	}

	w := createTestWebhook(t, app, "https://example.com", []string{"demo2.create"}, func(w *core.Webhook) {
		w.SetClient(client.Id)
	})

	saveTestRecord(t, app, "demo2", map[string]any{"title": "a"})
	app.Webhooks().FlushEvents()
	if n := len(findTestDeliveries(t, app, w.Id)); n != 1 {
		t.Fatalf("Expected 1 delivery, got %d", n)
	}

	// revoke the client scope -> rechecked on match
	client.SetScopes([]string{})
	if err := app.Save(client); err != nil {
		t.Fatal(err)
	}
	saveTestRecord(t, app, "demo2", map[string]any{"title": "b"})
	app.Webhooks().FlushEvents()
	deliveries := findTestDeliveries(t, app, w.Id)
	if n := len(deliveries); n != 1 {
		t.Fatalf("Expected still 1 delivery after the scope revoke, got %d", n)
	}

	// rechecked on dispatch (the already queued delivery should be disabled)
	app.Webhooks().ProcessDue(context.Background(), 10)
	d, _ := app.FindWebhookDeliveryById(deliveries[0].Id)
	if d.Status != core.WebhookDeliveryStatusDisabled || !strings.Contains(d.Error, "OAuth2 client") {
		t.Fatalf("Expected disabled delivery because of the revoked scope, got %q %q", d.Status, d.Error)
	}

	// webhooks:* allows everything
	client.SetScopes([]string{"webhooks:*"})
	app.Save(client)
	w.SetTopics([]string{"*.*", "orders.paid"})
	if err := app.Save(w); err != nil {
		t.Fatalf("Expected webhooks:* to allow all topics, got %v", err)
	}

	// cascade delete
	if err := app.Delete(client); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindWebhookById(w.Id); err == nil {
		t.Fatal("Expected the client-linked webhook to be cascade deleted")
	}
}

// -------------------------------------------------------------------

func TestWebhooksE2EDeliveryRetryAndDedupe(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	receiver := newWebhookReceiver("")
	defer receiver.Close()

	// fail the first attempt
	receiver.status = func(n int) int {
		if n == 1 {
			return http.StatusInternalServerError
		}
		return http.StatusOK
	}

	w := createTestWebhook(t, app, receiver.URL+"/hook", []string{"demo2.create"}, nil)
	receiver.mu.Lock()
	receiver.secret = w.Secret()
	receiver.mu.Unlock()

	var sendEvents, resultEvents int
	app.OnWebhookSend(w.Id).BindFunc(func(e *core.WebhookSendEvent) error {
		sendEvents++
		e.Request.Header.Set("X-Custom", "custom")
		return e.Next()
	})
	app.OnWebhookDelivery("demo2.create").BindFunc(func(e *core.WebhookDeliveryEvent) error {
		resultEvents++
		return e.Next()
	})

	record := saveTestRecord(t, app, "demo2", map[string]any{"title": "e2e"})
	app.Webhooks().FlushEvents()

	ctx := context.Background()

	// 1st attempt
	if n, err := app.Webhooks().ProcessDue(ctx, 10); n != 1 || err != nil {
		t.Fatalf("Expected 1 processed delivery, got %d (%v)", n, err)
	}

	deliveries := findTestDeliveries(t, app, w.Id)
	if len(deliveries) != 1 {
		t.Fatalf("Expected 1 delivery, got %d", len(deliveries))
	}
	d := deliveries[0]
	if d.Status != core.WebhookDeliveryStatusRetrying || d.Attempts != 1 || d.ResponseStatus != 500 || d.NextAttemptAt.IsZero() {
		t.Fatalf("Unexpected delivery state after the 1st attempt: %q %d %d %v", d.Status, d.Attempts, d.ResponseStatus, d.NextAttemptAt)
	}

	// not due yet
	if n, _ := app.Webhooks().ProcessDue(ctx, 10); n != 0 {
		t.Fatalf("Expected no due deliveries, got %d", n)
	}

	// force the retry
	_, err := app.AuxNonconcurrentDB().Update(
		core.WebhookDeliveriesTableName,
		dbx.Params{"nextAttemptAt": time.Now().Add(-time.Second).UTC().Format("2006-01-02 15:04:05.000Z")},
		dbx.HashExp{"id": d.Id},
	).Execute()
	if err != nil {
		t.Fatal(err)
	}

	if n, err := app.Webhooks().ProcessDue(ctx, 10); n != 1 || err != nil {
		t.Fatalf("Expected 1 retried delivery, got %d (%v)", n, err)
	}

	d, _ = app.FindWebhookDeliveryById(d.Id)
	if d.Status != core.WebhookDeliveryStatusSuccess || d.Attempts != 2 || d.ResponseStatus != 200 || !d.NextAttemptAt.IsZero() {
		t.Fatalf("Unexpected delivery state after the retry: %q %d %d", d.Status, d.Attempts, d.ResponseStatus)
	}
	if d.ResponseBody != `{"received":true}` || d.RequestHeaders[http.CanonicalHeaderKey(webhooks.HeaderEventId)] != d.EventId || d.RequestBody == "" {
		t.Fatalf("Expected the attempt request/response to be logged, got %#v", d)
	}

	received := receiver.received()
	if len(received) != 2 {
		t.Fatalf("Expected 2 received requests, got %d", len(received))
	}

	// dedupe by event id
	processed := map[string]int{}
	for _, r := range received {
		if !r.valid {
			t.Fatal("Expected valid HMAC signature")
		}
		if r.header.Get(webhooks.HeaderTopic) != "demo2.create" {
			t.Fatalf("Expected the human friendly topic header, got %q", r.header.Get(webhooks.HeaderTopic))
		}
		if r.header.Get(webhooks.HeaderWebhookId) != d.Id {
			t.Fatalf("Expected the delivery id header, got %q", r.header.Get(webhooks.HeaderWebhookId))
		}
		if r.header.Get(webhooks.HeaderApiVersion) != core.WebhooksApiVersion || r.header.Get(webhooks.HeaderTriggeredAt) == "" {
			t.Fatal("Missing api version or triggered at headers")
		}
		if r.header.Get("User-Agent") != webhooks.DefaultUserAgent || r.header.Get("X-Custom") != "custom" {
			t.Fatal("Missing user agent or the hook custom header")
		}
		if !strings.Contains(string(r.body), record.Id) {
			t.Fatalf("Expected the record id in the body, got %s", r.body)
		}
		processed[r.header.Get(webhooks.HeaderEventId)]++
	}
	if len(processed) != 1 || processed[d.EventId] != 2 {
		t.Fatalf("Expected 2 requests with the same event id %q, got %v", d.EventId, processed)
	}

	if sendEvents != 2 || resultEvents != 2 {
		t.Fatalf("Expected 2 send and 2 delivery hook calls, got %d and %d", sendEvents, resultEvents)
	}

	// subscription stats
	w, _ = app.FindWebhookById(w.Id)
	if w.FailureCount() != 0 || w.LastSuccessAt().IsZero() || w.LastFailureAt().IsZero() {
		t.Fatalf("Unexpected subscription stats %d %v %v", w.FailureCount(), w.LastSuccessAt(), w.LastFailureAt())
	}

	// redeliver
	redelivered, err := app.Webhooks().Redeliver(ctx, d.Id)
	if err != nil {
		t.Fatal(err)
	}
	if redelivered.Id == d.Id || redelivered.EventId != d.EventId || redelivered.RedeliveryOf != d.Id || redelivered.Status != core.WebhookDeliveryStatusSuccess {
		t.Fatalf("Unexpected redelivery %#v", redelivered)
	}
	if received := receiver.received(); len(received) != 3 || received[2].header.Get(webhooks.HeaderEventId) != d.EventId {
		t.Fatal("Expected the redelivery to be sent with the same event id")
	}

	// pending deliveries can't be redelivered
	saveTestRecord(t, app, "demo2", map[string]any{"title": "pending"})
	app.Webhooks().FlushEvents()
	all := findTestDeliveries(t, app, w.Id)
	if _, err := app.Webhooks().Redeliver(ctx, all[len(all)-1].Id); !errors.Is(err, core.ErrWebhookNotRedeliverable) {
		t.Fatalf("Expected ErrWebhookNotRedeliverable, got %v", err)
	}
}

func TestWebhooksDispatcherBackground(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	receiver := newWebhookReceiver("")
	defer receiver.Close()

	w := createTestWebhook(t, app, receiver.URL, []string{"demo2.create"}, nil)
	receiver.mu.Lock()
	receiver.secret = w.Secret()
	receiver.mu.Unlock()

	app.Webhooks().Start()

	for i := 0; i < 5; i++ {
		saveTestRecord(t, app, "demo2", map[string]any{"title": "bg"})
	}

	deadline := time.Now().Add(5 * time.Second)
	for len(receiver.received()) < 5 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	if err := app.Webhooks().Stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	if n := len(receiver.received()); n != 5 {
		t.Fatalf("Expected 5 received webhooks, got %d", n)
	}
}

func TestWebhookSSRFBlockedByDefault(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	app.Settings().Webhooks.AllowPrivateTargets = false
	app.Settings().Webhooks.MaxAttempts = 1

	receiver := newWebhookReceiver("")
	defer receiver.Close()

	w := createTestWebhook(t, app, receiver.URL, []string{"demo2.create"}, nil)
	saveTestRecord(t, app, "demo2", map[string]any{"title": "a"})
	app.Webhooks().FlushEvents()
	app.Webhooks().ProcessDue(context.Background(), 10)

	d := findTestDeliveries(t, app, w.Id)[0]
	if d.Status != core.WebhookDeliveryStatusFailed || !strings.Contains(d.Error, "not allowed") {
		t.Fatalf("Expected blocked target failure, got %q %q", d.Status, d.Error)
	}
	if n := len(receiver.received()); n != 0 {
		t.Fatalf("Expected no received requests, got %d", n)
	}
}

func TestWebhookAutoDisable(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	app.Settings().Webhooks.MaxAttempts = 1
	app.Settings().Webhooks.AutoDisableAfter = 2

	receiver := newWebhookReceiver("")
	defer receiver.Close()
	receiver.status = func(n int) int { return http.StatusInternalServerError }

	w := createTestWebhook(t, app, receiver.URL, []string{"demo2.create"}, nil)
	receiver.mu.Lock()
	receiver.secret = w.Secret()
	receiver.mu.Unlock()

	ctx := context.Background()

	saveTestRecord(t, app, "demo2", map[string]any{"title": "1"})
	app.Webhooks().FlushEvents()
	app.Webhooks().ProcessDue(ctx, 10)

	w, _ = app.FindWebhookById(w.Id)
	if !w.Active() || w.FailureCount() != 1 {
		t.Fatalf("Expected active subscription with 1 failure, got %v %d", w.Active(), w.FailureCount())
	}

	saveTestRecord(t, app, "demo2", map[string]any{"title": "2"})
	app.Webhooks().FlushEvents()
	app.Webhooks().ProcessDue(ctx, 10)

	w, _ = app.FindWebhookById(w.Id)
	if w.Active() || w.FailureCount() != 2 || !strings.Contains(w.DisabledReason(), "500") {
		t.Fatalf("Expected auto disabled subscription, got %v %d %q", w.Active(), w.FailureCount(), w.DisabledReason())
	}

	// no new deliveries for disabled subscriptions
	saveTestRecord(t, app, "demo2", map[string]any{"title": "3"})
	app.Webhooks().FlushEvents()
	if n := len(findTestDeliveries(t, app, w.Id)); n != 2 {
		t.Fatalf("Expected 2 deliveries, got %d", n)
	}

	// reactivation resets the failures state
	w.SetActive(true)
	if err := app.Save(w); err != nil {
		t.Fatal(err)
	}
	if w.FailureCount() != 0 || w.DisabledReason() != "" {
		t.Fatalf("Expected reset failures state, got %d %q", w.FailureCount(), w.DisabledReason())
	}
}

func TestWebhookSendHookSkipAndInactive(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	receiver := newWebhookReceiver("")
	defer receiver.Close()

	skipped := createTestWebhook(t, app, receiver.URL, []string{"demo2.create"}, nil)
	deactivated := createTestWebhook(t, app, receiver.URL, []string{"demo2.create"}, nil)

	app.OnWebhookSend(skipped.Id).Bind(&hook.Handler[*core.WebhookSendEvent]{
		Func: func(e *core.WebhookSendEvent) error {
			return nil // skip
		},
	})

	saveTestRecord(t, app, "demo2", map[string]any{"title": "a"})
	app.Webhooks().FlushEvents()

	// deactivate after enqueue
	deactivated.SetActive(false)
	app.Save(deactivated)

	app.Webhooks().ProcessDue(context.Background(), 10)

	for _, w := range []*core.Webhook{skipped, deactivated} {
		d := findTestDeliveries(t, app, w.Id)[0]
		if d.Status != core.WebhookDeliveryStatusDisabled || d.Attempts != 0 || d.Error == "" {
			t.Fatalf("Expected disabled delivery, got %q %d %q", d.Status, d.Attempts, d.Error)
		}
	}

	if n := len(receiver.received()); n != 0 {
		t.Fatalf("Expected no received requests, got %d", n)
	}
}

func TestWebhookSendTest(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	receiver := newWebhookReceiver("")
	defer receiver.Close()

	w := createTestWebhook(t, app, receiver.URL, []string{"*.*", "demo2.create"}, func(w *core.Webhook) {
		w.SetActive(false) // test sends are allowed for inactive subscriptions
	})
	receiver.mu.Lock()
	receiver.secret = w.Secret()
	receiver.mu.Unlock()

	ctx := context.Background()

	if _, err := app.Webhooks().SendTest(ctx, w, "*.create"); !errors.Is(err, core.ErrWebhookInvalidTopic) {
		t.Fatalf("Expected wildcard topic error, got %v", err)
	}
	if _, err := app.Webhooks().SendTest(ctx, w, "orders.paid"); !errors.Is(err, core.ErrWebhookInvalidTopic) {
		t.Fatalf("Expected non-matching topic error, got %v", err)
	}

	d, err := app.Webhooks().SendTest(ctx, w, "users.update")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Test || d.Status != core.WebhookDeliveryStatusSuccess || d.Attempts != 1 || d.ResponseStatus != 200 {
		t.Fatalf("Unexpected test delivery %#v", d)
	}

	received := receiver.received()
	if len(received) != 1 || !received[0].valid || received[0].header.Get(webhooks.HeaderTest) != "true" || received[0].header.Get(webhooks.HeaderTopic) != "users.update" {
		t.Fatalf("Unexpected received test webhook %#v", received)
	}

	// default topic (first non-wildcard)
	d, err = app.Webhooks().SendTest(ctx, w, "")
	if err != nil {
		t.Fatal(err)
	}
	if core.RenderWebhookTopic(app, d.Topic) != "demo2.create" {
		t.Fatalf("Expected the default demo2.create topic, got %q", d.Topic)
	}

	// test deliveries are not redeliverable and don't affect the stats
	if _, err := app.Webhooks().Redeliver(ctx, d.Id); !errors.Is(err, core.ErrWebhookNotRedeliverable) {
		t.Fatalf("Expected ErrWebhookNotRedeliverable, got %v", err)
	}
	w, _ = app.FindWebhookById(w.Id)
	if !w.LastSuccessAt().IsZero() {
		t.Fatal("Expected the test send to not update the subscription stats")
	}
}

func TestWebhookDeliveriesStatsAndCleanup(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	app.Settings().Webhooks.AllowPrivateTargets = false
	app.Settings().Webhooks.MaxAttempts = 1

	w := createTestWebhook(t, app, "http://127.0.0.1:1", []string{"demo2.*"}, nil)

	r := saveTestRecord(t, app, "demo2", map[string]any{"title": "a"})
	saveTestRecord(t, app, "demo2", map[string]any{"title": "b"})
	app.Delete(r)
	app.Webhooks().FlushEvents()

	// fail the 2 creates, keep the delete pending
	createTopic := r.Collection().Id + ".create"
	app.AuxNonconcurrentDB().Update(core.WebhookDeliveriesTableName, dbx.Params{"nextAttemptAt": "2999-01-01 00:00:00.000Z"}, dbx.HashExp{"topic": r.Collection().Id + ".delete"}).Execute()
	app.Webhooks().ProcessDue(context.Background(), 10)

	stats, err := app.WebhookDeliveriesStats(core.WebhookDeliveriesStatsParams{GroupBy: core.WebhookDeliveriesStatsGroupByTopic})
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("Expected 2 stats groups, got %d", len(stats))
	}
	for _, s := range stats {
		if s.Group == createTopic && (s.Total != 2 || s.Failed != 2 || s.Attempts != 2) {
			t.Fatalf("Unexpected create stats %#v", s)
		}
		if s.Group != createTopic && (s.Total != 1 || s.Pending != 1) {
			t.Fatalf("Unexpected delete stats %#v", s)
		}
	}

	// cleanup deletes only the completed deliveries
	if err := app.DeleteOldWebhookDeliveries(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	remaining := findTestDeliveries(t, app, w.Id)
	if len(remaining) != 1 || remaining[0].Status != core.WebhookDeliveryStatusPending {
		t.Fatalf("Expected only the pending delivery to remain, got %d", len(remaining))
	}
}

// R1-F2: the payload never contains the hidden fields even if the saved record
// instance was unhidden (e.g. by the API enrich of a staff request).
func TestWebhookPayloadExcludesHiddenFieldsOfUnhiddenRecords(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	w := createTestWebhook(t, app, "https://example.com/1", []string{"users.update"}, nil)

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	user.Unhide(user.Collection().Fields.FieldNames()...)
	user.Set("name", "unhidden")
	if err := app.Save(user); err != nil {
		t.Fatal(err)
	}

	app.Webhooks().FlushEvents()

	deliveries := findTestDeliveries(t, app, w.Id)
	if len(deliveries) != 1 {
		t.Fatalf("Expected 1 delivery, got %d", len(deliveries))
	}

	payload := string(deliveries[0].Payload)
	for _, hidden := range []string{`"tokenKey"`, `"password"`, user.TokenKey()} {
		if strings.Contains(payload, hidden) {
			t.Fatalf("The hidden %s should not be in the payload %s", hidden, payload)
		}
	}
}

// TestWebhooksBootstrapClearInsideTransaction checks that clearing the bootstrap state
// while the caller holds the data db writer (e.g. app.Restart() called from a transactional hook)
// doesn't wait for the in-flight webhook attempts (their subscription stats update requires the data db writer).
func TestWebhooksBootstrapClearInsideTransaction(t *testing.T) {
	app := newWebhooksTestApp(t)
	// note: no deferred cleanup because on deadlock it would block forever
	// (the cleanup is called explicitly on success)

	requested := make(chan struct{}, 1)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requested <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	createTestWebhook(t, app, server.URL, []string{"demo2.create"}, nil)

	app.Webhooks().Start()

	saveTestRecord(t, app, "demo2", map[string]any{"title": "inflight"})

	// wait for the in-flight attempt
	select {
	case <-requested:
	case <-time.After(5 * time.Second):
		t.Fatal("The webhook request was not sent")
	}

	cleared := make(chan error, 1)

	go func() {
		cleared <- app.RunInTransaction(func(txApp core.App) error {
			// note: the transaction holds the single data db writer connection
			if _, err := txApp.DB().NewQuery("UPDATE {{_params}} SET [[updated]] = [[updated]] WHERE 1 = 0").Execute(); err != nil {
				return err
			}

			// complete the in-flight attempt (its stats update will wait for the writer)
			close(release)

			return txApp.ClearBootstrap()
		})
	}()

	select {
	case err := <-cleared:
		if err != nil {
			t.Logf("ClearBootstrap inside transaction returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("ClearBootstrap inside a transaction deadlocked waiting for the in-flight webhook attempt")
	}

	app.Cleanup()
}

func TestWebhookManagedInstallationHeaders(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	plainReceiver := newWebhookReceiver("")
	defer plainReceiver.Close()

	managedReceiver := newWebhookReceiver("")
	defer managedReceiver.Close()

	// a regular subscription (no installation headers)
	plain := createTestWebhook(t, app, plainReceiver.URL+"/plain", []string{"demo2.create"}, nil)
	plainReceiver.mu.Lock()
	plainReceiver.secret = plain.Secret()
	plainReceiver.mu.Unlock()

	// an application installation with a managed subscription of the same topic
	demo2, err := app.FindCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := core.ParseApplicationManifest([]byte(`{
		"handle":"managed-headers",
		"name":"Managed headers",
		"version":"1.0.0",
		"application_url":"`+managedReceiver.URL+`",
		"access":{"scopes":["read_demo2"]},
		"webhooks":{"subscriptions":[{"topics":["demo2.create"],"uri":"`+managedReceiver.URL+`/managed"}]}
	}`), core.ApplicationManifestFormatJSON)
	if err != nil {
		t.Fatal(err)
	}

	imported, err := app.ImportApplicationManifest(manifest, core.ApplicationManifestFormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}

	installed, err := app.InstallApplication(imported.Application, core.Permissions{
		Collections: map[string][]string{demo2.Id: {core.PermissionActionList, core.PermissionActionView}},
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	managedReceiver.mu.Lock()
	managedReceiver.secret = installed.WebhookSecret
	managedReceiver.mu.Unlock()

	managed, err := app.FindAllWebhooksByApplicationInstallation(installed.Installation.Id)
	if err != nil || len(managed) != 1 {
		t.Fatalf("Expected 1 managed webhook, got %d (%v)", len(managed), err)
	}
	if managed[0].ApplicationInstallationRef() != installed.Installation.Id || plain.ApplicationInstallationRef() != "" {
		t.Fatalf("Unexpected ApplicationInstallationRef %q / %q", managed[0].ApplicationInstallationRef(), plain.ApplicationInstallationRef())
	}

	saveTestRecord(t, app, "demo2", map[string]any{"title": "managed headers"})
	app.Webhooks().FlushEvents()

	if n, err := app.Webhooks().ProcessDue(context.Background(), 10); n != 2 || err != nil {
		t.Fatalf("Expected 2 processed deliveries, got %d (%v)", n, err)
	}

	installations, err := app.FindCollectionByNameOrId(core.CollectionNameApplicationInstallations)
	if err != nil {
		t.Fatal(err)
	}
	expectedIssuer := core.OAuth2Issuer(app, installations)

	managedRequests := managedReceiver.received()
	if len(managedRequests) != 1 || !managedRequests[0].valid {
		t.Fatalf("Expected 1 valid managed delivery, got %d", len(managedRequests))
	}
	h := managedRequests[0].header
	if v := h.Get(webhooks.HeaderApplicationInstallation); v != installed.Installation.Id {
		t.Fatalf("Expected the installation header %q, got %q", installed.Installation.Id, v)
	}
	if v := h.Get(webhooks.HeaderIssuer); v != expectedIssuer || !strings.HasSuffix(v, "/oauth2/"+core.CollectionNameApplicationInstallations) {
		t.Fatalf("Expected the issuer header %q, got %q", expectedIssuer, v)
	}

	plainRequests := plainReceiver.received()
	if len(plainRequests) != 1 || !plainRequests[0].valid {
		t.Fatalf("Expected 1 valid plain delivery, got %d", len(plainRequests))
	}
	for _, name := range []string{webhooks.HeaderApplicationInstallation, webhooks.HeaderIssuer} {
		if _, ok := plainRequests[0].header[http.CanonicalHeaderKey(name)]; ok {
			t.Fatalf("Expected no %s header for a regular subscription", name)
		}
	}

	// the signature still covers only the body (the installation headers are informational)
	if !webhooks.CheckSignature(managedRequests[0].body, installed.WebhookSecret, h.Get(webhooks.HeaderHmac)) {
		t.Fatal("Expected the body signature with the installation webhook secret")
	}
}
