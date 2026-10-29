package core_test

import (
	"context"
	"slices"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/security"
)

func TestWebhookTopicsNormalizeAndRender(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	users, _ := app.FindCollectionByNameOrId("users")

	scenarios := []struct {
		topic    string
		expected string
		err      bool
	}{
		{"", "", true},
		{"demo2", "", true},
		{"demo2.", "", true},
		{"demo2.create.x", "", true},
		{"demo2.create", demo2.Id + ".create", false},
		{demo2.Id + ".update", demo2.Id + ".update", false},
		{"demo2.*", demo2.Id + ".*", false},
		{"demo2.unknown", "", true},
		{"demo2.auth", "", true},     // not an auth collection
		{"demo2.verified", "", true}, // not an auth collection
		{"users.auth", users.Id + ".auth", false},
		{"users.verified", users.Id + ".verified", false},
		{"*.*", "*.*", false},
		{"*.delete", "*.delete", false},
		{"*.auth", "*.auth", false},
		{"*.unknown", "", true},
		{"_superusers.create", "pbc_3142635823.create", false},
		{"_otps.create", "", true},
		{"_authSessions.create", "", true},
		{"_webhooks.create", "", true},
		{"orders.paid", "orders.paid", false},
		{"orders.*", "orders.*", false},
		{"orders.pa id", "", true},
		{"or ders.paid", "", true},
	}

	for _, s := range scenarios {
		t.Run(s.topic, func(t *testing.T) {
			v, err := core.NormalizeWebhookTopic(app, s.topic)
			if (err != nil) != s.err {
				t.Fatalf("Expected err %v, got %v", s.err, err)
			}
			if v != s.expected {
				t.Fatalf("Expected %q, got %q", s.expected, v)
			}
		})
	}

	// render
	if v := core.RenderWebhookTopic(app, demo2.Id+".create"); v != "demo2.create" {
		t.Fatalf("Expected demo2.create, got %q", v)
	}
	if v := core.RenderWebhookTopic(app, "*.create"); v != "*.create" {
		t.Fatalf("Expected *.create, got %q", v)
	}
	if v := core.RenderWebhookTopic(app, "orders.paid"); v != "orders.paid" {
		t.Fatalf("Expected orders.paid, got %q", v)
	}
}

func TestWebhookTopicsMatching(t *testing.T) {
	t.Parallel()

	app := newWebhooksTestApp(t)
	defer app.Cleanup()

	demo2, _ := app.FindCollectionByNameOrId("demo2")

	exactCreate := createTestWebhook(t, app, "https://example.com/1", []string{"demo2.create"}, nil)
	collectionAll := createTestWebhook(t, app, "https://example.com/2", []string{"demo2.*"}, nil)
	anyDelete := createTestWebhook(t, app, "https://example.com/3", []string{"*.delete"}, nil)
	all := createTestWebhook(t, app, "https://example.com/4", []string{"*.*"}, nil)
	superusersExplicit := createTestWebhook(t, app, "https://example.com/5", []string{"_superusers.create"}, nil)
	inactive := createTestWebhook(t, app, "https://example.com/6", []string{"*.*"}, func(w *core.Webhook) { w.SetActive(false) })
	custom := createTestWebhook(t, app, "https://example.com/7", []string{"orders.*"}, nil)

	r := saveTestRecord(t, app, "demo2", map[string]any{"title": "a"})
	r.Set("title", "b-"+security.PseudorandomString(6))
	if err := app.Save(r); err != nil {
		t.Fatal(err)
	}
	if err := app.Delete(r); err != nil {
		t.Fatal(err)
	}

	// system collection (excluded from the wildcards)
	su := saveTestRecord(t, app, core.CollectionNameSuperusers, map[string]any{"email": "new_su@example.com", "password": "1234567890"})

	app.Webhooks().FlushEvents()

	topicsOf := func(w *core.Webhook) []string {
		var result []string
		for _, d := range findTestDeliveries(t, app, w.Id) {
			result = append(result, d.Topic)
		}
		return result
	}

	scenarios := []struct {
		webhook  *core.Webhook
		expected []string
	}{
		{exactCreate, []string{demo2.Id + ".create"}},
		{collectionAll, []string{demo2.Id + ".create", demo2.Id + ".update", demo2.Id + ".delete"}},
		{anyDelete, []string{demo2.Id + ".delete"}},
		{all, []string{demo2.Id + ".create", demo2.Id + ".update", demo2.Id + ".delete"}},
		{superusersExplicit, []string{su.Collection().Id + ".create"}},
		{inactive, nil},
		{custom, nil},
	}

	for i, s := range scenarios {
		topics := topicsOf(s.webhook)
		if !slices.Equal(topics, s.expected) {
			t.Errorf("[%d] Expected topics %v, got %v", i, s.expected, topics)
		}
	}

	// the same event should have the same event id across the subscriptions
	d1 := findTestDeliveries(t, app, exactCreate.Id)[0]
	d2 := findTestDeliveries(t, app, all.Id)[0]
	if d1.EventId != d2.EventId || d1.Id == d2.Id {
		t.Fatalf("Expected the same event id and different delivery ids, got %q/%q %q/%q", d1.EventId, d2.EventId, d1.Id, d2.Id)
	}

	// custom topic
	if err := app.Webhooks().Trigger(context.Background(), "orders.paid", map[string]any{"amount": 10}); err != nil {
		t.Fatal(err)
	}
	customDeliveries := findTestDeliveries(t, app, custom.Id)
	if len(customDeliveries) != 1 || customDeliveries[0].Topic != "orders.paid" || string(customDeliveries[0].Payload) != `{"amount":10}` {
		t.Fatalf("Unexpected custom deliveries %#v", customDeliveries)
	}
	// custom topics are not matched by the collection wildcards
	if n := len(findTestDeliveries(t, app, all.Id)); n != 3 {
		t.Fatalf("Expected the *.* subscription to not match custom topics, got %d deliveries", n)
	}
}
