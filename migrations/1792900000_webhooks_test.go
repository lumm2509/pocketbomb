package migrations_test

import (
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func assertWebhooksFinalState(t testing.TB, app core.App) {
	t.Helper()

	webhooks, err := app.FindCollectionByNameOrId(core.CollectionNameWebhooks)
	if err != nil {
		t.Fatal(err)
	}
	if !webhooks.System || webhooks.ListRule != nil || webhooks.CreateRule != nil {
		t.Fatal("Expected a system _webhooks collection with nil rules")
	}
	for _, name := range []string{"secret", "topics", "filter", "client", "actorRef", "applicationInstallationRef"} {
		if webhooks.Fields.GetByName(name) == nil {
			t.Fatalf("Missing _webhooks %q field", name)
		}
	}
	if !webhooks.Fields.GetByName("secret").GetHidden() {
		t.Fatal("Expected the hidden secret field")
	}
	for _, idx := range []string{"active", "client", "applicationInstallationRef"} {
		if webhooks.GetIndex("idx_webhooks_"+idx) == "" {
			t.Fatalf("Missing _webhooks %q index", idx)
		}
	}
	if !app.AuxHasTable(core.WebhookDeliveriesTableName) {
		t.Fatal("Expected the webhook deliveries aux table")
	}

	// a subscription saved by a trusted programmatic save has an empty actor (aka. Owner subscription)
	w := core.NewWebhook(app)
	w.SetName("test")
	w.SetURI("https://example.com/hook")
	w.SetTopics([]string{"demo2.create"})
	if err := app.Save(w); err != nil {
		t.Fatal(err)
	}
	if w.ActorRef() != "" {
		t.Fatalf("Expected an empty actorRef, got %q", w.ActorRef())
	}
}

func TestWebhooksMigrationFreshDB(t *testing.T) {
	app := newFreshApp(t)

	webhooks, err := app.FindCollectionByNameOrId(core.CollectionNameWebhooks)
	if err != nil || webhooks.Fields.GetByName("actorRef") == nil || webhooks.Fields.GetByName("applicationInstallationRef") == nil {
		t.Fatalf("Expected the final _webhooks collection, got %v", err)
	}
	if !app.AuxHasTable(core.WebhookDeliveriesTableName) {
		t.Fatal("Expected the webhook deliveries aux table")
	}
}

func TestWebhooksMigrationUpstreamDB(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	downToUpstream(t, app)
	upFromUpstream(t, app)

	assertWebhooksFinalState(t, app)
}
