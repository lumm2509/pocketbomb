package core_test

import (
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestCheckOAuth2ClientAndWebhookChanges(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	role, _ := tests.CreateRole(app, "integrations", core.Permissions{System: map[string]string{
		core.PermissionResourceOAuth2Clients: core.PermissionLevelWrite,
		core.PermissionResourceWebhooks:      core.PermissionLevelWrite,
	}})
	staff, _ := tests.CreateStaff(app, "integrations@example.com", role.Id)
	staffInfo := &core.RequestInfo{Auth: staff}

	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	ownerInfo := &core.RequestInfo{Auth: owner}

	users, _ := app.FindCollectionByNameOrId("users")
	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)

	newClient := func(collection *core.Collection, firstParty bool) *core.OAuth2Client {
		c := core.NewOAuth2Client(app)
		c.SetName("test")
		c.SetClientId("test_" + collection.Name)
		c.SetType(core.OAuth2ClientTypePublic)
		c.SetCollectionRef(collection.Id)
		c.SetRedirectURIs([]string{"https://example.com/cb"})
		c.SetFirstParty(firstParty)
		return c
	}

	scenarios := []struct {
		name    string
		info    *core.RequestInfo
		client  *core.OAuth2Client
		allowed bool
	}{
		{"staff third-party users client", staffInfo, newClient(users, false), true},
		{"staff first-party users client", staffInfo, newClient(users, true), false},
		{"staff _superusers client", staffInfo, newClient(superusers, true), false},
		{"Owner first-party users client", ownerInfo, newClient(users, true), true},
		{"Owner _superusers client", ownerInfo, newClient(superusers, true), true},
	}
	for _, s := range scenarios {
		err := core.CheckOAuth2ClientChange(app, s.info, s.client.Record)
		if (err == nil) != s.allowed {
			t.Fatalf("[%s] Expected allowed %v, got %v", s.name, s.allowed, err)
		}
	}

	// existing first-party client changes (e.g. redirect URIs) are Owner only
	existing := newClient(users, true)
	if err := app.Save(existing); err != nil {
		t.Fatal(err)
	}
	existing, _ = app.FindOAuth2ClientById(existing.Id)
	existing.SetRedirectURIs([]string{"https://evil.example.com/cb"})
	if err := core.CheckOAuth2ClientChange(app, staffInfo, existing.Record); err == nil {
		t.Fatal("Expected the existing first-party client change to be denied for a non-Owner")
	}
	existing.SetFirstParty(false)
	if err := core.CheckOAuth2ClientChange(app, staffInfo, existing.Record); err == nil {
		t.Fatal("Expected the first-party flag removal to be denied for a non-Owner")
	}

	// webhooks
	webhookCollection, _ := app.FindCollectionByNameOrId(core.CollectionNameWebhooks)
	webhook := func(topics ...string) *core.Record {
		r := core.NewRecord(webhookCollection)
		r.Set("topics", topics)
		return r
	}

	webhookScenarios := []struct {
		info    *core.RequestInfo
		topics  []string
		allowed bool
	}{
		{staffInfo, []string{"users.update", "demo1.*"}, true},
		{staffInfo, []string{"*.create"}, true},
		{staffInfo, []string{"_superusers.update"}, false},
		{staffInfo, []string{superusers.Id + ".update"}, false},
		{staffInfo, []string{"users.create", "_externalAuths.create"}, false},
		{ownerInfo, []string{"_superusers.update"}, true},
	}
	for i, s := range webhookScenarios {
		err := core.CheckWebhookChange(app, s.info, webhook(s.topics...))
		if (err == nil) != s.allowed {
			t.Fatalf("[%d] Expected allowed %v for %v, got %v", i, s.allowed, s.topics, err)
		}
	}
}
