package migrations_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	_ "github.com/lumm2509/pocketbomb/migrations"
	"github.com/lumm2509/pocketbomb/tests"
)

// forkMigrationsTotal is the number of the system migrations applied after
// the last upstream one (auth v2, llm logs, webhooks, webhook deliveries, rbac, applications and api keys).
const forkMigrationsTotal = 7

// forkCollections are the system collections created by the fork migrations.
var forkCollections = []string{
	core.CollectionNameOAuth2Clients,
	core.CollectionNameAuthSessions,
	core.CollectionNameOAuth2Consents,
	core.CollectionNameWebhooks,
	core.CollectionNameRoles,
	core.CollectionNameRoleAssignments,
	core.CollectionNameApplications,
	core.CollectionNameApplicationVersions,
	core.CollectionNameApplicationInstallations,
	core.CollectionNameAPIKeys,
}

// downToUpstream reverts the fork migrations of the provided (fixture) app
// so that it has the shape of an upstream created database.
func downToUpstream(t testing.TB, app core.App) {
	t.Helper()

	reverted, err := core.NewMigrationsRunner(app, core.SystemMigrations).Down(forkMigrationsTotal)
	if err != nil {
		t.Fatalf("Down failed: %v", err)
	}
	if len(reverted) != forkMigrationsTotal {
		t.Fatalf("Expected %d reverted migrations, got %v", forkMigrationsTotal, reverted)
	}

	for _, name := range forkCollections {
		if _, err := app.FindCollectionByNameOrId(name); err == nil || app.HasTable(name) {
			t.Fatalf("Expected %q to be removed by the down migrations", name)
		}
	}
	for _, table := range []string{"_llmLogs", core.WebhookDeliveriesTableName} {
		if app.AuxHasTable(table) {
			t.Fatalf("Expected the %q aux table to be removed by the down migrations", table)
		}
	}

	// the upstream schema is restored
	if _, err := app.FindCollectionByNameOrId("_mfas"); err != nil || !app.HasTable("_mfas") {
		t.Fatalf("Expected the upstream _mfas collection to be restored, got %v", err)
	}
	otps, _ := app.FindCollectionByNameOrId(core.CollectionNameOTPs)
	if otps.Fields.GetByName("sessionRef") != nil || otps.GetIndex("idx_otps_sessionRef") != "" {
		t.Fatal("Expected the _otps.sessionRef field and index to be removed")
	}
	for _, r := range app.Settings().RateLimits.Rules {
		if r.Label == "/oauth2/" {
			t.Fatal("Expected the /oauth2/ rate limit rule to be removed")
		}
	}
	authCollections, _ := app.FindAllCollections(core.CollectionTypeAuth)
	for _, c := range authCollections {
		if len(c.DefaultRoles) != 0 {
			t.Fatalf("Expected no %q default roles after down, got %v", c.Name, c.DefaultRoles)
		}
	}
}

// upFromUpstream applies the pending (fork) system migrations.
func upFromUpstream(t testing.TB, app core.App) {
	t.Helper()

	applied, err := core.NewMigrationsRunner(app, core.SystemMigrations).Up()
	if err != nil {
		t.Fatalf("Up failed: %v", err)
	}
	if len(applied) != forkMigrationsTotal {
		t.Fatalf("Expected %d applied migrations, got %v", forkMigrationsTotal, applied)
	}
}

// newFreshApp creates and bootstraps a new app with an empty data dir
// (all system migrations are applied by the bootstrap).
func newFreshApp(t testing.TB) core.App {
	t.Helper()

	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = app.ResetBootstrapState()
	})

	return app
}

// assertAuthV2FinalState checks the auth v2 final schema and the built-in data.
func assertAuthV2FinalState(t testing.TB, app core.App) {
	t.Helper()

	sessions, err := app.FindCollectionByNameOrId(core.CollectionNameAuthSessions)
	if err != nil {
		t.Fatal(err)
	}
	if !sessions.System || sessions.ListRule != nil || sessions.ViewRule != nil || sessions.CreateRule != nil || sessions.UpdateRule != nil || sessions.DeleteRule != nil {
		t.Fatal("Expected system _authSessions collection with nil rules")
	}
	for _, idx := range []string{"handleHash", "codeHash", "refreshTokenHash", "prevRefreshTokenHash", "recordRef_collectionRef", "parent", "expiresAt", "impersonatorSession", "impersonator", "launchJti"} {
		if sessions.GetIndex("idx_authSessions_"+idx) == "" {
			t.Fatalf("Missing _authSessions %q index", idx)
		}
	}
	hidden := map[string]bool{"impersonatorSession": true, "impersonatorKeyHash": true, "refreshRotatedAt": false, "otpRecordRef": true}
	for name, isHidden := range hidden {
		field := sessions.Fields.GetByName(name)
		if field == nil || !field.GetSystem() || field.GetHidden() != isHidden {
			t.Fatalf("Unexpected _authSessions %q field %v", name, field)
		}
	}

	consents, err := app.FindCollectionByNameOrId(core.CollectionNameOAuth2Consents)
	if err != nil {
		t.Fatal(err)
	}
	if consents.ListRule == nil || strings.Contains(*consents.ListRule, "@request.oauth2.clientId") ||
		*consents.ListRule != *consents.ViewRule || *consents.ListRule != *consents.DeleteRule ||
		consents.CreateRule != nil || consents.UpdateRule != nil {
		t.Fatalf("Unexpected _oauth2Consents rules %v", consents.ListRule)
	}

	for _, name := range []string{"_oauth2Grants", "_oauth2Codes", "_mfas"} {
		if _, err := app.FindCollectionByNameOrId(name); err == nil || app.HasTable(name) {
			t.Fatalf("Expected no %q collection", name)
		}
	}

	otps, err := app.FindCollectionByNameOrId(core.CollectionNameOTPs)
	if err != nil {
		t.Fatal(err)
	}
	if otps.Fields.GetByName("sessionRef") == nil || otps.GetIndex("idx_otps_sessionRef") == "" {
		t.Fatal("Expected _otps.sessionRef field and index")
	}

	client, err := app.FindOAuth2ClientByClientId(core.OAuth2DashboardClientId)
	if err != nil || !client.FirstParty() || client.IsConfidential() || client.Disabled() || len(client.RedirectURIs()) != 0 {
		t.Fatalf("Expected the dashboard client, got %v", err)
	}
	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if client.CollectionRef() != superusers.Id {
		t.Fatalf("Expected the dashboard client of the _superusers issuer, got %q", client.CollectionRef())
	}

	total := 0
	for _, r := range app.Settings().RateLimits.Rules {
		if r.Label == "/oauth2/" {
			total++
		}
	}
	if total != 1 {
		t.Fatalf("Expected a single /oauth2/ rate limit rule, got %d", total)
	}

	authCollections, _ := app.FindAllCollections(core.CollectionTypeAuth)
	for _, c := range authCollections {
		if _, ok := c.OAuth2Server.ActiveSigningKey(); !ok || c.OAuth2Server.CodeDuration <= 0 {
			t.Fatalf("Expected the %q issuer to be initialized", c.Name)
		}
	}
}

func TestAuthV2MigrationFreshDB(t *testing.T) {
	assertAuthV2FinalState(t, newFreshApp(t))
}

func TestAuthV2MigrationUpstreamDB(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	downToUpstream(t, app)

	// upstream data
	defaults := core.NewAuthCollection("defaults")
	legacyVerification := strings.Replace(
		defaults.VerificationTemplate.Body,
		core.EmailPlaceholderIssuerURL+"/verify-email?token="+core.EmailPlaceholderToken,
		core.EmailPlaceholderAppURL+"/_/#/auth/confirm-verification/"+core.EmailPlaceholderToken,
		1,
	)
	users, _ := app.FindCollectionByNameOrId("users")
	users.AuthToken.Duration = 604800
	users.VerificationTemplate.Body = legacyVerification
	users.ResetPasswordTemplate.Body = "custom"
	users.ConfirmEmailChangeTemplate.Body = `<a href="{APP_URL}/_/#/auth/confirm-email-change/{TOKEN}">custom change</a>`
	if err := app.Save(users); err != nil {
		t.Fatal(err)
	}

	clientsCollection, _ := app.FindCollectionByNameOrId("clients")
	clientsCollection.AuthToken.Duration = 1234 // customized
	clientsCollection.VerificationTemplate.Body = `<a href="{APP_URL}/_/#/auth/confirm-verification/{TOKEN}">custom verify</a>`
	clientsCollection.ResetPasswordTemplate.Body = `<a href="{APP_URL}/_/#/auth/confirm-password-reset/{TOKEN}">custom reset</a>`
	if err := app.Save(clientsCollection); err != nil {
		t.Fatal(err)
	}

	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	superusers.AuthToken.Duration = 86400
	if err := app.Save(superusers); err != nil {
		t.Fatal(err)
	}

	app.Settings().RateLimits.Rules = []core.RateLimitRule{
		{Label: "*:auth", MaxRequests: 2, Duration: 3},
		{Label: "*:authWithPassword", MaxRequests: 3, Duration: 3},
		{Label: "users:authWithOTP", MaxRequests: 4, Duration: 3},
		{Label: "users:requestOTP", MaxRequests: 5, Duration: 3},
		{Label: "*:authWithOAuth2", MaxRequests: 6, Duration: 3},
		{Label: "*:requestPasswordReset", MaxRequests: 7, Duration: 3},
		{Label: "*:confirmPasswordReset", MaxRequests: 8, Duration: 3},
		{Label: "*:confirmVerification", MaxRequests: 9, Duration: 3},
		{Label: "*:confirmEmailChange", MaxRequests: 10, Duration: 3},
		{Label: "*:listAuthMethods", MaxRequests: 11, Duration: 3},
		{Label: "users:authRefresh", MaxRequests: 12, Duration: 3},
		{Label: "POST /api/collections/users/auth-with-password", MaxRequests: 13, Duration: 3},
		{Label: "/api/collections/users/request-otp", MaxRequests: 14, Duration: 3},
		{Label: "*:create", MaxRequests: 15, Duration: 3},
		{Label: "/api/", MaxRequests: 16, Duration: 3},
	}
	if err := app.Save(app.Settings()); err != nil {
		t.Fatal(err)
	}

	upFromUpstream(t, app)

	assertAuthV2FinalState(t, app)

	users, _ = app.FindCollectionByNameOrId("users")
	superusers, _ = app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	clientsCollection, _ = app.FindCollectionByNameOrId("clients")

	if users.AuthToken.Duration != 3600 || superusers.AuthToken.Duration != 3600 {
		t.Fatalf("Expected the legacy default durations to be migrated to 3600, got %d and %d", users.AuthToken.Duration, superusers.AuthToken.Duration)
	}
	if clientsCollection.AuthToken.Duration != 1234 {
		t.Fatalf("Expected the customized duration to remain unchanged, got %d", clientsCollection.AuthToken.Duration)
	}
	if users.OAuth2Server.SessionDuration != defaults.OAuth2Server.SessionDuration {
		t.Fatalf("Expected default session duration, got %d", users.OAuth2Server.SessionDuration)
	}
	if users.VerificationTemplate.Body != defaults.VerificationTemplate.Body {
		t.Fatalf("Expected the legacy default verification template to be migrated, got\n%s", users.VerificationTemplate.Body)
	}
	if users.ResetPasswordTemplate.Body != "custom" {
		t.Fatal("Expected the customized template to remain unchanged")
	}
	for _, body := range []string{users.ConfirmEmailChangeTemplate.Body, clientsCollection.VerificationTemplate.Body, clientsCollection.ResetPasswordTemplate.Body} {
		if strings.Contains(body, "/_/#/auth/") || !strings.Contains(body, "{ISSUER_URL}/") || !strings.Contains(body, "custom") {
			t.Fatalf("Expected rewritten custom template link, got %q", body)
		}
	}

	labels := []string{}
	for _, r := range app.Settings().RateLimits.Rules {
		labels = append(labels, r.Label)
	}
	expected := []string{
		"*:auth",
		"*:oauth2LoginPassword",
		"users:oauth2LoginOTPVerify",
		"users:oauth2LoginOTP",
		"*:oauth2LoginOAuth2",
		"*:oauth2PasswordReset",
		"*:oauth2PasswordResetConfirm",
		"*:oauth2VerifyEmail",
		"*:oauth2EmailChangeConfirm",
		"*:create",
		"/api/",
		"/oauth2/",
	}
	if !slices.Equal(labels, expected) {
		t.Fatalf("Expected rate limit labels\n%v\ngot\n%v", expected, labels)
	}
	last := app.Settings().RateLimits.Rules[len(labels)-1]
	if last.MaxRequests != 300 || last.Duration != 10 {
		t.Fatalf("Expected the default /oauth2/ 300/10s rule, got %v", last)
	}

	// persisted
	if err := app.ReloadSettings(); err != nil {
		t.Fatal(err)
	}
	if len(app.Settings().RateLimits.Rules) != len(expected) {
		t.Fatalf("Expected the migrated rules to be persisted, got %v", app.Settings().RateLimits.Rules)
	}
}

func TestAuthV2MigrationKeepsExistingOAuth2RateLimitRule(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	downToUpstream(t, app)

	app.Settings().RateLimits.Rules = []core.RateLimitRule{
		{Label: "/oauth2/", MaxRequests: 50, Duration: 5},
	}
	if err := app.Save(app.Settings()); err != nil {
		t.Fatal(err)
	}

	upFromUpstream(t, app)

	rules := app.Settings().RateLimits.Rules
	if len(rules) != 1 || rules[0].MaxRequests != 50 || rules[0].Duration != 5 {
		t.Fatalf("Expected the custom /oauth2/ rule to be untouched, got %v", rules)
	}
}

func TestOAuth2ReservedCustomScopes(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}

	// existing conflicting custom scopes are kept and still saveable
	legacy := []string{"posts:read", "read_legacy", "write_legacy", "system:legacy"}
	users.OAuth2Server.Scopes = legacy
	if err := app.SaveNoValidate(users); err != nil {
		t.Fatal(err)
	}

	users, err = app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	if len(users.OAuth2Server.Scopes) != len(legacy) {
		t.Fatalf("Expected the legacy scopes to be kept, got %v", users.OAuth2Server.Scopes)
	}

	users.OAuth2Server.ConsentRequired = !users.OAuth2Server.ConsentRequired
	if err := app.Save(users); err != nil {
		t.Fatalf("Expected the collection with existing conflicting scopes to be saveable, got %v", err)
	}

	// but a newly added conflicting scope is rejected
	users.OAuth2Server.Scopes = append(users.OAuth2Server.Scopes, "write_new")
	if err := app.Save(users); err == nil {
		t.Fatal("Expected the new conflicting scope to be rejected")
	}
}
