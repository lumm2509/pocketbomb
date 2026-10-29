package core_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestAuthorize(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo1, _ := app.FindCollectionByNameOrId("demo1")
	demo2, _ := app.FindCollectionByNameOrId("demo2")
	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	externalAuths, _ := app.FindCollectionByNameOrId(core.CollectionNameExternalAuths)
	logsCollection := core.NewBaseCollection("_unmappedSystem")
	logsCollection.System = true

	limitedRole, err := tests.CreateRole(app, "limited", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
		System: map[string]string{
			core.PermissionResourceLogs:     core.PermissionLevelRead,
			core.PermissionResourceSessions: core.PermissionLevelWrite,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	limited, err := tests.CreateStaff(app, "limited@example.com", limitedRole.Id)
	if err != nil {
		t.Fatal(err)
	}

	none, err := tests.CreateStaff(app, "none@example.com")
	if err != nil {
		t.Fatal(err)
	}

	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	customer, _ := app.FindAuthRecordByEmail("users", "test@example.com")

	restricted, _ := app.FindAuthRecordByEmail("users", "test2@example.com")
	if err := tests.AssignRoles(app, restricted, limitedRole.Id); err != nil {
		t.Fatal(err)
	}

	info := func(auth *core.Record) *core.RequestInfo {
		return &core.RequestInfo{Auth: auth}
	}

	thirdParty := func(auth *core.Record, scopes ...string) *core.RequestInfo {
		return &core.RequestInfo{Auth: auth, OAuth2: core.RequestInfoOAuth2{ClientId: "3p", Scopes: scopes}}
	}

	firstParty := func(auth *core.Record) *core.RequestInfo {
		return &core.RequestInfo{Auth: auth, OAuth2: core.RequestInfoOAuth2{ClientId: "1p", FirstParty: true}}
	}

	type expect struct {
		allowed bool
		bypass  bool
	}

	scenarios := []struct {
		name     string
		info     *core.RequestInfo
		target   core.AuthorizeTarget
		expected expect
	}{
		// guests
		{"guest regular collection", info(nil), core.AuthorizeTarget{Collection: demo1, Action: "list"}, expect{true, false}},
		{"guest system collection", info(nil), core.AuthorizeTarget{Collection: superusers, Action: "list"}, expect{true, false}},
		{"guest system resource", info(nil), core.AuthorizeTarget{Resource: "logs", Level: "read"}, expect{false, false}},

		// customers
		{"customer default role", info(customer), core.AuthorizeTarget{Collection: demo1, Action: "delete"}, expect{true, false}},
		{"customer first-party token", firstParty(customer), core.AuthorizeTarget{Collection: demo1, Action: "delete"}, expect{true, false}},
		{"customer restricted allowed action", info(restricted), core.AuthorizeTarget{Collection: demo2, Action: "view"}, expect{true, false}},
		{"customer restricted denied action", info(restricted), core.AuthorizeTarget{Collection: demo2, Action: "create"}, expect{false, false}},
		{"customer restricted other collection", info(restricted), core.AuthorizeTarget{Collection: demo1, Action: "list"}, expect{false, false}},
		{"customer system collection (rules)", info(restricted), core.AuthorizeTarget{Collection: externalAuths, Action: "list"}, expect{true, false}},
		{"customer system resource (even if in the role)", info(restricted), core.AuthorizeTarget{Resource: "logs", Level: "read"}, expect{false, false}},

		// third-party tokens
		{"third-party with scope", thirdParty(customer, "read_demo2"), core.AuthorizeTarget{Collection: demo2, Action: "list"}, expect{true, false}},
		{"third-party read scope write action", thirdParty(customer, "read_demo2"), core.AuthorizeTarget{Collection: demo2, Action: "update"}, expect{false, false}},
		{"third-party write scope", thirdParty(customer, "write_demo2"), core.AuthorizeTarget{Collection: demo2, Action: "update"}, expect{true, false}},
		{"third-party without scope", thirdParty(customer, "openid"), core.AuthorizeTarget{Collection: demo2, Action: "list"}, expect{false, false}},
		{"third-party scope but no role permission", thirdParty(restricted, "write_demo2"), core.AuthorizeTarget{Collection: demo2, Action: "update"}, expect{false, false}},
		{"third-party system collection", thirdParty(customer, "read_demo2"), core.AuthorizeTarget{Collection: externalAuths, Action: "list"}, expect{false, false}},
		{"third-party staff (never Owner)", thirdParty(owner, "read_demo2"), core.AuthorizeTarget{Resource: "logs", Level: "read"}, expect{false, false}},
		{"third-party staff collection (no bypass)", thirdParty(owner, "read_demo2"), core.AuthorizeTarget{Collection: demo2, Action: "list"}, expect{false, false}},

		// Owner
		{"Owner regular collection", info(owner), core.AuthorizeTarget{Collection: demo1, Action: "delete"}, expect{true, true}},
		{"Owner system collection", info(owner), core.AuthorizeTarget{Collection: superusers, Action: "delete"}, expect{true, true}},
		{"Owner unmapped system collection", info(owner), core.AuthorizeTarget{Collection: logsCollection, Action: "list"}, expect{true, true}},
		{"Owner sql", info(owner), core.AuthorizeTarget{Resource: "sql", Level: "write"}, expect{true, true}},

		// limited staff
		{"staff allowed collection action", info(limited), core.AuthorizeTarget{Collection: demo2, Action: "view"}, expect{true, true}},
		{"staff denied collection action", info(limited), core.AuthorizeTarget{Collection: demo2, Action: "create"}, expect{false, false}},
		{"staff denied collection", info(limited), core.AuthorizeTarget{Collection: demo1, Action: "list"}, expect{false, false}},
		{"staff mapped system collection with permission", info(limited), core.AuthorizeTarget{Collection: externalAuths, Action: "delete"}, expect{true, true}},
		{"staff mapped system collection without permission (rules)", info(limited), core.AuthorizeTarget{Collection: superusers, Action: "list"}, expect{true, false}},
		{"staff unmapped system collection (rules)", info(limited), core.AuthorizeTarget{Collection: logsCollection, Action: "list"}, expect{true, false}},
		{"staff system read", info(limited), core.AuthorizeTarget{Resource: "logs", Level: "read"}, expect{true, true}},
		{"staff system write with read", info(limited), core.AuthorizeTarget{Resource: "logs", Level: "write"}, expect{false, false}},
		{"staff sql", info(limited), core.AuthorizeTarget{Resource: "sql", Level: "write"}, expect{false, false}},
		{"staff unknown resource", info(limited), core.AuthorizeTarget{Resource: "missing", Level: "read"}, expect{false, false}},

		// staff without roles
		{"staff none collection", info(none), core.AuthorizeTarget{Collection: demo2, Action: "list"}, expect{false, false}},
		{"staff none system resource", info(none), core.AuthorizeTarget{Resource: "logs", Level: "read"}, expect{false, false}},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			access := core.Authorize(app, s.info, s.target)
			if access.Allowed != s.expected.allowed || access.BypassRules != s.expected.bypass {
				t.Fatalf("Expected %+v, got %+v", s.expected, access)
			}
		})
	}
}

func TestRequestRolesRuleField(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	editor, _ := tests.CreateRole(app, "Editor", core.Permissions{Collections: map[string][]string{"*": {"list", "view"}}})
	user2, _ := app.FindAuthRecordByEmail("users", "test2@example.com")
	if err := tests.AssignRoles(app, user2, editor.Id, core.RoleIdCustomer); err != nil {
		t.Fatal(err)
	}

	demo2, _ := app.FindCollectionByNameOrId("demo2")
	record, err := app.FindFirstRecordByFilter(demo2, "id != ''")
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		auth     *core.Record
		rule     string
		expected bool
	}{
		{user, "@request.roles = 'Customer'", true},
		{user, "@request.roles:each ?= 'Editor'", false},
		{user2, "@request.roles:each ?= 'Editor'", true},
		{user2, "@request.roles:each ?= 'Customer'", true},
		{nil, "@request.roles:each ?= 'Customer'", false},
	}

	for i, s := range scenarios {
		ok, err := app.CanAccessRecord(record, &core.RequestInfo{Auth: s.auth}, &s.rule)
		if err != nil {
			t.Fatalf("[%d] %v", i, err)
		}
		if ok != s.expected {
			t.Fatalf("[%d] Expected %v for %q, got %v", i, s.expected, s.rule, ok)
		}
	}
}

func TestAuthorizeReadOnlyFields(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	users, _ := app.FindCollectionByNameOrId("users")
	demo1, _ := app.FindCollectionByNameOrId("demo1")
	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name       string
		oauth2     core.RequestInfoOAuth2
		collection *core.Collection
		expected   []string
	}{
		{"first-party token", core.RequestInfoOAuth2{ClientId: "test", FirstParty: true}, users, nil},
		{"no token data", core.RequestInfoOAuth2{}, users, nil},
		{"third-party token on a regular collection", core.RequestInfoOAuth2{ClientId: "test", Scopes: []string{"write_demo1"}}, demo1, nil},
		{
			"third-party token on an auth collection",
			core.RequestInfoOAuth2{ClientId: "test", Scopes: []string{"write_users"}},
			users,
			[]string{core.FieldNameEmail, core.FieldNamePassword, core.FieldNameTokenKey, core.FieldNameVerified, core.FieldNameEmailVisibility},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			info := &core.RequestInfo{Auth: user, OAuth2: s.oauth2}

			access := info.CollectionAccess(app, s.collection, core.PermissionActionUpdate)
			if !access.Allowed {
				t.Fatal("Expected the action to be allowed")
			}

			if !slices.Equal(access.ReadOnlyFields, s.expected) {
				t.Fatalf("Expected read-only fields %v, got %v", s.expected, access.ReadOnlyFields)
			}
		})
	}
}

func TestOwnerOnlyLevels(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	scenarios := []struct {
		resource string
		level    string
		valid    bool
	}{
		{"collections", "read", true},
		{"collections", "write", false},
		{"settings", "read", true},
		{"settings", "write", false},
		{"backups", "read", false},
		{"backups", "write", false},
		{"sql", "write", false},
		{"logs", "write", true},
		{"impersonate", "write", true},
	}

	for _, s := range scenarios {
		t.Run(s.resource+"_"+s.level, func(t *testing.T) {
			resource, ok := core.FindPermissionResource(s.resource)
			if !ok {
				t.Fatalf("Missing resource %q", s.resource)
			}

			if v := resource.IsAssignableLevel(s.level); v != s.valid {
				t.Fatalf("Expected IsAssignableLevel %v, got %v", s.valid, v)
			}

			err := core.Permissions{System: map[string]string{s.resource: s.level}}.Validate(app)
			if (err == nil) != s.valid {
				t.Fatalf("Expected valid %v, got %v", s.valid, err)
			}
			if err != nil && !strings.Contains(err.Error(), "Owner") {
				t.Fatalf("Expected an Owner only error, got %v", err)
			}
		})
	}

	backups, _ := core.FindPermissionResource("backups")
	if backups.Assignable {
		t.Fatal("Expected backups to not be assignable")
	}

	all := core.AllPermissions()
	for resource, level := range all.System {
		r, _ := core.FindPermissionResource(resource)
		if !r.IsAssignableLevel(level) {
			t.Fatalf("AllPermissions contains the not assignable %s %s", resource, level)
		}
	}
}

func TestAuthorizeIgnoresLegacyOwnerOnlyLevels(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// a legacy role saved before R1-F1 (bypassing the validation)
	legacy := core.NewRole(app)
	legacy.SetName("legacy")
	legacy.SetPermissions(core.Permissions{System: map[string]string{
		"collections": "write",
		"settings":    "write",
		"backups":     "write",
		"sql":         "write",
	}})
	if err := app.SaveNoValidate(legacy); err != nil {
		t.Fatal(err)
	}

	staff, err := tests.CreateStaff(app, "legacy@example.com", legacy.Id)
	if err != nil {
		t.Fatal(err)
	}

	info := &core.RequestInfo{Auth: staff}

	denied := [][2]string{
		{"collections", "write"},
		{"settings", "write"},
		{"backups", "read"},
		{"backups", "write"},
		{"sql", "write"},
	}
	for _, d := range denied {
		if info.Can(app, d[0], d[1]) {
			t.Fatalf("Expected %s %s to be denied for a non-Owner", d[0], d[1])
		}
	}

	// the lower assignable levels are still implied
	if !info.Can(app, "collections", "read") || !info.Can(app, "settings", "read") {
		t.Fatal("Expected collections/settings read to be allowed")
	}

	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	for _, d := range denied {
		if !(&core.RequestInfo{Auth: owner}).Can(app, d[0], d[1]) {
			t.Fatalf("Expected %s %s to be allowed for an Owner", d[0], d[1])
		}
	}
}

func TestSessionsPermissionNeverBypassesCreateUpdate(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	role, _ := tests.CreateRole(app, "sessions admin", core.Permissions{System: map[string]string{
		core.PermissionResourceSessions: core.PermissionLevelWrite,
	}})
	staff, _ := tests.CreateStaff(app, "sessions@example.com", role.Id)
	info := &core.RequestInfo{Auth: staff}

	for _, name := range []string{core.CollectionNameOTPs, core.CollectionNameExternalAuths, core.CollectionNameAuthSessions, core.CollectionNameOAuth2Consents, core.CollectionNameAuthOrigins} {
		c, _ := app.FindCollectionByNameOrId(name)

		for _, action := range []string{"list", "view", "delete"} {
			if !info.CollectionAccess(app, c, action).BypassRules {
				t.Fatalf("[%s] Expected %s bypass", name, action)
			}
		}

		for _, action := range []string{"create", "update"} {
			if info.CollectionAccess(app, c, action).BypassRules {
				t.Fatalf("[%s] Expected no %s bypass (Owner only)", name, action)
			}
		}
	}
}

func TestAuthorizeApplication(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo1, _ := app.FindCollectionByNameOrId("demo1")
	demo2, _ := app.FindCollectionByNameOrId("demo2")
	users, _ := app.FindCollectionByNameOrId("users")
	webhooks, _ := app.FindCollectionByNameOrId(core.CollectionNameWebhooks)
	externalAuths, _ := app.FindCollectionByNameOrId(core.CollectionNameExternalAuths)
	applications, _ := app.FindCollectionByNameOrId(core.CollectionNameApplications)

	_, installed := installTestApplication(t, app, "authz-app", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view", "create"}},
		System: map[string]string{
			core.PermissionResourceLogs:     core.PermissionLevelRead,
			core.PermissionResourceWebhooks: core.PermissionLevelWrite,
		},
	})

	newInfo := func(scopes ...string) *core.RequestInfo {
		record, err := app.FindRecordById(core.CollectionNameApplicationInstallations, installed.Installation.Id)
		if err != nil {
			t.Fatal(err)
		}
		return &core.RequestInfo{
			Auth:   record,
			OAuth2: core.RequestInfoOAuth2{ClientId: installed.Client.ClientId(), Scopes: scopes},
		}
	}

	full := newInfo(core.ApplicationGrantScopes(app, installed.Installation.Permissions())...)

	perms := full.Permissions(app)
	if perms.Kind != core.ActorKindApplication || perms.Owner || perms.ThirdParty || len(perms.Roles) != 0 || !perms.IsApplication() || perms.IsStaff() {
		t.Fatalf("Unexpected application actor permissions %#v", perms)
	}

	collectionScenarios := []struct {
		name     string
		info     *core.RequestInfo
		c        *core.Collection
		action   string
		expected core.Access
	}{
		{"granted list", full, demo2, "list", core.Access{Allowed: true, BypassRules: true}},
		{"granted create", full, demo2, "create", core.Access{Allowed: true, BypassRules: true}},
		{"not granted delete", full, demo2, "delete", core.Access{}},
		{"not granted collection", full, demo1, "list", core.Access{}},
		{"auth collection not granted", full, users, "view", core.Access{}},
		{"mapped grantable system collection", full, webhooks, "create", core.Access{Allowed: true, BypassRules: true}},
		{"mapped not grantable system collection (no own-record fallback)", full, externalAuths, "list", core.Access{}},
		{"applications system collection", full, applications, "list", core.Access{}},
		{"scope narrowed (read only)", newInfo("read_demo2", "system:read_webhooks"), demo2, "create", core.Access{}},
		{"scope narrowed read", newInfo("read_demo2"), demo2, "view", core.Access{Allowed: true, BypassRules: true}},
		{"scope narrowed system collection", newInfo("system:read_webhooks"), webhooks, "create", core.Access{}},
		{"no scopes", newInfo(), demo2, "list", core.Access{}},
		{"scope beyond grant", newInfo("write_demo1", "read_demo1"), demo1, "list", core.Access{}},
	}

	for _, s := range collectionScenarios {
		t.Run(s.name, func(t *testing.T) {
			access := s.info.CollectionAccess(app, s.c, s.action)
			if !reflect.DeepEqual(access, s.expected) {
				t.Fatalf("Expected %#v, got %#v", s.expected, access)
			}
		})
	}

	systemScenarios := []struct {
		name     string
		info     *core.RequestInfo
		resource string
		level    string
		expected bool
	}{
		{"logs read", full, core.PermissionResourceLogs, core.PermissionLevelRead, true},
		{"logs write", full, core.PermissionResourceLogs, core.PermissionLevelWrite, false},
		{"webhooks write", full, core.PermissionResourceWebhooks, core.PermissionLevelWrite, true},
		{"webhooks write with read scope", newInfo("system:read_webhooks"), core.PermissionResourceWebhooks, core.PermissionLevelWrite, false},
		{"settings not granted", full, core.PermissionResourceSettings, core.PermissionLevelRead, false},
		{"applications", full, core.PermissionResourceApplications, core.PermissionLevelRead, false},
		{"sql", full, core.PermissionResourceSQL, core.PermissionLevelWrite, false},
	}

	for _, s := range systemScenarios {
		t.Run(s.name, func(t *testing.T) {
			if v := s.info.Can(app, s.resource, s.level); v != s.expected {
				t.Fatalf("Expected %v, got %v", s.expected, v)
			}
		})
	}

	// a stored non grantable level (e.g. written with a raw SQL update) is ignored
	if _, err := app.DB().NewQuery("UPDATE {{_applicationInstallations}} SET [[permissions]] = {:p} WHERE id = {:id}").Bind(map[string]any{
		"p":  `{"collections":{},"system":{"staff":"write","sql":"write","logs":"read"}}`,
		"id": installed.Installation.Id,
	}).Execute(); err != nil {
		t.Fatal(err)
	}
	tampered := newInfo("system:write_staff", "system:read_logs", "system:write_sql")
	if tampered.Can(app, core.PermissionResourceStaff, core.PermissionLevelRead) || tampered.Can(app, core.PermissionResourceSQL, core.PermissionLevelWrite) {
		t.Fatal("Expected the not grantable stored levels to be ignored")
	}
	if !tampered.Can(app, core.PermissionResourceLogs, core.PermissionLevelRead) {
		t.Fatal("Expected the grantable stored level to be applied")
	}
}
