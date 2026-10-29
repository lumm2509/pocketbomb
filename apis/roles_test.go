package apis_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

// rbacRolesSetup creates:
//   - "Roles manager" role: roles write + logs read + demo2 list
//   - "Logs admin" role: logs write (not held by the roles manager)
//   - manager@example.com staff with the "Roles manager" role
//   - target@example.com staff without roles
func rbacRolesSetup(t testing.TB, app *tests.TestApp) (manager *core.Record, target *core.Record, managerRole *core.Role, logsAdmin *core.Role) {
	t.Helper()

	demo2, err := app.FindCollectionByNameOrId("demo2")
	if err != nil {
		t.Fatal(err)
	}

	managerRole, err = tests.CreateRole(app, "Roles manager", core.Permissions{
		Collections: map[string][]string{demo2.Id: {core.PermissionActionList}},
		System: map[string]string{
			core.PermissionResourceRoles: core.PermissionLevelWrite,
			core.PermissionResourceLogs:  core.PermissionLevelRead,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	logsAdmin, err = tests.CreateRole(app, "Logs admin", core.Permissions{
		System: map[string]string{core.PermissionResourceLogs: core.PermissionLevelWrite},
	})
	if err != nil {
		t.Fatal(err)
	}

	manager, err = tests.CreateStaff(app, "manager@example.com", managerRole.Id)
	if err != nil {
		t.Fatal(err)
	}

	target, err = tests.CreateStaff(app, "target@example.com")
	if err != nil {
		t.Fatal(err)
	}

	return manager, target, managerRole, logsAdmin
}

func TestRolesApiEscalationAndInvariants(t *testing.T) {
	t.Parallel()

	type scenario struct {
		name           string
		actor          string // staff email
		method         string
		url            string
		body           func(app *tests.TestApp, manager, target *core.Record, managerRole, logsAdmin *core.Role) string
		expectedStatus int
		content        []string
		after          func(t testing.TB, app *tests.TestApp)
	}

	ownerRoleId := core.RoleIdOwner

	scenarios := []scenario{
		{
			name:   "create role within the actor permissions",
			actor:  "manager@example.com",
			method: http.MethodPost,
			url:    "/api/collections/_roles/records",
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return `{"name":"Logs reader","permissions":{"system":{"logs":"read"}}}`
			},
			expectedStatus: 200,
			content:        []string{`"name":"Logs reader"`},
		},
		{
			name:   "create role escalating a system permission",
			actor:  "manager@example.com",
			method: http.MethodPost,
			url:    "/api/collections/_roles/records",
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return `{"name":"Escalated","permissions":{"system":{"settings":"write"}}}`
			},
			expectedStatus: 403,
		},
		{
			name:   "create role escalating the collections wildcard",
			actor:  "manager@example.com",
			method: http.MethodPost,
			url:    "/api/collections/_roles/records",
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return `{"name":"Escalated","permissions":{"collections":{"*":["list"]}}}`
			},
			expectedStatus: 403,
		},
		{
			name:   "create role with the not assignable sql resource (Owner)",
			actor:  "test@example.com",
			method: http.MethodPost,
			url:    "/api/collections/_roles/records",
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return `{"name":"SQL","permissions":{"system":{"sql":"write"}}}`
			},
			expectedStatus: 400,
		},
		{
			name:   "update role adding a permission the actor doesn't hold",
			actor:  "manager@example.com",
			method: http.MethodPatch,
			url:    "/api/collections/_roles/records/{managerRole}",
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return `{"permissions":{"system":{"roles":"write","logs":"write"}}}`
			},
			expectedStatus: 403,
		},
		{
			name:   "update/delete role with a permission the actor doesn't hold",
			actor:  "manager@example.com",
			method: http.MethodDelete,
			url:    "/api/collections/_roles/records/{logsAdmin}",
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return ""
			},
			expectedStatus: 403,
		},
		{
			name:   "Owner deletes a regular role",
			actor:  "test@example.com",
			method: http.MethodDelete,
			url:    "/api/collections/_roles/records/{logsAdmin}",
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return ""
			},
			expectedStatus: 204,
		},
		{
			name:   "update the system Owner role",
			actor:  "test@example.com",
			method: http.MethodPatch,
			url:    "/api/collections/_roles/records/" + ownerRoleId,
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return `{"name":"Boss"}`
			},
			expectedStatus: 403,
		},
		{
			name:   "delete the system Owner role",
			actor:  "test@example.com",
			method: http.MethodDelete,
			url:    "/api/collections/_roles/records/" + ownerRoleId,
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return ""
			},
			expectedStatus: 403,
		},
		{
			name:   "assign a covered role to another staff",
			actor:  "manager@example.com",
			method: http.MethodPut,
			url:    "/api/roles/assignments",
			body: func(app *tests.TestApp, _, target *core.Record, managerRole, _ *core.Role) string {
				return `{"collection":"_superusers","record":"` + target.Id + `","roles":["` + managerRole.Id + `"]}`
			},
			expectedStatus: 200,
			content:        []string{`"explicit":true`},
		},
		{
			name:   "assign a not covered role (escalation)",
			actor:  "manager@example.com",
			method: http.MethodPut,
			url:    "/api/roles/assignments",
			body: func(app *tests.TestApp, _, target *core.Record, _, logsAdmin *core.Role) string {
				return `{"collection":"_superusers","record":"` + target.Id + `","roles":["` + logsAdmin.Id + `"]}`
			},
			expectedStatus: 403,
		},
		{
			name:   "assign the Owner role by a non-Owner",
			actor:  "manager@example.com",
			method: http.MethodPut,
			url:    "/api/roles/assignments",
			body: func(app *tests.TestApp, _, target *core.Record, _, _ *core.Role) string {
				return `{"collection":"_superusers","record":"` + target.Id + `","roles":["` + ownerRoleId + `"]}`
			},
			expectedStatus: 403,
		},
		{
			name:   "assign the Owner role by an Owner",
			actor:  "test@example.com",
			method: http.MethodPut,
			url:    "/api/roles/assignments",
			body: func(app *tests.TestApp, _, target *core.Record, _, _ *core.Role) string {
				return `{"collection":"_superusers","record":"` + target.Id + `","roles":["` + ownerRoleId + `"]}`
			},
			expectedStatus: 200,
			content:        []string{`"owner":true`},
		},
		{
			name:   "assign the Owner role to a non-staff record",
			actor:  "test@example.com",
			method: http.MethodPut,
			url:    "/api/roles/assignments",
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return `{"collection":"users","record":"4q1xlclmfloku33","roles":["` + ownerRoleId + `"]}`
			},
			expectedStatus: 400,
		},
		{
			name:   "self assignment change (non-Owner)",
			actor:  "manager@example.com",
			method: http.MethodPut,
			url:    "/api/roles/assignments",
			body: func(app *tests.TestApp, manager, _ *core.Record, managerRole, _ *core.Role) string {
				// note: unassigning the own (covered) role so that the self-assignment is the only reason
				return `{"collection":"_superusers","record":"` + manager.Id + `","roles":[]}`
			},
			expectedStatus: 403,
		},
		{
			name:   "self unassignment (Owner)",
			actor:  "test@example.com",
			method: http.MethodPut,
			url:    "/api/roles/assignments",
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return `{"collection":"_superusers","record":"sywbhecnh46rhm0","roles":[]}`
			},
			expectedStatus: 403,
		},
		{
			name:   "set customer roles",
			actor:  "manager@example.com",
			method: http.MethodPut,
			url:    "/api/roles/assignments",
			body: func(app *tests.TestApp, _, _ *core.Record, managerRole, _ *core.Role) string {
				return `{"collection":"users","record":"4q1xlclmfloku33","roles":[]}`
			},
			expectedStatus: 200,
			content:        []string{`"explicit":false`, `"effective":["` + core.RoleIdCustomer + `"]`},
		},
		{
			name:   "records API: escalating role assignment",
			actor:  "manager@example.com",
			method: http.MethodPost,
			url:    "/api/collections/_roleAssignments/records",
			body: func(app *tests.TestApp, _, target *core.Record, _, logsAdmin *core.Role) string {
				return `{"collectionRef":"` + target.Collection().Id + `","recordRef":"` + target.Id + `","role":"` + logsAdmin.Id + `"}`
			},
			expectedStatus: 403,
		},
		{
			name:   "records API: escalating role create",
			actor:  "manager@example.com",
			method: http.MethodPost,
			url:    "/api/collections/_roles/records",
			body: func(app *tests.TestApp, _, _ *core.Record, _, _ *core.Role) string {
				return `{"name":"x","permissions":{"system":{"backups":"write"}}}`
			},
			expectedStatus: 403,
		},
		{
			name:   "records API: batch Owner assignment by a non-Owner",
			actor:  "manager@example.com",
			method: http.MethodPost,
			url:    "/api/batch",
			body: func(app *tests.TestApp, _, target *core.Record, _, _ *core.Role) string {
				return `{"requests":[{"method":"POST","url":"/api/collections/_roleAssignments/records","body":{"collectionRef":"` + target.Collection().Id + `","recordRef":"` + target.Id + `","role":"` + ownerRoleId + `"}}]}`
			},
			expectedStatus: 400,
			content:        []string{`"status":403`},
		},
		{
			name:   "non-Owner staff cannot change an Owner account",
			actor:  "manager@example.com",
			method: http.MethodPatch,
			url:    "/api/collections/_superusers/records/sbmbsdb40jyxf7h",
			body: func(app *tests.TestApp, _, _ *core.Record, managerRole, _ *core.Role) string {
				// grant staff write to the manager role
				managerRole.SetPermissions(core.Permissions{System: map[string]string{
					core.PermissionResourceRoles: core.PermissionLevelWrite,
					core.PermissionResourceStaff: core.PermissionLevelWrite,
				}})
				_ = app.Save(managerRole)
				return `{"email":"hijack@example.com"}`
			},
			expectedStatus: 403,
		},
	}

	for _, s := range scenarios {
		headers := map[string]string{"Content-Type": "application/json"}
		body := &strings.Builder{}

		// note: the records API delete action parses the (unknown length) request body
		var reqBody io.Reader = &lazyReader{builder: body}
		if s.method == http.MethodDelete {
			reqBody = nil
		}

		expectedContent := append([]string{`"`}, s.content...)
		if s.expectedStatus == http.StatusNoContent {
			expectedContent = nil
		}

		(&tests.ApiScenario{
			Name:            s.name,
			Method:          s.method,
			URL:             s.url,
			Body:            reqBody,
			Headers:         headers,
			ExpectedStatus:  s.expectedStatus,
			ExpectedContent: expectedContent,
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				manager, target, managerRole, logsAdmin := rbacRolesSetup(t, app)

				body.WriteString(s.body(app, manager, target, managerRole, logsAdmin))

				actor, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, s.actor)
				if err != nil {
					t.Fatal(err)
				}

				token, err := tests.NewSessionAuthToken(app, actor)
				if err != nil {
					t.Fatal(err)
				}
				headers["Authorization"] = token

				e.Router.BindFunc(func(re *core.RequestEvent) error {
					switch re.Request.PathValue("id") {
					case "{managerRole}":
						re.Request.SetPathValue("id", managerRole.Id)
					case "{logsAdmin}":
						re.Request.SetPathValue("id", logsAdmin.Id)
					}
					return re.Next()
				})
			},
		}).Test(t)
	}
}

func TestLastOwnerInvariant(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// keep a single Owner
	for _, email := range []string{"test2@example.com", "test3@example.com", "test4@example.com"} {
		su, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, email)
		if err != nil {
			t.Fatal(err)
		}
		if err := app.Delete(su); err != nil {
			t.Fatal(err)
		}
	}

	total, err := app.CountOwners()
	if err != nil || total != 1 {
		t.Fatalf("Expected 1 Owner, got %d (%v)", total, err)
	}

	last, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// deleting the last Owner record fails (the assignment cascade fails)
	if err := app.Delete(last); err == nil {
		t.Fatal("Expected the last Owner record delete to fail")
	}

	// deleting the last Owner assignment fails
	assignments, err := app.FindAllRoleAssignmentsByRecord(last)
	if err != nil || len(assignments) != 1 {
		t.Fatalf("Expected 1 assignment, got %d (%v)", len(assignments), err)
	}
	if err := app.Delete(assignments[0]); err == nil {
		t.Fatal("Expected the last Owner assignment delete to fail")
	}

	// changing the role of the last Owner assignment fails
	assignments[0].SetRole(core.RoleIdCustomer)
	if err := app.Save(assignments[0]); err == nil {
		t.Fatal("Expected the last Owner assignment role change to fail")
	}

	// with a second Owner the first could be removed
	second, err := tests.CreateStaff(app, "second@example.com", core.RoleIdOwner)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Delete(last); err != nil {
		t.Fatalf("Expected the Owner delete to succeed with another Owner, got %v", err)
	}
	if !app.IsOwnerRecord(second) {
		t.Fatal("Expected the second staff to be Owner")
	}
}
