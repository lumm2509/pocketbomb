package core_test

import (
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestClientFilterJoinCheck(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo1, _ := app.FindCollectionByNameOrId("demo1")
	demo2, _ := app.FindCollectionByNameOrId("demo2")
	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)

	role, _ := tests.CreateRole(app, "demo2 only", core.Permissions{Collections: map[string][]string{demo2.Id: {"list"}}})
	staff, _ := tests.CreateStaff(app, "demo2@example.com", role.Id)
	customer, _ := app.FindAuthRecordByEmail("users", "test2@example.com")
	if err := tests.AssignRoles(app, customer, role.Id); err != nil {
		t.Fatal(err)
	}
	defaultCustomer, _ := app.FindAuthRecordByEmail("users", "test@example.com")

	scenarios := []struct {
		name    string
		auth    *core.Record
		target  *core.Collection
		allowed bool
	}{
		{"staff allowed collection", staff, demo2, true},
		{"staff not allowed collection", staff, demo1, false},
		{"staff system collection without permission", staff, superusers, false},
		{"restricted customer not allowed collection", customer, demo1, false},
		{"default customer regular collection", defaultCustomer, demo1, true},
		{"default customer system collection", defaultCustomer, superusers, false},
		{"guest regular collection (rules only)", nil, demo1, true},
	}

	for _, s := range scenarios {
		err := core.ClientFilterJoinCheck(app, &core.RequestInfo{Auth: s.auth})(s.target)
		if (err == nil) != s.allowed {
			t.Fatalf("[%s] Expected allowed %v, got %v", s.name, s.allowed, err)
		}
	}
}

func TestCheckApplicationInstallationChange(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	demo1, _ := app.FindCollectionByNameOrId("demo1")
	demo2, _ := app.FindCollectionByNameOrId("demo2")

	installerRole, err := tests.CreateRole(app, "installer", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
		System:      map[string]string{core.PermissionResourceApplications: core.PermissionLevelWrite},
	})
	if err != nil {
		t.Fatal(err)
	}
	readerRole, err := tests.CreateRole(app, "reader", core.Permissions{
		Collections: map[string][]string{demo2.Id: {"list", "view"}},
		System:      map[string]string{core.PermissionResourceApplications: core.PermissionLevelRead},
	})
	if err != nil {
		t.Fatal(err)
	}

	installer, _ := tests.CreateStaff(app, "installer@example.com", installerRole.Id)
	reader, _ := tests.CreateStaff(app, "reader@example.com", readerRole.Id)
	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")

	newInstallation := func(grant core.Permissions) *core.Record {
		i := core.NewApplicationInstallation(app)
		i.SetPermissions(grant)
		return i.Record
	}

	covered := core.Permissions{Collections: map[string][]string{demo2.Id: {"list"}}}
	notCovered := core.Permissions{Collections: map[string][]string{demo1.Id: {"list"}}}

	scenarios := []struct {
		name     string
		actor    *core.Record
		grant    core.Permissions
		expected bool
	}{
		{"owner any grant", owner, notCovered, true},
		{"installer covered grant", installer, covered, true},
		{"installer not covered grant", installer, notCovered, false},
		{"installer not covered system level", installer, core.Permissions{System: map[string]string{"logs": "read"}}, false},
		{"applications read only", reader, covered, false},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			err := core.CheckApplicationInstallationChange(app, &core.RequestInfo{Auth: s.actor}, newInstallation(s.grant))
			if (err == nil) != s.expected {
				t.Fatalf("Expected allowed %v, got %v", s.expected, err)
			}
		})
	}

	// existing installations require covering the original grant too
	_, installed := installTestApplication(t, app, "check-app", notCovered)
	fresh, _ := app.FindApplicationInstallationById(installed.Installation.Id)
	fresh.SetPermissions(covered)
	if err := core.CheckApplicationInstallationChange(app, &core.RequestInfo{Auth: installer}, fresh.Record); err == nil {
		t.Fatal("Expected the narrowing of a not covered grant to be denied")
	}

	// trusted programmatic change
	if err := core.CheckApplicationInstallationChange(app, nil, fresh.Record); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRoleChanges(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	managerRole, _ := tests.CreateRole(app, "manager", core.Permissions{System: map[string]string{
		core.PermissionResourceRoles: core.PermissionLevelWrite,
		core.PermissionResourceLogs:  core.PermissionLevelRead,
	}})
	manager, _ := tests.CreateStaff(app, "manager@example.com", managerRole.Id)
	target, _ := tests.CreateStaff(app, "target@example.com")
	owner, _ := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test@example.com")

	managerInfo := &core.RequestInfo{Auth: manager}
	ownerInfo := &core.RequestInfo{Auth: owner}

	covered := core.NewRole(app)
	covered.SetName("covered")
	covered.SetPermissions(core.Permissions{System: map[string]string{core.PermissionResourceLogs: core.PermissionLevelRead}})
	if err := core.CheckRoleChange(app, managerInfo, covered.Record, false); err != nil {
		t.Fatalf("Expected covered role change to be allowed, got %v", err)
	}

	escalated := core.NewRole(app)
	escalated.SetName("escalated")
	escalated.SetPermissions(core.Permissions{System: map[string]string{core.PermissionResourceLogs: core.PermissionLevelWrite}})
	if err := core.CheckRoleChange(app, managerInfo, escalated.Record, false); err == nil {
		t.Fatal("Expected escalated role change to be denied")
	}
	if err := core.CheckRoleChange(app, ownerInfo, escalated.Record, false); err != nil {
		t.Fatalf("Expected Owner role change to be allowed, got %v", err)
	}
	if err := core.CheckRoleChange(app, nil, escalated.Record, false); err != nil {
		t.Fatalf("Expected programmatic role change to be allowed, got %v", err)
	}

	ownerRole, _ := app.FindOwnerRole()
	if err := core.CheckRoleChange(app, ownerInfo, ownerRole.Record, false); err == nil {
		t.Fatal("Expected system role change to be denied (even for Owners)")
	}

	assignment := func(record *core.Record, roleId string) *core.Record {
		ra := core.NewRoleAssignment(app)
		ra.SetCollectionRef(record.Collection().Id)
		ra.SetRecordRef(record.Id)
		ra.SetRole(roleId)
		return ra.Record
	}

	if err := core.CheckRoleAssignmentChange(app, managerInfo, assignment(target, managerRole.Id)); err != nil {
		t.Fatalf("Expected covered assignment to be allowed, got %v", err)
	}
	if err := core.CheckRoleAssignmentChange(app, managerInfo, assignment(target, core.RoleIdOwner)); err == nil {
		t.Fatal("Expected Owner assignment by a non-Owner to be denied")
	}
	if err := core.CheckRoleAssignmentChange(app, ownerInfo, assignment(target, core.RoleIdOwner)); err != nil {
		t.Fatalf("Expected Owner assignment by an Owner to be allowed, got %v", err)
	}
	if err := core.CheckRoleAssignmentChange(app, managerInfo, assignment(target, core.RoleIdCustomer)); err == nil {
		t.Fatal("Expected not covered (Customer) assignment to be denied")
	}
	if err := core.CheckRoleAssignmentChange(app, managerInfo, assignment(manager, managerRole.Id)); err == nil {
		t.Fatal("Expected self assignment to be denied")
	}
	if err := core.CheckRoleAssignmentChange(app, ownerInfo, assignment(owner, core.RoleIdOwner)); err == nil {
		t.Fatal("Expected Owner self assignment to be denied")
	}

	// staff records changes
	if err := core.CheckStaffRecordChange(app, managerInfo, owner); err == nil {
		t.Fatal("Expected Owner account change by a non-Owner to be denied")
	}
	if err := core.CheckStaffRecordChange(app, managerInfo, manager); err != nil {
		t.Fatalf("Expected own account change to be allowed, got %v", err)
	}
	if err := core.CheckStaffRecordChange(app, managerInfo, target); err != nil {
		t.Fatalf("Expected change of a staff without permissions to be allowed, got %v", err)
	}

	// impersonation
	if err := core.CheckImpersonation(app, managerInfo, target); err == nil {
		t.Fatal("Expected impersonation without permission to be denied")
	}
	user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	if err := core.CheckImpersonation(app, ownerInfo, user); err != nil {
		t.Fatalf("Expected Owner impersonation to be allowed, got %v", err)
	}

	impRole, _ := tests.CreateRole(app, "impersonator", core.Permissions{System: map[string]string{core.PermissionResourceImpersonate: core.PermissionLevelWrite}})
	impersonator, _ := tests.CreateStaff(app, "imp@example.com", impRole.Id)
	impInfo := &core.RequestInfo{Auth: impersonator}
	if err := core.CheckImpersonation(app, impInfo, user); err != nil {
		t.Fatalf("Expected impersonation with permission to be allowed, got %v", err)
	}
	if err := core.CheckImpersonation(app, impInfo, owner); err == nil {
		t.Fatal("Expected impersonation of an Owner by a non-Owner to be denied")
	}
	if err := core.CheckImpersonation(app, impInfo, manager); err == nil {
		t.Fatal("Expected impersonation of a staff with not held permissions to be denied")
	}
}
