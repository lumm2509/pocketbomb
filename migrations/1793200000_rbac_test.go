package migrations_test

import (
	"slices"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestRBACMigrationUpstreamDB(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// upstream state (the RBAC tables and the default roles are removed)
	downToUpstream(t, app)

	// a superuser created before R1 and the installer superuser
	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	legacy := core.NewRecord(superusers)
	legacy.SetEmail("legacy@example.com")
	legacy.SetPassword("1234567890")
	if err := app.Save(legacy); err != nil {
		t.Fatal(err)
	}
	installer := core.NewRecord(superusers)
	installer.SetEmail(core.DefaultInstallerEmail)
	installer.SetPassword("1234567890")
	if err := app.Save(installer); err != nil {
		t.Fatal(err)
	}

	upFromUpstream(t, app)

	// built-in roles
	owner, err := app.FindOwnerRole()
	if err != nil || owner.Id != core.RoleIdOwner || !owner.System() {
		t.Fatalf("Expected the system Owner role, got %v (%v)", owner, err)
	}
	customer, err := app.FindRoleById(core.RoleIdCustomer)
	if err != nil || customer.System() || customer.Name() != core.RoleNameCustomer {
		t.Fatalf("Expected the editable Customer role, got %v (%v)", customer, err)
	}
	if !slices.Equal(customer.Permissions().Collections[core.PermissionAllCollections], []string{"create", "delete", "list", "update", "view"}) {
		t.Fatalf("Unexpected Customer permissions %v", customer.Permissions())
	}

	// all existing superusers are Owners (except the installer one)
	all, _ := app.FindAllRecords(core.CollectionNameSuperusers)
	for _, su := range all {
		isOwner := app.IsOwnerRecord(su)
		if su.Email() == core.DefaultInstallerEmail {
			if isOwner {
				t.Fatal("Expected the installer superuser to not be Owner")
			}
			continue
		}
		if !isOwner {
			t.Fatalf("Expected superuser %q to be Owner", su.Email())
		}
	}

	// the non-superusers auth collections use the Customer role as default
	authCollections, _ := app.FindAllCollections(core.CollectionTypeAuth)
	for _, c := range authCollections {
		if c.Name == core.CollectionNameSuperusers || c.Name == core.CollectionNameApplicationInstallations {
			if len(c.DefaultRoles) != 0 {
				t.Fatalf("Expected no %s default roles, got %v", c.Name, c.DefaultRoles)
			}
			continue
		}
		if !slices.Equal(c.DefaultRoles, []string{core.RoleIdCustomer}) {
			t.Fatalf("Expected the %q Customer default role, got %v", c.Name, c.DefaultRoles)
		}
	}

	// behavior preserved: the customers keep all collection actions (rules decide)
	user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	demo1, _ := app.FindCollectionByNameOrId("demo1")
	info := &core.RequestInfo{Auth: user}
	for _, action := range core.PermissionCollectionActions {
		access := info.CollectionAccess(app, demo1, action)
		if !access.Allowed || access.BypassRules {
			t.Fatalf("Expected customer %s access governed by the rules, got %+v", action, access)
		}
	}
	if !(&core.RequestInfo{Auth: legacy}).IsOwner(app) {
		t.Fatal("Expected the legacy superuser to have the Owner bypass")
	}
}

func TestRBACMigrationFreshDB(t *testing.T) {
	app := newFreshApp(t)

	owner, err := app.FindOwnerRole()
	if err != nil || owner.Id != core.RoleIdOwner || !owner.System() {
		t.Fatalf("Expected the system Owner role, got %v (%v)", owner, err)
	}

	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(users.DefaultRoles, []string{core.RoleIdCustomer}) {
		t.Fatalf("Expected the Customer default role, got %v", users.DefaultRoles)
	}

	for _, name := range []string{core.CollectionNameRoles, core.CollectionNameRoleAssignments} {
		c, err := app.FindCollectionByNameOrId(name)
		if err != nil || !c.System || c.ListRule != nil {
			t.Fatalf("Unexpected %s collection %v (%v)", name, c, err)
		}
	}
}
