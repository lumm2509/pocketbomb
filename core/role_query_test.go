package core_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestFindAllRoles(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	roles, err := app.FindAllRoles()
	if err != nil {
		t.Fatal(err)
	}

	if len(roles) < 2 {
		t.Fatalf("Expected at least the 2 built-in roles, got %d", len(roles))
	}

	var foundOwner, foundCustomer bool
	for i, r := range roles {
		switch r.Name() {
		case core.RoleNameOwner:
			foundOwner = true
			if !r.System() {
				t.Fatal("Expected the Owner role to be a system role")
			}
		case core.RoleNameCustomer:
			foundCustomer = true
		}

		// system roles are ordered first
		if i > 0 && r.System() && !roles[i-1].System() {
			t.Fatalf("Expected the system roles to be ordered first, got %q after %q", r.Name(), roles[i-1].Name())
		}
	}

	if !foundOwner || !foundCustomer {
		t.Fatalf("Expected the Owner and Customer roles, got %v", roles)
	}
}

func TestAssignOwnerRole(t *testing.T) {
	t.Parallel()

	t.Run("nil record", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		if err := app.AssignOwnerRole(nil); err == nil {
			t.Fatal("Expected nil record error")
		}
	})

	t.Run("non superuser", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		user, err := app.FindAuthRecordByEmail("users", "test@example.com")
		if err != nil {
			t.Fatal(err)
		}

		if err := app.AssignOwnerRole(user); err == nil {
			t.Fatal("Expected non superuser error")
		}
	})

	t.Run("already owner", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		superusers, err := app.FindAllRecords(core.CollectionNameSuperusers)
		if err != nil {
			t.Fatal(err)
		}

		for _, su := range superusers {
			if !app.IsOwnerRecord(su) {
				continue
			}

			totalBefore, _ := app.CountOwners()
			if err := app.AssignOwnerRole(su); err != nil {
				t.Fatalf("Expected no-op for an existing owner, got %v", err)
			}
			totalAfter, _ := app.CountOwners()
			if totalAfter != totalBefore {
				t.Fatalf("Expected no new assignment, got %d -> %d", totalBefore, totalAfter)
			}

			return
		}

		t.Fatal("Expected at least one existing owner")
	})

	t.Run("new owner", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		staff, err := tests.CreateStaff(app, "assign_owner@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if app.IsOwnerRecord(staff) {
			t.Fatal("Expected the new staff to not be an owner")
		}

		totalBefore, _ := app.CountOwners()
		if err := app.AssignOwnerRole(staff); err != nil {
			t.Fatal(err)
		}

		totalAfter, _ := app.CountOwners()
		if totalAfter != totalBefore+1 {
			t.Fatalf("Expected the Owner assignments to increase, got %d -> %d", totalBefore, totalAfter)
		}
		if !app.IsOwnerRecord(staff) {
			t.Fatal("Expected the staff to become an owner")
		}
	})

	t.Run("missing owner role", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		owner, err := app.FindOwnerRole()
		if err != nil {
			t.Fatal(err)
		}
		owner.SetName("Renamed Owner")
		if err := app.SaveNoValidate(owner); err != nil {
			t.Fatal(err)
		}

		staff, err := tests.CreateStaff(app, "missing_owner_role@example.com")
		if err != nil {
			t.Fatal(err)
		}

		err = app.AssignOwnerRole(staff)
		if err == nil || !strings.Contains(err.Error(), "missing Owner role") {
			t.Fatalf("Expected missing Owner role error, got %v", err)
		}
	})
}

func TestFindRecordRolesBranches(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	t.Run("nil record", func(t *testing.T) {
		roles, err := app.FindRecordRoles(nil)
		if err != nil || len(roles) != 0 {
			t.Fatalf("Expected empty roles, got %v (%v)", roles, err)
		}
	})

	t.Run("non auth record", func(t *testing.T) {
		records, err := app.FindAllRecords("demo1")
		if err != nil || len(records) == 0 {
			t.Fatalf("Expected demo1 records, got %d (%v)", len(records), err)
		}

		roles, err := app.FindRecordRoles(records[0])
		if err != nil || len(roles) != 0 {
			t.Fatalf("Expected empty roles, got %v (%v)", roles, err)
		}
	})

	t.Run("explicit assignment", func(t *testing.T) {
		role, err := tests.CreateRole(app, "explicit", core.Permissions{})
		if err != nil {
			t.Fatal(err)
		}

		user, err := app.FindAuthRecordByEmail("users", "test@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if err := tests.AssignRoles(app, user, role.Id); err != nil {
			t.Fatal(err)
		}

		roles, err := app.FindRecordRoles(user)
		if err != nil || len(roles) != 1 || roles[0].Id != role.Id {
			t.Fatalf("Expected the explicit role, got %v (%v)", roles, err)
		}
	})
}

func TestFindRoleLookupErrors(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	if _, err := app.FindRoleByName("missing_role_name"); err == nil {
		t.Fatal("Expected missing role name error")
	}

	owner, err := app.FindOwnerRole()
	if err != nil {
		t.Fatal(err)
	}
	owner.SetName("Renamed")
	if err := app.SaveNoValidate(owner); err != nil {
		t.Fatal(err)
	}

	if _, err := app.FindOwnerRole(); err == nil {
		t.Fatal("Expected missing Owner role error")
	}
}

// TestSystemAlertsOnlyToOwners verifies that the system alerts are sent only
// to the superusers with the Owner role (R1-F3).
//
// note: it uses the already migrated test fixture instead of a fresh BaseApp
// (the existing TestSendSystemAlert* tests depend on the migrations import of tests/app.go).
func TestSystemAlertsOnlyToOwners(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// staff members without the Owner role
	role, err := tests.CreateRole(app, "alerts staff", core.Permissions{
		System: map[string]string{core.PermissionResourceLogs: core.PermissionLevelWrite},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tests.CreateStaff(app, "staff_with_role@example.com", role.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := tests.CreateStaff(app, "staff_without_roles@example.com"); err != nil {
		t.Fatal(err)
	}

	// one more Owner
	if _, err := tests.CreateStaff(app, "owner2@example.com", core.RoleIdOwner); err != nil {
		t.Fatal(err)
	}

	superusers, err := app.FindAllRecords(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}

	expected := []string{}
	for _, su := range superusers {
		if app.IsOwnerRecord(su) {
			expected = append(expected, su.Email())
		}
	}
	if len(expected) != 5 { // 4 fixture Owners + owner2
		t.Fatalf("Expected 5 Owners, got %v", expected)
	}

	app.TestMailer.Reset()

	if err := core.SendSystemAlertToAllSuperusers(app, "Test alert", "Test alert details"); err != nil {
		t.Fatal(err)
	}

	recipients := []string{}
	for _, m := range app.TestMailer.Messages() {
		for _, to := range m.To {
			recipients = append(recipients, to.Address)
		}
	}

	slices.Sort(recipients)
	slices.Sort(expected)

	if !slices.Equal(recipients, expected) {
		t.Fatalf("Expected the alerts to be sent only to the Owners %v, got %v", expected, recipients)
	}

	for _, r := range recipients {
		if r == "staff_with_role@example.com" || r == "staff_without_roles@example.com" {
			t.Fatalf("The non-Owner %q received a system alert", r)
		}
	}
}
