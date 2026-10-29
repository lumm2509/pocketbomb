package core_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/pocketbase/dbx"
)

func TestRolePreValidate(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	ctx := context.Background()

	t.Run("role nil record", func(t *testing.T) {
		r := &core.Role{}
		if err := r.PreValidate(ctx, app); err == nil {
			t.Fatal("Expected error for nil record")
		}
	})

	t.Run("role wrong collection", func(t *testing.T) {
		r := &core.Role{}
		r.SetProxyRecord(core.NewRecord(core.NewBaseCollection("not_roles")))
		if err := r.PreValidate(ctx, app); err == nil {
			t.Fatal("Expected error for non role collection")
		}
	})

	t.Run("role valid", func(t *testing.T) {
		if err := core.NewRole(app).PreValidate(ctx, app); err != nil {
			t.Fatalf("Expected valid role proxy, got %v", err)
		}
	})

	t.Run("role assignment nil record", func(t *testing.T) {
		ra := &core.RoleAssignment{}
		if err := ra.PreValidate(ctx, app); err == nil {
			t.Fatal("Expected error for nil record")
		}
	})

	t.Run("role assignment wrong collection", func(t *testing.T) {
		ra := &core.RoleAssignment{}
		ra.SetProxyRecord(core.NewRecord(core.NewBaseCollection("not_assignments")))
		if err := ra.PreValidate(ctx, app); err == nil {
			t.Fatal("Expected error for non role assignment collection")
		}
	})

	t.Run("role assignment valid", func(t *testing.T) {
		if err := core.NewRoleAssignment(app).PreValidate(ctx, app); err != nil {
			t.Fatalf("Expected valid role assignment proxy, got %v", err)
		}
	})
}

func TestRoleAccessors(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	role, err := tests.CreateRole(app, "accessors", core.Permissions{
		Collections: map[string][]string{"*": {"list"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if role.Description() != "" {
		t.Fatalf("Expected empty description, got %q", role.Description())
	}
	role.SetDescription("a test role")
	if err := app.Save(role); err != nil {
		t.Fatal(err)
	}
	if role.Description() != "a test role" {
		t.Fatalf("Unexpected description %q", role.Description())
	}

	if role.System() {
		t.Fatal("Expected a regular role")
	}
	if role.Created().IsZero() || role.Updated().IsZero() {
		t.Fatalf("Expected non-zero timestamps, got %v / %v", role.Created(), role.Updated())
	}

	owner, err := app.FindOwnerRole()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.System() {
		t.Fatal("Expected the Owner role to be a system role")
	}

	ra := core.NewRoleAssignment(app)
	ra.SetCollectionRef("collection_id")
	ra.SetRecordRef("record_id")
	ra.SetRole(role.Id)

	if ra.CollectionRef() != "collection_id" {
		t.Fatalf("Unexpected collection ref %q", ra.CollectionRef())
	}
	if ra.RecordRef() != "record_id" {
		t.Fatalf("Unexpected record ref %q", ra.RecordRef())
	}
	if ra.Role() != role.Id {
		t.Fatalf("Unexpected role %q", ra.Role())
	}
}

func TestCheckNotLastOwnerAssignment(t *testing.T) {
	t.Parallel()

	t.Run("non owner assignment delete", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		role, err := tests.CreateRole(app, "deletable", core.Permissions{})
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

		assignments, err := app.FindAllRoleAssignmentsByRecord(user)
		if err != nil || len(assignments) != 1 {
			t.Fatalf("Expected 1 assignment, got %d (%v)", len(assignments), err)
		}

		if err := app.Delete(assignments[0]); err != nil {
			t.Fatalf("Expected the non-owner assignment delete to succeed, got %v", err)
		}
	})

	t.Run("missing role assignment delete", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		user, err := app.FindAuthRecordByEmail("users", "test@example.com")
		if err != nil {
			t.Fatal(err)
		}

		ra := core.NewRoleAssignment(app)
		ra.SetCollectionRef(user.Collection().Id)
		ra.SetRecordRef(user.Id)
		ra.SetRole("missing_role")
		if err := app.SaveNoValidate(ra); err != nil {
			t.Fatal(err)
		}

		// a missing role is not checked as a potential last owner
		if err := app.Delete(ra); err != nil {
			t.Fatalf("Expected the delete to succeed, got %v", err)
		}
	})

	t.Run("owner demote and last owner protection", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		owner, err := app.FindOwnerRole()
		if err != nil {
			t.Fatal(err)
		}
		customer, err := app.FindRoleByName(core.RoleNameCustomer)
		if err != nil {
			t.Fatal(err)
		}

		assignments, err := app.FindAllRecords(
			core.CollectionNameRoleAssignments,
			dbx.HashExp{"role": owner.Id},
		)
		if err != nil || len(assignments) < 2 {
			t.Fatalf("Expected at least 2 Owner assignments, got %d (%v)", len(assignments), err)
		}

		// demoting an owner is allowed while more than one exists
		demoted := &core.RoleAssignment{Record: assignments[0]}
		demoted.SetRole(customer.Id)
		if err := app.Save(demoted); err != nil {
			t.Fatalf("Expected the owner demotion to succeed, got %v", err)
		}

		// remove all but one owner
		for {
			remaining, err := app.FindAllRecords(
				core.CollectionNameRoleAssignments,
				dbx.HashExp{"role": owner.Id},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(remaining) <= 1 {
				break
			}
			if err := app.Delete(remaining[0]); err != nil {
				t.Fatalf("Expected the owner assignment delete to succeed, got %v", err)
			}
		}

		last, err := app.FindAllRecords(
			core.CollectionNameRoleAssignments,
			dbx.HashExp{"role": owner.Id},
		)
		if err != nil || len(last) != 1 {
			t.Fatalf("Expected exactly 1 remaining owner, got %d (%v)", len(last), err)
		}

		if err := app.Delete(last[0]); err == nil ||
			!strings.Contains(err.Error(), "At least one Owner") {
			t.Fatalf("Expected the last Owner delete to fail, got %v", err)
		}

		// the last Owner also cannot be demoted
		lastOwner := &core.RoleAssignment{Record: last[0]}
		lastOwner.SetRole(customer.Id)
		if err := app.Save(lastOwner); err == nil {
			t.Fatal("Expected the last Owner demotion to fail")
		}
	})
}

// TestLastOwnerConcurrentDeletes simulates two concurrent deletes of the last
// two Owner assignments where both pass the (non-atomic) last Owner pre-check:
// the second delete must be rejected because it is rechecked after the write.
func TestLastOwnerConcurrentDeletes(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	owner, err := app.FindOwnerRole()
	if err != nil {
		t.Fatal(err)
	}

	// keep exactly 2 Owner assignments
	all, err := app.FindAllRecords(core.CollectionNameRoleAssignments, dbx.HashExp{"role": owner.Id})
	if err != nil {
		t.Fatal(err)
	}
	for len(all) < 2 {
		staff, err := tests.CreateStaff(app, "owner_extra@example.com", owner.Id)
		if err != nil {
			t.Fatal(err)
		}
		_ = staff
		all, _ = app.FindAllRecords(core.CollectionNameRoleAssignments, dbx.HashExp{"role": owner.Id})
	}
	for len(all) > 2 {
		if err := app.Delete(all[len(all)-1]); err != nil {
			t.Fatal(err)
		}
		all = all[:len(all)-1]
	}

	a, b := all[0], all[1]

	// the concurrent delete of "b" commits right after the pre-check of "a" passed
	fired := false
	app.OnRecordDeleteExecute(core.CollectionNameRoleAssignments).Bind(&hook.Handler[*core.RecordEvent]{
		Func: func(e *core.RecordEvent) error {
			if !fired && e.Record.Id == a.Id {
				fired = true
				if _, err := app.NonconcurrentDB().Delete(core.CollectionNameRoleAssignments, dbx.HashExp{"id": b.Id}).Execute(); err != nil {
					t.Fatal(err)
				}
			}
			return e.Next()
		},
		Priority: -999,
	})

	err = app.Delete(a)
	if !fired {
		t.Fatal("Expected the concurrent delete to be simulated")
	}

	var verr interface{ Code() string }
	if err == nil || !errors.As(err, &verr) || verr.Code() != "validation_last_owner" {
		t.Fatalf("Expected validation_last_owner error, got %v", err)
	}

	total, err := app.CountOwners()
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("Expected 1 Owner to remain, got %d", total)
	}
}

// TestLastOwnerConcurrentRoleChange is similar to TestLastOwnerConcurrentDeletes but for an assignment role change.
func TestLastOwnerConcurrentRoleChange(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	owner, err := app.FindOwnerRole()
	if err != nil {
		t.Fatal(err)
	}

	other, err := tests.CreateRole(app, "other", core.Permissions{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tests.CreateStaff(app, "owner_extra@example.com", owner.Id); err != nil {
		t.Fatal(err)
	}

	all, err := app.FindAllRecords(core.CollectionNameRoleAssignments, dbx.HashExp{"role": owner.Id})
	if err != nil || len(all) < 2 {
		t.Fatalf("Expected at least 2 Owner assignments, got %d (%v)", len(all), err)
	}

	// remove all other owner assignments except the first one directly
	for _, r := range all[1:] {
		if _, err := app.NonconcurrentDB().Delete(core.CollectionNameRoleAssignments, dbx.HashExp{"id": r.Id}).Execute(); err != nil {
			t.Fatal(err)
		}
	}
	// and add a second one back so that the pre-check passes
	second := core.NewRoleAssignment(app)
	second.SetCollectionRef(all[1].GetString("collectionRef"))
	second.SetRecordRef(all[1].GetString("recordRef"))
	second.SetRole(owner.Id)
	if err := app.Save(second); err != nil {
		t.Fatal(err)
	}

	first, _ := app.FindRecordById(core.CollectionNameRoleAssignments, all[0].Id)

	fired := false
	app.OnRecordUpdateExecute(core.CollectionNameRoleAssignments).Bind(&hook.Handler[*core.RecordEvent]{
		Func: func(e *core.RecordEvent) error {
			if !fired {
				fired = true
				if _, err := app.NonconcurrentDB().Delete(core.CollectionNameRoleAssignments, dbx.HashExp{"id": second.Id}).Execute(); err != nil {
					t.Fatal(err)
				}
			}
			return e.Next()
		},
		Priority: -999,
	})

	first.Set("role", other.Id)
	err = app.Save(first)

	var verr interface{ Code() string }
	if err == nil || !errors.As(err, &verr) || verr.Code() != "validation_last_owner" {
		t.Fatalf("Expected validation_last_owner error, got %v", err)
	}

	if total, _ := app.CountOwners(); total != 1 {
		t.Fatalf("Expected 1 Owner to remain, got %d", total)
	}
}

func TestCollectionDefaultRoles(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// new auth collections use the Customer role by default
	c := core.NewAuthCollection("rbac_new_auth")
	if err := app.Save(c); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.DefaultRoles, []string{core.RoleIdCustomer}) {
		t.Fatalf("Expected the Customer default role, got %v", c.DefaultRoles)
	}

	// explicitly empty default roles are kept
	c2 := core.NewAuthCollection("rbac_new_auth2")
	c2.DefaultRoles = []string{}
	if err := app.Save(c2); err != nil {
		t.Fatal(err)
	}
	if len(c2.DefaultRoles) != 0 {
		t.Fatalf("Expected no default roles, got %v", c2.DefaultRoles)
	}

	// missing role
	c.DefaultRoles = []string{"missing"}
	if err := app.Save(c); err == nil {
		t.Fatal("Expected missing default role error")
	}

	// Owner cannot be default
	c.DefaultRoles = []string{core.RoleIdOwner}
	if err := app.Save(c); err == nil {
		t.Fatal("Expected Owner default role error")
	}

	// _superusers cannot have default roles
	superusers, _ := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	superusers.DefaultRoles = []string{core.RoleIdCustomer}
	if err := app.Save(superusers); err == nil {
		t.Fatal("Expected _superusers default roles error")
	}
}

func TestRoleModelInvariants(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	owner, err := app.FindOwnerRole()
	if err != nil {
		t.Fatal(err)
	}

	// system roles are immutable and not deletable
	owner.SetName("Boss")
	if err := app.Save(owner); err == nil {
		t.Fatal("Expected system role name change error")
	}
	owner, _ = app.FindOwnerRole()
	if err := app.Delete(owner); err == nil {
		t.Fatal("Expected system role delete error")
	}

	// regular role cannot become system
	role, err := tests.CreateRole(app, "regular", core.Permissions{})
	if err != nil {
		t.Fatal(err)
	}
	role.SetSystem(true)
	if err := app.Save(role); err == nil {
		t.Fatal("Expected system flag change error")
	}
	role, _ = app.FindRoleById(role.Id)

	// the Owner role only for staff
	user, _ := app.FindAuthRecordByEmail("users", "test@example.com")
	if err := tests.AssignRoles(app, user, core.RoleIdOwner); err == nil {
		t.Fatal("Expected Owner assignment error for a non-staff record")
	}

	// cascade delete of the assignments on record delete
	if err := tests.AssignRoles(app, user, role.Id); err != nil {
		t.Fatal(err)
	}
	if err := app.Delete(user); err != nil {
		t.Fatal(err)
	}
	if total, _ := app.CountRecords(core.CollectionNameRoleAssignments, nil); total != 4 { // only the 4 Owners
		t.Fatalf("Expected the user assignments to be deleted, got %d assignments", total)
	}

	// deleted role is removed from the default roles and its assignments are deleted
	staff, err := tests.CreateStaff(app, "rbac_staff@example.com", role.Id)
	if err != nil {
		t.Fatal(err)
	}
	clients, _ := app.FindCollectionByNameOrId("clients")
	clients.DefaultRoles = []string{core.RoleIdCustomer, role.Id}
	if err := app.Save(clients); err != nil {
		t.Fatal(err)
	}
	if err := app.Delete(role); err != nil {
		t.Fatal(err)
	}
	if a, _ := app.FindAllRoleAssignmentsByRecord(staff); len(a) != 0 {
		t.Fatalf("Expected the role assignments to be deleted, got %d", len(a))
	}
	clients, _ = app.FindCollectionByNameOrId("clients")
	if !slices.Equal(clients.DefaultRoles, []string{core.RoleIdCustomer}) {
		t.Fatalf("Expected the deleted role to be removed from the default roles, got %v", clients.DefaultRoles)
	}
}
