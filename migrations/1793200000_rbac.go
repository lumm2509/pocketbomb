package migrations

import (
	"fmt"
	"slices"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/pocketbase/dbx"
)

// RBAC:
//   - creates the _roles and _roleAssignments system collections
//   - creates the built-in system Owner role and the editable Customer role
//     (all collection actions, aka. the collection rules keep deciding)
//   - assigns the Owner role to all existing superusers (except the installer one)
//   - sets the Customer role as default role of all existing non-superusers auth collections
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		if err := createRolesCollection(txApp); err != nil {
			return fmt.Errorf("_roles error: %w", err)
		}

		if err := createRoleAssignmentsCollection(txApp); err != nil {
			return fmt.Errorf("_roleAssignments error: %w", err)
		}

		owner := core.NewRole(txApp)
		owner.Id = core.RoleIdOwner
		owner.SetName(core.RoleNameOwner)
		owner.SetDescription("Full access to everything (built-in).")
		owner.SetSystem(true)
		owner.SetPermissions(core.Permissions{})
		if err := txApp.Save(owner); err != nil {
			return fmt.Errorf("failed to create the Owner role: %w", err)
		}

		customer := core.NewRole(txApp)
		customer.Id = core.RoleIdCustomer
		customer.SetName(core.RoleNameCustomer)
		customer.SetDescription("Default role of the non-staff auth records (the collection API rules still apply).")
		customer.SetPermissions(core.Permissions{
			Collections: map[string][]string{
				core.PermissionAllCollections: slices.Clone(core.PermissionCollectionActions),
			},
		})
		if err := txApp.Save(customer); err != nil {
			return fmt.Errorf("failed to create the Customer role: %w", err)
		}

		superusers, err := txApp.FindAllRecords(
			core.CollectionNameSuperusers,
			dbx.Not(dbx.HashExp{"email": core.DefaultInstallerEmail}),
		)
		if err != nil {
			return err
		}

		for _, su := range superusers {
			if err := txApp.AssignOwnerRole(su); err != nil {
				return fmt.Errorf("failed to assign the Owner role to superuser %q: %w", su.Id, err)
			}
		}

		authCollections, err := txApp.FindAllCollections(core.CollectionTypeAuth)
		if err != nil {
			return err
		}

		for _, c := range authCollections {
			if c.Name == core.CollectionNameSuperusers || len(c.DefaultRoles) > 0 {
				continue
			}

			c.DefaultRoles = []string{customer.Id}

			if err := txApp.Save(c); err != nil {
				return fmt.Errorf("failed to set the %q default roles: %w", c.Name, err)
			}
		}

		return nil
	}, func(txApp core.App) error {
		authCollections, err := txApp.FindAllCollections(core.CollectionTypeAuth)
		if err != nil {
			return err
		}

		for _, c := range authCollections {
			if len(c.DefaultRoles) == 0 {
				continue
			}

			c.DefaultRoles = nil

			if err := txApp.SaveNoValidate(c); err != nil {
				return err
			}
		}

		for _, name := range []string{core.CollectionNameRoleAssignments, core.CollectionNameRoles} {
			if _, err := txApp.DB().DropTable(name).Execute(); err != nil {
				return err
			}

			if _, err := txApp.DB().Delete("_collections", dbx.HashExp{"name": name}).Execute(); err != nil {
				return err
			}
		}

		return txApp.ReloadCachedCollections()
	})
}

func createRolesCollection(txApp core.App) error {
	col := core.NewBaseCollection(core.CollectionNameRoles)
	col.System = true

	col.Fields.Add(&core.TextField{
		Name:     "name",
		System:   true,
		Required: true,
		Max:      100,
	})
	col.Fields.Add(&core.TextField{
		Name:   "description",
		System: true,
		Max:    1000,
	})
	col.Fields.Add(&core.JSONField{
		Name:   "permissions",
		System: true,
	})
	col.Fields.Add(&core.BoolField{
		Name:   "system",
		System: true,
	})
	col.Fields.Add(&core.AutodateField{
		Name:     "created",
		System:   true,
		OnCreate: true,
	})
	col.Fields.Add(&core.AutodateField{
		Name:     "updated",
		System:   true,
		OnCreate: true,
		OnUpdate: true,
	})

	col.AddIndex("idx_roles_name", true, "name", "")

	return txApp.Save(col)
}

func createRoleAssignmentsCollection(txApp core.App) error {
	col := core.NewBaseCollection(core.CollectionNameRoleAssignments)
	col.System = true

	col.Fields.Add(&core.TextField{
		Name:     "collectionRef",
		System:   true,
		Required: true,
	})
	col.Fields.Add(&core.TextField{
		Name:     "recordRef",
		System:   true,
		Required: true,
	})
	col.Fields.Add(&core.TextField{
		Name:     "role",
		System:   true,
		Required: true,
	})
	col.Fields.Add(&core.AutodateField{
		Name:     "created",
		System:   true,
		OnCreate: true,
	})
	col.Fields.Add(&core.AutodateField{
		Name:     "updated",
		System:   true,
		OnCreate: true,
		OnUpdate: true,
	})

	col.AddIndex("idx_roleAssignments_unique", true, "collectionRef,recordRef,role", "")
	col.AddIndex("idx_roleAssignments_role", false, "role", "")

	return txApp.Save(col)
}
