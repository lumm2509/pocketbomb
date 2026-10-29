package tests

import (
	"github.com/lumm2509/pocketbomb/core"
)

// CreateRole creates and persists a new RBAC role with the provided permissions.
func CreateRole(app core.App, name string, permissions core.Permissions) (*core.Role, error) {
	role := core.NewRole(app)
	role.SetName(name)
	role.SetPermissions(permissions)

	if err := app.Save(role); err != nil {
		return nil, err
	}

	return role, nil
}

// AssignRoles creates explicit role assignments for the provided auth record.
func AssignRoles(app core.App, record *core.Record, roleIds ...string) error {
	for _, id := range roleIds {
		ra := core.NewRoleAssignment(app)
		ra.SetCollectionRef(record.Collection().Id)
		ra.SetRecordRef(record.Id)
		ra.SetRole(id)

		if err := app.Save(ra); err != nil {
			return err
		}
	}

	return nil
}

// CreateStaff creates and persists a new _superusers record (password "1234567890")
// with explicit assignments of the provided role ids (no roles = staff without permissions).
func CreateStaff(app core.App, email string, roleIds ...string) (*core.Record, error) {
	collection, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		return nil, err
	}

	staff := core.NewRecord(collection)
	staff.SetEmail(email)
	staff.SetPassword("1234567890")

	if err := app.Save(staff); err != nil {
		return nil, err
	}

	if err := AssignRoles(app, staff, roleIds...); err != nil {
		return nil, err
	}

	return staff, nil
}
