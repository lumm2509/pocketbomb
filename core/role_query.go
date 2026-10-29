package core

import (
	"errors"
	"fmt"

	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/pocketbase/dbx"
)

// FindRoleById returns the role with the specified id.
func (app *BaseApp) FindRoleById(id string) (*Role, error) {
	result := &Role{}

	err := app.RecordQuery(CollectionNameRoles).
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindRoleByName returns the role with the specified name.
func (app *BaseApp) FindRoleByName(name string) (*Role, error) {
	result := &Role{}

	err := app.RecordQuery(CollectionNameRoles).
		AndWhere(dbx.HashExp{"name": name}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindOwnerRole returns the built-in system Owner role.
func (app *BaseApp) FindOwnerRole() (*Role, error) {
	result := &Role{}

	err := app.RecordQuery(CollectionNameRoles).
		AndWhere(dbx.HashExp{"name": RoleNameOwner, "system": true}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindAllRoles returns all roles ordered by name (the system roles first).
func (app *BaseApp) FindAllRoles() ([]*Role, error) {
	result := []*Role{}

	err := app.RecordQuery(CollectionNameRoles).
		OrderBy("system DESC", "name ASC").
		All(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindRolesByIds returns the roles with the specified ids (the missing ones are ignored).
func (app *BaseApp) FindRolesByIds(ids []string) ([]*Role, error) {
	result := []*Role{}

	ids = list.ToUniqueStringSlice(ids)
	if len(ids) == 0 {
		return result, nil
	}

	err := app.RecordQuery(CollectionNameRoles).
		AndWhere(dbx.In("id", list.ToInterfaceSlice(ids)...)).
		OrderBy("system DESC", "name ASC").
		All(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindAllRoleAssignmentsByRecord returns the explicit role assignments of the provided auth record.
func (app *BaseApp) FindAllRoleAssignmentsByRecord(authRecord *Record) ([]*RoleAssignment, error) {
	result := []*RoleAssignment{}

	err := app.RecordQuery(CollectionNameRoleAssignments).
		AndWhere(dbx.HashExp{
			"collectionRef": authRecord.Collection().Id,
			"recordRef":     authRecord.Id,
		}).
		OrderBy("created ASC").
		All(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindRecordRoles returns the effective roles of the provided auth record:
// its explicit role assignments or, if there are none, the collection DefaultRoles
// (the _superusers collection has no default roles).
func (app *BaseApp) FindRecordRoles(authRecord *Record) ([]*Role, error) {
	if authRecord == nil || !authRecord.Collection().IsAuth() {
		return []*Role{}, nil
	}

	assignments, err := app.FindAllRoleAssignmentsByRecord(authRecord)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(assignments))
	for _, a := range assignments {
		ids = append(ids, a.Role())
	}

	if len(ids) == 0 && !authRecord.IsSuperuser() {
		ids = authRecord.Collection().DefaultRoles
	}

	return app.FindRolesByIds(ids)
}

// CountOwners returns the total number of Owner role assignments.
func (app *BaseApp) CountOwners() (int, error) {
	owner, err := app.FindOwnerRole()
	if err != nil {
		return 0, err
	}

	var total int

	err = app.RecordQuery(CollectionNameRoleAssignments).
		Select("count(*)").
		AndWhere(dbx.HashExp{"role": owner.Id}).
		Row(&total)

	return total, err
}

// IsOwnerRecord reports whether the provided auth record has an explicit Owner role assignment.
func (app *BaseApp) IsOwnerRecord(authRecord *Record) bool {
	if authRecord == nil || !authRecord.IsSuperuser() {
		return false
	}

	owner, err := app.FindOwnerRole()
	if err != nil {
		return false
	}

	var exists int

	err = app.RecordQuery(CollectionNameRoleAssignments).
		Select("(1)").
		AndWhere(dbx.HashExp{
			"collectionRef": authRecord.Collection().Id,
			"recordRef":     authRecord.Id,
			"role":          owner.Id,
		}).
		Limit(1).
		Row(&exists)

	return err == nil && exists > 0
}

// AssignOwnerRole assigns the built-in Owner role to the provided superuser (if not already).
//
// It is a trusted programmatic helper (e.g. used by the installer and the superuser CLI commands)
// and it doesn't perform the actor checks of [CheckRoleAssignmentsChange].
func (app *BaseApp) AssignOwnerRole(superuser *Record) error {
	if superuser == nil || !superuser.IsSuperuser() {
		return errors.New("the Owner role could be assigned only to superusers")
	}

	if app.IsOwnerRecord(superuser) {
		return nil
	}

	owner, err := app.FindOwnerRole()
	if err != nil {
		return fmt.Errorf("missing Owner role: %w", err)
	}

	ra := NewRoleAssignment(app)
	ra.SetCollectionRef(superuser.Collection().Id)
	ra.SetRecordRef(superuser.Id)
	ra.SetRole(owner.Id)

	return app.Save(ra)
}
