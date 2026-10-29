package core

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"

	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

const (
	CollectionNameRoles           = "_roles"
	CollectionNameRoleAssignments = "_roleAssignments"
)

// Built-in roles names.
const (
	// RoleNameOwner is the name of the built-in system Owner role
	// (it bypasses everything, aka. the superuser access before R1).
	RoleNameOwner = "Owner"

	// RoleNameCustomer is the name of the built-in (editable) Customer role
	// (the default role of the non-superusers auth collections).
	RoleNameCustomer = "Customer"
)

// Built-in roles ids (deterministic so that the collections DefaultRoles
// in the generated migrations and exports are portable between installations).
const (
	RoleIdOwner    = "pbroleowner0000"
	RoleIdCustomer = "pbrolecustomer0"
)

var (
	_ Model        = (*Role)(nil)
	_ PreValidator = (*Role)(nil)
	_ RecordProxy  = (*Role)(nil)

	_ Model        = (*RoleAssignment)(nil)
	_ PreValidator = (*RoleAssignment)(nil)
	_ RecordProxy  = (*RoleAssignment)(nil)
)

// Role defines a Record proxy for working with the RBAC roles collection.
type Role struct {
	*Record
}

// NewRole instantiates and returns a new blank *Role model.
//
// Example usage:
//
//	role := core.NewRole(app)
//	role.SetName("Editor")
//	role.SetPermissions(core.Permissions{Collections: map[string][]string{"*": {"list", "view"}}})
//	app.Save(role)
func NewRole(app App) *Role {
	m := &Role{}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameRoles)
	if err != nil {
		// this is just to make tests easier since it is a system collection and it is expected to be always accessible
		// (note: the loaded record is further checked on Role.PreValidate())
		c = NewBaseCollection("@__invalid__")
	}

	m.Record = NewRecord(c)

	return m
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *Role) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameRoles {
		return errors.New("missing or invalid role ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *Role) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *Role) SetProxyRecord(record *Record) {
	m.Record = record
}

// Name returns the "name" record field value.
func (m *Role) Name() string {
	return m.GetString("name")
}

// SetName updates the "name" record field value.
func (m *Role) SetName(name string) {
	m.Set("name", name)
}

// Description returns the "description" record field value.
func (m *Role) Description() string {
	return m.GetString("description")
}

// SetDescription updates the "description" record field value.
func (m *Role) SetDescription(description string) {
	m.Set("description", description)
}

// System reports whether the role is a built-in system role (not editable or deletable).
func (m *Role) System() bool {
	return m.GetBool("system")
}

// SetSystem updates the "system" record field value.
func (m *Role) SetSystem(system bool) {
	m.Set("system", system)
}

// IsOwner reports whether the role is the built-in system Owner role.
func (m *Role) IsOwner() bool {
	return isOwnerRoleRecord(m.Record)
}

func isOwnerRoleRecord(record *Record) bool {
	return record != nil && record.GetBool("system") && record.GetString("name") == RoleNameOwner
}

// Permissions returns the normalized "permissions" record field value.
func (m *Role) Permissions() Permissions {
	return parseRolePermissions(m.Get("permissions"))
}

// SetPermissions updates the "permissions" record field value.
func (m *Role) SetPermissions(permissions Permissions) {
	permissions = permissions.Clone()
	permissions.Normalize()
	m.Set("permissions", permissions)
}

// Created returns the "created" record field value.
func (m *Role) Created() types.DateTime {
	return m.GetDateTime("created")
}

// Updated returns the "updated" record field value.
func (m *Role) Updated() types.DateTime {
	return m.GetDateTime("updated")
}

// parseRolePermissions normalizes the raw "permissions" field value.
func parseRolePermissions(raw any) Permissions {
	result := Permissions{}

	var data []byte
	switch v := raw.(type) {
	case Permissions:
		result = v.Clone()
	case *Permissions:
		if v != nil {
			result = v.Clone()
		}
	case types.JSONRaw:
		data = v
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		data, _ = json.Marshal(v)
	}

	if len(data) > 0 {
		_ = json.Unmarshal(data, &result)
	}

	result.Normalize()

	return result
}

// -------------------------------------------------------------------

// RoleAssignment defines a Record proxy for working with the RBAC role assignments collection.
type RoleAssignment struct {
	*Record
}

// NewRoleAssignment instantiates and returns a new blank *RoleAssignment model.
//
// Example usage:
//
//	ra := core.NewRoleAssignment(app)
//	ra.SetCollectionRef(user.Collection().Id)
//	ra.SetRecordRef(user.Id)
//	ra.SetRole(role.Id)
//	app.Save(ra)
func NewRoleAssignment(app App) *RoleAssignment {
	m := &RoleAssignment{}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameRoleAssignments)
	if err != nil {
		// this is just to make tests easier since it is a system collection and it is expected to be always accessible
		// (note: the loaded record is further checked on RoleAssignment.PreValidate())
		c = NewBaseCollection("@__invalid__")
	}

	m.Record = NewRecord(c)

	return m
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *RoleAssignment) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameRoleAssignments {
		return errors.New("missing or invalid role assignment ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *RoleAssignment) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *RoleAssignment) SetProxyRecord(record *Record) {
	m.Record = record
}

// CollectionRef returns the "collectionRef" record field value.
func (m *RoleAssignment) CollectionRef() string {
	return m.GetString("collectionRef")
}

// SetCollectionRef updates the "collectionRef" record field value.
func (m *RoleAssignment) SetCollectionRef(collectionId string) {
	m.Set("collectionRef", collectionId)
}

// RecordRef returns the "recordRef" record field value.
func (m *RoleAssignment) RecordRef() string {
	return m.GetString("recordRef")
}

// SetRecordRef updates the "recordRef" record field value.
func (m *RoleAssignment) SetRecordRef(recordId string) {
	m.Set("recordRef", recordId)
}

// Role returns the "role" record field value (aka. the related role id).
func (m *RoleAssignment) Role() string {
	return m.GetString("role")
}

// SetRole updates the "role" record field value.
func (m *RoleAssignment) SetRole(roleId string) {
	m.Set("role", roleId)
}

// -------------------------------------------------------------------
// Model level invariants
// -------------------------------------------------------------------

var errLastOwner = validation.NewError("validation_last_owner", "At least one Owner must always exist.")

func (app *BaseApp) registerRoleHooks() {
	recordRefHooks[*RoleAssignment](app, CollectionNameRoleAssignments, CollectionTypeAuth)

	// roles validation
	app.OnRecordValidate(CollectionNameRoles).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			original := e.Record.Original()

			if !e.Record.IsNew() && original.GetBool("system") {
				if e.Record.GetString("name") != original.GetString("name") ||
					!e.Record.GetBool("system") ||
					!parseRolePermissions(e.Record.Get("permissions")).Covers(parseRolePermissions(original.Get("permissions"))) ||
					!parseRolePermissions(original.Get("permissions")).Covers(parseRolePermissions(e.Record.Get("permissions"))) {
					return validation.Errors{"system": validation.NewError("validation_system_role", "The system roles cannot be changed.")}
				}
			}

			if !e.Record.IsNew() && !original.GetBool("system") && e.Record.GetBool("system") {
				return validation.Errors{"system": validation.NewError("validation_system_role", "A regular role cannot become a system role.")}
			}

			// note: the Owner role permissions are ignored (it bypasses everything)
			if isOwnerRoleRecord(e.Record) {
				return e.Next()
			}

			if err := parseRolePermissions(e.Record.Get("permissions")).Validate(e.App); err != nil {
				return validation.Errors{"permissions": err}
			}

			return e.Next()
		},
		Priority: 99,
	})

	// system roles cannot be deleted
	app.OnRecordDelete(CollectionNameRoles).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if e.Record.GetBool("system") {
				return errors.New("the system roles cannot be deleted")
			}

			return e.Next()
		},
		Priority: -99,
	})

	// assignments validation
	app.OnRecordValidate(CollectionNameRoleAssignments).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			roleId := e.Record.GetString("role")

			role, err := e.App.FindRoleById(roleId)
			if err != nil {
				return validation.Errors{"role": validation.NewError("validation_missing_role", "Missing or invalid role.")}
			}

			superusers, _ := e.App.FindCachedCollectionByNameOrId(CollectionNameSuperusers)

			if role.IsOwner() && (superusers == nil || e.Record.GetString("collectionRef") != superusers.Id) {
				return validation.Errors{"role": validation.NewError("validation_owner_staff_only", "The Owner role could be assigned only to superusers.")}
			}

			// last Owner on role change
			if !e.Record.IsNew() && e.Record.Original().GetString("role") != roleId {
				if err := checkNotLastOwnerAssignment(e.App, e.Record.Original()); err != nil {
					return validation.Errors{"role": err}
				}
			}

			return e.Next()
		},
		Priority: 99,
	})

	// at least one Owner must always exist
	app.OnRecordDelete(CollectionNameRoleAssignments).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if err := checkNotLastOwnerAssignment(e.App, e.Record); err != nil {
				return err
			}

			return e.Next()
		},
		Priority: -99,
	})

	// recheck the last Owner invariant after the write and in the same transaction
	// (the checks above are not atomic and two concurrent deletes/changes of the
	// last two Owner assignments could otherwise both pass)
	ensureOwnerExists := &hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			originalApp := e.App
			defer func() {
				e.App = originalApp
			}()

			return e.App.RunInTransaction(func(txApp App) error {
				e.App = txApp

				if err := e.Next(); err != nil {
					return err
				}

				role, err := txApp.FindRoleById(e.Record.Original().GetString("role"))
				if err != nil || !role.IsOwner() {
					return nil // not an Owner assignment change
				}

				total, err := txApp.CountOwners()
				if err != nil {
					return err
				}
				if total < 1 {
					return errLastOwner
				}

				return nil
			})
		},
		Priority: 99,
	}
	app.OnRecordDeleteExecute(CollectionNameRoleAssignments).Bind(ensureOwnerExists)
	app.OnRecordUpdateExecute(CollectionNameRoleAssignments).Bind(ensureOwnerExists)

	// the _superusers collection must not have default roles and
	// the default roles of the other auth collections must exist
	app.OnCollectionValidate().Bind(&hook.Handler[*CollectionEvent]{
		Func: func(e *CollectionEvent) error {
			if !e.Collection.IsAuth() {
				return e.Next()
			}

			if e.Collection.Name == CollectionNameSuperusers && len(e.Collection.DefaultRoles) > 0 {
				return validation.Errors{"defaultRoles": validation.NewError(
					"validation_superusers_default_roles",
					"The "+CollectionNameSuperusers+" collection cannot have default roles.",
				)}
			}

			if len(e.Collection.DefaultRoles) > 0 {
				roles, err := e.App.FindRolesByIds(e.Collection.DefaultRoles)
				if err != nil || len(roles) != len(list.ToUniqueStringSlice(e.Collection.DefaultRoles)) {
					return validation.Errors{"defaultRoles": validation.NewError("validation_invalid_default_roles", "Missing or invalid default role(s).")}
				}

				for _, r := range roles {
					if r.IsOwner() {
						return validation.Errors{"defaultRoles": validation.NewError("validation_owner_default_role", "The Owner role cannot be a default role.")}
					}
				}
			}

			return e.Next()
		},
		Priority: 99,
	})

	// the new auth collections use the built-in Customer role as default
	// (unless their DefaultRoles are explicitly set)
	app.OnCollectionCreate().Bind(&hook.Handler[*CollectionEvent]{
		Func: func(e *CollectionEvent) error {
			if e.Collection.IsAuth() && e.Collection.DefaultRoles == nil && e.Collection.Name != CollectionNameSuperusers {
				if customer, err := e.App.FindRoleByName(RoleNameCustomer); err == nil {
					e.Collection.DefaultRoles = []string{customer.Id}
				}
			}

			return e.Next()
		},
		Priority: -99,
	})

	// remove the deleted role from the collections DefaultRoles
	app.OnRecordAfterDeleteSuccess(CollectionNameRoles).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			collections, err := e.App.FindAllCollections(CollectionTypeAuth)
			if err != nil {
				return err
			}

			for _, c := range collections {
				if !slices.Contains(c.DefaultRoles, e.Record.Id) {
					continue
				}

				c.DefaultRoles = slices.DeleteFunc(slices.Clone(c.DefaultRoles), func(id string) bool {
					return id == e.Record.Id
				})

				if err := e.App.Save(c); err != nil {
					e.App.Logger().Warn("Failed to remove the deleted role from the collection default roles", "collection", c.Name, "error", err)
				}
			}

			return e.Next()
		},
	})

	// the role assignments of a deleted role
	app.OnRecordDeleteExecute(CollectionNameRoles).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			originalApp := e.App
			txErr := e.App.RunInTransaction(func(txApp App) error {
				e.App = txApp

				if err := e.Next(); err != nil {
					return err
				}

				assignments, err := txApp.FindAllRecords(CollectionNameRoleAssignments, dbx.HashExp{"role": e.Record.Id})
				if err != nil {
					return err
				}

				for _, a := range assignments {
					if err := txApp.Delete(a); err != nil {
						return err
					}
				}

				return nil
			})
			e.App = originalApp

			return txErr
		},
		Priority: 99,
	})
}

func checkNotLastOwnerAssignment(app App, assignment *Record) error {
	role, err := app.FindRoleById(assignment.GetString("role"))
	if err != nil || !role.IsOwner() {
		return nil
	}

	total, err := app.CountOwners()
	if err != nil {
		return err
	}

	if total <= 1 {
		return errLastOwner
	}

	return nil
}
