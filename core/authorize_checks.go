package core

import (
	"errors"
	"fmt"
	"slices"
)

// actorCovers reports whether the actor holds every permission of the provided set.
func actorCovers(app App, info *RequestInfo, permissions Permissions) bool {
	perms := info.Permissions(app)

	if perms.Owner {
		return true
	}

	if !perms.IsStaff() || perms.ThirdParty {
		return false
	}

	return perms.Permissions.Covers(permissions)
}

// CheckRoleChange checks whether the request actor is allowed to create, update or delete the provided role
// (the actor must hold every permission of the old and the new role permissions; the system roles cannot be changed).
//
// A nil info is treated as a trusted programmatic change.
func CheckRoleChange(app App, info *RequestInfo, role *Record, deleting bool) error {
	if info == nil {
		return nil
	}

	if !info.Can(app, PermissionResourceRoles, PermissionLevelWrite) {
		return errPermissionDenied
	}

	if role.GetBool("system") || (!role.IsNew() && role.Original().GetBool("system")) {
		return errPermissionDenied
	}

	if !actorCovers(app, info, parseRolePermissions(role.Get("permissions"))) {
		return errPermissionDenied
	}

	if !role.IsNew() && !actorCovers(app, info, parseRolePermissions(role.Original().Get("permissions"))) {
		return errPermissionDenied
	}

	return nil
}

// CheckRoleAssignmentChange checks whether the request actor is allowed to create or delete
// the provided role assignment:
//   - an actor cannot change its own assignments
//   - the Owner role could be assigned/unassigned only by an Owner
//   - the actor must hold every permission of the assigned/unassigned role
//
// A nil info is treated as a trusted programmatic change.
func CheckRoleAssignmentChange(app App, info *RequestInfo, assignment *Record) error {
	if info == nil {
		return nil
	}

	if !info.Can(app, PermissionResourceRoles, PermissionLevelWrite) {
		return errPermissionDenied
	}

	check := func(collectionRef, recordRef, roleId string) error {
		if info.Auth != nil && info.Auth.Collection().Id == collectionRef && info.Auth.Id == recordRef {
			return errSelfAssignment
		}

		role, err := app.FindRoleById(roleId)
		if err != nil {
			return nil // validated by the model
		}

		if role.IsOwner() {
			if !info.IsOwner(app) {
				return errPermissionDenied
			}
			return nil
		}

		if !actorCovers(app, info, role.Permissions()) {
			return errPermissionDenied
		}

		return nil
	}

	if err := check(assignment.GetString("collectionRef"), assignment.GetString("recordRef"), assignment.GetString("role")); err != nil {
		return err
	}

	if !assignment.IsNew() {
		original := assignment.Original()
		if err := check(original.GetString("collectionRef"), original.GetString("recordRef"), original.GetString("role")); err != nil {
			return err
		}
	}

	return nil
}

// CheckStaffRecordChange checks whether the request actor is allowed to update or delete
// the provided staff (_superusers) record: a non-Owner actor cannot change an Owner
// or a staff member with permissions that the actor doesn't hold (no escalation by account takeover).
//
// The actor's own record is always allowed (e.g. password change).
//
// A nil info is treated as a trusted programmatic change.
func CheckStaffRecordChange(app App, info *RequestInfo, staff *Record) error {
	if info == nil || staff.IsNew() || !staff.IsSuperuser() {
		return nil
	}

	if info.Auth != nil && info.Auth.Id == staff.Id && info.Auth.IsSuperuser() {
		return nil
	}

	if info.IsOwner(app) {
		return nil
	}

	if app.IsOwnerRecord(staff) {
		return errPermissionDenied
	}

	roles, err := app.FindRecordRoles(staff)
	if err != nil {
		return err
	}

	for _, r := range roles {
		if !actorCovers(app, info, r.Permissions()) {
			return errPermissionDenied
		}
	}

	return nil
}

// CheckImpersonation checks whether the request actor is allowed to impersonate the provided auth record
// (impersonate permission and, for staff subjects, the no-escalation checks of [CheckStaffRecordChange]).
func CheckImpersonation(app App, info *RequestInfo, subject *Record) error {
	if !info.Can(app, PermissionResourceImpersonate, PermissionLevelWrite) {
		return errPermissionDenied
	}

	if subject.IsSuperuser() {
		if info.Auth != nil && info.Auth.Id == subject.Id {
			return nil
		}
		if info.IsOwner(app) {
			return nil
		}
		if app.IsOwnerRecord(subject) {
			return errPermissionDenied
		}
		return CheckStaffRecordChange(app, info, subject)
	}

	return nil
}

var errSelfAssignment = errors.New("an actor cannot change its own role assignments")

// FilterCollectionsByAccess returns the collections that the request actor could see in the dashboard
// (all for collections read, otherwise the regular collections with at least one permission).
func FilterCollectionsByAccess(app App, info *RequestInfo, collections []*Collection) []*Collection {
	if info.Can(app, PermissionResourceCollections, PermissionLevelRead) {
		return collections
	}

	result := make([]*Collection, 0, len(collections))
	for _, c := range collections {
		if c.System {
			resource, mapped := SystemCollectionPermissionResource(c.Name)
			if mapped && info.Can(app, resource, PermissionLevelRead) {
				result = append(result, c)
			}
			continue
		}

		if slices.ContainsFunc(PermissionCollectionActions, func(action string) bool {
			return info.CollectionAccess(app, c, action).BypassRules
		}) {
			result = append(result, c)
		}
	}

	return result
}

// ClientFilterJoinCheck returns a [RecordFieldResolver.SetJoinCollectionCheck] function
// that allows the client-side filter/sort joins only into the collections that
// the request actor could list (system collections: only with rules bypass, e.g. Owners).
func ClientFilterJoinCheck(app App, info *RequestInfo) func(c *Collection) error {
	return func(c *Collection) error {
		access := info.CollectionAccess(app, c, PermissionActionList)

		if c.System {
			if !access.BypassRules {
				return fmt.Errorf("the client filter cannot reference the %q system collection", c.Name)
			}
			return nil
		}

		if !access.Allowed {
			return fmt.Errorf("the client filter cannot reference the %q collection", c.Name)
		}

		return nil
	}
}

// CheckApplicationInstallationChange checks whether the request actor is allowed to install,
// change (grant/version), rotate the secret of or uninstall the provided installation:
//   - the actor must have the applications write permission
//   - the actor must hold every permission of the new grant and (for existing installations)
//     of the original grant (nobody grants what they don't have; rotating the secret or
//     uninstalling hands over/removes the whole grant)
//
// A nil info is treated as a trusted programmatic change.
func CheckApplicationInstallationChange(app App, info *RequestInfo, installation *Record) error {
	if info == nil {
		return nil
	}

	if !info.Can(app, PermissionResourceApplications, PermissionLevelWrite) {
		return errPermissionDenied
	}

	if !actorCovers(app, info, parseRolePermissions(installation.Get("permissions"))) {
		return errPermissionDenied
	}

	if !installation.IsNew() && !actorCovers(app, info, parseRolePermissions(installation.Original().Get("permissions"))) {
		return errPermissionDenied
	}

	return nil
}
