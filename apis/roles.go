package apis

import (
	"net/http"
	"slices"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/router"
)

// bindRolesApi registers the RBAC roles api endpoints.
//
// The roles CRUD is handled by the records API of the _roles system collection.
//
// The actor checks (no escalation, Owner assignable only by an Owner and no
// self-assignment, see [core.CheckRoleChange] and [core.CheckRoleAssignmentChange])
// are applied by the assignments endpoint and by the records API request hooks
// (see bindRecordAccessHooks), while the model invariants (e.g. the last Owner) are enforced in core.
func bindRolesApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	read := RequirePermission(core.PermissionResourceRoles, core.PermissionLevelRead)
	write := RequirePermission(core.PermissionResourceRoles, core.PermissionLevelWrite)

	sub := rg.Group("/roles")
	sub.GET("", rolesList).Bind(read)
	sub.GET("/assignments", roleAssignmentsView).Bind(read)
	sub.PUT("/assignments", roleAssignmentsSet).Bind(write)

}

type roleResponse struct {
	Id          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Permissions core.Permissions `json:"permissions"`
	System      bool             `json:"system"`
	Owner       bool             `json:"owner"`
	Created     string           `json:"created"`
	Updated     string           `json:"updated"`
}

func newRoleResponse(role *core.Role) roleResponse {
	return roleResponse{
		Id:          role.Id,
		Name:        role.Name(),
		Description: role.Description(),
		Permissions: role.Permissions(),
		System:      role.System(),
		Owner:       role.IsOwner(),
		Created:     role.Created().String(),
		Updated:     role.Updated().String(),
	}
}

type rolesListResponse struct {
	Items     []roleResponse            `json:"items"`
	Resources []core.PermissionResource `json:"resources"`
	Actions   []string                  `json:"actions"`
}

// GET /api/roles
func rolesList(e *core.RequestEvent) error {
	roles, err := e.App.FindAllRoles()
	if err != nil {
		return e.InternalServerError("Failed to load the roles.", err)
	}

	result := rolesListResponse{
		Items:     make([]roleResponse, len(roles)),
		Resources: core.PermissionResources,
		Actions:   core.PermissionCollectionActions,
	}

	for i, r := range roles {
		result.Items[i] = newRoleResponse(r)
	}

	return e.JSON(http.StatusOK, result)
}

type roleAssignmentsResponse struct {
	CollectionId string   `json:"collectionId"`
	RecordId     string   `json:"recordId"`
	Explicit     bool     `json:"explicit"`
	Roles        []string `json:"roles"`
	Effective    []string `json:"effective"`
	Owner        bool     `json:"owner"`

	// Permissions is the union of the effective roles permissions
	Permissions core.Permissions `json:"permissions"`
}

func loadAssignmentsTarget(e *core.RequestEvent, collectionIdOrName string, recordId string) (*core.Record, error) {
	collection, err := e.App.FindCachedCollectionByNameOrId(collectionIdOrName)
	if err != nil || !collection.IsAuth() {
		return nil, e.NotFoundError("Missing or invalid auth collection.", err)
	}

	record, err := e.App.FindRecordById(collection, recordId)
	if err != nil {
		return nil, e.NotFoundError("Missing or invalid auth record.", err)
	}

	return record, nil
}

func newRoleAssignmentsResponse(e *core.RequestEvent, record *core.Record) (*roleAssignmentsResponse, error) {
	assignments, err := e.App.FindAllRoleAssignmentsByRecord(record)
	if err != nil {
		return nil, err
	}

	effective, err := e.App.FindRecordRoles(record)
	if err != nil {
		return nil, err
	}

	result := &roleAssignmentsResponse{
		CollectionId: record.Collection().Id,
		RecordId:     record.Id,
		Explicit:     len(assignments) > 0,
		Roles:        make([]string, 0, len(assignments)),
		Effective:    make([]string, 0, len(effective)),
		Permissions:  core.Permissions{Collections: map[string][]string{}, System: map[string]string{}},
	}

	for _, a := range assignments {
		result.Roles = append(result.Roles, a.Role())
	}

	for _, r := range effective {
		result.Effective = append(result.Effective, r.Id)
		if r.IsOwner() {
			result.Owner = true
			continue
		}
		result.Permissions.Merge(r.Permissions())
	}

	return result, nil
}

// GET /api/roles/assignments?collection=...&record=...
func roleAssignmentsView(e *core.RequestEvent) error {
	query := e.Request.URL.Query()

	record, err := loadAssignmentsTarget(e, query.Get("collection"), query.Get("record"))
	if err != nil {
		return err
	}

	result, err := newRoleAssignmentsResponse(e, record)
	if err != nil {
		return e.InternalServerError("Failed to load the role assignments.", err)
	}

	return e.JSON(http.StatusOK, result)
}

type roleAssignmentsForm struct {
	Collection string   `json:"collection"`
	Record     string   `json:"record"`
	Roles      []string `json:"roles"`
}

// PUT /api/roles/assignments
//
// Replaces the explicit role assignments of the specified auth record
// (an empty list means that the collection DefaultRoles apply).
func roleAssignmentsSet(e *core.RequestEvent) error {
	form := &roleAssignmentsForm{}
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	record, err := loadAssignmentsTarget(e, form.Collection, form.Record)
	if err != nil {
		return err
	}

	newRoles := list.ToUniqueStringSlice(form.Roles)

	actorInfo := e.ActorInfo()

	var forbiddenErr error

	txErr := e.App.RunInTransaction(func(txApp core.App) error {
		existing, err := txApp.FindAllRoleAssignmentsByRecord(record)
		if err != nil {
			return err
		}

		existingRoles := make([]string, 0, len(existing))

		// add the new ones first so that the last Owner check passes on replacement
		for _, a := range existing {
			existingRoles = append(existingRoles, a.Role())
		}

		for _, roleId := range newRoles {
			if slices.Contains(existingRoles, roleId) {
				continue
			}

			ra := core.NewRoleAssignment(txApp)
			ra.SetCollectionRef(record.Collection().Id)
			ra.SetRecordRef(record.Id)
			ra.SetRole(roleId)

			if err := core.CheckRoleAssignmentChange(txApp, actorInfo, ra.Record); err != nil {
				forbiddenErr = err
				return err
			}

			if err := txApp.Save(ra); err != nil {
				return err
			}
		}

		for _, a := range existing {
			if slices.Contains(newRoles, a.Role()) {
				continue
			}

			if err := core.CheckRoleAssignmentChange(txApp, actorInfo, a.Record); err != nil {
				forbiddenErr = err
				return err
			}

			if err := txApp.Delete(a); err != nil {
				return err
			}
		}

		return nil
	})
	if txErr != nil {
		if forbiddenErr != nil {
			return e.ForbiddenError("You are not allowed to perform this role assignment change.", forbiddenErr)
		}
		return firstApiError(txErr, e.BadRequestError("Failed to save the role assignments.", txErr))
	}

	result, err := newRoleAssignmentsResponse(e, record)
	if err != nil {
		return e.InternalServerError("Failed to load the role assignments.", err)
	}

	return e.JSON(http.StatusOK, result)
}
