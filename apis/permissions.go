package apis

import (
	"errors"
	"net/http"
	"slices"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/router"
)

// bindPermissionsApi registers the RBAC permissions api endpoints.
func bindPermissionsApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	rg.GET("/permissions/me", permissionsMe).Bind(RequireAuth())
}

// permissionsRegistry is the RBAC registry vocabulary (see core/permissions.go).
type permissionsRegistry struct {
	Resources []core.PermissionResource `json:"resources"`
	Actions   []string                  `json:"actions"`

	// SystemCollections maps the system collection names to their system resource.
	SystemCollections map[string]string `json:"systemCollections"`
}

type permissionsMeResponse struct {
	*core.ActorPermissions

	// Collections is the list of the collection ids (incl. system collections)
	// that the actor could see in the dashboard.
	Collections []string `json:"collections"`

	// Record is the enriched actor auth record (public export + email, never the secret fields).
	//
	// For the third-party tokens it is returned only with the "openid"+"profile"
	// or "email" scopes (and the email only with the "email" scope).
	Record *core.Record `json:"record,omitempty"`

	// Application is the installed application of the application actors and of the
	// application extensions online tokens (onBehalfOf; no secrets).
	Application *permissionsMeApplication `json:"application,omitempty"`

	// Registry is the RBAC registry vocabulary (e.g. for the permission-aware dashboard).
	Registry permissionsRegistry `json:"registry"`
}

type permissionsMeApplication struct {
	Id             string `json:"id"`
	Handle         string `json:"handle"`
	Name           string `json:"name"`
	InstallationId string `json:"installationId"`
	VersionId      string `json:"versionId"`
	Version        string `json:"version"`
	ClientId       string `json:"clientId"`
}

// GET /api/permissions/me
//
// Returns the RBAC permissions of the current actor (e.g. for the permission-aware dashboard).
func permissionsMe(e *core.RequestEvent) error {
	info, err := e.RequestInfo()
	if err != nil {
		return e.BadRequestError("", err)
	}

	perms := info.Permissions(e.App)
	if perms == nil {
		return e.InternalServerError("", errors.New("failed to resolve the actor permissions"))
	}

	result := permissionsMeResponse{
		ActorPermissions: perms,
		Collections:      []string{},
		Registry: permissionsRegistry{
			Resources:         core.PermissionResources,
			Actions:           core.PermissionCollectionActions,
			SystemCollections: core.SystemCollectionPermissionResources(),
		},
	}

	if perms.IsStaff() || perms.IsApplication() {
		collections, err := e.App.FindAllCollections()
		if err != nil {
			return e.InternalServerError("", err)
		}

		for _, c := range core.FilterCollectionsByAccess(e.App, info, collections) {
			result.Collections = append(result.Collections, c.Id)
		}
	}

	record, err := permissionsMeRecord(e, info, perms)
	if err != nil {
		return e.InternalServerError("Failed to load the actor record.", err)
	}
	result.Record = record

	if perms.IsApplication() {
		result.Application, err = newPermissionsMeApplication(e, info, &core.ApplicationInstallation{Record: info.Auth})
		if err != nil {
			return e.InternalServerError("Failed to load the actor application.", err)
		}
	} else if perms.IsOnBehalfOfApplication() {
		installation, err := e.App.FindApplicationInstallationById(perms.OnBehalfOf.InstallationId)
		if err != nil {
			return e.InternalServerError("Failed to load the application installation.", err)
		}

		result.Application, err = newPermissionsMeApplication(e, info, installation)
		if err != nil {
			return e.InternalServerError("Failed to load the actor application.", err)
		}
	}

	return e.JSON(http.StatusOK, result)
}

// permissionsMeRecord returns the enriched actor own record (or nil if the
// third-party token scopes don't allow it).
//
// Note that no collection view permission is required (it is the actor itself)
// but the secret fields (tokenKey, passwords, etc.) are never exported, not even for the Owners.
func permissionsMeRecord(e *core.RequestEvent, info *core.RequestInfo, perms *core.ActorPermissions) (*core.Record, error) {
	if info.Auth == nil {
		return nil, nil
	}

	withEmail := true
	if perms.ThirdParty {
		scopes := info.OAuth2.Scopes
		withEmail = slices.Contains(scopes, core.OAuth2ScopeEmail)
		withProfile := slices.Contains(scopes, core.OAuth2ScopeOpenId) && slices.Contains(scopes, core.OAuth2ScopeProfile)
		if !withEmail && !withProfile {
			return nil, nil
		}
	}

	// a copy so that the request auth record flags are not changed
	record := info.Auth.Fresh()

	if err := EnrichRecord(e, record); err != nil {
		return nil, err
	}

	record.Hide(core.SecretFieldNames(record.Collection())...)

	if withEmail {
		record.IgnoreEmailVisibility(true)
	} else {
		record.Hide(core.FieldNameEmail)
	}

	return record, nil
}

// newPermissionsMeApplication returns the installed application data of the provided installation
// (the application actor itself or the installation of an online token).
func newPermissionsMeApplication(e *core.RequestEvent, info *core.RequestInfo, installation *core.ApplicationInstallation) (*permissionsMeApplication, error) {
	application, err := e.App.FindApplicationById(installation.ApplicationRef())
	if err != nil {
		return nil, err
	}

	result := &permissionsMeApplication{
		Id:             application.Id,
		Handle:         application.Handle(),
		Name:           application.Name(),
		InstallationId: installation.Id,
		VersionId:      installation.VersionRef(),
		ClientId:       info.OAuth2.ClientId,
	}

	if version, err := e.App.FindApplicationVersionById(installation.VersionRef()); err == nil {
		result.Version = version.Version()
	}

	return result, nil
}
