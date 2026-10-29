package core

import (
	"slices"
	"strings"
	"sync"
)

// RBAC glossary:
//   - staff: a _superusers record actor (the upstream identifiers such as
//     [Record.IsSuperuser] and the SuperuserIPs setting keep their names
//     and refer to the staff records)
//   - Owner: the built-in Owner role (see [RoleNameOwner]); a staff member
//     with it bypasses every check
//   - record owner: the auth record that owns a record (e.g. the "Owner"
//     in the RequireSuperuserOrOwnerAuth apis middleware)

// Actor kinds.
const (
	ActorKindGuest    = "guest"
	ActorKindCustomer = "customer" // non-_superusers auth record
	ActorKindStaff    = "staff"    // _superusers auth record

	// ActorKindApplication is the kind of the application installations
	// (_applicationInstallations auth records).
	ActorKindApplication = "application"
)

// ActorPermissions defines the resolved RBAC permissions of a request actor.
type ActorPermissions struct {
	// Kind is the actor kind (guest, customer, staff or application).
	Kind string `json:"kind"`

	// Owner indicates whether the actor is a staff member with the built-in Owner role
	// (it bypasses everything; always false for third-party OAuth2 client tokens).
	Owner bool `json:"owner"`

	// Roles is the list of the actor effective role names
	// (the explicit assignments or the collection default roles).
	Roles []string `json:"roles"`

	// RoleIds is the list of the actor effective role ids.
	RoleIds []string `json:"roleIds"`

	// Permissions is the union of the actor roles permissions
	// (for the applications it is the installation grant).
	Permissions Permissions `json:"permissions"`

	// ThirdParty indicates whether the request is authorized with
	// an access token of a third-party (aka. non first-party) OAuth2 client.
	ThirdParty bool `json:"thirdParty"`

	// Scopes is the list of the effective collection scopes of a third-party token
	// (the permissions of a third-party token are the role permissions ∩ the collection scopes)
	// or the collection and system scopes of an application token (grant ∩ scopes).
	Scopes []string `json:"scopes"`

	// OnBehalfOf is set for the application extensions online tokens: the staff member acts on behalf
	// of an application installation and Permissions are the effective staff permissions ∩ installation grant
	// (never Owner; see [Authorize]).
	OnBehalfOf *ActorOnBehalfOf `json:"onBehalfOf,omitempty"`
}

// ActorOnBehalfOf describes the application installation on whose behalf a staff member acts.
type ActorOnBehalfOf struct {
	// Kind is always [ActorKindApplication].
	Kind string `json:"kind"`

	InstallationId string `json:"installationId"`
	ApplicationId  string `json:"applicationId"`
}

// IsStaff reports whether the actor is a staff member (_superusers record).
func (p *ActorPermissions) IsStaff() bool {
	return p != nil && p.Kind == ActorKindStaff
}

// IsApplication reports whether the actor is an application installation.
func (p *ActorPermissions) IsApplication() bool {
	return p != nil && p.Kind == ActorKindApplication
}

// IsOnBehalfOfApplication reports whether the actor is a staff member acting on behalf
// of an application installation (application extension online token).
func (p *ActorPermissions) IsOnBehalfOfApplication() bool {
	return p != nil && p.OnBehalfOf != nil
}

// ResolveActorPermissions resolves the RBAC permissions of the provided request info actor.
//
// Prefer [RequestInfo.Permissions] since it caches the result.
func ResolveActorPermissions(app App, info *RequestInfo) (*ActorPermissions, error) {
	result := &ActorPermissions{
		Kind:        ActorKindGuest,
		Roles:       []string{},
		RoleIds:     []string{},
		Permissions: Permissions{Collections: map[string][]string{}, System: map[string]string{}},
		Scopes:      []string{},
	}

	if info == nil || info.Auth == nil {
		return result, nil
	}

	// the application installations permissions are their grant (never roles)
	// read live from the (per request loaded) installation record
	if info.Auth.Collection().Name == CollectionNameApplicationInstallations {
		result.Kind = ActorKindApplication
		result.Permissions = ApplicationGrantPermissions(parseRolePermissions(info.Auth.Get("permissions")))

		// note: a token without OAuth2 data (or with a different client) has no scopes and therefore no access
		for _, s := range info.OAuth2.Scopes {
			if IsOAuth2CollectionScope(s) || IsOAuth2SystemScope(s) {
				result.Scopes = append(result.Scopes, s)
			}
		}

		return result, nil
	}

	result.Kind = ActorKindCustomer
	if info.Auth.IsSuperuser() {
		result.Kind = ActorKindStaff
	}

	result.ThirdParty = info.OAuth2.ClientId != "" && !info.OAuth2.FirstParty

	roles, err := app.FindRecordRoles(info.Auth)
	if err != nil {
		return result, err
	}

	for _, role := range roles {
		result.Roles = append(result.Roles, role.Name())
		result.RoleIds = append(result.RoleIds, role.Id)

		if role.IsOwner() {
			if result.Kind == ActorKindStaff {
				result.Owner = true
			}
			continue
		}

		result.Permissions.Merge(role.Permissions())
	}

	// the application extensions online tokens (the installation managed client of a staff actor)
	if info.OAuth2.ApplicationInstallationId != "" {
		return resolveOnBehalfOfPermissions(app, info, result)
	}

	if result.ThirdParty {
		// third-party tokens never bypass anything
		result.Owner = false

		for _, s := range info.OAuth2.Scopes {
			// note: only the collection scopes (the system:* scopes are not grantable in R1)
			if IsOAuth2CollectionScope(s) {
				result.Scopes = append(result.Scopes, s)
			}
		}
	}

	return result, nil
}

// resolveOnBehalfOfPermissions resolves the permissions of an application extension online token
// (a staff actor with the installation managed client token, see [ApplicationLaunchClaims]):
//   - the Owner bypass never applies (Owner is always false)
//   - Permissions = staff permissions ∩ installation grant (read live; an Owner staff member
//     has all assignable permissions and therefore the effective permissions are the grant)
//   - webhooks is at most read (the webhooks are managed with the manifest or the installation
//     offline token; an online token can't create or redirect a subscription that outlives it)
//   - Scopes = the token collection and system scopes (also checked by [Authorize])
//
// Any other actor kind (e.g. a customer) with a managed client token fails closed (no permissions).
func resolveOnBehalfOfPermissions(app App, info *RequestInfo, result *ActorPermissions) (*ActorPermissions, error) {
	staffPermissions := result.Permissions
	if result.Owner {
		// note: the Owner only levels are never application grantable anyway
		staffPermissions = AllPermissions()
	}

	result.Owner = false
	result.ThirdParty = true
	result.Permissions = Permissions{Collections: map[string][]string{}, System: map[string]string{}}

	if result.Kind != ActorKindStaff {
		return result, nil
	}

	installation, err := app.FindApplicationInstallationById(info.OAuth2.ApplicationInstallationId)
	if err != nil {
		return result, err
	}

	result.OnBehalfOf = &ActorOnBehalfOf{
		Kind:           ActorKindApplication,
		InstallationId: installation.Id,
		ApplicationId:  installation.ApplicationRef(),
	}

	if !installation.IsActive() {
		return result, nil
	}

	result.Permissions = applicationOnBehalfOfPermissions(staffPermissions, installation)

	for _, s := range info.OAuth2.Scopes {
		if IsOAuth2CollectionScope(s) || IsOAuth2SystemScope(s) {
			result.Scopes = append(result.Scopes, s)
		}
	}

	return result, nil
}

// AuthorizeTarget defines the target of an authorization check.
//
// Set either Collection and Action (collection target) or Resource and Level (system resource target).
type AuthorizeTarget struct {
	Collection *Collection
	Action     string

	Resource string
	Level    string
}

// Access defines the result of an authorization check.
type Access struct {
	// Allowed indicates whether the actor is allowed to perform the action
	// (for the collection targets the collection rules could still deny it unless BypassRules is set).
	Allowed bool

	// BypassRules indicates whether the actor bypasses the collection API rules
	// for the target action (aka. the superuser access before R1; the hidden fields are also visible).
	BypassRules bool

	// ReadOnlyFields is the list of the target collection record fields
	// that the actor is not allowed to change.
	ReadOnlyFields []string
}

// thirdPartyReadOnlyAuthFields are the auth record fields that can't be changed with
// a non first-party OAuth2 access token (no account takeover by a third-party client).
var thirdPartyReadOnlyAuthFields = []string{
	FieldNameEmail,
	FieldNamePassword,
	FieldNameTokenKey,
	FieldNameVerified,
	FieldNameEmailVisibility,
}

// Authorize is the single RBAC evaluation point.
//
// System resource targets are allowed only for staff members (never with
// third-party tokens): Owners always, the others with the assignable resource level.
//
// Collection targets: guests are governed only by the rules; staff with the
// mapped system resource level bypass the system collections rules (the others
// fall back to the rules); regular collections require the role permission
// (third-party tokens: role permissions ∩ collection scopes, never bypassing the rules).
//
// Applications and extension online tokens are evaluated by [authorizeApplication]
// (installation grant (∩ staff permissions) ∩ token scopes).
//
// API keys only restrict: their permissions are a ceiling for the regular collections.
//
// Non first-party tokens get the auth account fields as Access.ReadOnlyFields.
func Authorize(app App, info *RequestInfo, target AuthorizeTarget) Access {
	access := authorizeActor(app, info, target)

	if access.Allowed &&
		info != nil && info.APIKey != nil &&
		target.Collection != nil && !target.Collection.System &&
		!info.APIKey.Permissions.CanCollection(target.Collection.Id, target.Action) {
		return Access{}
	}

	if access.Allowed &&
		info != nil && info.OAuth2.ClientId != "" && !info.OAuth2.FirstParty &&
		target.Collection != nil && target.Collection.IsAuth() {
		access.ReadOnlyFields = slices.Clone(thirdPartyReadOnlyAuthFields)
	}

	return access
}

// authorizeActor evaluates the target for the request actor (without the API key ceiling).
func authorizeActor(app App, info *RequestInfo, target AuthorizeTarget) Access {
	perms := info.Permissions(app)

	// note: the online tokens permissions are already the staff permissions ∩ installation grant
	if perms.IsApplication() || perms.IsOnBehalfOfApplication() {
		return authorizeApplication(perms, target)
	}

	// (fail closed) a managed client token of any other actor
	if info != nil && info.OAuth2.ApplicationInstallationId != "" {
		return Access{}
	}

	// system resource
	if target.Collection == nil {
		if !perms.IsStaff() || perms.ThirdParty {
			return Access{}
		}

		if perms.Owner {
			return Access{Allowed: true, BypassRules: true}
		}

		// note: the Owner only (aka. Owner-equivalent) levels are never granted
		// with a role, even if a legacy role has them stored
		resource, ok := FindPermissionResource(target.Resource)
		if !ok || !resource.IsAssignableLevel(target.Level) {
			return Access{}
		}

		if perms.Permissions.HasSystem(target.Resource, target.Level) {
			return Access{Allowed: true, BypassRules: true}
		}

		return Access{}
	}

	collection := target.Collection

	if perms.Kind == ActorKindGuest {
		return Access{Allowed: true}
	}

	if collection.System {
		if perms.ThirdParty {
			return Access{}
		}

		if perms.Owner {
			return Access{Allowed: true, BypassRules: true}
		}

		if perms.IsStaff() {
			resource, mapped := SystemCollectionPermissionResource(collection.Name)
			level := PermissionActionLevel(target.Action)

			// note: creating or changing OTPs, external auths, sessions, consents or auth origins
			// would allow taking over any account (incl. the Owners) and therefore the sessions
			// permission grants only list/view/delete (aka. revocation; create/update are Owner only)
			//
			// similarly, the applications records are created/changed only through the dedicated
			// API endpoints (manifest import, install, grant changes, rotate secret)
			// and the API keys too (create, rotate, enable/disable; the tokens are generated by the server)
			ownerOnlyAction := (resource == PermissionResourceSessions || resource == PermissionResourceApplications ||
				collection.Name == CollectionNameAPIKeys) &&
				(target.Action == PermissionActionCreate || target.Action == PermissionActionUpdate)

			if mapped && !ownerOnlyAction && perms.Permissions.HasSystem(resource, level) {
				if res, ok := FindPermissionResource(resource); ok && res.IsAssignableLevel(level) {
					return Access{Allowed: true, BypassRules: true}
				}
			}
		}

		// own-record behavior (the collection rules decide)
		return Access{Allowed: true}
	}

	if perms.Owner {
		return Access{Allowed: true, BypassRules: true}
	}

	if !perms.Permissions.CanCollection(collection.Id, target.Action) {
		return Access{}
	}

	if perms.ThirdParty {
		if !OAuth2ScopesAllowCollection(perms.Scopes, collection, target.Action) {
			return Access{}
		}

		// third-party tokens never bypass the rules
		return Access{Allowed: true}
	}

	if perms.IsStaff() {
		return Access{Allowed: true, BypassRules: true}
	}

	return Access{Allowed: true}
}

// authorizeApplication evaluates the targets of an application installation actor
// (effective = installation grant ∩ token scopes; the secret fields are still Owner only)
// and of an application extension online token (effective = staff permissions ∩ installation grant ∩ token scopes).
func authorizeApplication(perms *ActorPermissions, target AuthorizeTarget) Access {
	if target.Collection == nil {
		return authorizeApplicationSystem(perms, target.Resource, target.Level)
	}

	collection := target.Collection

	// note: no own-record fallback for the applications
	if collection.System {
		resource, mapped := SystemCollectionPermissionResource(collection.Name)
		if !mapped {
			return Access{}
		}

		return authorizeApplicationSystem(perms, resource, PermissionActionLevel(target.Action))
	}

	if perms.Permissions.CanCollection(collection.Id, target.Action) &&
		OAuth2ScopesAllowCollection(perms.Scopes, collection, target.Action) {
		return Access{Allowed: true, BypassRules: true}
	}

	return Access{}
}

func authorizeApplicationSystem(perms *ActorPermissions, resource string, level string) Access {
	r, ok := FindPermissionResource(resource)
	if !ok ||
		!r.IsApplicationGrantableLevel(level) ||
		!perms.Permissions.HasSystem(resource, level) ||
		!OAuth2ScopesAllowSystem(perms.Scopes, resource, level) {
		return Access{}
	}

	return Access{Allowed: true, BypassRules: true}
}

// -------------------------------------------------------------------
// RequestEvent helpers
// -------------------------------------------------------------------

// ActorInfo returns a lightweight RequestInfo with only the request actor data
// (auth record and OAuth2 token data) that could be used for the RBAC checks
// without parsing the request body (e.g. in middlewares running before the route handler).
//
// The resolved actor permissions are cached per request.
func (e *RequestEvent) ActorInfo() *RequestInfo {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.cachedActorInfo == nil {
		e.cachedActorInfo = &RequestInfo{
			Context:          RequestInfoContextDefault,
			Method:           e.Request.Method,
			Query:            map[string]string{},
			Headers:          map[string]string{},
			Body:             map[string]any{},
			permissionsCache: &requestInfoPermissionsCache{},
		}
	}

	e.cachedActorInfo.Auth = e.Auth
	e.cachedActorInfo.OAuth2 = e.requestInfoOAuth2()
	e.cachedActorInfo.APIKey = e.requestInfoAPIKey()

	return e.cachedActorInfo
}

// Can reports whether the request actor has the specified RBAC system resource level (see [Authorize]).
func (e *RequestEvent) Can(resource string, level string) bool {
	return e.ActorInfo().Can(e.App, resource, level)
}

// IsOwner reports whether the request actor is an Owner (see [Authorize]).
func (e *RequestEvent) IsOwner() bool {
	return e.ActorInfo().IsOwner(e.App)
}

// IsStaff reports whether the request actor is a staff member acting directly (see [RequestInfo.IsStaff]).
func (e *RequestEvent) IsStaff() bool {
	return e.Auth != nil && e.ActorInfo().IsStaff()
}

// IsApplication reports whether the request actor is an application installation.
func (e *RequestEvent) IsApplication() bool {
	return e.Auth != nil && e.Auth.Collection().Name == CollectionNameApplicationInstallations
}

// -------------------------------------------------------------------
// RequestInfo helpers
// -------------------------------------------------------------------

// requestInfoPermissionsCache caches the resolved actor permissions of a RequestInfo
// (it is shared between the RequestInfo shallow copies and it is keyed by the actor).
type requestInfoPermissionsCache struct {
	mu    sync.Mutex
	key   string
	value *ActorPermissions
}

func (info *RequestInfo) permissionsCacheKey() string {
	if info == nil || info.Auth == nil {
		return "guest"
	}

	return info.Auth.Collection().Id + "/" + info.Auth.Id + "/" + info.Auth.TokenKey() + "|" +
		info.OAuth2.ClientId + "|" + strings.Join(info.OAuth2.Scopes, " ") + "|" + boolKey(info.OAuth2.FirstParty) + "|" +
		info.OAuth2.ApplicationInstallationId
}

func boolKey(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// Permissions returns the resolved (and cached per request) RBAC permissions of the request actor.
//
// On error it fails closed (the actor is returned without any role permission).
func (info *RequestInfo) Permissions(app App) *ActorPermissions {
	if info == nil {
		perms, _ := ResolveActorPermissions(app, nil)
		return perms
	}

	key := info.permissionsCacheKey()

	if info.permissionsCache != nil {
		info.permissionsCache.mu.Lock()
		defer info.permissionsCache.mu.Unlock()

		if info.permissionsCache.value != nil && info.permissionsCache.key == key {
			return info.permissionsCache.value
		}
	}

	perms, err := ResolveActorPermissions(app, info)
	if err != nil {
		app.Logger().Warn("Failed to resolve the actor permissions", "error", err)
	}

	if info.permissionsCache != nil {
		info.permissionsCache.key = key
		info.permissionsCache.value = perms
	}

	return perms
}

// CollectionAccess returns the [Authorize] result for the specified collection action.
func (info *RequestInfo) CollectionAccess(app App, collection *Collection, action string) Access {
	return Authorize(app, info, AuthorizeTarget{Collection: collection, Action: action})
}

// Can reports whether the request actor has the specified system resource level (see [Authorize]).
func (info *RequestInfo) Can(app App, resource string, level string) bool {
	return Authorize(app, info, AuthorizeTarget{Resource: resource, Level: level}).Allowed
}

// IsOwner reports whether the request actor is an Owner (never for third-party tokens).
func (info *RequestInfo) IsOwner(app App) bool {
	return info.Permissions(app).Owner
}

// IsStaff reports whether the request actor is a staff member acting directly, aka. a _superusers
// record authorized with a first-party token (e.g. the dashboard) and not on behalf of an application.
//
// It is false for the third-party clients tokens and the application extensions online tokens
// of a staff member (their access is evaluated only by [Authorize]) while the identity related
// checks (e.g. the superuser IPs allow-list) should check the actor record itself.
//
// A trusted programmatic RequestInfo without OAuth2 token data is treated as first-party.
func (info *RequestInfo) IsStaff() bool {
	return info != nil &&
		info.Auth != nil &&
		info.Auth.IsSuperuser() &&
		(info.OAuth2.ClientId == "" || info.OAuth2.FirstParty) &&
		info.OAuth2.ApplicationInstallationId == ""
}

// IsApplication reports whether the request actor is an application installation.
func (info *RequestInfo) IsApplication() bool {
	return info != nil && info.Auth != nil && info.Auth.Collection().Name == CollectionNameApplicationInstallations
}
