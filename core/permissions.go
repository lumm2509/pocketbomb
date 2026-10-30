package core

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/lumm2509/pocketbomb/tools/list"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// Permissions registry (RBAC): the collection actions, the system resources
// with their levels and the system collections mapping (see [Authorize]).

// Collection actions.
const (
	PermissionActionList   = "list"
	PermissionActionView   = "view"
	PermissionActionCreate = "create"
	PermissionActionUpdate = "update"
	PermissionActionDelete = "delete"
)

// PermissionCollectionActions is the list of all collection actions.
var PermissionCollectionActions = []string{
	PermissionActionList,
	PermissionActionView,
	PermissionActionCreate,
	PermissionActionUpdate,
	PermissionActionDelete,
}

// PermissionAllCollections is the collections permissions key that
// matches every regular (non-system) collection, including future ones.
const PermissionAllCollections = "*"

// System resources access levels (write implies read).
const (
	PermissionLevelNone  = ""
	PermissionLevelRead  = "read"
	PermissionLevelWrite = "write"
)

// System resources.
const (
	PermissionResourceSettings      = "settings"
	PermissionResourceCollections   = "collections"
	PermissionResourceLogs          = "logs"
	PermissionResourceBackups       = "backups"
	PermissionResourceCrons         = "crons"
	PermissionResourceWebhooks      = "webhooks"
	PermissionResourceLLM           = "llm"
	PermissionResourceOAuth2Clients = "oauth2_clients"
	PermissionResourceRoles         = "roles"
	PermissionResourceStaff         = "staff"
	PermissionResourceSessions      = "sessions"
	PermissionResourceImpersonate   = "impersonate"
	PermissionResourceApplications  = "applications"
	PermissionResourceAppProxy      = "app_proxy"

	// PermissionResourceSQL is available only for the Owners
	// (raw SQL bypasses everything and it is not assignable).
	PermissionResourceSQL = "sql"
)

// PermissionResource describes a single system resource of the registry.
type PermissionResource struct {
	Name  string `json:"name"`
	Label string `json:"label"`

	// Levels is the list of all levels of the resource.
	Levels []string `json:"levels"`

	// OwnerOnlyLevels is the list of the levels that are Owner-equivalent
	// and therefore available only for the Owners (they cannot be granted with a role).
	OwnerOnlyLevels []string `json:"ownerOnlyLevels"`

	// Assignable indicates whether at least one level of the resource could be granted with a role.
	Assignable bool `json:"assignable"`

	// ApplicationGrantable indicates whether the assignable levels of the resource
	// could be also granted to an application installation (see [Permissions.ValidateApplicationGrant]).
	ApplicationGrantable bool `json:"applicationGrantable"`

	// Note is an optional explanation of the Owner only levels.
	Note string `json:"note,omitempty"`
}

// IsAssignableLevel reports whether the specified level could be granted with a role.
func (r PermissionResource) IsAssignableLevel(level string) bool {
	return slices.Contains(r.Levels, level) && !slices.Contains(r.OwnerOnlyLevels, level)
}

// IsApplicationGrantableLevel reports whether the specified level could be
// granted to an application installation (the Owner only levels never are).
func (r PermissionResource) IsApplicationGrantableLevel(level string) bool {
	return r.ApplicationGrantable && r.IsAssignableLevel(level)
}

// AssignableLevels returns the levels that could be granted with a role.
func (r PermissionResource) AssignableLevels() []string {
	result := make([]string, 0, len(r.Levels))
	for _, l := range r.Levels {
		if r.IsAssignableLevel(l) {
			result = append(result, l)
		}
	}
	return result
}

// applicationGrantable marks the resource as grantable to the application installations.
func applicationGrantable(r PermissionResource) PermissionResource {
	r.ApplicationGrantable = true
	return r
}

func newPermissionResource(name, label string, levels []string, ownerOnlyLevels []string, note string) PermissionResource {
	r := PermissionResource{Name: name, Label: label, Levels: levels, OwnerOnlyLevels: ownerOnlyLevels, Note: note}
	if r.OwnerOnlyLevels == nil {
		r.OwnerOnlyLevels = []string{}
	}
	r.Assignable = len(r.AssignableLevels()) > 0
	return r
}

var readWrite = []string{PermissionLevelRead, PermissionLevelWrite}

// PermissionResources is the list of all known system resources.
//
// The Owner-equivalent levels (they allow reading the token secrets, the signing private keys,
// the auth records tokenKey or the whole database, or redirecting the Owners sign-in) are Owner only:
//   - collections write (view collections and dry-run with arbitrary SELECTs, system collections options and rules)
//   - backups (the archive contains the whole database; restore replaces it)
//   - settings write (e.g. the AppURL is trusted by the dashboard client redirect validation and used for the mail links)
//   - sql (raw SQL bypasses everything)
//
// Only the resources marked as ApplicationGrantable could be granted to the application
// installations (settings read, collections read, logs, crons, webhooks, llm and app_proxy);
// the staff, roles, sessions, impersonate, oauth2_clients and applications resources
// (and the Owner only levels) are never grantable to an application.
var PermissionResources = []PermissionResource{
	applicationGrantable(newPermissionResource(PermissionResourceSettings, "Application settings", readWrite, []string{PermissionLevelWrite},
		"write is Owner only (the AppURL, mail and storage settings could be used to take over the Owners accounts)")),
	applicationGrantable(newPermissionResource(PermissionResourceCollections, "Collections schema", readWrite, []string{PermissionLevelWrite},
		"write is Owner only (view collections could select any secret)")),
	applicationGrantable(newPermissionResource(PermissionResourceLogs, "Logs", readWrite, nil, "")),
	newPermissionResource(PermissionResourceBackups, "Backups", readWrite, readWrite,
		"Owner only (the backups contain the whole database)"),
	applicationGrantable(newPermissionResource(PermissionResourceCrons, "Crons", readWrite, nil, "")),
	applicationGrantable(newPermissionResource(PermissionResourceWebhooks, "Webhooks", readWrite, nil, "")),
	applicationGrantable(newPermissionResource(PermissionResourceLLM, "LLM", readWrite, nil, "")),
	newPermissionResource(PermissionResourceOAuth2Clients, "OAuth2 clients", readWrite, nil, ""),
	newPermissionResource(PermissionResourceRoles, "Roles", readWrite, nil, ""),
	newPermissionResource(PermissionResourceStaff, "Staff (superusers)", readWrite, nil, ""),
	newPermissionResource(PermissionResourceSessions, "Sessions, consents and auth records data", readWrite, nil, ""),
	newPermissionResource(PermissionResourceImpersonate, "Impersonate", []string{PermissionLevelWrite}, nil, ""),
	newPermissionResource(PermissionResourceApplications, "Applications (install, grants and credentials)", readWrite, nil, ""),
	applicationGrantable(newPermissionResource(PermissionResourceAppProxy, "App proxy (receive public storefront requests)", []string{PermissionLevelWrite}, nil, "")),
	newPermissionResource(PermissionResourceSQL, "SQL console", []string{PermissionLevelWrite}, []string{PermissionLevelWrite},
		"Owner only (raw SQL bypasses everything)"),
}

// FindPermissionResource returns the registry entry of the specified system resource.
func FindPermissionResource(name string) (PermissionResource, bool) {
	for _, r := range PermissionResources {
		if r.Name == name {
			return r, true
		}
	}

	return PermissionResource{}, false
}

// systemCollectionResources maps the system collections to their system resource
// (the unmapped system collections are accessible only by the Owners,
// the non-staff actors are still governed by the collection rules).
var systemCollectionResources = map[string]string{
	CollectionNameSuperusers:      PermissionResourceStaff,
	CollectionNameRoles:           PermissionResourceRoles,
	CollectionNameRoleAssignments: PermissionResourceRoles,
	CollectionNameAuthSessions:    PermissionResourceSessions,
	CollectionNameOAuth2Consents:  PermissionResourceSessions,
	CollectionNameOTPs:            PermissionResourceSessions,
	CollectionNameExternalAuths:   PermissionResourceSessions,
	CollectionNameAuthOrigins:     PermissionResourceSessions,
	CollectionNameOAuth2Clients:   PermissionResourceOAuth2Clients,
	CollectionNameAPIKeys:         PermissionResourceOAuth2Clients,
	CollectionNameWebhooks:        PermissionResourceWebhooks,

	CollectionNameApplications:             PermissionResourceApplications,
	CollectionNameApplicationVersions:      PermissionResourceApplications,
	CollectionNameApplicationInstallations: PermissionResourceApplications,
}

// SystemCollectionPermissionResource returns the system resource of the
// specified system collection name (false if the collection is not mapped).
func SystemCollectionPermissionResource(collectionName string) (string, bool) {
	r, ok := systemCollectionResources[collectionName]
	return r, ok
}

// SystemCollectionPermissionResources returns a copy of the system collections to system resources mapping.
func SystemCollectionPermissionResources() map[string]string {
	return maps.Clone(systemCollectionResources)
}

// PermissionActionLevel returns the system resource level required for the specified collection action
// (list and view require read, the others write).
func PermissionActionLevel(action string) string {
	if action == PermissionActionList || action == PermissionActionView {
		return PermissionLevelRead
	}

	return PermissionLevelWrite
}

// -------------------------------------------------------------------

// Permissions defines the permissions set of a role.
//
// Example JSON:
//
//	{
//	  "collections": {"*": ["list", "view"], "COLLECTION_ID": ["create"]},
//	  "system": {"settings": "read", "logs": "write"}
//	}
type Permissions struct {
	// Collections maps a regular collection id (or "*") to the granted actions.
	Collections map[string][]string `form:"collections" json:"collections"`

	// System maps a system resource name to its granted level ("read" or "write").
	System map[string]string `form:"system" json:"system"`
}

// Clone returns a deep copy of the permissions set.
func (p Permissions) Clone() Permissions {
	clone := Permissions{
		Collections: make(map[string][]string, len(p.Collections)),
		System:      maps.Clone(p.System),
	}
	if clone.System == nil {
		clone.System = map[string]string{}
	}

	for k, v := range p.Collections {
		clone.Collections[k] = slices.Clone(v)
	}

	return clone
}

// Normalize removes the empty entries and the duplicated actions.
func (p *Permissions) Normalize() {
	if p.Collections == nil {
		p.Collections = map[string][]string{}
	}
	if p.System == nil {
		p.System = map[string]string{}
	}

	for k, actions := range p.Collections {
		actions = list.ToUniqueStringSlice(actions)
		if len(actions) == 0 || k == "" {
			delete(p.Collections, k)
			continue
		}
		slices.Sort(actions)
		p.Collections[k] = actions
	}

	for k, level := range p.System {
		if level == PermissionLevelNone || k == "" {
			delete(p.System, k)
		}
	}
}

// IsEmpty reports whether the permissions set doesn't grant anything.
func (p Permissions) IsEmpty() bool {
	for _, actions := range p.Collections {
		if len(actions) > 0 {
			return false
		}
	}

	for _, level := range p.System {
		if level != PermissionLevelNone {
			return false
		}
	}

	return true
}

// CanCollection reports whether the specified action is granted for
// the provided regular collection id (directly or via "*").
func (p Permissions) CanCollection(collectionId string, action string) bool {
	return slices.Contains(p.Collections[collectionId], action) ||
		slices.Contains(p.Collections[PermissionAllCollections], action)
}

// HasAnyCollectionAction reports whether at least one action is granted for
// the provided regular collection id (directly or via "*").
func (p Permissions) HasAnyCollectionAction(collectionId string) bool {
	return len(p.Collections[collectionId]) > 0 || len(p.Collections[PermissionAllCollections]) > 0
}

// SystemLevel returns the granted level of the specified system resource.
func (p Permissions) SystemLevel(resource string) string {
	return p.System[resource]
}

// HasSystem reports whether the specified system resource level is granted (write implies read).
func (p Permissions) HasSystem(resource string, level string) bool {
	granted := p.System[resource]

	switch level {
	case PermissionLevelRead:
		return granted == PermissionLevelRead || granted == PermissionLevelWrite
	case PermissionLevelWrite:
		return granted == PermissionLevelWrite
	}

	return false
}

// Merge merges the other permissions set into the current one (union).
func (p *Permissions) Merge(other Permissions) {
	if p.Collections == nil {
		p.Collections = map[string][]string{}
	}
	if p.System == nil {
		p.System = map[string]string{}
	}

	for k, actions := range other.Collections {
		p.Collections[k] = list.ToUniqueStringSlice(append(p.Collections[k], actions...))
	}

	for k, level := range other.System {
		if p.HasSystem(k, level) {
			continue
		}
		if level == PermissionLevelRead || level == PermissionLevelWrite {
			p.System[k] = level
		}
	}

	p.Normalize()
}

// Intersect returns a new permissions set with only the permissions granted by both sets
// (e.g. the effective staff permissions ∩ installation grant of an online token).
//
// The "*" collections entry of the result has only the actions granted with "*" by both sets
// and the system levels are the lowest of both (write ∩ read = read).
func (p Permissions) Intersect(other Permissions) Permissions {
	result := Permissions{Collections: map[string][]string{}, System: map[string]string{}}

	for _, action := range PermissionCollectionActions {
		if slices.Contains(p.Collections[PermissionAllCollections], action) &&
			slices.Contains(other.Collections[PermissionAllCollections], action) {
			result.Collections[PermissionAllCollections] = append(result.Collections[PermissionAllCollections], action)
		}
	}

	keys := map[string]struct{}{}
	for k := range p.Collections {
		keys[k] = struct{}{}
	}
	for k := range other.Collections {
		keys[k] = struct{}{}
	}

	for k := range keys {
		if k == PermissionAllCollections {
			continue
		}

		for _, action := range PermissionCollectionActions {
			if p.CanCollection(k, action) && other.CanCollection(k, action) &&
				!slices.Contains(result.Collections[PermissionAllCollections], action) {
				result.Collections[k] = append(result.Collections[k], action)
			}
		}
	}

	for k := range p.System {
		switch {
		case p.HasSystem(k, PermissionLevelWrite) && other.HasSystem(k, PermissionLevelWrite):
			result.System[k] = PermissionLevelWrite
		case p.HasSystem(k, PermissionLevelRead) && other.HasSystem(k, PermissionLevelRead):
			result.System[k] = PermissionLevelRead
		}
	}

	result.Normalize()

	return result
}

// Covers reports whether the current permissions set grants every
// permission of the other set (used for the no-escalation checks).
//
// Note that the "*" collections entry of the other set is covered only
// by a "*" entry with the same actions (it also matches future collections).
func (p Permissions) Covers(other Permissions) bool {
	for k, actions := range other.Collections {
		for _, action := range actions {
			if k == PermissionAllCollections {
				if !slices.Contains(p.Collections[PermissionAllCollections], action) {
					return false
				}
				continue
			}

			if !p.CanCollection(k, action) {
				return false
			}
		}
	}

	for k, level := range other.System {
		if level == PermissionLevelNone {
			continue
		}
		if !p.HasSystem(k, level) {
			return false
		}
	}

	return true
}

// Validate checks the permissions set against the registry
// (known actions, assignable system resources and levels,
// existing regular collections).
func (p Permissions) Validate(app App) error {
	errs := validation.Errors{}

	for k, actions := range p.Collections {
		if k != PermissionAllCollections {
			collection, err := app.FindCachedCollectionByNameOrId(k)
			if err != nil || collection.Id != k {
				errs["collections."+k] = validation.NewError("validation_unknown_collection", "Unknown collection id.")
				continue
			}

			if collection.System {
				errs["collections."+k] = validation.NewError(
					"validation_system_collection",
					"The system collections are governed by the system resources permissions.",
				)
				continue
			}
		}

		for _, action := range actions {
			if !slices.Contains(PermissionCollectionActions, action) {
				errs["collections."+k] = validation.NewError("validation_unknown_action", fmt.Sprintf("Unknown collection action %q.", action))
				break
			}
		}
	}

	for k, level := range p.System {
		resource, ok := FindPermissionResource(k)
		if !ok {
			errs["system."+k] = validation.NewError("validation_unknown_resource", "Unknown system resource.")
			continue
		}

		if level == PermissionLevelNone {
			continue
		}

		if !slices.Contains(resource.Levels, level) {
			errs["system."+k] = validation.NewError("validation_invalid_level", fmt.Sprintf("Invalid level %q.", level))
			continue
		}

		if !resource.IsAssignableLevel(level) {
			errs["system."+k] = validation.NewError("validation_owner_only", fmt.Sprintf("The %s %s permission is available only for the Owners.", k, level))
		}
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}

// AllPermissions returns a permissions set that grants everything assignable
// (used for the Owners preview).
func AllPermissions() Permissions {
	result := Permissions{
		Collections: map[string][]string{
			PermissionAllCollections: slices.Clone(PermissionCollectionActions),
		},
		System: map[string]string{},
	}

	for _, r := range PermissionResources {
		levels := r.AssignableLevels()
		if len(levels) > 0 {
			result.System[r.Name] = levels[len(levels)-1]
		}
	}

	return result
}

var errPermissionDenied = errors.New("permission denied")
