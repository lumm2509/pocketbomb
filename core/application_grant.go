package core

import (
	"fmt"
	"slices"
	"strings"

	validation "github.com/pocketbase/ozzo-validation/v4"
)

// ValidateApplicationGrant checks the permissions set as an application installation grant:
// the regular [Permissions.Validate] registry checks and only the [PermissionResource.ApplicationGrantable]
// system resources (the Owner only levels are never grantable).
func (p Permissions) ValidateApplicationGrant(app App) error {
	if err := p.Validate(app); err != nil {
		return err
	}

	errs := validation.Errors{}

	for k, level := range p.System {
		if level == PermissionLevelNone {
			continue
		}

		resource, _ := FindPermissionResource(k)
		if !resource.IsApplicationGrantableLevel(level) {
			errs["system."+k] = validation.NewError(
				"validation_not_application_grantable",
				fmt.Sprintf("The %s %s permission cannot be granted to an application.", k, level),
			)
		}
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}

// ApplicationGrantPermissions returns a copy of the provided grant with only the
// entries that could be granted to an application (defense in depth for the
// stored grants; the regular collections existence is checked on save).
func ApplicationGrantPermissions(grant Permissions) Permissions {
	result := grant.Clone()
	result.Normalize()

	for k, actions := range result.Collections {
		result.Collections[k] = slices.DeleteFunc(actions, func(a string) bool {
			return !slices.Contains(PermissionCollectionActions, a)
		})
	}

	for k, level := range result.System {
		resource, ok := FindPermissionResource(k)
		if !ok || !resource.IsApplicationGrantableLevel(level) {
			delete(result.System, k)
		}
	}

	result.Normalize()

	return result
}

// ApplicationGrantScopes returns the OAuth2 scopes derived from an application installation grant:
//   - read_{name} if any of list/view is granted for the regular collection (directly or via "*")
//   - write_{name} if any of create/update/delete is granted (non-view collections only)
//   - system:{level}_{resource} for every granted application grantable system resource level
//
// The CRUD granularity comes from the grant itself (effective = grant ∩ token scopes).
func ApplicationGrantScopes(app App, grant Permissions) []string {
	grant = ApplicationGrantPermissions(grant)

	result := []string{}

	collections, _ := app.Store().Get(StoreKeyCachedCollections).([]*Collection)
	if collections == nil {
		collections, _ = app.FindAllCollections()
	}

	for _, c := range collections {
		if c.System {
			continue
		}

		if grant.CanCollection(c.Id, PermissionActionList) || grant.CanCollection(c.Id, PermissionActionView) {
			result = append(result, OAuth2ScopePrefixRead+c.Name)
		}

		if !c.IsView() && (grant.CanCollection(c.Id, PermissionActionCreate) ||
			grant.CanCollection(c.Id, PermissionActionUpdate) ||
			grant.CanCollection(c.Id, PermissionActionDelete)) {
			result = append(result, OAuth2ScopePrefixWrite+c.Name)
		}
	}

	for _, r := range PermissionResources {
		level := grant.System[r.Name]
		if level != PermissionLevelNone && r.IsApplicationGrantableLevel(level) {
			result = append(result, OAuth2SystemScope(r.Name, level))
		}
	}

	slices.Sort(result)

	return slices.Compact(result)
}

// applicationScopeCovered reports whether the provided scope is in the provided scopes
// (write_x implies read_x and system:write_r implies system:read_r).
func applicationScopeCovered(scope string, scopes []string) bool {
	if slices.Contains(scopes, scope) {
		return true
	}

	if name, ok := strings.CutPrefix(scope, OAuth2ScopePrefixSystem+OAuth2ScopePrefixRead); ok {
		return slices.Contains(scopes, OAuth2ScopePrefixSystem+OAuth2ScopePrefixWrite+name)
	}

	if name, ok := strings.CutPrefix(scope, OAuth2ScopePrefixRead); ok {
		return slices.Contains(scopes, OAuth2ScopePrefixWrite+name)
	}

	return false
}

// applicationManifestAllowedScopes returns the scopes that could be granted to an installation
// of the provided manifest (its scopes and optional scopes).
func applicationManifestAllowedScopes(manifest *ApplicationManifest) []string {
	if manifest == nil {
		return []string{}
	}

	result := append(slices.Clone(manifest.Access.Scopes), manifest.Access.OptionalScopes...)
	slices.Sort(result)

	return slices.Compact(result)
}

// applicationGrantExceedingScopes returns the grant derived scopes that are not within the provided allowed scopes.
func applicationGrantExceedingScopes(app App, grant Permissions, allowed []string) []string {
	result := []string{}

	for _, s := range ApplicationGrantScopes(app, grant) {
		if !applicationScopeCovered(s, allowed) {
			result = append(result, s)
		}
	}

	return result
}

// applicationVersionRequiresApproval reports whether the new manifest requests a scope that is neither
// in the old manifest scopes (incl. the optional ones) nor in the current grant derived scopes.
func applicationVersionRequiresApproval(oldManifest *ApplicationManifest, newManifest *ApplicationManifest, grantScopes []string) bool {
	previous := applicationManifestAllowedScopes(oldManifest)

	for _, s := range newManifest.Access.Scopes {
		if !applicationScopeCovered(s, previous) && !applicationScopeCovered(s, grantScopes) {
			return true
		}
	}

	return false
}
