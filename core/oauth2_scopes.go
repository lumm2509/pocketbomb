package core

import (
	"fmt"
	"slices"
	"strings"

	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/pocketbase/dbx"
)

// Collection scopes prefixes (Shopify style).
//
// read_{collectionName} grants list and view,
// write_{collectionName} grants create, update and delete (and implies read).
const (
	OAuth2ScopePrefixRead  = "read_"
	OAuth2ScopePrefixWrite = "write_"
)

// OAuth2ScopePrefixSystem is the namespace prefix of the system resources scopes
// (system:read_{resource}, system:write_{resource}).
//
// The system scopes have their own namespace so that they never collide with
// the collection scopes (e.g. the "read_settings" scope of a regular collection
// named "settings" never maps to the settings system resource).
const OAuth2ScopePrefixSystem = "system:"

// OAuth2SystemScope returns the system scope of the provided system resource and level
// (e.g. "system:read_settings").
func OAuth2SystemScope(resource string, level string) string {
	if level == PermissionLevelWrite {
		return OAuth2ScopePrefixSystem + OAuth2ScopePrefixWrite + resource
	}

	return OAuth2ScopePrefixSystem + OAuth2ScopePrefixRead + resource
}

// IsOAuth2CollectionScope reports whether the provided scope has the
// collection scopes format (read_{name} or write_{name}).
func IsOAuth2CollectionScope(scope string) bool {
	return strings.HasPrefix(scope, OAuth2ScopePrefixRead) || strings.HasPrefix(scope, OAuth2ScopePrefixWrite)
}

// IsOAuth2SystemScope reports whether the provided scope is in the system scopes namespace.
func IsOAuth2SystemScope(scope string) bool {
	return strings.HasPrefix(scope, OAuth2ScopePrefixSystem)
}

// OAuth2SystemScopes returns the reserved system resources scopes (system:read_{resource}, system:write_{resource}).
//
// They are part of the registry but they are NOT grantable to the regular OAuth2 clients
// (they are not part of [OAuth2AllowedScopes] and the third-party tokens are always
// denied the system permissions); only the application installations tokens could
// carry them (see [ApplicationGrantScopes]).
func OAuth2SystemScopes() []string {
	result := make([]string, 0, len(PermissionResources)*2)

	for _, r := range PermissionResources {
		for _, level := range r.AssignableLevels() {
			result = append(result, OAuth2SystemScope(r.Name, level))
		}
	}

	return result
}

// OAuth2CollectionScopes returns the read/write scopes of the provided regular collection
// (the view collections have only a read scope; the system collections have no scopes).
func OAuth2CollectionScopes(collection *Collection) []string {
	if collection == nil || collection.System {
		return nil
	}

	if collection.IsView() {
		return []string{OAuth2ScopePrefixRead + collection.Name}
	}

	return []string{OAuth2ScopePrefixRead + collection.Name, OAuth2ScopePrefixWrite + collection.Name}
}

// OAuth2AllCollectionScopes returns the scopes of all regular collections.
func OAuth2AllCollectionScopes(app App) []string {
	collections, _ := app.Store().Get(StoreKeyCachedCollections).([]*Collection)
	if collections == nil {
		var err error
		collections, err = app.FindAllCollections()
		if err != nil {
			return nil
		}
	}

	result := make([]string, 0, len(collections)*2)
	for _, c := range collections {
		result = append(result, OAuth2CollectionScopes(c)...)
	}

	return result
}

// OAuth2AllowedScopes returns all scopes supported by the issuer of the provided auth collection
// (the builtin and custom scopes of the collection and the collection scopes of every regular collection).
func OAuth2AllowedScopes(app App, collection *Collection) []string {
	return list.ToUniqueStringSlice(append(collection.OAuth2Server.AllowedScopes(), OAuth2AllCollectionScopes(app)...))
}

// OAuth2ScopesAllowCollection reports whether the provided scopes grant
// the specified action on the provided regular collection.
func OAuth2ScopesAllowCollection(scopes []string, collection *Collection, action string) bool {
	if collection == nil || collection.System {
		return false // the system scopes are not grantable in R1
	}

	if slices.Contains(scopes, OAuth2ScopePrefixWrite+collection.Name) {
		return true
	}

	if action == PermissionActionList || action == PermissionActionView {
		return slices.Contains(scopes, OAuth2ScopePrefixRead+collection.Name)
	}

	return false
}

// OAuth2ScopeLabel returns a human friendly description of the provided collection or system scope
// (empty string for the other scopes and for the scopes of unknown collections or resources).
func OAuth2ScopeLabel(app App, scope string) string {
	if IsOAuth2SystemScope(scope) {
		return oauth2SystemScopeLabel(scope)
	}

	var name, label string

	switch {
	case strings.HasPrefix(scope, OAuth2ScopePrefixWrite):
		name = strings.TrimPrefix(scope, OAuth2ScopePrefixWrite)
		label = "Read, create, update and delete your %s data"
	case strings.HasPrefix(scope, OAuth2ScopePrefixRead):
		name = strings.TrimPrefix(scope, OAuth2ScopePrefixRead)
		label = "Read your %s data"
	default:
		return ""
	}

	collection, err := app.FindCachedCollectionByNameOrId(name)
	if err != nil || collection.System || collection.Name != name {
		return ""
	}

	return fmt.Sprintf(label, collection.Name)
}

func oauth2SystemScopeLabel(scope string) string {
	name := strings.TrimPrefix(scope, OAuth2ScopePrefixSystem)

	var level, label string

	switch {
	case strings.HasPrefix(name, OAuth2ScopePrefixWrite):
		name = strings.TrimPrefix(name, OAuth2ScopePrefixWrite)
		level = PermissionLevelWrite
		label = "Read and manage the %s (system)"
	case strings.HasPrefix(name, OAuth2ScopePrefixRead):
		name = strings.TrimPrefix(name, OAuth2ScopePrefixRead)
		level = PermissionLevelRead
		label = "Read the %s (system)"
	default:
		return ""
	}

	resource, ok := FindPermissionResource(name)
	if !ok || !slices.Contains(resource.Levels, level) {
		return ""
	}

	return fmt.Sprintf(label, resource.Label)
}

// RenameOAuth2CollectionScopes returns a copy of the provided scopes with the
// collection scopes of oldName replaced with the ones of newName.
func RenameOAuth2CollectionScopes(scopes []string, oldName string, newName string) ([]string, bool) {
	changed := false
	result := make([]string, len(scopes))

	for i, s := range scopes {
		switch s {
		case OAuth2ScopePrefixRead + oldName:
			result[i] = OAuth2ScopePrefixRead + newName
			changed = true
		case OAuth2ScopePrefixWrite + oldName:
			result[i] = OAuth2ScopePrefixWrite + newName
			changed = true
		default:
			result[i] = s
		}
	}

	return result, changed
}

// OAuth2ScopesAllowSystem reports whether the provided scopes grant the specified
// system resource level (system:write_{resource} implies system:read_{resource}).
//
// Note that the system scopes are grantable only to the application installations.
func OAuth2ScopesAllowSystem(scopes []string, resource string, level string) bool {
	if slices.Contains(scopes, OAuth2SystemScope(resource, PermissionLevelWrite)) {
		return true
	}

	return level == PermissionLevelRead && slices.Contains(scopes, OAuth2SystemScope(resource, PermissionLevelRead))
}

func (app *BaseApp) registerOAuth2ScopesHooks() {
	// rewrite the OAuth2 collection scopes on collection rename
	app.OnCollectionUpdateExecute().Bind(&hook.Handler[*CollectionEvent]{
		Func: func(e *CollectionEvent) error {
			old, _ := e.App.FindCachedCollectionByNameOrId(e.Collection.Id)
			if old == nil || old.Name == e.Collection.Name || e.Collection.System {
				return e.Next()
			}

			oldName := old.Name

			originalApp := e.App
			txErr := e.App.RunInTransaction(func(txApp App) error {
				e.App = txApp

				if err := e.Next(); err != nil {
					return err
				}

				return rewriteOAuth2CollectionScopes(txApp, oldName, e.Collection.Name)
			})
			e.App = originalApp

			return txErr
		},
		Priority: 99,
	})
}

// rewriteOAuth2CollectionScopes replaces the collection scopes of a renamed collection
// in the OAuth2 clients, consents and auth sessions.
//
// note: the records are saved without validation because the
// collections cache is updated only after the transaction commit.
func rewriteOAuth2CollectionScopes(app App, oldName string, newName string) error {
	targets := map[string][]string{
		CollectionNameOAuth2Clients:  {"scopes"},
		CollectionNameOAuth2Consents: {"scopes"},
		CollectionNameAuthSessions:   {"scopes", "scopesRequested"},
	}

	for collectionName, fields := range targets {
		for _, field := range fields {
			records, err := app.FindAllRecords(
				collectionName,
				// note: instr is used instead of LIKE because the scopes contain "_"
				dbx.NewExp(
					"(instr([["+field+"]], {:readScope}) > 0 OR instr([["+field+"]], {:writeScope}) > 0)",
					dbx.Params{
						"readScope":  `"` + OAuth2ScopePrefixRead + oldName + `"`,
						"writeScope": `"` + OAuth2ScopePrefixWrite + oldName + `"`,
					},
				),
			)
			if err != nil {
				return err
			}

			for _, r := range records {
				scopes, changed := RenameOAuth2CollectionScopes(r.GetStringSlice(field), oldName, newName)
				if !changed {
					continue
				}

				r.Set(field, scopes)

				if err := app.SaveNoValidate(r); err != nil {
					return fmt.Errorf("failed to rewrite the %s %q scopes: %w", collectionName, r.Id, err)
				}
			}
		}
	}

	return nil
}
