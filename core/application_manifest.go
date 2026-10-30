package core

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/security"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// Application manifest
// -------------------------------------------------------------------
//
// The developers describe their application with a "pocketbase.app.toml" (or JSON) manifest.
// The server parses, validates and normalizes it to JSON and stores it in the
// _applicationVersions.manifest field together with its sha256 digest
// (TOML is only an input format and the manifest is never read from the filesystem at runtime).
//
// Supported keys:
//
//	handle          = "my-app"                           # required, ^[a-z0-9][a-z0-9\-]{1,62}$
//	name            = "My app"                           # required
//	version         = "1.0.0"                            # required, semver-ish, immutable once imported
//	description     = "..."
//	application_url = "https://example.com"
//	install_url     = "https://example.com/pb/install"   # required for the catalog apps (same host as application_url)
//	uninstall_url   = "https://example.com/pb/uninstall" # optional (same host as application_url)
//	icon_url        = "https://example.com/icon.png"     # optional (inlined as data: URI on import, see [ApplicationCatalogs])
//
//	[developer]
//	name = "ACME"
//	url  = "https://acme.example.com"
//
//	[access]
//	scopes          = ["read_posts", "write_posts", "system:read_logs"]
//	optional_scopes = ["read_comments"]                  # grantable by the staff at install/update time
//
//	[[webhooks.subscriptions]]                           # the installation managed webhooks
//	topics = ["posts.create", "posts.update"]
//	uri    = "https://hooks.example.com/pb"
//	filter = "status = 'published'"                      # optional
//	fields = ["id", "title"]                             # optional
//
//	[[extensions]]                                       # max 20, declarative (no application code runs inside PocketBase)
//	type   = "dashboard.navigation"                      # dashboard.navigation or dashboard.record_action
//	handle = "home"                                      # unique per manifest (same format as the application handle)
//	label  = "My app"
//	path   = "/pb/home"                                  # relative to the application_url origin (same host)
//
//	[[extensions]]
//	type       = "dashboard.record_action"
//	handle     = "inspect-post"
//	label      = "Inspect"
//	path       = "/pb/posts"
//	collection = "posts"                                 # required for (and only for) the record actions
//
//	[app_proxy]                                          # requires the write_app_proxy scope
//	url     = "https://example.com/proxy"                # same host as application_url
//	prefix  = "apps"                                     # a, apps, community or tools
//	subpath = "reviews"                                  # ^[A-Za-z0-9_-]{1,30}$ (not admin, services, password or login)
//
// The webhooks topics can't be in the "application" lifecycle namespace (the applications learn about
// their own lifecycle only through the install_url/uninstall_url notifications).
//
// The install_url, uninstall_url, icon_url and webhooks uri must be https urls
// (http is accepted only for the loopback hosts, e.g. for local development).
//
// Any other key is rejected with a validation error naming the key.

// Supported application manifest source formats.
const (
	ApplicationManifestFormatTOML = "toml"
	ApplicationManifestFormatJSON = "json"
)

// ApplicationManifestMaxSize is the max size of a raw application manifest (in bytes).
const ApplicationManifestMaxSize = 256 << 10

// applicationManifestMaxWebhooks is the max number of the manifest webhook subscriptions.
const applicationManifestMaxWebhooks = 20

// applicationManifestMaxExtensions is the max number of the manifest extensions.
const applicationManifestMaxExtensions = 20

// Supported application manifest extension types.
const (
	// ApplicationExtensionTypeNavigation is a dashboard navigation link
	// (listed under "Applications" for the staff with the applications read permission).
	ApplicationExtensionTypeNavigation = "dashboard.navigation"

	// ApplicationExtensionTypeRecordAction is a dashboard record panel action of a single collection
	// (shown only if both the staff and the installation grant could view the collection records).
	ApplicationExtensionTypeRecordAction = "dashboard.record_action"
)

// ApplicationExtensionTypes is the list of the supported manifest extension types.
var ApplicationExtensionTypes = []string{
	ApplicationExtensionTypeNavigation,
	ApplicationExtensionTypeRecordAction,
}

var (
	applicationHandleRegex          = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{1,62}$`)
	applicationVersionRegex         = regexp.MustCompile(`^v?(0|[1-9]\d*)(\.(0|[1-9]\d*)){0,2}([\-+][0-9A-Za-z.\-+]+)?$`)
	applicationCollectionScopeRegex = regexp.MustCompile(`^(read|write)_\w+$`)
	applicationCollectionNameRegex  = regexp.MustCompile(`^\w+$`)
)

// applicationManifestSchema is the tree of the supported manifest keys
// (nil leaf = scalar or list value, nested map = table/object).
var applicationManifestSchema = map[string]any{
	"handle":          nil,
	"name":            nil,
	"version":         nil,
	"description":     nil,
	"application_url": nil,
	"install_url":     nil,
	"uninstall_url":   nil,
	"icon_url":        nil,
	"developer": map[string]any{
		"name": nil,
		"url":  nil,
	},
	"access": map[string]any{
		"scopes":          nil,
		"optional_scopes": nil,
	},
	"webhooks": map[string]any{
		"subscriptions": nil, // list of tables (see applicationManifestWebhookSchema)
	},
	"extensions": nil, // list of tables (see applicationManifestExtensionSchema)
	"app_proxy": map[string]any{
		"url":     nil,
		"prefix":  nil,
		"subpath": nil,
	},
}

// applicationManifestWebhookSchema is the keys tree of a single webhooks.subscriptions item.
var applicationManifestWebhookSchema = map[string]any{
	"topics": nil,
	"uri":    nil,
	"filter": nil,
	"fields": nil,
}

// applicationManifestExtensionSchema is the keys tree of a single extensions item.
var applicationManifestExtensionSchema = map[string]any{
	"type":       nil,
	"handle":     nil,
	"label":      nil,
	"path":       nil,
	"collection": nil,
}

// ApplicationManifest defines the normalized application manifest.
type ApplicationManifest struct {
	Handle         string                       `json:"handle"`
	Name           string                       `json:"name"`
	Version        string                       `json:"version"`
	Description    string                       `json:"description"`
	ApplicationURL string                       `json:"application_url"`
	Developer      ApplicationManifestDeveloper `json:"developer"`
	Access         ApplicationManifestAccess    `json:"access"`

	// note: omitzero so that the canonical JSON (and the digest) of the manifests
	// without these keys is the same as before they were introduced
	InstallURL   string                      `json:"install_url,omitzero"`
	UninstallURL string                      `json:"uninstall_url,omitzero"`
	IconURL      string                      `json:"icon_url,omitzero"`
	Webhooks     ApplicationManifestWebhooks `json:"webhooks,omitzero"`

	// Extensions is the list of the declarative dashboard extensions (see [ApplicationExtensionTypes]).
	Extensions []ApplicationManifestExtension `json:"extensions,omitzero"`

	// AppProxy is the optional application proxy configuration (see [ApplicationProxyPrefixes]).
	AppProxy *ApplicationManifestAppProxy `json:"app_proxy,omitzero"`
}

// ApplicationManifestAppProxy defines the manifest app_proxy table.
type ApplicationManifestAppProxy struct {
	// URL is the base proxy target url (on the application_url host; it always comes from the installed version).
	URL string `json:"url"`

	// Prefix and Subpath are the defaults of a new installation public path "/{prefix}/{subpath}".
	Prefix  string `json:"prefix"`
	Subpath string `json:"subpath"`
}

// ApplicationManifestExtension defines a single declarative manifest extension.
//
// The extensions are launched from the dashboard with a short-lived signed launch token
// POSTed to the extension URL (see [ApplicationManifest.ExtensionURL]).
type ApplicationManifestExtension struct {
	Type   string `json:"type"`
	Handle string `json:"handle"`
	Label  string `json:"label"`

	// Path is the extension path relative to the application_url origin (e.g. "/pb/home").
	Path string `json:"path"`

	// Collection is the record action collection name (record actions only).
	Collection string `json:"collection,omitzero"`
}

// ApplicationManifestWebhooks defines the manifest webhooks table.
type ApplicationManifestWebhooks struct {
	// Subscriptions is the list of the installation managed webhook subscriptions.
	Subscriptions []ApplicationManifestWebhookSubscription `json:"subscriptions,omitzero"`
}

// ApplicationManifestWebhookSubscription defines a single manifest managed webhook subscription.
type ApplicationManifestWebhookSubscription struct {
	// Topics is the list of the subscription topics in the "{collectionName}.{op}"
	// (or "{namespace}.{name}" for the custom topics) format.
	Topics []string `json:"topics"`
	URI    string   `json:"uri"`
	Filter string   `json:"filter,omitzero"`
	Fields []string `json:"fields,omitzero"`
}

// ApplicationManifestDeveloper defines the manifest developer table.
type ApplicationManifestDeveloper struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// ApplicationManifestAccess defines the manifest access table.
type ApplicationManifestAccess struct {
	// Scopes is the list of the scopes that the application requests
	// (collection scopes read_{name}/write_{name} or the application
	// grantable system scopes system:read_{resource}/system:write_{resource}).
	Scopes []string `json:"scopes"`

	// OptionalScopes is the list of the optional scopes the application could work with.
	OptionalScopes []string `json:"optional_scopes"`
}

// ParseApplicationManifest parses, validates and normalizes the provided raw manifest
// in the specified source format ("toml" or "json").
//
// Unknown keys and invalid values are returned as [validation.Errors]
// keyed by the manifest key path (e.g. "developer.url").
func ParseApplicationManifest(data []byte, format string) (*ApplicationManifest, error) {
	if len(data) == 0 {
		return nil, validation.Errors{"manifest": validation.ErrRequired}
	}

	if len(data) > ApplicationManifestMaxSize {
		return nil, validation.Errors{"manifest": validation.NewError(
			"validation_manifest_too_large",
			fmt.Sprintf("The manifest must be less than %d bytes.", ApplicationManifestMaxSize),
		)}
	}

	raw := map[string]any{}

	switch format {
	case ApplicationManifestFormatTOML:
		if err := toml.Unmarshal(data, &raw); err != nil {
			return nil, validation.Errors{"manifest": validation.NewError("validation_invalid_toml", "Invalid TOML: "+err.Error())}
		}
	case ApplicationManifestFormatJSON:
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, validation.Errors{"manifest": validation.NewError("validation_invalid_json", "Invalid JSON: "+err.Error())}
		}
	default:
		return nil, validation.Errors{"manifest": validation.NewError("validation_invalid_format", "Unsupported manifest format (toml or json).")}
	}

	errs := validation.Errors{}
	checkApplicationManifestKeys(raw, applicationManifestSchema, "", errs)
	if len(errs) > 0 {
		return nil, errs
	}

	manifest, err := applicationManifestFromMap(raw)
	if err != nil {
		return nil, err
	}

	if err := manifest.Validate(); err != nil {
		return nil, err
	}

	return manifest, nil
}

// applicationManifestListSchemas maps the manifest list of tables keys to their items keys tree.
var applicationManifestListSchemas = map[string]map[string]any{
	"webhooks.subscriptions": applicationManifestWebhookSchema,
	"extensions":             applicationManifestExtensionSchema,
}

// checkApplicationManifestKeys collects the unknown (or wrongly nested) keys of the raw manifest.
func checkApplicationManifestKeys(raw map[string]any, schema map[string]any, prefix string, errs validation.Errors) {
	for key, value := range raw {
		path := prefix + key

		def, ok := schema[key]
		if !ok {
			errs[path] = validation.NewError("validation_unknown_manifest_key", "Unknown manifest key {{.key}}.").
				SetParams(map[string]any{"key": path})
			continue
		}

		if itemSchema, ok := applicationManifestListSchemas[path]; ok {
			items, ok := applicationManifestTables(value)
			if !ok {
				errs[path] = validation.NewError("validation_invalid_manifest_value", "The manifest key {{.key}} must be a list of tables/objects.").
					SetParams(map[string]any{"key": path})
				continue
			}
			for i, item := range items {
				checkApplicationManifestKeys(item, itemSchema, path+"."+strconv.Itoa(i)+".", errs)
			}
			continue
		}

		nested, isTable := def.(map[string]any)
		if !isTable {
			continue
		}

		table, ok := value.(map[string]any)
		if !ok {
			errs[path] = validation.NewError("validation_invalid_manifest_table", "The manifest key {{.key}} must be a table/object.").
				SetParams(map[string]any{"key": path})
			continue
		}

		checkApplicationManifestKeys(table, nested, path+".", errs)
	}
}

// applicationManifestTables returns the provided raw list of tables (TOML array of tables or JSON array of objects).
func applicationManifestTables(value any) ([]map[string]any, bool) {
	switch v := value.(type) {
	case []map[string]any:
		return v, true
	case []any:
		result := make([]map[string]any, 0, len(v))
		for _, item := range v {
			table, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			result = append(result, table)
		}
		return result, true
	}

	return nil, false
}

// applicationManifestFromMap converts the already key checked raw manifest into its typed form.
func applicationManifestFromMap(raw map[string]any) (*ApplicationManifest, error) {
	manifest := &ApplicationManifest{}

	errs := validation.Errors{}

	str := func(path string, value any, dst *string) {
		if value == nil {
			return
		}
		v, ok := value.(string)
		if !ok {
			errs[path] = validation.NewError("validation_invalid_manifest_value", "The manifest key {{.key}} must be a string.").
				SetParams(map[string]any{"key": path})
			return
		}
		*dst = strings.TrimSpace(v)
	}

	strs := func(path string, value any, dst *[]string) {
		if value == nil {
			return
		}
		items, ok := value.([]any)
		if !ok {
			errs[path] = validation.NewError("validation_invalid_manifest_value", "The manifest key {{.key}} must be a list of strings.").
				SetParams(map[string]any{"key": path})
			return
		}
		result := make([]string, 0, len(items))
		for _, item := range items {
			v, ok := item.(string)
			if !ok {
				errs[path] = validation.NewError("validation_invalid_manifest_value", "The manifest key {{.key}} must be a list of strings.").
					SetParams(map[string]any{"key": path})
				return
			}
			if v = strings.TrimSpace(v); v != "" {
				result = append(result, v)
			}
		}
		*dst = result
	}

	str("handle", raw["handle"], &manifest.Handle)
	str("name", raw["name"], &manifest.Name)
	str("version", raw["version"], &manifest.Version)
	str("description", raw["description"], &manifest.Description)
	str("application_url", raw["application_url"], &manifest.ApplicationURL)
	str("install_url", raw["install_url"], &manifest.InstallURL)
	str("uninstall_url", raw["uninstall_url"], &manifest.UninstallURL)
	str("icon_url", raw["icon_url"], &manifest.IconURL)

	if developer, ok := raw["developer"].(map[string]any); ok {
		str("developer.name", developer["name"], &manifest.Developer.Name)
		str("developer.url", developer["url"], &manifest.Developer.URL)
	}

	if access, ok := raw["access"].(map[string]any); ok {
		strs("access.scopes", access["scopes"], &manifest.Access.Scopes)
		strs("access.optional_scopes", access["optional_scopes"], &manifest.Access.OptionalScopes)
	}

	if webhooks, ok := raw["webhooks"].(map[string]any); ok {
		items, _ := applicationManifestTables(webhooks["subscriptions"])
		for i, item := range items {
			path := "webhooks.subscriptions." + strconv.Itoa(i) + "."
			sub := ApplicationManifestWebhookSubscription{}
			strs(path+"topics", item["topics"], &sub.Topics)
			str(path+"uri", item["uri"], &sub.URI)
			str(path+"filter", item["filter"], &sub.Filter)
			strs(path+"fields", item["fields"], &sub.Fields)
			manifest.Webhooks.Subscriptions = append(manifest.Webhooks.Subscriptions, sub)
		}
	}

	items, _ := applicationManifestTables(raw["extensions"])
	for i, item := range items {
		path := "extensions." + strconv.Itoa(i) + "."
		ext := ApplicationManifestExtension{}
		str(path+"type", item["type"], &ext.Type)
		str(path+"handle", item["handle"], &ext.Handle)
		str(path+"label", item["label"], &ext.Label)
		str(path+"path", item["path"], &ext.Path)
		str(path+"collection", item["collection"], &ext.Collection)
		manifest.Extensions = append(manifest.Extensions, ext)
	}

	if proxy, ok := raw["app_proxy"].(map[string]any); ok {
		manifest.AppProxy = &ApplicationManifestAppProxy{}
		str("app_proxy.url", proxy["url"], &manifest.AppProxy.URL)
		str("app_proxy.prefix", proxy["prefix"], &manifest.AppProxy.Prefix)
		str("app_proxy.subpath", proxy["subpath"], &manifest.AppProxy.Subpath)
	}

	if len(errs) > 0 {
		return nil, errs
	}

	manifest.Normalize()

	return manifest, nil
}

// Normalize trims the manifest values and sorts/dedupes its scopes lists.
func (m *ApplicationManifest) Normalize() {
	m.Handle = strings.TrimSpace(m.Handle)
	m.Name = strings.TrimSpace(m.Name)
	m.Version = strings.TrimSpace(m.Version)
	m.Description = strings.TrimSpace(m.Description)
	m.ApplicationURL = strings.TrimSpace(m.ApplicationURL)
	m.Developer.Name = strings.TrimSpace(m.Developer.Name)
	m.Developer.URL = strings.TrimSpace(m.Developer.URL)
	m.InstallURL = strings.TrimSpace(m.InstallURL)
	m.UninstallURL = strings.TrimSpace(m.UninstallURL)
	m.IconURL = strings.TrimSpace(m.IconURL)

	normalizeScopes := func(scopes []string) []string {
		scopes = slices.Clone(scopes)
		for i, scope := range scopes {
			if scope == ApplicationProxyManifestScope {
				scopes[i] = OAuth2SystemScope(PermissionResourceAppProxy, PermissionLevelWrite)
			}
		}

		result := list.ToUniqueStringSlice(scopes)
		result = slices.DeleteFunc(result, func(s string) bool { return s == "" })
		sort.Strings(result)
		return result
	}

	m.Access.Scopes = normalizeScopes(m.Access.Scopes)
	m.Access.OptionalScopes = normalizeScopes(m.Access.OptionalScopes)

	// note: the subscriptions order is kept (the managed webhooks are synced by position)
	for i := range m.Webhooks.Subscriptions {
		sub := &m.Webhooks.Subscriptions[i]
		sub.URI = strings.TrimSpace(sub.URI)
		sub.Filter = strings.TrimSpace(sub.Filter)
		sub.Topics = list.ToUniqueStringSlice(slices.DeleteFunc(slices.Clone(sub.Topics), func(s string) bool {
			return strings.TrimSpace(s) == ""
		}))
		if len(sub.Fields) == 0 {
			sub.Fields = nil
		}
	}
	if len(m.Webhooks.Subscriptions) == 0 {
		m.Webhooks.Subscriptions = nil
	}

	// note: the extensions order is kept (it is the dashboard display order)
	for i := range m.Extensions {
		ext := &m.Extensions[i]
		ext.Type = strings.TrimSpace(ext.Type)
		ext.Handle = strings.TrimSpace(ext.Handle)
		ext.Label = strings.TrimSpace(ext.Label)
		ext.Path = strings.TrimSpace(ext.Path)
		ext.Collection = strings.TrimSpace(ext.Collection)
	}
	if len(m.Extensions) == 0 {
		m.Extensions = nil
	}

	if m.AppProxy != nil {
		m.AppProxy.URL = strings.TrimSpace(m.AppProxy.URL)
		m.AppProxy.Prefix = strings.TrimSpace(m.AppProxy.Prefix)
		m.AppProxy.Subpath = strings.TrimSpace(m.AppProxy.Subpath)
	}
}

// Validate validates the (already normalized) manifest fields.
func (m *ApplicationManifest) Validate() error {
	errs := validation.Errors{}

	set := func(key string, err error) {
		if err != nil {
			errs[key] = err
		}
	}

	set("handle", validation.Validate(m.Handle, validation.Required, validation.Match(applicationHandleRegex).
		Error("Must be 2-63 lowercase letters, numbers or dashes (and it must not start with a dash).")))
	set("name", validation.Validate(m.Name, validation.Required, validation.Length(1, 100)))
	set("version", validation.Validate(m.Version, validation.Required, validation.Length(1, 50), validation.Match(applicationVersionRegex).
		Error("Must be a semver-like version (e.g. 1.0.0 or 1.2.0-beta.1).")))
	set("description", validation.Validate(m.Description, validation.Length(0, 1000)))
	set("application_url", validation.Validate(m.ApplicationURL, validation.Length(0, 2000), validation.By(checkApplicationHTTPURL)))
	set("developer.name", validation.Validate(m.Developer.Name, validation.Length(0, 100)))
	set("developer.url", validation.Validate(m.Developer.URL, validation.Length(0, 2000), validation.By(checkApplicationHTTPURL)))
	set("access.scopes", validation.Validate(m.Access.Scopes, validation.Length(0, 500), validation.Each(validation.By(checkApplicationScope))))
	set("access.optional_scopes", validation.Validate(m.Access.OptionalScopes, validation.Length(0, 500), validation.Each(validation.By(checkApplicationScope))))
	set("install_url", validation.Validate(m.InstallURL, validation.Length(0, 2000), validation.By(checkApplicationNotificationURL), validation.By(m.checkApplicationHost)))
	set("icon_url", validation.Validate(m.IconURL, validation.Length(0, 2000), validation.By(checkApplicationNotificationURL)))
	set("uninstall_url", validation.Validate(m.UninstallURL, validation.Length(0, 2000), validation.By(checkApplicationNotificationURL), validation.By(m.checkApplicationHost)))

	if len(m.Webhooks.Subscriptions) > applicationManifestMaxWebhooks {
		set("webhooks.subscriptions", validation.NewError(
			"validation_too_many_webhooks",
			fmt.Sprintf("Max %d webhook subscriptions are allowed.", applicationManifestMaxWebhooks),
		))
	}
	for i, sub := range m.Webhooks.Subscriptions {
		path := "webhooks.subscriptions." + strconv.Itoa(i) + "."
		set(path+"topics", validation.Validate(sub.Topics, validation.Required, validation.Length(1, 50), validation.Each(validation.By(checkApplicationWebhookTopic))))
		set(path+"uri", validation.Validate(sub.URI, validation.Required, validation.Length(1, 2000), validation.By(checkApplicationNotificationURL)))
		set(path+"filter", validation.Validate(sub.Filter, validation.Length(0, 2000)))
		set(path+"fields", validation.Validate(sub.Fields, validation.Length(0, 100), validation.By(checkWebhookFields)))
	}

	if len(m.Extensions) > applicationManifestMaxExtensions {
		set("extensions", validation.NewError(
			"validation_too_many_extensions",
			fmt.Sprintf("Max %d extensions are allowed.", applicationManifestMaxExtensions),
		))
	}
	handles := map[string]struct{}{}
	for i, ext := range m.Extensions {
		path := "extensions." + strconv.Itoa(i) + "."

		if !slices.Contains(ApplicationExtensionTypes, ext.Type) {
			set(path+"type", validation.NewError(
				"validation_unknown_extension_type",
				"Unknown extension type {{.type}} of the manifest key {{.key}} (expected one of {{.types}}).",
			).SetParams(map[string]any{"type": ext.Type, "key": path + "type", "types": strings.Join(ApplicationExtensionTypes, ", ")}))
		}

		set(path+"handle", validation.Validate(ext.Handle, validation.Required, validation.Match(applicationHandleRegex).
			Error("Must be 2-63 lowercase letters, numbers or dashes (and it must not start with a dash).")))
		if _, ok := handles[ext.Handle]; ok && ext.Handle != "" {
			set(path+"handle", validation.NewError("validation_duplicated_extension_handle", "The extension handles must be unique."))
		}
		handles[ext.Handle] = struct{}{}

		set(path+"label", validation.Validate(ext.Label, validation.Required, validation.Length(1, 100)))
		set(path+"path", validation.Validate(ext.Path, validation.Required, validation.Length(1, 2000), validation.By(m.checkApplicationExtensionPath)))

		if ext.Type == ApplicationExtensionTypeRecordAction {
			set(path+"collection", validation.Validate(ext.Collection, validation.Required, validation.Length(1, 255), validation.Match(applicationCollectionNameRegex).
				Error("Must be a valid collection name.")))
		} else if ext.Collection != "" {
			set(path+"collection", validation.NewError(
				"validation_extension_collection_not_allowed",
				"The collection is allowed only for the {{.type}} extensions.",
			).SetParams(map[string]any{"type": ApplicationExtensionTypeRecordAction}))
		}
	}

	if proxy := m.AppProxy; proxy != nil {
		set("app_proxy.url", validation.Validate(proxy.URL, validation.Required, validation.Length(1, 2000), validation.By(checkApplicationNotificationURL), validation.By(m.checkApplicationHost), validation.By(checkApplicationProxyURLShape)))
		set("app_proxy.prefix", validation.Validate(proxy.Prefix, validation.Required, validation.By(checkApplicationProxyPrefix)))
		set("app_proxy.subpath", validation.Validate(proxy.Subpath, validation.Required, validation.By(checkApplicationProxySubpath)))

		if !slices.Contains(applicationManifestAllowedScopes(m), OAuth2SystemScope(PermissionResourceAppProxy, PermissionLevelWrite)) {
			set("access.scopes", validation.NewError(
				"validation_app_proxy_scope_required",
				"The app_proxy table requires the "+ApplicationProxyManifestScope+" scope.",
			))
		}
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}

// FindExtension returns the manifest extension with the provided handle (if any).
func (m *ApplicationManifest) FindExtension(handle string) (ApplicationManifestExtension, bool) {
	for _, ext := range m.Extensions {
		if ext.Handle == handle {
			return ext, true
		}
	}

	return ApplicationManifestExtension{}, false
}

// ExtensionURL returns the absolute launch URL of the provided extension
// (the application_url origin + the extension path; always on the application_url host).
func (m *ApplicationManifest) ExtensionURL(ext ApplicationManifestExtension) (string, error) {
	appURL, err := url.Parse(m.ApplicationURL)
	if m.ApplicationURL == "" || err != nil || appURL.Host == "" || (appURL.Scheme != "http" && appURL.Scheme != "https") {
		return "", errors.New("the extensions require a valid application_url")
	}

	if err := checkApplicationExtensionPathFormat(ext.Path); err != nil {
		return "", err
	}

	result := appURL.Scheme + "://" + appURL.Host + ext.Path

	// defense in depth (the path format already guarantees it)
	parsed, err := url.Parse(result)
	if err != nil || !strings.EqualFold(parsed.Host, appURL.Host) || parsed.Scheme != appURL.Scheme {
		return "", errors.New("the extension URL must be on the application_url host")
	}

	return result, nil
}

// checkApplicationExtensionPath checks the extension path format
// and that the manifest has an application_url (the extension URL origin).
func (m *ApplicationManifest) checkApplicationExtensionPath(value any) error {
	v, _ := value.(string)
	if v == "" {
		return nil // nonempty state is validated separately
	}

	if err := checkApplicationExtensionPathFormat(v); err != nil {
		return validation.NewError("validation_invalid_extension_path", err.Error())
	}

	if _, err := m.ExtensionURL(ApplicationManifestExtension{Path: v}); err != nil {
		return validation.NewError("validation_extension_application_url", "The extensions require an application_url (the extension URL is the application_url origin + path).")
	}

	return nil
}

// checkApplicationExtensionPathFormat checks that the provided extension path is a relative
// path that could only be resolved on the application_url host (no scheme, host or "//").
func checkApplicationExtensionPathFormat(path string) error {
	invalid := errors.New("The path must be relative to the application_url origin (it must start with a single \"/\" and it can't have a scheme or host).")

	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\ \t\r\n") {
		return invalid
	}

	u, err := url.Parse(path)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return invalid
	}

	return nil
}

// JSON returns the canonical JSON serialization of the manifest
// (the stored _applicationVersions.manifest value).
func (m *ApplicationManifest) JSON() ([]byte, error) {
	return json.Marshal(m, json.Deterministic(true))
}

// Digest returns the hex encoded sha256 digest of the canonical manifest JSON.
func (m *ApplicationManifest) Digest() (string, error) {
	raw, err := m.JSON()
	if err != nil {
		return "", err
	}

	return security.SHA256(string(raw)), nil
}

func checkApplicationHTTPURL(value any) error {
	v, _ := value.(string)
	if v == "" {
		return nil
	}

	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return validation.NewError("validation_invalid_url", "Must be a valid http(s) URL.")
	}

	return nil
}

// checkApplicationNotificationURL checks that the provided url is an https url
// (http is accepted only for the loopback hosts, e.g. for local development;
// the send time checks are in [checkApplicationRemoteURL]).
func checkApplicationNotificationURL(value any) error {
	v, _ := value.(string)
	if v == "" {
		return nil
	}

	u, err := url.Parse(v)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" ||
		(u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackURLHost(u))) {
		return validation.NewError("validation_invalid_https_url", "Must be a valid https URL (http is allowed only for the loopback hosts).")
	}

	return nil
}

// checkApplicationHost checks that the provided url host is the same as the application_url host.
func (m *ApplicationManifest) checkApplicationHost(value any) error {
	v, _ := value.(string)
	if v == "" {
		return nil
	}

	u, err := url.Parse(v)
	if err != nil {
		return nil // reported by the url format check
	}

	appURL, err := url.Parse(m.ApplicationURL)
	if m.ApplicationURL == "" || err != nil || !strings.EqualFold(appURL.Host, u.Host) {
		return validation.NewError("validation_application_host_mismatch", "The url host must be the same as the application_url host.")
	}

	return nil
}

// checkApplicationWebhookTopic checks the manifest webhook topic format
// (the topic collections are resolved and checked against the installation grant on install).
func checkApplicationWebhookTopic(value any) error {
	v, _ := value.(string)

	ns, op, ok := splitWebhookTopic(v)
	if ok && strings.EqualFold(ns, ApplicationLifecycleTopicNamespace) {
		return validation.NewError(
			"validation_webhook_topic_application_lifecycle",
			"The applications can't subscribe to the {{.namespace}}.* lifecycle topics (use the install_url/uninstall_url notifications).",
		).SetParams(map[string]any{"namespace": ApplicationLifecycleTopicNamespace})
	}

	if !ok || ns == WebhookTopicWildcard || !webhookTopicPartRegex.MatchString(ns) || !webhookTopicPartRegex.MatchString(op) {
		return validation.NewError(
			"validation_invalid_webhook_topic",
			"Invalid topic {{.topic}} (expected {collection}.{operation} or {namespace}.{name}; the wildcards are not allowed).",
		).SetParams(map[string]any{"topic": v})
	}

	return nil
}

// checkApplicationScope checks the application scope format:
//   - a collection scope read_{name} or write_{name} (the collection could be missing
//     on this instance since the same manifest could be deployed to multiple instances)
//   - or an application grantable system scope system:read_{resource} or system:write_{resource}
func checkApplicationScope(value any) error {
	v, _ := value.(string)

	if IsOAuth2SystemScope(v) {
		if !isApplicationGrantableSystemScope(v) {
			return validation.NewError("validation_invalid_application_scope", "The system scope {{.scope}} cannot be granted to an application.").
				SetParams(map[string]any{"scope": v})
		}
		return nil
	}

	if !applicationCollectionScopeRegex.MatchString(v) {
		return validation.NewError("validation_invalid_application_scope", "Invalid scope {{.scope}} (expected read_{collection}, write_{collection} or system:{read|write}_{resource}).").
			SetParams(map[string]any{"scope": v})
	}

	return nil
}

// isApplicationGrantableSystemScope reports whether the provided scope is a system scope
// of an application grantable system resource level (e.g. "system:read_logs").
func isApplicationGrantableSystemScope(scope string) bool {
	name, ok := strings.CutPrefix(scope, OAuth2ScopePrefixSystem)
	if !ok {
		return false
	}

	var level string
	switch {
	case strings.HasPrefix(name, OAuth2ScopePrefixWrite):
		name = strings.TrimPrefix(name, OAuth2ScopePrefixWrite)
		level = PermissionLevelWrite
	case strings.HasPrefix(name, OAuth2ScopePrefixRead):
		name = strings.TrimPrefix(name, OAuth2ScopePrefixRead)
		level = PermissionLevelRead
	default:
		return false
	}

	resource, ok := FindPermissionResource(name)

	return ok && resource.IsApplicationGrantableLevel(level)
}

// applicationManifestFromJSON parses a stored (canonical JSON) manifest.
func applicationManifestFromJSON(raw []byte) (*ApplicationManifest, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty application manifest")
	}

	return ParseApplicationManifest(raw, ApplicationManifestFormatJSON)
}
