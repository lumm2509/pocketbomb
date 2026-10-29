package core

import (
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// Applications (aka. extensions)
// -------------------------------------------------------------------
//
// An application (_applications) is described by immutable manifest versions
// (_applicationVersions) and it could be installed once (single tenant).
//
// The installation (_applicationInstallations) is an auth record and it is the actor
// of the application requests (actor kind "application"). Its permissions are the
// installation grant (never roles) and they are read live on every request.
//
// An application authenticates ONLY with its installation managed OAuth2 client: a confidential
// managed OAuth2 client that exchanges its client_id + client_secret at the
// {issuer}/token endpoint (grant_type=client_credentials) for a short-lived access token
// (there is no other application authentication mechanism).
//
// An installation of an application with an install_url is pending until the application
// acknowledged the signed install notification (with its credentials) and only the active
// installations could obtain and use access tokens (see [App.InstallApplication]).
//
// Model level invariants (enforced for every save path):
//   - the versions are immutable and they could be deleted only when not installed
//   - the installation grant is validated against the registry (application grantable resources only)
//     and the grant of a catalog application must be within its manifest scopes and optional scopes
//   - the managed OAuth2 clients and webhooks could be changed only through the installation
//   - roles cannot be assigned to the installations
//   - one installation per application

const (
	CollectionNameApplications             = "_applications"
	CollectionNameApplicationVersions      = "_applicationVersions"
	CollectionNameApplicationInstallations = "_applicationInstallations"
)

// Supported application sources.
const (
	ApplicationSourceCustom  = "custom"
	ApplicationSourceCatalog = "catalog"
)

// Application installation statuses.
const (
	ApplicationInstallationStatusPending = "pending"
	ApplicationInstallationStatusActive  = "active"
)

// applicationPendingInstallationMaxAge is the max age of a pending installation
// (the older ones are deleted by the auth sessions cleanup cron).
const applicationPendingInstallationMaxAge = 10 * time.Minute

// applicationWebhookSecretLength is the length of the installation managed webhooks secret.
const applicationWebhookSecretLength = 40

// ApplicationInstallationTokenDuration is the default access token duration
// of the _applicationInstallations issuer (in seconds).
const ApplicationInstallationTokenDuration = 3600

// applicationManagedClientIdPrefix is the client_id prefix of the managed OAuth2 clients.
const applicationManagedClientIdPrefix = "pbapp_"

var (
	_ Model        = (*Application)(nil)
	_ PreValidator = (*Application)(nil)
	_ RecordProxy  = (*Application)(nil)

	_ Model        = (*ApplicationVersion)(nil)
	_ PreValidator = (*ApplicationVersion)(nil)
	_ RecordProxy  = (*ApplicationVersion)(nil)

	_ Model        = (*ApplicationInstallation)(nil)
	_ PreValidator = (*ApplicationInstallation)(nil)
	_ RecordProxy  = (*ApplicationInstallation)(nil)
)

func newApplicationsProxyRecord(app App, collectionName string) *Record {
	c, err := app.FindCachedCollectionByNameOrId(collectionName)
	if err != nil {
		// this is just to make tests easier since it is a system collection and it is expected to be always accessible
		// (note: the loaded record is further checked on PreValidate())
		c = NewBaseCollection("@__invalid__")
	}

	return NewRecord(c)
}

// -------------------------------------------------------------------
// Application
// -------------------------------------------------------------------

// Application defines a Record proxy for working with the applications collection.
type Application struct {
	*Record
}

// NewApplication instantiates and returns a new blank *Application model.
//
// Prefer [App.ImportApplicationManifest] for creating applications.
func NewApplication(app App) *Application {
	return &Application{newApplicationsProxyRecord(app, CollectionNameApplications)}
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *Application) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameApplications {
		return errors.New("missing or invalid application ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *Application) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *Application) SetProxyRecord(record *Record) {
	m.Record = record
}

// Handle returns the "handle" record field value.
func (m *Application) Handle() string {
	return m.GetString("handle")
}

// Name returns the "name" record field value.
func (m *Application) Name() string {
	return m.GetString("name")
}

// Source returns the "source" record field value (custom or catalog).
func (m *Application) Source() string {
	return m.GetString("source")
}

// LatestVersionRef returns the "latestVersionRef" record field value.
func (m *Application) LatestVersionRef() string {
	return m.GetString("latestVersionRef")
}

// loadManifest copies the manifest metadata into the application fields.
func (m *Application) loadManifest(manifest *ApplicationManifest) {
	m.Set("handle", manifest.Handle)
	m.Set("name", manifest.Name)
	m.Set("description", manifest.Description)
	m.Set("applicationURL", manifest.ApplicationURL)
	m.Set("developerName", manifest.Developer.Name)
	m.Set("developerURL", manifest.Developer.URL)
}

// -------------------------------------------------------------------
// ApplicationVersion
// -------------------------------------------------------------------

// ApplicationVersion defines a Record proxy for working with the (immutable) application versions collection.
type ApplicationVersion struct {
	*Record
}

// NewApplicationVersion instantiates and returns a new blank *ApplicationVersion model.
func NewApplicationVersion(app App) *ApplicationVersion {
	return &ApplicationVersion{newApplicationsProxyRecord(app, CollectionNameApplicationVersions)}
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *ApplicationVersion) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameApplicationVersions {
		return errors.New("missing or invalid application version ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *ApplicationVersion) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *ApplicationVersion) SetProxyRecord(record *Record) {
	m.Record = record
}

// ApplicationRef returns the "applicationRef" record field value.
func (m *ApplicationVersion) ApplicationRef() string {
	return m.GetString("applicationRef")
}

// Version returns the "version" record field value.
func (m *ApplicationVersion) Version() string {
	return m.GetString("version")
}

// ManifestDigest returns the "manifestDigest" record field value.
func (m *ApplicationVersion) ManifestDigest() string {
	return m.GetString("manifestDigest")
}

// Manifest returns the parsed normalized "manifest" record field value.
func (m *ApplicationVersion) Manifest() (*ApplicationManifest, error) {
	return applicationManifestFromJSON(m.manifestRaw())
}

func (m *ApplicationVersion) manifestRaw() []byte {
	switch v := m.GetRaw("manifest").(type) {
	case types.JSONRaw:
		return v
	case []byte:
		return v
	case string:
		return []byte(v)
	case nil:
		return nil
	default:
		raw, _ := json.Marshal(v)
		return raw
	}
}

// -------------------------------------------------------------------
// ApplicationInstallation
// -------------------------------------------------------------------

// ApplicationInstallation defines a Record proxy for working with the
// application installations auth collection (aka. the application actors).
type ApplicationInstallation struct {
	*Record
}

// NewApplicationInstallation instantiates and returns a new blank *ApplicationInstallation model.
//
// Prefer [App.InstallApplication] since it also creates the managed OAuth2 client.
func NewApplicationInstallation(app App) *ApplicationInstallation {
	return &ApplicationInstallation{newApplicationsProxyRecord(app, CollectionNameApplicationInstallations)}
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *ApplicationInstallation) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameApplicationInstallations {
		return errors.New("missing or invalid application installation ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *ApplicationInstallation) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *ApplicationInstallation) SetProxyRecord(record *Record) {
	m.Record = record
}

// ApplicationRef returns the "applicationRef" record field value.
func (m *ApplicationInstallation) ApplicationRef() string {
	return m.GetString("applicationRef")
}

// VersionRef returns the "versionRef" record field value.
func (m *ApplicationInstallation) VersionRef() string {
	return m.GetString("versionRef")
}

// SetVersionRef updates the "versionRef" record field value.
func (m *ApplicationInstallation) SetVersionRef(versionId string) {
	m.Set("versionRef", versionId)
}

// Permissions returns the normalized installation grant ("permissions" record field value).
func (m *ApplicationInstallation) Permissions() Permissions {
	return parseRolePermissions(m.Get("permissions"))
}

// SetPermissions updates the installation grant ("permissions" record field value).
func (m *ApplicationInstallation) SetPermissions(permissions Permissions) {
	permissions = permissions.Clone()
	permissions.Normalize()
	m.Set("permissions", permissions)
}

// InstalledBy returns the "installedBy" record field value (the installer staff record id, if any).
func (m *ApplicationInstallation) InstalledBy() string {
	return m.GetString("installedBy")
}

// SecretRotatedAt returns the "secretRotatedAt" record field value.
func (m *ApplicationInstallation) SecretRotatedAt() types.DateTime {
	return m.GetDateTime("secretRotatedAt")
}

// Status returns the "status" record field value (pending or active).
func (m *ApplicationInstallation) Status() string {
	return m.GetString("status")
}

// IsActive reports whether the installation is active (aka. it could obtain and use access tokens).
func (m *ApplicationInstallation) IsActive() bool {
	return m.Status() == ApplicationInstallationStatusActive
}

// WebhookSecret returns the "webhookSecret" record field value
// (the signing secret shared by the installation managed webhooks).
func (m *ApplicationInstallation) WebhookSecret() string {
	return m.GetString("webhookSecret")
}

// -------------------------------------------------------------------
// Model level invariants
// -------------------------------------------------------------------

func (app *BaseApp) registerApplicationHooks() {
	// applications
	app.OnRecordValidate(CollectionNameApplications).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			errs := validation.Errors{}

			if err := validation.Validate(e.Record.GetString("handle"), validation.Required, validation.Match(applicationHandleRegex)); err != nil {
				errs["handle"] = err
			}

			if icon := e.Record.GetString("iconURL"); icon != "" && SafeApplicationIconURL(icon) == "" {
				errs["iconURL"] = validation.NewError("validation_invalid_application_icon", "The application icon must be an inlined png, jpeg, webp or gif data: URI.")
			}

			if !e.Record.IsNew() && e.Record.Original().GetString("handle") != e.Record.GetString("handle") {
				errs["handle"] = validation.NewError("validation_application_handle_change", "The application handle cannot be changed.")
			}

			if latest := e.Record.GetString("latestVersionRef"); latest != "" {
				version, err := e.App.FindApplicationVersionById(latest)
				if err != nil || version.ApplicationRef() != e.Record.Id {
					errs["latestVersionRef"] = validation.NewError("validation_invalid_version", "The version must belong to the application.")
				}
			}

			if len(errs) > 0 {
				return errs
			}

			return e.Next()
		},
		Priority: 99,
	})

	// versions: normalize the manifest and its digest on create
	app.OnRecordCreate(CollectionNameApplicationVersions).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			manifest, err := applicationManifestFromJSON((&ApplicationVersion{e.Record}).manifestRaw())
			if err == nil {
				if normalized, err := manifest.JSON(); err == nil {
					e.Record.Set("manifest", types.JSONRaw(normalized))
					e.Record.Set("manifestDigest", security.SHA256(string(normalized)))
				}
			}

			return e.Next()
		},
		Priority: -99,
	})

	app.OnRecordValidate(CollectionNameApplicationVersions).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			version := &ApplicationVersion{e.Record}

			manifest, err := version.Manifest()
			if err != nil {
				return validation.Errors{"manifest": validation.NewError("validation_invalid_manifest", "Invalid application manifest: "+err.Error())}
			}

			application, err := e.App.FindApplicationById(version.ApplicationRef())
			if err != nil {
				return validation.Errors{"applicationRef": validation.NewError("validation_invalid_application", "Missing or invalid application.")}
			}

			if manifest.Handle != application.Handle() {
				return validation.Errors{"manifest": validation.NewError("validation_manifest_handle_mismatch", "The manifest handle must match the application handle.")}
			}

			if manifest.Version != version.Version() {
				return validation.Errors{"version": validation.NewError("validation_manifest_version_mismatch", "The version must match the manifest version.")}
			}

			if digest, _ := manifest.Digest(); digest != version.ManifestDigest() {
				return validation.Errors{"manifestDigest": validation.NewError("validation_manifest_digest_mismatch", "Invalid manifest digest.")}
			}

			return e.Next()
		},
		Priority: 99,
	})

	// versions are immutable (any save path, incl. SaveNoValidate)
	app.OnRecordUpdate(CollectionNameApplicationVersions).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			return validation.Errors{"version": validation.NewError("validation_application_version_immutable", "The application versions are immutable.")}
		},
		Priority: -99,
	})

	// versions could be deleted only when not installed
	app.OnRecordDelete(CollectionNameApplicationVersions).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			var total int
			err := e.App.RecordQuery(CollectionNameApplicationInstallations).
				Select("count(*)").
				AndWhere(dbx.HashExp{"versionRef": e.Record.Id}).
				Row(&total)
			if err != nil {
				return err
			}

			if total > 0 {
				return errors.New("the application version is installed and cannot be deleted")
			}

			return e.Next()
		},
		Priority: -99,
	})

	// installations
	app.OnRecordCreate(CollectionNameApplicationInstallations).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			// the installations never authenticate with a password
			// (the field is required by the auth collections)
			if e.Record.GetString(FieldNamePassword) == "" {
				e.Record.SetRandomPassword()
			}

			// the installations without install notification are active right away
			if e.Record.GetString("status") == "" {
				e.Record.Set("status", ApplicationInstallationStatusActive)
			}

			if e.Record.GetString("webhookSecret") == "" {
				e.Record.Set("webhookSecret", security.RandomString(applicationWebhookSecretLength))
			}

			return e.Next()
		},
		Priority: -99,
	})

	app.OnRecordValidate(CollectionNameApplicationInstallations).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			errs := validation.Errors{}

			if err := parseRolePermissions(e.Record.Get("permissions")).ValidateApplicationGrant(e.App); err != nil {
				errs["permissions"] = err
			}

			applicationId := e.Record.GetString("applicationRef")

			if !e.Record.IsNew() && e.Record.Original().GetString("applicationRef") != applicationId {
				errs["applicationRef"] = validation.NewError("validation_installation_application_change", "The installation application cannot be changed.")
			}

			version, err := e.App.FindApplicationVersionById(e.Record.GetString("versionRef"))
			if err != nil || version.ApplicationRef() != applicationId {
				errs["versionRef"] = validation.NewError("validation_invalid_version", "The version must belong to the installed application.")
			} else if errs["permissions"] == nil {
				// the catalog applications grant must be within the manifest scopes and optional scopes
				application, err := e.App.FindApplicationById(applicationId)
				manifest, manifestErr := version.Manifest()
				if err == nil && manifestErr == nil && application.Source() == ApplicationSourceCatalog {
					exceeding := applicationGrantExceedingScopes(e.App, parseRolePermissions(e.Record.Get("permissions")), applicationManifestAllowedScopes(manifest))
					if len(exceeding) > 0 {
						errs["permissions"] = validation.NewError(
							"validation_grant_exceeds_manifest_scopes",
							"The grant exceeds the application requested scopes and optional scopes ({{.scopes}}).",
						).SetParams(map[string]any{"scopes": strings.Join(exceeding, ", ")})
					}
				}
			}

			if !e.Record.IsNew() &&
				e.Record.Original().GetString("status") == ApplicationInstallationStatusActive &&
				e.Record.GetString("status") != ApplicationInstallationStatusActive {
				errs["status"] = validation.NewError("validation_installation_status_change", "An active installation cannot become pending again.")
			}

			if len(errs) > 0 {
				return errs
			}

			return e.Next()
		},
		Priority: 99,
	})

	// the webhook subscriptions of an uninstalled application are deleted
	// (they could no longer receive anything anyway, see [webhookActorCanView])
	app.OnRecordDeleteExecute(CollectionNameApplicationInstallations).Bind(&hook.Handler[*RecordEvent]{
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

				if _, err := txApp.FindCachedCollectionByNameOrId(CollectionNameWebhooks); err != nil {
					return nil
				}

				webhooks, err := txApp.FindAllRecords(CollectionNameWebhooks, dbx.HashExp{"actorRef": WebhookActorRef(e.Record)})
				if err != nil {
					return err
				}

				for _, w := range webhooks {
					if err := txApp.Delete(w); err != nil {
						return err
					}
				}

				return nil
			})
		},
		Priority: 99,
	})

	// roles cannot be assigned to the installations (their permissions are the grant)
	app.OnRecordValidate(CollectionNameRoleAssignments).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			installations, err := e.App.FindCachedCollectionByNameOrId(CollectionNameApplicationInstallations)
			if err == nil && e.Record.GetString("collectionRef") == installations.Id {
				return validation.Errors{"collectionRef": validation.NewError(
					"validation_installation_roles",
					"Roles cannot be assigned to the application installations (their permissions are the installation grant).",
				)}
			}

			return e.Next()
		},
		Priority: 98,
	})

	// the installations collection options are fixed: no login methods, no API rules and no default roles
	app.OnCollectionValidate().Bind(&hook.Handler[*CollectionEvent]{
		Func: func(e *CollectionEvent) error {
			if e.Collection.Name != CollectionNameApplicationInstallations {
				return e.Next()
			}

			c := e.Collection

			errs := validation.Errors{}
			fixed := func(key string, invalid bool) {
				if invalid {
					errs[key] = validation.NewError(
						"validation_installations_collection_fixed",
						"The "+CollectionNameApplicationInstallations+" collection option cannot be changed.",
					)
				}
			}

			fixed("passwordAuth", c.PasswordAuth.Enabled)
			fixed("otp", c.OTP.Enabled)
			fixed("oauth2", c.OAuth2.Enabled)
			fixed("mfa", c.MFA.Enabled)
			fixed("defaultRoles", len(c.DefaultRoles) > 0)
			fixed("listRule", c.ListRule != nil)
			fixed("viewRule", c.ViewRule != nil)
			fixed("createRule", c.CreateRule != nil)
			fixed("updateRule", c.UpdateRule != nil)
			fixed("deleteRule", c.DeleteRule != nil)
			fixed("authRule", c.AuthRule != nil)
			fixed("manageRule", c.ManageRule != nil)

			if len(errs) > 0 {
				return errs
			}

			return e.Next()
		},
		Priority: 99,
	})

	// managed OAuth2 clients could be changed only through their installation
	managedClientGuard := &hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			managed := e.Record.GetString("applicationInstallationRef") != "" ||
				(!e.Record.IsNew() && e.Record.Original().GetString("applicationInstallationRef") != "")

			if managed && !isManagedOAuth2ClientChange(e.Context) {
				return errManagedOAuth2Client
			}

			return e.Next()
		},
		Priority: -99,
	}
	app.OnRecordCreate(CollectionNameOAuth2Clients).Bind(managedClientGuard)
	app.OnRecordUpdate(CollectionNameOAuth2Clients).Bind(managedClientGuard)
	app.OnRecordDelete(CollectionNameOAuth2Clients).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			installationId := e.Record.GetString("applicationInstallationRef")
			if installationId == "" || isManagedOAuth2ClientChange(e.Context) {
				return e.Next()
			}

			// deleted together with its installation (relation cascade in the same transaction)
			if _, err := e.App.FindApplicationInstallationById(installationId); err != nil {
				return e.Next()
			}

			return errManagedOAuth2Client
		},
		Priority: -99,
	})

	// managed webhooks could be changed only through their installation
	managedWebhookGuard := &hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			managed := e.Record.GetString("applicationInstallationRef") != "" ||
				(!e.Record.IsNew() && e.Record.Original().GetString("applicationInstallationRef") != "")

			if managed && !isManagedWebhookChange(e.Context) {
				return errManagedWebhook
			}

			return e.Next()
		},
		Priority: -99,
	}
	app.OnRecordCreate(CollectionNameWebhooks).Bind(managedWebhookGuard)
	app.OnRecordUpdate(CollectionNameWebhooks).Bind(managedWebhookGuard)
	app.OnRecordDelete(CollectionNameWebhooks).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			installationId := e.Record.GetString("applicationInstallationRef")
			if installationId == "" || isManagedWebhookChange(e.Context) {
				return e.Next()
			}

			// deleted together with its installation (relation cascade in the same transaction)
			if _, err := e.App.FindApplicationInstallationById(installationId); err != nil {
				return e.Next()
			}

			return errManagedWebhook
		},
		Priority: -99,
	})

	// uninstall notification and lifecycle webhook (any delete path; sent after the commit)
	app.OnRecordDelete(CollectionNameApplicationInstallations).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			app.prepareApplicationUninstall(e.App, e.Record)

			err := e.Next()
			if err != nil {
				app.completeApplicationUninstall(e.Record.Id, false)
			}

			return err
		},
		Priority: -99,
	})
	app.OnRecordAfterDeleteSuccess(CollectionNameApplicationInstallations).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			app.completeApplicationUninstall(e.Record.Id, true)
			return e.Next()
		},
		Priority: -99,
	})
	app.OnRecordAfterDeleteError(CollectionNameApplicationInstallations).Bind(&hook.Handler[*RecordErrorEvent]{
		Func: func(e *RecordErrorEvent) error {
			app.completeApplicationUninstall(e.Record.Id, false)
			return e.Next()
		},
		Priority: -99,
	})

	// the lifecycle custom webhook topics (registered after the collections are loaded
	// since the custom topic namespace must not clash with a collection)
	app.OnBootstrap().Bind(&hook.Handler[*BootstrapEvent]{
		Func: func(e *BootstrapEvent) error {
			if err := e.Next(); err != nil {
				return err
			}

			for topic, description := range applicationLifecycleTopics {
				if err := app.webhooks.RegisterTopic(topic, description); err != nil {
					app.Logger().Warn("Failed to register the application lifecycle webhook topic", slog.String("topic", topic), slog.String("error", err.Error()))
				}
			}

			return nil
		},
	})
}
