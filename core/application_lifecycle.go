package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// Applications lifecycle (install, update, rotate, uninstall)
// -------------------------------------------------------------------
//
// Install: the installation (pending if the manifest has an install_url), its managed OAuth2
// client and its managed webhooks are created in a single transaction. Then (outside of the
// transaction) the credentials are POSTed to the install_url as a JWT signed with the active
// signing key of the _applicationInstallations issuer. A 2xx response activates the installation,
// otherwise everything is deleted again (the stale pending installations are also deleted
// by the auth sessions cleanup cron).
//
// The managed webhooks are synced with the installed manifest version on install and update
// (by position) and they share the installation webhook secret (rotated with the client secret).
//
// Uninstall (any delete path): the sessions, the managed client and the managed webhooks are deleted
// (relation cascade) and after the commit a signed "application.uninstalled" notification is sent
// to the uninstall_url (best-effort, failures are only logged).
//
// The lifecycle custom webhook topics application.installed, application.uninstalled and
// application.scopes_update are triggered for the active installations.

// ErrApplicationUpdateRequiresApproval is returned when an installation version update requests
// scopes beyond the previous version and the current grant without an explicitly submitted grant
// (the grant never grows automatically).
var ErrApplicationUpdateRequiresApproval = validation.NewError(
	"validation_application_update_requires_approval",
	"The new version requests scopes beyond the current grant (submit the new permissions to approve them).",
)

// ApplicationInstallResult defines the [App.InstallApplication] result.
type ApplicationInstallResult struct {
	Installation *ApplicationInstallation
	Client       *OAuth2Client

	// ClientSecret is the plain client secret of the managed OAuth2 client
	// (it is returned only once; only its hash is stored).
	ClientSecret string

	// WebhookSecret is the signing secret of the installation managed webhooks.
	WebhookSecret string

	// Notified indicates whether the credentials were delivered to the
	// application install_url (aka. the application has an install_url).
	Notified bool
}

// InstallApplication installs the provided application (latest version) with the provided grant,
// creates its confidential managed OAuth2 client (client_credentials and token_exchange grants) and its managed
// webhooks and, if the manifest has an install_url, delivers the credentials with a signed install
// notification (the installation is activated only on a 2xx response, otherwise it is deleted and
// an [*ApplicationNotificationError] is returned).
//
// The catalog applications must have an install_url and their grant must be within the
// manifest scopes and optional scopes.
//
// installedBy is the optional staff record id that installed the application.
func (app *BaseApp) InstallApplication(application *Application, grant Permissions, installedBy string) (*ApplicationInstallResult, error) {
	event := new(ApplicationInstallEvent)
	event.App = app
	event.Application = application
	event.Permissions = grant
	event.InstalledBy = installedBy

	err := app.OnApplicationInstall().Trigger(event, func(e *ApplicationInstallEvent) error {
		result, err := app.installApplication(e.Application, e.Permissions, e.InstalledBy)
		e.Result = result
		return err
	})

	return event.Result, err
}

func (app *BaseApp) installApplication(application *Application, grant Permissions, installedBy string) (*ApplicationInstallResult, error) {
	if application == nil || application.Id == "" {
		return nil, errors.New("missing application")
	}

	if application.LatestVersionRef() == "" {
		return nil, validation.Errors{"versionRef": validation.NewError("validation_missing_version", "The application has no version.")}
	}

	version, err := app.FindApplicationVersionById(application.LatestVersionRef())
	if err != nil {
		return nil, err
	}

	manifest, err := version.Manifest()
	if err != nil {
		return nil, err
	}

	if application.Source() == ApplicationSourceCatalog && manifest.InstallURL == "" {
		return nil, validation.Errors{"install_url": validation.NewError("validation_catalog_install_url_required", "The catalog applications must have an install_url.")}
	}

	status := ApplicationInstallationStatusActive
	if manifest.InstallURL != "" {
		status = ApplicationInstallationStatusPending
	}

	result := &ApplicationInstallResult{
		ClientSecret:  security.RandomString(50),
		WebhookSecret: security.RandomString(applicationWebhookSecretLength),
	}

	txErr := app.RunInTransaction(func(txApp App) error {
		installation := NewApplicationInstallation(txApp)
		installation.Set("applicationRef", application.Id)
		installation.SetVersionRef(version.Id)
		installation.SetPermissions(grant)
		installation.Set("installedBy", installedBy)
		installation.Set("status", status)
		installation.Set("webhookSecret", result.WebhookSecret)
		if err := txApp.Save(installation); err != nil {
			return err
		}

		client := NewOAuth2Client(txApp)
		client.SetName(application.Name())
		client.SetClientId(applicationManagedClientIdPrefix + security.RandomStringWithAlphabet(24, "abcdefghijklmnopqrstuvwxyz0123456789"))
		client.SetType(OAuth2ClientTypeConfidential)
		client.SetCollectionRef(installation.Collection().Id)
		client.SetGrantTypes(slices.Clone(OAuth2ManagedClientGrantTypes))
		client.Set("applicationInstallationRef", installation.Id)
		client.SetClientSecret(result.ClientSecret)
		if err := txApp.SaveWithContext(withManagedOAuth2ClientChange(context.Background()), client); err != nil {
			return err
		}

		if err := syncApplicationManagedWebhooks(txApp, installation, application, manifest); err != nil {
			return err
		}

		result.Installation = installation
		result.Client = client

		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	scopes := ApplicationGrantScopes(app, result.Installation.Permissions())

	if status == ApplicationInstallationStatusPending {
		notifyErr := app.sendApplicationNotification(context.Background(), &applicationNotification{
			event:          ApplicationEventInstalled,
			url:            manifest.InstallURL,
			handle:         application.Handle(),
			version:        version.Version(),
			installationId: result.Installation.Id,
			clientId:       result.Client.ClientId(),
			scopes:         scopes,
			clientSecret:   result.ClientSecret,
			webhookSecret:  result.WebhookSecret,
		})
		if notifyErr != nil {
			// rollback (the pending installations are deleted without uninstall notifications)
			if err := app.Delete(result.Installation); err != nil {
				return nil, errors.Join(notifyErr, err)
			}
			return nil, notifyErr
		}

		fresh, err := app.FindApplicationInstallationById(result.Installation.Id)
		if err != nil {
			return nil, fmt.Errorf("the pending installation was deleted before its activation: %w", err)
		}

		fresh.Set("status", ApplicationInstallationStatusActive)
		if err := app.Save(fresh); err != nil {
			return nil, err
		}

		result.Installation = fresh
		result.Notified = true
	}

	app.triggerApplicationLifecycleWebhook(ApplicationEventInstalled, result.Installation.Id, application.Handle(), version.Version(), scopes)

	return result, nil
}

// RotateApplicationInstallationSecret generates a new client secret for the managed OAuth2 client
// and a new managed webhooks secret of the provided installation and ends every session of
// the installation (the installation tokenKey is also changed so that the old access tokens are rejected).
//
// The plain client secret is returned only once (only its hash is stored) and the new webhook
// secret is loaded in the provided installation.
//
// If the manifest of an active installation has an install_url, the new secrets are also delivered
// with a signed "application.credentials_rotated" notification. If it fails an [*ApplicationNotificationError]
// is returned together with the (already rotated) client and secret.
func (app *BaseApp) RotateApplicationInstallationSecret(installation *ApplicationInstallation) (*OAuth2Client, string, error) {
	event := new(ApplicationSecretRotateEvent)
	event.App = app
	event.Installation = installation

	err := app.OnApplicationSecretRotate().Trigger(event, func(e *ApplicationSecretRotateEvent) error {
		client, secret, err := app.rotateApplicationInstallationSecret(e.Installation)
		e.Client = client
		e.ClientSecret = secret
		return err
	})

	return event.Client, event.ClientSecret, err
}

func (app *BaseApp) rotateApplicationInstallationSecret(installation *ApplicationInstallation) (*OAuth2Client, string, error) {
	if installation == nil || installation.Id == "" {
		return nil, "", errors.New("missing application installation")
	}

	secret := security.RandomString(50)
	webhookSecret := security.RandomString(applicationWebhookSecretLength)

	var client *OAuth2Client

	txErr := app.RunInTransaction(func(txApp App) error {
		var err error

		client, err = txApp.FindApplicationInstallationClient(installation.Id)
		if err != nil {
			return fmt.Errorf("missing managed OAuth2 client: %w", err)
		}

		client.SetClientSecret(secret)
		if err := txApp.SaveWithContext(withManagedOAuth2ClientChange(context.Background()), client); err != nil {
			return err
		}

		fresh, err := txApp.FindApplicationInstallationById(installation.Id)
		if err != nil {
			return err
		}

		// note: the tokenKey change ends all installation sessions (see registerAuthSessionHooks)
		fresh.Set("secretRotatedAt", types.NowDateTime())
		fresh.Set("webhookSecret", webhookSecret)
		fresh.RefreshTokenKey()
		if err := txApp.Save(fresh); err != nil {
			return err
		}

		webhooks, err := txApp.FindAllWebhooksByApplicationInstallation(installation.Id)
		if err != nil {
			return err
		}
		for _, w := range webhooks {
			w.SetSecret(webhookSecret)
			if err := txApp.SaveWithContext(withManagedWebhookChange(context.Background()), w); err != nil {
				return err
			}
		}

		installation.SetProxyRecord(fresh.Record)

		return txApp.EndAllAuthSessionsByClient(client)
	})
	if txErr != nil {
		return nil, "", txErr
	}

	if installation.IsActive() {
		application, version, manifest, err := findApplicationInstallationManifest(app, installation)
		if err != nil {
			return client, secret, err
		}

		if manifest.InstallURL != "" {
			err := app.sendApplicationNotification(context.Background(), &applicationNotification{
				event:          ApplicationEventCredentialsRotated,
				url:            manifest.InstallURL,
				handle:         application.Handle(),
				version:        version.Version(),
				installationId: installation.Id,
				clientId:       client.ClientId(),
				scopes:         ApplicationGrantScopes(app, installation.Permissions()),
				clientSecret:   secret,
				webhookSecret:  webhookSecret,
			})
			if err != nil {
				return client, secret, err
			}
		}
	}

	return client, secret, nil
}

// UpdateApplicationInstallation changes the installation version and/or grant
// (an empty versionRef keeps the current version and a nil grant keeps the current grant)
// and re-syncs its managed webhooks with the installed manifest version.
//
// The grant never grows automatically: if the new version requests a scope that is neither
// in the previous version scopes (incl. the optional ones) nor in the current grant, the update
// requires an explicitly submitted grant (otherwise [ErrApplicationUpdateRequiresApproval] is returned).
//
// The "application.scopes_update" lifecycle webhook is triggered when the grant scopes change.
//
// The actor checks are performed by [CheckApplicationInstallationChange].
func (app *BaseApp) UpdateApplicationInstallation(installation *ApplicationInstallation, versionRef string, grant *Permissions) error {
	event := new(ApplicationInstallationUpdateEvent)
	event.App = app
	event.Installation = installation
	event.VersionRef = versionRef
	event.Permissions = grant

	return app.OnApplicationInstallationUpdate().Trigger(event, func(e *ApplicationInstallationUpdateEvent) error {
		return app.updateApplicationInstallation(e.Installation, e.VersionRef, e.Permissions)
	})
}

func (app *BaseApp) updateApplicationInstallation(installation *ApplicationInstallation, versionRef string, grant *Permissions) error {
	if installation == nil || installation.Id == "" {
		return errors.New("missing application installation")
	}

	var oldScopes []string
	var application *Application
	var version *ApplicationVersion

	txErr := app.RunInTransaction(func(txApp App) error {
		fresh, err := txApp.FindApplicationInstallationById(installation.Id)
		if err != nil {
			return err
		}

		oldScopes = ApplicationGrantScopes(txApp, fresh.Permissions())

		var oldManifest *ApplicationManifest
		application, _, oldManifest, err = findApplicationInstallationManifest(txApp, fresh)
		if err != nil {
			return err
		}

		if versionRef == "" {
			versionRef = fresh.VersionRef()
		}

		version, err = txApp.FindApplicationVersionById(versionRef)
		if err != nil || version.ApplicationRef() != application.Id {
			return validation.Errors{"versionRef": validation.NewError("validation_invalid_version", "The version must belong to the installed application.")}
		}

		manifest, err := version.Manifest()
		if err != nil {
			return err
		}

		if grant == nil && version.Id != fresh.VersionRef() && applicationVersionRequiresApproval(oldManifest, manifest, oldScopes) {
			return validation.Errors{"permissions": ErrApplicationUpdateRequiresApproval}
		}

		if grant != nil {
			fresh.SetPermissions(*grant)
		}
		fresh.SetVersionRef(version.Id)
		if fresh.WebhookSecret() == "" {
			fresh.Set("webhookSecret", security.RandomString(applicationWebhookSecretLength))
		}
		if err := txApp.Save(fresh); err != nil {
			return err
		}

		if err := syncApplicationManagedWebhooks(txApp, fresh, application, manifest); err != nil {
			return err
		}

		installation.SetProxyRecord(fresh.Record)

		return nil
	})
	if txErr != nil {
		return txErr
	}

	newScopes := ApplicationGrantScopes(app, installation.Permissions())
	if installation.IsActive() && !slices.Equal(oldScopes, newScopes) {
		app.triggerApplicationLifecycleWebhook(ApplicationEventScopesUpdate, installation.Id, application.Handle(), version.Version(), newScopes)
	}

	return nil
}

// UninstallApplication deletes the provided installation together with its managed
// OAuth2 client, webhooks and sessions (the uninstall notification and the
// "application.uninstalled" lifecycle webhook are sent after the commit).
func (app *BaseApp) UninstallApplication(installation *ApplicationInstallation) error {
	if installation == nil || installation.Id == "" {
		return errors.New("missing application installation")
	}

	event := new(ApplicationUninstallEvent)
	event.App = app
	event.Installation = installation

	return app.OnApplicationUninstall().Trigger(event, func(e *ApplicationUninstallEvent) error {
		return e.App.Delete(e.Installation)
	})
}

// findApplicationInstallationManifest returns the application, the installed version and its manifest.
func findApplicationInstallationManifest(app App, installation *ApplicationInstallation) (*Application, *ApplicationVersion, *ApplicationManifest, error) {
	application, err := app.FindApplicationById(installation.ApplicationRef())
	if err != nil {
		return nil, nil, nil, err
	}

	version, err := app.FindApplicationVersionById(installation.VersionRef())
	if err != nil {
		return nil, nil, nil, err
	}

	manifest, err := version.Manifest()
	if err != nil {
		return nil, nil, nil, err
	}

	return application, version, manifest, nil
}

// -------------------------------------------------------------------
// Managed webhooks
// -------------------------------------------------------------------

type managedWebhookChangeKey struct{}

// withManagedWebhookChange marks the save/delete context as a managed webhook change performed
// by the application installation services or by the webhooks system maintenance
// (auto-disable, removed collection topics), aka. the only allowed paths.
func withManagedWebhookChange(ctx context.Context) context.Context {
	return context.WithValue(ctx, managedWebhookChangeKey{}, true)
}

func isManagedWebhookChange(ctx context.Context) bool {
	if ctx == nil {
		return false
	}

	v, _ := ctx.Value(managedWebhookChangeKey{}).(bool)

	return v
}

var errManagedWebhook = errors.New("the application managed webhooks could be changed only through their application installation")

// applicationInstallationActorInfo returns the request info of the installation actor
// with the scopes of its whole grant (e.g. for the managed webhooks W1/W2 checks).
func applicationInstallationActorInfo(app App, installation *ApplicationInstallation) *RequestInfo {
	return &RequestInfo{
		Context: RequestInfoContextDefault,
		Auth:    installation.Record,
		OAuth2:  RequestInfoOAuth2{Scopes: ApplicationGrantScopes(app, installation.Permissions())},
	}
}

// syncApplicationManagedWebhooks creates, updates (by position) and deletes the managed webhooks of the
// provided installation so that they match the manifest webhook subscriptions.
//
// The managed webhooks actor is the installation and their topics and filter must pass the regular
// webhook actor checks for the installation grant (no system collections, only the viewable
// collections and no wildcards).
func syncApplicationManagedWebhooks(txApp App, installation *ApplicationInstallation, application *Application, manifest *ApplicationManifest) error {
	existing, err := txApp.FindAllWebhooksByApplicationInstallation(installation.Id)
	if err != nil {
		return err
	}

	info := applicationInstallationActorInfo(txApp, installation)
	ctx := withManagedWebhookChange(context.Background())
	errs := validation.Errors{}

	for i, sub := range manifest.Webhooks.Subscriptions {
		key := "webhooks.subscriptions." + strconv.Itoa(i)

		var webhook *Webhook
		if i < len(existing) {
			webhook = existing[i]
		} else {
			webhook = NewWebhook(txApp)
		}

		name := application.Name() + " #" + strconv.Itoa(i+1)
		if len(name) > 255 {
			name = name[:255]
		}

		webhook.SetName(name)
		webhook.SetURI(sub.URI)
		webhook.SetTopics(sub.Topics)
		webhook.SetFilter(sub.Filter)
		webhook.SetFields(sub.Fields)
		webhook.SetSecret(installation.WebhookSecret())
		webhook.SetActive(true)
		webhook.SetClient("")
		webhook.SetActorRef(WebhookActorRef(installation.Record))
		webhook.Set("applicationInstallationRef", installation.Id)

		if err := CheckWebhookChange(txApp, info, webhook.Record); err != nil {
			errs[key] = validation.NewError("validation_webhook_topic_system", "The applications can't subscribe to the system collections topics.")
			continue
		}

		if err := CheckWebhookTopicsAccess(txApp, info, webhook.Topics()); err != nil {
			errs[key] = err
			continue
		}

		if err := CheckWebhookFilterAccess(txApp, info, webhook.Record); err != nil {
			errs[key] = err
			continue
		}

		if err := txApp.SaveWithContext(ctx, webhook); err != nil {
			errs[key] = err
			continue
		}
	}

	if len(errs) > 0 {
		return errs
	}

	if len(existing) > len(manifest.Webhooks.Subscriptions) {
		for _, w := range existing[len(manifest.Webhooks.Subscriptions):] {
			if err := txApp.DeleteWithContext(ctx, w); err != nil {
				return err
			}
		}
	}

	return nil
}

// -------------------------------------------------------------------
// Pending installations cleanup
// -------------------------------------------------------------------

// deleteStalePendingApplicationInstallations deletes the pending installations older than
// 10 minutes (e.g. after a process crash during the install notification).
func (app *BaseApp) deleteStalePendingApplicationInstallations() error {
	if _, err := app.FindCachedCollectionByNameOrId(CollectionNameApplicationInstallations); err != nil {
		return nil // not migrated yet
	}

	installations := []*ApplicationInstallation{}

	err := app.RecordQuery(CollectionNameApplicationInstallations).
		AndWhere(dbx.HashExp{"status": ApplicationInstallationStatusPending}).
		AndWhere(dbx.NewExp("[[created]] < {:date}", dbx.Params{
			"date": types.NowDateTime().Add(-applicationPendingInstallationMaxAge).String(),
		})).
		All(&installations)
	if err != nil {
		return err
	}

	var errs []error
	for _, installation := range installations {
		if err := app.Delete(installation); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// -------------------------------------------------------------------
// Uninstall notifications
// -------------------------------------------------------------------

// prepareApplicationUninstall stores the uninstall notification data of an active installation
// that is about to be deleted (the installed version, the client and the application could
// be deleted in the same transaction).
func (app *BaseApp) prepareApplicationUninstall(txApp App, record *Record) {
	installation := &ApplicationInstallation{record}
	if !installation.IsActive() {
		return
	}

	n := &applicationNotification{
		event:          ApplicationEventUninstalled,
		installationId: installation.Id,
		scopes:         ApplicationGrantScopes(txApp, installation.Permissions()),
	}

	if application, err := txApp.FindApplicationById(installation.ApplicationRef()); err == nil {
		n.handle = application.Handle()
	}

	if version, err := txApp.FindApplicationVersionById(installation.VersionRef()); err == nil {
		n.version = version.Version()
		if manifest, err := version.Manifest(); err == nil {
			n.url = manifest.UninstallURL
		}
	}

	if client, err := txApp.FindApplicationInstallationClient(installation.Id); err == nil {
		n.clientId = client.ClientId()
	}

	app.applicationCatalogs.pendingUninstalls.Store(installation.Id, n)
}

// completeApplicationUninstall sends the stored uninstall notification (best-effort)
// and triggers the "application.uninstalled" lifecycle webhook.
func (app *BaseApp) completeApplicationUninstall(installationId string, success bool) {
	value, ok := app.applicationCatalogs.pendingUninstalls.LoadAndDelete(installationId)
	if !ok || !success {
		return
	}

	n := value.(*applicationNotification)

	if n.url != "" && n.handle != "" {
		ctx, cancel := context.WithTimeout(context.Background(), applicationCatalogTimeout+time.Second)
		defer cancel()

		if err := app.sendApplicationNotification(ctx, n); err != nil {
			app.Logger().Warn(
				"Failed to send the application uninstall notification",
				slog.String("installation", n.installationId),
				slog.String("handle", n.handle),
				slog.String("error", err.Error()),
			)
		}
	}

	app.triggerApplicationLifecycleWebhook(ApplicationEventUninstalled, n.installationId, n.handle, n.version, n.scopes)
}

type managedOAuth2ClientChangeKey struct{}

// withManagedOAuth2ClientChange marks the save/delete context as a managed OAuth2 client change
// performed by the application installation services (the only allowed path).
func withManagedOAuth2ClientChange(ctx context.Context) context.Context {
	return context.WithValue(ctx, managedOAuth2ClientChangeKey{}, true)
}

func isManagedOAuth2ClientChange(ctx context.Context) bool {
	if ctx == nil {
		return false
	}

	v, _ := ctx.Value(managedOAuth2ClientChangeKey{}).(bool)

	return v
}

var errManagedOAuth2Client = errors.New("the application managed OAuth2 clients could be changed only through their application installation")

// ApplicationLifecycleTopicNamespace is the namespace of the application lifecycle custom webhook topics
// (the application installations can't subscribe to it).
const ApplicationLifecycleTopicNamespace = "application"

// triggerApplicationLifecycleWebhook triggers the provided lifecycle custom webhook topic
// (failures are only logged).
func (app *BaseApp) triggerApplicationLifecycleWebhook(topic string, installationId string, handle string, version string, scopes []string) {
	payload := map[string]any{
		"installation_id": installationId,
		"handle":          handle,
		"version":         version,
		"scopes":          scopes,
	}

	if err := app.Webhooks().Trigger(context.Background(), topic, payload); err != nil {
		app.Logger().Warn(
			"Failed to trigger the application lifecycle webhook",
			slog.String("topic", topic),
			slog.String("installation", installationId),
			slog.String("error", err.Error()),
		)
	}
}

// applicationLifecycleTopics are the registered application lifecycle custom webhook topics.
var applicationLifecycleTopics = map[string]string{
	ApplicationEventInstalled:    "An application was installed (payload: installation_id, handle, version, scopes).",
	ApplicationEventUninstalled:  "An application was uninstalled (payload: installation_id, handle, version, scopes).",
	ApplicationEventScopesUpdate: "An application installation grant was changed (payload: installation_id, handle, version, scopes).",
}
