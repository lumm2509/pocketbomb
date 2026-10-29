package apis

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/router"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// bindApplicationsApi registers the applications (aka. extensions) api endpoints.
//
// The applications authenticate only with their installation managed OAuth2 client: the install and rotate-secret endpoints
// return the managed OAuth2 client credentials ONCE and the access tokens are issued
// only by the {issuer}/token client_credentials grant (see [oauth2TokenClientCredentials]).
//
// The catalog applications are discovered from the catalog sources of the settings (see [core.ApplicationCatalogs])
// and their credentials are delivered only to their install_url (signed install notification).
//
// The model invariants (immutable versions, grant registry validation, managed clients and webhooks,
// no roles for the installations, single installation) are enforced in core on every save path,
// while the actor checks (applications write + the actor must hold the whole grant, see
// [core.CheckApplicationInstallationChange]) apply only to the API requests.
//
// The manifest extensions are listed for and launched by the staff from the dashboard
// (launch token POSTed to the extension URL, see [core.ApplicationLaunchClaims]).
func bindApplicationsApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	read := RequirePermission(core.PermissionResourceApplications, core.PermissionLevelRead)
	write := RequirePermission(core.PermissionResourceApplications, core.PermissionLevelWrite)

	sub := rg.Group("/applications")
	sub.GET("", applicationsList).Bind(read)
	sub.POST("", applicationCreate).Bind(write)
	sub.POST("/manifests", applicationManifestImport).Bind(write)
	sub.GET("/extensions", applicationExtensionsList).Bind(read)
	sub.GET("/catalog", applicationCatalogList).Bind(read)
	sub.GET("/catalog/manifest", applicationCatalogManifest).Bind(read)
	sub.POST("/catalog/install", applicationCatalogInstall).Bind(write)
	sub.POST("/catalog/import", applicationCatalogImport).Bind(write)
	sub.POST("/{id}/install", applicationInstall).Bind(write)
	sub.DELETE("/{id}", applicationDelete).Bind(write)
	sub.PATCH("/installations/{id}", applicationInstallationUpdate).Bind(write)
	sub.POST("/installations/{id}/rotate-secret", applicationInstallationRotateSecret).Bind(write)
	sub.DELETE("/installations/{id}", applicationUninstall).Bind(write)
	sub.POST("/installations/{id}/launch", applicationExtensionLaunch).Bind(read)
}

// -------------------------------------------------------------------
// Responses
// -------------------------------------------------------------------

type applicationVersionResponse struct {
	Id             string                    `json:"id"`
	Version        string                    `json:"version"`
	SourceFormat   string                    `json:"sourceFormat"`
	ManifestDigest string                    `json:"manifestDigest"`
	Manifest       *core.ApplicationManifest `json:"manifest"`
	CreatedBy      string                    `json:"createdBy"`
	Created        string                    `json:"created"`
}

type applicationWebhookResponse struct {
	Id             string   `json:"id"`
	Name           string   `json:"name"`
	URI            string   `json:"uri"`
	Topics         []string `json:"topics"`
	Filter         string   `json:"filter"`
	Active         bool     `json:"active"`
	DisabledReason string   `json:"disabledReason"`
}

type applicationInstallationResponse struct {
	Id              string                        `json:"id"`
	CollectionId    string                        `json:"collectionId"`
	Status          string                        `json:"status"`
	VersionRef      string                        `json:"versionRef"`
	Version         string                        `json:"version"`
	Permissions     core.Permissions              `json:"permissions"`
	Scopes          []string                      `json:"scopes"`
	ClientId        string                        `json:"clientId"`
	TokenURL        string                        `json:"tokenURL"`
	InstalledBy     string                        `json:"installedBy"`
	SecretRotatedAt string                        `json:"secretRotatedAt"`
	Webhooks        []*applicationWebhookResponse `json:"webhooks"`
	Created         string                        `json:"created"`
	Updated         string                        `json:"updated"`
}

type applicationResponse struct {
	Id             string                           `json:"id"`
	Handle         string                           `json:"handle"`
	Name           string                           `json:"name"`
	Description    string                           `json:"description"`
	IconURL        string                           `json:"iconURL"`
	DeveloperName  string                           `json:"developerName"`
	DeveloperURL   string                           `json:"developerURL"`
	ApplicationURL string                           `json:"applicationURL"`
	Source         string                           `json:"source"`
	CatalogURL     string                           `json:"catalogURL"`
	ManifestURL    string                           `json:"manifestURL"`
	LatestVersion  *applicationVersionResponse      `json:"latestVersion"`
	Versions       []*applicationVersionResponse    `json:"versions"`
	Installation   *applicationInstallationResponse `json:"installation"`
	Created        string                           `json:"created"`
	Updated        string                           `json:"updated"`
}

func newApplicationVersionResponse(version *core.ApplicationVersion) *applicationVersionResponse {
	manifest, _ := version.Manifest()

	return &applicationVersionResponse{
		Id:             version.Id,
		Version:        version.Version(),
		SourceFormat:   version.GetString("sourceFormat"),
		ManifestDigest: version.ManifestDigest(),
		Manifest:       manifest,
		CreatedBy:      version.GetString("createdBy"),
		Created:        version.GetDateTime("created").String(),
	}
}

func newApplicationInstallationResponse(e *core.RequestEvent, installation *core.ApplicationInstallation) *applicationInstallationResponse {
	result := &applicationInstallationResponse{
		Id:              installation.Id,
		CollectionId:    installation.Collection().Id,
		Status:          installation.Status(),
		VersionRef:      installation.VersionRef(),
		Permissions:     installation.Permissions(),
		Scopes:          core.ApplicationGrantScopes(e.App, installation.Permissions()),
		TokenURL:        core.OAuth2Issuer(e.App, installation.Collection()) + "/token",
		InstalledBy:     installation.InstalledBy(),
		SecretRotatedAt: installation.SecretRotatedAt().String(),
		Created:         installation.GetDateTime("created").String(),
		Updated:         installation.GetDateTime("updated").String(),
	}

	if version, err := e.App.FindApplicationVersionById(installation.VersionRef()); err == nil {
		result.Version = version.Version()
	}

	if client, err := e.App.FindApplicationInstallationClient(installation.Id); err == nil {
		result.ClientId = client.ClientId()
	}

	// the managed webhooks (read-only; never their secret)
	result.Webhooks = []*applicationWebhookResponse{}
	if webhooks, err := e.App.FindAllWebhooksByApplicationInstallation(installation.Id); err == nil {
		for _, w := range webhooks {
			topics := make([]string, len(w.Topics()))
			for i, t := range w.Topics() {
				topics[i] = core.RenderWebhookTopic(e.App, t)
			}

			result.Webhooks = append(result.Webhooks, &applicationWebhookResponse{
				Id:             w.Id,
				Name:           w.Name(),
				URI:            w.URI(),
				Topics:         topics,
				Filter:         w.Filter(),
				Active:         w.Active(),
				DisabledReason: w.DisabledReason(),
			})
		}
	}

	return result
}

func newApplicationResponse(e *core.RequestEvent, application *core.Application) (*applicationResponse, error) {
	result := &applicationResponse{
		Id:             application.Id,
		Handle:         application.Handle(),
		Name:           application.Name(),
		Description:    application.GetString("description"),
		IconURL:        application.GetString("iconURL"),
		DeveloperName:  application.GetString("developerName"),
		DeveloperURL:   application.GetString("developerURL"),
		ApplicationURL: application.GetString("applicationURL"),
		Source:         application.Source(),
		CatalogURL:     application.GetString("catalogURL"),
		ManifestURL:    application.GetString("manifestURL"),
		Versions:       []*applicationVersionResponse{},
		Created:        application.GetDateTime("created").String(),
		Updated:        application.GetDateTime("updated").String(),
	}

	versions, err := e.App.FindAllApplicationVersionsByApplication(application.Id)
	if err != nil {
		return nil, err
	}

	for _, v := range versions {
		item := newApplicationVersionResponse(v)
		result.Versions = append(result.Versions, item)
		if v.Id == application.LatestVersionRef() {
			result.LatestVersion = item
		}
	}

	if installation, err := e.App.FindApplicationInstallationByApplication(application.Id); err == nil {
		result.Installation = newApplicationInstallationResponse(e, installation)
	}

	return result, nil
}

type applicationsListResponse struct {
	Items []*applicationResponse `json:"items"`

	// Resources is the permissions registry (the applicationGrantable flag
	// marks the system resources that could be granted to an application).
	Resources []core.PermissionResource `json:"resources"`
	Actions   []string                  `json:"actions"`

	// SuperuserIPsRestricted indicates whether the staff access is restricted to the SuperuserIPs
	// (also for the applications acting on behalf of a staff member, aka. the extensions online tokens).
	SuperuserIPsRestricted bool `json:"superuserIPsRestricted"`
}

// GET /api/applications
func applicationsList(e *core.RequestEvent) error {
	applications, err := e.App.FindAllApplications()
	if err != nil {
		return e.InternalServerError("Failed to load the applications.", err)
	}

	result := applicationsListResponse{
		Items:     make([]*applicationResponse, 0, len(applications)),
		Resources: core.PermissionResources,
		Actions:   core.PermissionCollectionActions,

		SuperuserIPsRestricted: len(e.App.Settings().SuperuserIPs) > 0,
	}

	for _, a := range applications {
		item, err := newApplicationResponse(e, a)
		if err != nil {
			return e.InternalServerError("Failed to load the application.", err)
		}
		result.Items = append(result.Items, item)
	}

	return e.JSON(http.StatusOK, result)
}

// -------------------------------------------------------------------
// Manifests
// -------------------------------------------------------------------

type applicationManifestImportResponse struct {
	Application *applicationResponse        `json:"application"`
	Version     *applicationVersionResponse `json:"version"`
	Created     bool                        `json:"created"`
	Unchanged   bool                        `json:"unchanged"`
}

// importApplicationManifest triggers the manifest import hook and imports the provided manifest.
func importApplicationManifest(e *core.RequestEvent, manifest *core.ApplicationManifest, sourceFormat string) error {
	createdBy := ""
	if e.IsStaff() {
		createdBy = e.Auth.Id
	}

	event := new(core.ApplicationManifestImportRequestEvent)
	event.RequestEvent = e
	event.Manifest = manifest
	event.SourceFormat = sourceFormat

	return e.App.OnApplicationManifestImportRequest().Trigger(event, func(e *core.ApplicationManifestImportRequestEvent) error {
		result, err := e.App.ImportApplicationManifest(e.Manifest, e.SourceFormat, createdBy)
		if err != nil {
			return firstApiError(err, e.BadRequestError("Failed to import the application manifest.", err))
		}
		e.Result = result

		application, err := newApplicationResponse(e.RequestEvent, result.Application)
		if err != nil {
			return e.InternalServerError("Failed to load the application.", err)
		}

		return e.JSON(http.StatusOK, applicationManifestImportResponse{
			Application: application,
			Version:     newApplicationVersionResponse(result.Version),
			Created:     result.Created,
			Unchanged:   result.Unchanged,
		})
	})
}

// POST /api/applications/manifests
//
// Imports a raw application manifest ("application/toml" or "application/json" body):
// creates a custom application or a new (immutable) version of an existing custom application
// with the same handle (the same version with the same manifest is a no-op).
func applicationManifestImport(e *core.RequestEvent) error {
	mediaType, _, _ := mime.ParseMediaType(e.Request.Header.Get("Content-Type"))

	var format string
	switch {
	case strings.HasSuffix(mediaType, "/toml") || strings.HasSuffix(mediaType, "/x-toml"):
		format = core.ApplicationManifestFormatTOML
	case strings.HasSuffix(mediaType, "/json"):
		format = core.ApplicationManifestFormatJSON
	default:
		return e.BadRequestError("Unsupported manifest Content-Type (application/toml or application/json).", nil)
	}

	data, err := io.ReadAll(io.LimitReader(e.Request.Body, core.ApplicationManifestMaxSize+1))
	if err != nil {
		return e.BadRequestError("Failed to read the manifest.", err)
	}

	manifest, err := core.ParseApplicationManifest(data, format)
	if err != nil {
		return e.BadRequestError("Invalid application manifest.", err)
	}

	return importApplicationManifest(e, manifest, format)
}

type applicationCreateForm struct {
	Handle         string   `json:"handle"`
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Description    string   `json:"description"`
	ApplicationURL string   `json:"applicationURL"`
	DeveloperName  string   `json:"developerName"`
	DeveloperURL   string   `json:"developerURL"`
	Scopes         []string `json:"scopes"`
}

// POST /api/applications
//
// Creates a custom application from the dashboard form (the form is converted
// to a manifest and imported the same way as POST /api/applications/manifests).
func applicationCreate(e *core.RequestEvent) error {
	form := &applicationCreateForm{}
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	if form.Version == "" {
		form.Version = "1.0.0"
	}

	manifest := &core.ApplicationManifest{
		Handle:         form.Handle,
		Name:           form.Name,
		Version:        form.Version,
		Description:    form.Description,
		ApplicationURL: form.ApplicationURL,
		Developer:      core.ApplicationManifestDeveloper{Name: form.DeveloperName, URL: form.DeveloperURL},
		Access:         core.ApplicationManifestAccess{Scopes: form.Scopes},
	}
	manifest.Normalize()

	if err := manifest.Validate(); err != nil {
		return e.BadRequestError("An error occurred while validating the submitted data.", applicationFormErrors(err))
	}

	if _, err := e.App.FindApplicationByHandle(manifest.Handle); err == nil {
		return e.BadRequestError("An error occurred while validating the submitted data.", validation.Errors{
			"handle": validation.NewError("validation_handle_exists", "An application with this handle already exists."),
		})
	}

	return importApplicationManifest(e, manifest, core.ApplicationManifestFormatJSON)
}

// applicationFormErrors renames the manifest validation errors keys to the create form fields.
func applicationFormErrors(err error) error {
	verrs, ok := err.(validation.Errors)
	if !ok {
		return err
	}

	keys := map[string]string{
		"application_url": "applicationURL",
		"developer.name":  "developerName",
		"developer.url":   "developerURL",
		"access.scopes":   "scopes",
	}

	result := validation.Errors{}
	for k, v := range verrs {
		if renamed, ok := keys[k]; ok {
			k = renamed
		}
		result[k] = v
	}

	return result
}

// DELETE /api/applications/{id}
//
// Deletes a not installed application and all its versions.
func applicationDelete(e *core.RequestEvent) error {
	application, err := e.App.FindApplicationById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("Missing or invalid application.", err)
	}

	if _, err := e.App.FindApplicationInstallationByApplication(application.Id); err == nil {
		return e.BadRequestError("The application is installed (uninstall it first).", nil)
	}

	if err := e.App.Delete(application); err != nil {
		return firstApiError(err, e.BadRequestError("Failed to delete the application.", err))
	}

	return e.NoContent(http.StatusNoContent)
}

// -------------------------------------------------------------------
// Installations
// -------------------------------------------------------------------

type applicationCredentialsResponse struct {
	Installation *applicationInstallationResponse `json:"installation"`
	ClientId     string                           `json:"clientId"`

	// ClientSecret is the plain client secret (returned only once and only
	// when it is not delivered to the application with a notification).
	ClientSecret string `json:"clientSecret"`

	// WebhookSecret is the managed webhooks signing secret (returned together with the client secret).
	WebhookSecret string `json:"webhookSecret"`

	TokenURL string `json:"tokenURL"`

	// Notified indicates whether the credentials were delivered only to the
	// application with a signed notification (and therefore they are not returned).
	Notified bool `json:"notified"`
}

type applicationInstallForm struct {
	Permissions core.Permissions `json:"permissions"`
}

// applicationNotificationApiError returns the API error of a failed (rejected) application notification
// (incl. the application response status and reason) or nil if err is not a notification error.
func applicationNotificationApiError(e *core.RequestEvent, err error) error {
	var notificationErr *core.ApplicationNotificationError
	if !errors.As(err, &notificationErr) {
		return nil
	}

	return e.BadRequestError(notificationErr.Error(), validation.Errors{
		"installURL": validation.NewError("validation_application_notification_failed", notificationErr.Error()),
	})
}

// POST /api/applications/{id}/install
//
// Installs the application (latest version) with the submitted grant
// (the actor must hold every permission of the grant) and returns the
// managed OAuth2 client credentials ONCE (unless they were delivered to
// the application install_url with the signed install notification).
func applicationInstall(e *core.RequestEvent) error {
	application, err := e.App.FindApplicationById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("Missing or invalid application.", err)
	}

	form := &applicationInstallForm{}
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	return installApplication(e, application, form.Permissions)
}

// installApplication triggers the install request hook and installs the provided application.
func installApplication(e *core.RequestEvent, application *core.Application, permissions core.Permissions) error {
	if _, err := e.App.FindApplicationInstallationByApplication(application.Id); err == nil {
		return e.BadRequestError("The application is already installed.", nil)
	}

	// note: the check is performed on the final grant right before the install (see below)
	check := func(e *core.ApplicationInstallRequestEvent) error {
		pending := core.NewApplicationInstallation(e.App)
		pending.SetPermissions(e.Permissions)
		if err := core.CheckApplicationInstallationChange(e.App, e.ActorInfo(), pending.Record); err != nil {
			return e.ForbiddenError("You are not allowed to install the application with this grant (you must hold every granted permission).", err)
		}
		return nil
	}

	event := new(core.ApplicationInstallRequestEvent)
	event.RequestEvent = e
	event.Application = application
	event.Permissions = permissions

	return e.App.OnApplicationInstallRequest().Trigger(event, func(e *core.ApplicationInstallRequestEvent) error {
		if err := check(e); err != nil {
			return err
		}

		installedBy := ""
		if e.IsStaff() {
			installedBy = e.Auth.Id
		}

		result, err := e.App.InstallApplication(e.Application, e.Permissions, installedBy)
		if err != nil {
			if apiErr := applicationNotificationApiError(e.RequestEvent, err); apiErr != nil {
				return apiErr
			}
			return firstApiError(err, e.BadRequestError("Failed to install the application.", err))
		}
		e.Result = result

		setOAuth2NoStoreHeaders(e.RequestEvent)

		installation := newApplicationInstallationResponse(e.RequestEvent, result.Installation)

		response := applicationCredentialsResponse{
			Installation: installation,
			ClientId:     result.Client.ClientId(),
			TokenURL:     installation.TokenURL,
			Notified:     result.Notified,
		}

		// the secrets travel only once: either to the application install_url or in this response
		if !result.Notified {
			response.ClientSecret = result.ClientSecret
			response.WebhookSecret = result.WebhookSecret
		}

		return e.JSON(http.StatusOK, response)
	})
}

type applicationInstallationUpdateForm struct {
	Permissions *core.Permissions `json:"permissions"`
	VersionRef  *string           `json:"versionRef"`
}

// PATCH /api/applications/installations/{id}
//
// Changes the installation grant and/or version (the actor must hold every
// permission of the old and the new grant; a narrowed grant applies immediately).
//
// If the new version requests scopes beyond the previous version and the current grant,
// the new grant must be submitted (the grant never grows automatically).
// The managed webhooks are re-synced.
func applicationInstallationUpdate(e *core.RequestEvent) error {
	installation, err := e.App.FindApplicationInstallationById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("Missing or invalid application installation.", err)
	}

	form := &applicationInstallationUpdateForm{}
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	versionRef := ""
	if form.VersionRef != nil {
		versionRef = *form.VersionRef
		installation.SetVersionRef(versionRef)
	}
	if form.Permissions != nil {
		installation.SetPermissions(*form.Permissions)
	}

	if err := core.CheckApplicationInstallationChange(e.App, e.ActorInfo(), installation.Record); err != nil {
		return e.ForbiddenError("You are not allowed to perform this installation change (you must hold every permission of the old and the new grant).", err)
	}

	if err := e.App.UpdateApplicationInstallation(installation, versionRef, form.Permissions); err != nil {
		return firstApiError(err, e.BadRequestError("Failed to save the application installation.", err))
	}

	return e.JSON(http.StatusOK, newApplicationInstallationResponse(e, installation))
}

// POST /api/applications/installations/{id}/rotate-secret
//
// Generates a new managed client secret and managed webhooks secret and ends every installation session.
//
// The new secrets are delivered to the application install_url (if any) with a signed
// "application.credentials_rotated" notification and the custom applications secrets are also
// returned ONCE (the catalog applications secrets are never returned).
func applicationInstallationRotateSecret(e *core.RequestEvent) error {
	installation, err := e.App.FindApplicationInstallationById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("Missing or invalid application installation.", err)
	}

	// note: the new secret hands over the whole grant
	if err := core.CheckApplicationInstallationChange(e.App, e.ActorInfo(), installation.Record); err != nil {
		return e.ForbiddenError("You are not allowed to rotate this installation secret (you must hold every permission of its grant).", err)
	}

	application, err := e.App.FindApplicationById(installation.ApplicationRef())
	if err != nil {
		return e.NotFoundError("Missing or invalid application.", err)
	}

	client, secret, err := e.App.RotateApplicationInstallationSecret(installation)
	if err != nil {
		if apiErr := applicationNotificationApiError(e, err); apiErr != nil {
			return apiErr
		}
		return firstApiError(err, e.BadRequestError("Failed to rotate the client secret.", err))
	}

	setOAuth2NoStoreHeaders(e)

	result := newApplicationInstallationResponse(e, installation)

	response := applicationCredentialsResponse{
		Installation: result,
		ClientId:     client.ClientId(),
		TokenURL:     result.TokenURL,
		Notified:     application.Source() == core.ApplicationSourceCatalog,
	}

	if !response.Notified {
		response.ClientSecret = secret
		response.WebhookSecret = installation.WebhookSecret()
	}

	return e.JSON(http.StatusOK, response)
}

// DELETE /api/applications/installations/{id}
//
// Uninstalls the application (the managed client and webhooks and every installation session
// are deleted and the application uninstall_url, if any, is notified).
func applicationUninstall(e *core.RequestEvent) error {
	installation, err := e.App.FindApplicationInstallationById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("Missing or invalid application installation.", err)
	}

	if err := core.CheckApplicationInstallationChange(e.App, e.ActorInfo(), installation.Record); err != nil {
		return e.ForbiddenError("You are not allowed to uninstall this application (you must hold every permission of its grant).", err)
	}

	application, err := e.App.FindApplicationById(installation.ApplicationRef())
	if err != nil {
		return e.NotFoundError("Missing or invalid application.", err)
	}

	event := new(core.ApplicationUninstallRequestEvent)
	event.RequestEvent = e
	event.Application = application
	event.Installation = installation

	return e.App.OnApplicationUninstallRequest().Trigger(event, func(e *core.ApplicationUninstallRequestEvent) error {
		if err := e.App.UninstallApplication(e.Installation); err != nil {
			return firstApiError(err, e.BadRequestError("Failed to uninstall the application.", err))
		}

		return e.NoContent(http.StatusNoContent)
	})
}
