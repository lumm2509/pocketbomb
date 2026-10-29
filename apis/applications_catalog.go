package apis

import (
	"net/http"
	"time"

	"github.com/lumm2509/pocketbomb/core"
)

type applicationCatalogEntryResponse struct {
	Source         string                            `json:"source"`
	Signed         bool                              `json:"signed"`
	Handle         string                            `json:"handle"`
	Name           string                            `json:"name"`
	Description    string                            `json:"description"`
	IconURL        string                            `json:"iconURL"`
	Developer      core.ApplicationManifestDeveloper `json:"developer"`
	Version        string                            `json:"version"`
	ManifestURL    string                            `json:"manifestURL"`
	ManifestDigest string                            `json:"manifestDigest"`

	// the local state of the entry handle
	ApplicationId    string `json:"applicationId"`
	Installed        bool   `json:"installed"`
	InstalledVersion string `json:"installedVersion"`
	UpdateAvailable  bool   `json:"updateAvailable"`

	// Conflict indicates that the handle belongs to a custom application.
	Conflict bool `json:"conflict"`
}

type applicationCatalogSourceResponse struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Signed    bool   `json:"signed"`
	Error     string `json:"error"`
	Total     int    `json:"total"`
	FetchedAt string `json:"fetchedAt"`
}

type applicationCatalogResponse struct {
	Sources []*applicationCatalogSourceResponse `json:"sources"`
	Items   []*applicationCatalogEntryResponse  `json:"items"`
}

func newApplicationCatalogEntryResponse(e *core.RequestEvent, source *core.ApplicationCatalogResult, entry core.ApplicationCatalogEntry) *applicationCatalogEntryResponse {
	result := &applicationCatalogEntryResponse{
		Source:         source.Name,
		Signed:         source.Signed,
		Handle:         entry.Handle,
		Name:           entry.Name,
		Description:    entry.Description,
		IconURL:        entry.SafeIconURL(),
		Developer:      entry.Developer,
		Version:        entry.Version,
		ManifestURL:    entry.ManifestURL,
		ManifestDigest: entry.ManifestDigest,
	}

	application, err := e.App.FindApplicationByHandle(entry.Handle)
	if err != nil {
		return result
	}

	if application.Source() != core.ApplicationSourceCatalog {
		result.Conflict = true
		return result
	}

	result.ApplicationId = application.Id

	installation, err := e.App.FindApplicationInstallationByApplication(application.Id)
	if err != nil {
		return result
	}

	result.Installed = true

	if version, err := e.App.FindApplicationVersionById(installation.VersionRef()); err == nil {
		result.InstalledVersion = version.Version()
		result.UpdateAvailable = version.Version() != entry.Version
	}

	return result
}

// GET /api/applications/catalog[?refresh=1]
//
// Returns the merged entries of all configured catalog sources (with their source, signed flag,
// installed status and update-available flag) and the per-source (non-fatal) errors.
func applicationCatalogList(e *core.RequestEvent) error {
	refresh := e.Request.URL.Query().Get("refresh") == "1"

	result := applicationCatalogResponse{
		Sources: []*applicationCatalogSourceResponse{},
		Items:   []*applicationCatalogEntryResponse{},
	}

	for _, source := range e.App.ApplicationCatalogs().List(e.Request.Context(), refresh) {
		result.Sources = append(result.Sources, &applicationCatalogSourceResponse{
			Name:      source.Name,
			URL:       source.URL,
			Signed:    source.Signed,
			Error:     source.Error,
			Total:     len(source.Entries),
			FetchedAt: source.FetchedAt.UTC().Format(time.RFC3339),
		})

		for _, entry := range source.Entries {
			result.Items = append(result.Items, newApplicationCatalogEntryResponse(e, source, entry))
		}
	}

	return e.JSON(http.StatusOK, result)
}

type applicationScopeResponse struct {
	Scope    string `json:"scope"`
	Label    string `json:"label"`
	Optional bool   `json:"optional"`
}

type applicationCatalogManifestResponse struct {
	Entry    *applicationCatalogEntryResponse `json:"entry"`
	Manifest *core.ApplicationManifest        `json:"manifest"`
	Scopes   []*applicationScopeResponse      `json:"scopes"`
}

// GET /api/applications/catalog/manifest?source=NAME&handle=HANDLE
//
// Fetches and verifies (without importing) the current manifest of a catalog entry
// (e.g. for the dashboard catalog detail and the install review).
func applicationCatalogManifest(e *core.RequestEvent) error {
	query := e.Request.URL.Query()

	source, entry, err := e.App.ApplicationCatalogs().FindEntry(e.Request.Context(), query.Get("source"), query.Get("handle"))
	if err != nil {
		return firstApiError(err, e.BadRequestError("Failed to load the catalog application.", err))
	}

	manifest, _, err := e.App.ApplicationCatalogs().FetchManifest(e.Request.Context(), entry)
	if err != nil {
		return e.BadRequestError("Failed to load the catalog application manifest: "+err.Error(), err)
	}

	sourceResult := &core.ApplicationCatalogResult{Name: source.Name, URL: source.URL, Signed: source.PublicKey != ""}

	result := applicationCatalogManifestResponse{
		Entry:    newApplicationCatalogEntryResponse(e, sourceResult, entry),
		Manifest: manifest,
		Scopes:   applicationScopesResponse(e.App, manifest),
	}

	return e.JSON(http.StatusOK, result)
}

// applicationScopesResponse returns the manifest scopes and optional scopes with their labels.
func applicationScopesResponse(app core.App, manifest *core.ApplicationManifest) []*applicationScopeResponse {
	result := []*applicationScopeResponse{}

	for _, s := range manifest.Access.Scopes {
		result = append(result, &applicationScopeResponse{Scope: s, Label: core.OAuth2ScopeLabel(app, s)})
	}

	for _, s := range manifest.Access.OptionalScopes {
		result = append(result, &applicationScopeResponse{Scope: s, Label: core.OAuth2ScopeLabel(app, s), Optional: true})
	}

	return result
}

type applicationCatalogForm struct {
	Source      string           `json:"source"`
	Handle      string           `json:"handle"`
	Permissions core.Permissions `json:"permissions"`
}

// importCatalogApplication imports the current catalog version of the submitted catalog entry.
func importCatalogApplication(e *core.RequestEvent, form *applicationCatalogForm) (*core.ApplicationManifestImportResult, error) {
	createdBy := ""
	if e.IsStaff() {
		createdBy = e.Auth.Id
	}

	result, err := e.App.ImportApplicationCatalogEntry(e.Request.Context(), form.Source, form.Handle, createdBy)
	if err != nil {
		return nil, firstApiError(err, e.BadRequestError("Failed to import the catalog application: "+err.Error(), err))
	}

	return result, nil
}

// POST /api/applications/catalog/install
//
// Imports the current catalog version of the submitted entry (verified signed index and manifest digest)
// and installs it with the submitted grant (it must be within the manifest scopes and optional scopes).
//
// The credentials are delivered only to the application install_url (signed install notification);
// if the application doesn't acknowledge it, the installation is rolled back and the
// application response status and reason are returned.
func applicationCatalogInstall(e *core.RequestEvent) error {
	form := &applicationCatalogForm{}
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	imported, err := importCatalogApplication(e, form)
	if err != nil {
		return err
	}

	return installApplication(e, imported.Application, form.Permissions)
}

// POST /api/applications/catalog/import
//
// Imports the current catalog version of the submitted entry as a new version
// of the catalog application (e.g. before an installation version update).
func applicationCatalogImport(e *core.RequestEvent) error {
	form := &applicationCatalogForm{}
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	imported, err := importCatalogApplication(e, form)
	if err != nil {
		return err
	}

	application, err := newApplicationResponse(e, imported.Application)
	if err != nil {
		return e.InternalServerError("Failed to load the application.", err)
	}

	return e.JSON(http.StatusOK, applicationManifestImportResponse{
		Application: application,
		Version:     newApplicationVersionResponse(imported.Version),
		Created:     imported.Created,
		Unchanged:   imported.Unchanged,
	})
}
