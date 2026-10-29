package apis

import (
	"errors"
	"net/http"

	"github.com/lumm2509/pocketbomb/core"
)

type applicationExtensionResponse struct {
	InstallationId    string `json:"installationId"`
	ApplicationId     string `json:"applicationId"`
	ApplicationHandle string `json:"applicationHandle"`
	ApplicationName   string `json:"applicationName"`
	IconURL           string `json:"iconURL"`
	Type              string `json:"type"`
	Handle            string `json:"handle"`
	Label             string `json:"label"`

	// record actions only
	Collection   string `json:"collection,omitempty"`
	CollectionId string `json:"collectionId,omitempty"`
}

// GET /api/applications/extensions
//
// Returns the manifest extensions (of the installed versions) of the active installations
// that the current staff member could launch (see [core.CheckApplicationExtensionAccess]),
// e.g. for the dashboard navigation and record panel actions.
func applicationExtensionsList(e *core.RequestEvent) error {
	info := e.ActorInfo()

	result := []*applicationExtensionResponse{}

	applications, err := e.App.FindAllApplications()
	if err != nil {
		return e.InternalServerError("Failed to load the applications.", err)
	}

	for _, application := range applications {
		installation, err := e.App.FindApplicationInstallationByApplication(application.Id)
		if err != nil || !installation.IsActive() {
			continue
		}

		version, err := e.App.FindApplicationVersionById(installation.VersionRef())
		if err != nil {
			continue
		}

		manifest, err := version.Manifest()
		if err != nil {
			continue
		}

		for _, ext := range manifest.Extensions {
			collection, err := core.CheckApplicationExtensionAccess(e.App, info, installation, ext, nil)
			if err != nil {
				continue
			}

			item := &applicationExtensionResponse{
				InstallationId:    installation.Id,
				ApplicationId:     application.Id,
				ApplicationHandle: application.Handle(),
				ApplicationName:   application.Name(),
				IconURL:           core.SafeApplicationIconURL(application.GetString("iconURL")),
				Type:              ext.Type,
				Handle:            ext.Handle,
				Label:             ext.Label,
			}
			if collection != nil {
				item.Collection = collection.Name
				item.CollectionId = collection.Id
			}

			result = append(result, item)
		}
	}

	return e.JSON(http.StatusOK, result)
}

type applicationExtensionLaunchForm struct {
	Extension string `json:"extension"`
	RecordId  string `json:"recordId"`
}

type applicationExtensionLaunchResponse struct {
	// URL is the extension URL (the application_url origin + the extension path).
	URL string `json:"url"`

	// LaunchToken is the short-lived single use launch token that must be POSTed
	// to the extension URL ("launch_token" form field; never in a URL).
	LaunchToken string `json:"launchToken"`
}

// POST /api/applications/installations/{id}/launch
//
// Issues a launch token for the submitted extension of the installation (staff only with the
// applications read permission and only with the first-party dashboard access token of their
// own, aka. non-impersonated, dashboard session; see [core.CheckApplicationExtensionAccess]).
func applicationExtensionLaunch(e *core.RequestEvent) error {
	staffSessionId, err := applicationLaunchDashboardSession(e)
	if err != nil {
		return e.ForbiddenError("The extensions could be launched only by the staff members from the dashboard.", err)
	}

	installation, err := e.App.FindApplicationInstallationById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("Missing or invalid application installation.", err)
	}

	form := &applicationExtensionLaunchForm{}
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	version, err := e.App.FindApplicationVersionById(installation.VersionRef())
	if err != nil {
		return e.NotFoundError("Missing or invalid application version.", err)
	}

	manifest, err := version.Manifest()
	if err != nil {
		return e.InternalServerError("Failed to load the application manifest.", err)
	}

	ext, ok := manifest.FindExtension(form.Extension)
	if !ok {
		return e.NotFoundError("Missing or invalid application extension.", nil)
	}

	var record *core.Record
	if ext.Type == core.ApplicationExtensionTypeRecordAction {
		if form.RecordId == "" {
			return e.BadRequestError("The record actions require a recordId.", nil)
		}

		record, err = e.App.FindRecordById(ext.Collection, form.RecordId)
		if err != nil {
			return e.NotFoundError("Missing or invalid record.", err)
		}
	} else if form.RecordId != "" {
		return e.BadRequestError("The navigation extensions don't have a record.", nil)
	}

	if _, err := core.CheckApplicationExtensionAccess(e.App, e.ActorInfo(), installation, ext, record); err != nil {
		return e.ForbiddenError("You are not allowed to launch this application extension.", err)
	}

	client, err := e.App.FindApplicationInstallationClient(installation.Id)
	if err != nil || client.Disabled() {
		return e.BadRequestError("The application installation client is missing or disabled.", err)
	}

	extensionURL, err := manifest.ExtensionURL(ext)
	if err != nil {
		return e.BadRequestError("Invalid application extension URL.", err)
	}

	claims := core.ApplicationLaunchClaims{
		ClientId:       client.ClientId(),
		StaffId:        e.Auth.Id,
		StaffSessionId: staffSessionId,
		InstallationId: installation.Id,
		Extension:      ext.Handle,
	}
	if record != nil {
		claims.Record = &core.ApplicationLaunchRecord{Collection: record.Collection().Name, Id: record.Id}
	}

	token, err := core.NewApplicationLaunchToken(e.App, claims)
	if err != nil {
		return e.InternalServerError("Failed to generate the launch token.", err)
	}

	setOAuth2NoStoreHeaders(e)

	return e.JSON(http.StatusOK, applicationExtensionLaunchResponse{URL: extensionURL, LaunchToken: token})
}

// applicationLaunchDashboardSession returns the staff dashboard session id ("sid") of the request
// access token if it is a first-party dashboard (pb_dashboard) access token of the staff member own
// session (impersonation and the other clients tokens are rejected).
func applicationLaunchDashboardSession(e *core.RequestEvent) (string, error) {
	if !e.IsStaff() {
		return "", errors.New("not a staff member")
	}

	info := e.ActorInfo()
	if !info.OAuth2.FirstParty || info.OAuth2.ClientId != core.OAuth2DashboardClientId {
		return "", errors.New("not a dashboard access token")
	}

	if info.OAuth2.Impersonated {
		return "", errors.New("impersonation tokens can't launch extensions")
	}

	// note: the token (incl. its live session) is already verified by the auth token loader
	sid := info.OAuth2.SessionId
	if sid == "" {
		return "", errors.New("the access token doesn't belong to the staff member")
	}

	return sid, nil
}
