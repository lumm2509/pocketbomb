package apis

import (
	"net/http"
	"strings"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/pages"
)

// human readable descriptions of the builtin scopes (used in the consent page)
var oauth2ScopeDescriptions = map[string]string{
	core.OAuth2ScopeOpenId:        "Verify your identity",
	core.OAuth2ScopeEmail:         "View your email address",
	core.OAuth2ScopeProfile:       "View your basic profile info",
	core.OAuth2ScopeOfflineAccess: "Stay signed in (access your data while you are not using the app)",
}

// oauth2RenderPage renders one of the hosted pages (see [pages.Render])
// with the issuer collection branding.
func oauth2RenderPage(e *core.RequestEvent, collection *core.Collection, status int, name string, page any) error {
	if err := pages.Render(e.Response, status, name, pages.NewBranding(e.App, collection), page); err != nil {
		return e.InternalServerError("Failed to render the hosted page.", err)
	}

	return nil
}

// oauth2RenderErrorPage renders the hosted error page.
func oauth2RenderErrorPage(e *core.RequestEvent, collection *core.Collection, status int, oerr *oauth2Error) error {
	return oauth2RenderPage(e, collection, status, "oauth2/message", pages.MessagePage{
		Heading:   "Something went wrong",
		Message:   oerr.Description,
		ErrorCode: oerr.Code,
	})
}

// oauth2RenderMessagePage renders a hosted info page.
func oauth2RenderMessagePage(e *core.RequestEvent, collection *core.Collection, status int, heading string, message string) error {
	return oauth2RenderPage(e, collection, status, "oauth2/message", pages.MessagePage{
		Heading: heading,
		Message: message,
	})
}

func oauth2RenderInvalidFormPage(e *core.RequestEvent, collection *core.Collection, err error) error {
	e.App.Logger().Debug("Invalid OAuth2 hosted page submission", "error", err)

	return oauth2RenderErrorPage(e, collection, http.StatusBadRequest, newOAuth2Error(
		http.StatusBadRequest,
		oauth2ErrInvalidRequest,
		"Invalid or expired form submission. Please go back to the application and try again.",
	))
}

// oauth2PageForm returns the common hidden fields of the flow forms.
func oauth2PageForm(e *core.RequestEvent, flow *oauth2Flow) pages.Form {
	return pages.Form{
		AuthState: flow.handle,
		CSRF:      oauth2CSRFToken(e, flow.collection),
	}
}

func oauth2PageClient(client *core.OAuth2Client) pages.Client {
	return pages.Client{Name: client.Name(), Logo: client.Logo()}
}

func oauth2UserLabel(record *core.Record) string {
	if record == nil {
		return ""
	}

	if email := record.Email(); email != "" {
		return email
	}

	return record.Id
}

func oauth2IdentityLabel(collection *core.Collection) string {
	fields := collection.PasswordAuth.IdentityFields
	if len(fields) == 0 {
		return "Email"
	}

	labels := make([]string, len(fields))
	for i, f := range fields {
		labels[i] = f
		if i == 0 && len(f) > 0 {
			labels[i] = strings.ToUpper(f[:1]) + f[1:]
		}
	}

	return strings.Join(labels, " or ")
}
