package apis

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
)

const (
	oauth2PromptNone    = "none"
	oauth2PromptLogin   = "login"
	oauth2PromptConsent = "consent"

	// treated as "login" since there is no multi-account session support
	oauth2PromptSelectAccount = "select_account"

	// OpenID Connect "Initiating User Registration via OpenID Connect 1.0":
	// the flow starts directly at the hosted signup page (supported only
	// by the issuers that allow the hosted signup, see oauth2SignupAllowed)
	oauth2PromptCreate = "create"
)

// the list of the supported authorization request parameters
// (the parameters that are preserved between the hosted login and consent steps)
var oauth2AuthorizeParams = []string{
	"client_id",
	"redirect_uri",
	"response_type",
	"response_mode",
	"scope",
	"state",
	"nonce",
	"code_challenge",
	"code_challenge_method",
	"prompt",
	"max_age",
	"login_hint",
	"ui_locales",
	"request",
	"request_uri",
}

// PKCE code_challenge (base64url encoded SHA256 = 43 chars; up to 128 for completeness)
var oauth2CodeChallengeRegex = regexp.MustCompile(`^[A-Za-z0-9\-\._~]{43,128}$`)

// oauth2AuthorizeRequest defines an OAuth2 authorization request.
type oauth2AuthorizeRequest struct {
	params     map[string]string
	duplicated []string

	// resolved after validate()
	client  *core.OAuth2Client
	scopes  []string
	prompts []string
	maxAge  int64 // -1 if not set
}

func newOAuth2AuthorizeRequest(values url.Values) *oauth2AuthorizeRequest {
	r := &oauth2AuthorizeRequest{params: map[string]string{}, maxAge: -1}

	for _, k := range oauth2AuthorizeParams {
		v := values[k]
		if len(v) > 1 {
			r.duplicated = append(r.duplicated, k)
		}
		if len(v) > 0 && v[0] != "" {
			r.params[k] = v[0]
		}
	}

	return r
}

func (r *oauth2AuthorizeRequest) get(key string) string {
	return r.params[key]
}

func (r *oauth2AuthorizeRequest) hasPrompt(prompt string) bool {
	return slices.Contains(r.prompts, prompt)
}

// validate validates the authorization request params and resolves its client and scopes.
//
// The errors before the client and redirect_uri validation are not redirectable
// (they must be shown to the user instead of redirecting to a possibly malicious URI).
func (r *oauth2AuthorizeRequest) validate(e *core.RequestEvent, collection *core.Collection) *oauth2Error {
	app := e.App

	pageErr := func(code string, description string) *oauth2Error {
		return newOAuth2Error(http.StatusBadRequest, code, description)
	}

	if slices.Contains(r.duplicated, "client_id") || slices.Contains(r.duplicated, "redirect_uri") {
		return pageErr(oauth2ErrInvalidRequest, "Duplicated client_id or redirect_uri parameter.")
	}

	clientId := r.get("client_id")
	if clientId == "" {
		return pageErr(oauth2ErrInvalidRequest, "Missing client_id parameter.")
	}

	client, err := app.FindOAuth2ClientByClientId(clientId)
	if err != nil || !client.IsUsable() || client.CollectionRef() != collection.Id {
		return pageErr(oauth2ErrInvalidClient, "Unknown or disabled client.")
	}

	redirectURI := r.get("redirect_uri")
	if redirectURI == "" {
		return pageErr(oauth2ErrInvalidRequest, "Missing redirect_uri parameter.")
	}

	if !oauth2AllowsRedirectURI(e, client, redirectURI) {
		return pageErr(oauth2ErrInvalidRequest, "The redirect_uri is not registered for the client.")
	}

	r.client = client

	// from here on the errors are redirected back to the client
	// ---
	redirectErr := func(code string, description string) *oauth2Error {
		err := newOAuth2Error(http.StatusBadRequest, code, description)
		err.redirectable = true
		return err
	}

	if len(r.duplicated) > 0 {
		return redirectErr(oauth2ErrInvalidRequest, "Duplicated "+r.duplicated[0]+" parameter.")
	}

	if r.get("request") != "" {
		return redirectErr(oauth2ErrRequestNotSupported, "The request parameter is not supported.")
	}

	if r.get("request_uri") != "" {
		return redirectErr(oauth2ErrRequestURINotSupported, "The request_uri parameter is not supported.")
	}

	if mode := r.get("response_mode"); mode != "" && mode != "query" {
		return redirectErr(oauth2ErrInvalidRequest, "Only query response_mode is supported.")
	}

	if r.get("response_type") != "code" {
		return redirectErr(oauth2ErrUnsupportedResponseType, "Only code response_type is supported.")
	}

	// since superuser tokens bypass all collection rules
	// allow only trusted first-party clients
	if collection.Name == core.CollectionNameSuperusers && !client.FirstParty() {
		return redirectErr(oauth2ErrUnauthorizedClient, "Only first-party clients are allowed to authenticate superusers.")
	}

	// scopes
	scopes := list.ToUniqueStringSlice(strings.Fields(r.get("scope")))
	if len(scopes) == 0 {
		return redirectErr(oauth2ErrInvalidScope, "Missing scope parameter.")
	}
	allowedScopes := core.OAuth2AllowedScopes(e.App, collection)
	clientScopes := client.Scopes()
	for _, s := range scopes {
		if !slices.Contains(allowedScopes, s) || !slices.Contains(clientScopes, s) {
			return redirectErr(oauth2ErrInvalidScope, "The scope "+s+" is not allowed for the client.")
		}
	}
	r.scopes = scopes

	// PKCE
	//
	// note: PKCE is required for all clients (incl. confidential) as recommended
	// by RFC 9700 and OAuth 2.1 (it also protects confidential clients against code injection)
	challenge := r.get("code_challenge")
	method := r.get("code_challenge_method")
	if challenge == "" {
		return redirectErr(oauth2ErrInvalidRequest, "PKCE code_challenge (S256) is required.")
	}
	if method != "S256" {
		// plain is the RFC 7636 default but only S256 is supported
		return redirectErr(oauth2ErrInvalidRequest, "Only S256 code_challenge_method is supported.")
	}
	if !oauth2CodeChallengeRegex.MatchString(challenge) {
		return redirectErr(oauth2ErrInvalidRequest, "Invalid code_challenge parameter.")
	}

	// prompt
	prompts := list.ToUniqueStringSlice(strings.Fields(r.get("prompt")))
	for _, p := range prompts {
		switch p {
		case oauth2PromptNone, oauth2PromptLogin, oauth2PromptConsent, oauth2PromptSelectAccount:
		case oauth2PromptCreate:
			// not declared in the issuer prompt_values_supported without the hosted signup
			// (the spec "unsupported prompt value" error: invalid_request)
			if !oauth2SignupAllowed(collection) {
				return redirectErr(oauth2ErrInvalidRequest, "Unsupported prompt value create (sign up is not allowed).")
			}
		default:
			return redirectErr(oauth2ErrInvalidRequest, "Unsupported prompt value "+p+".")
		}
	}
	if slices.Contains(prompts, oauth2PromptNone) && len(prompts) > 1 {
		return redirectErr(oauth2ErrInvalidRequest, "The prompt none value cannot be combined with other values.")
	}
	r.prompts = prompts

	// max_age
	r.maxAge = -1
	if rawMaxAge := r.get("max_age"); rawMaxAge != "" {
		maxAge, err := strconv.ParseInt(rawMaxAge, 10, 64)
		if err != nil || maxAge < 0 {
			return redirectErr(oauth2ErrInvalidRequest, "Invalid max_age parameter.")
		}
		r.maxAge = maxAge
	}

	// minimal sanity checks to prevent storing large strings
	if len(r.get("nonce")) > 512 {
		return redirectErr(oauth2ErrInvalidRequest, "The nonce parameter is too long.")
	}
	if len(r.get("state")) > 2048 {
		return redirectErr(oauth2ErrInvalidRequest, "The state parameter is too long.")
	}
	if len(r.get("login_hint")) > 255 {
		return redirectErr(oauth2ErrInvalidRequest, "The login_hint parameter is too long.")
	}
	if len(r.get("ui_locales")) > 255 {
		return redirectErr(oauth2ErrInvalidRequest, "The ui_locales parameter is too long.")
	}

	return nil
}

// -------------------------------------------------------------------
// Authorization endpoint
// -------------------------------------------------------------------

// GET|POST {issuer}/authorize
//
// Validates the authorization request, creates a new pending auth session
// bound to the current browser (binding cookie) and either:
//   - reuses the root SSO session (if any and allowed by prompt and max_age)
//   - or redirects to the hosted login page with the opaque auth_state handle.
func oauth2ServerAuthorize(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	values := e.Request.URL.Query()

	// OpenID Connect Core section 3.1.2.1 (form serialized POST)
	if e.Request.Method == http.MethodPost {
		if err := e.Request.ParseForm(); err != nil {
			return oauth2RenderErrorPage(e, collection, http.StatusBadRequest, newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Failed to read the request body."))
		}
		values = e.Request.PostForm
	}

	req := newOAuth2AuthorizeRequest(values)
	if oerr := req.validate(e, collection); oerr != nil {
		return oauth2AuthorizeErrorResponse(e, collection, req, oerr)
	}

	root := loadOAuth2SSOSession(e, collection)

	reuseSSO := root != nil &&
		!req.hasPrompt(oauth2PromptLogin) &&
		!req.hasPrompt(oauth2PromptSelectAccount) &&
		!req.hasPrompt(oauth2PromptCreate) &&
		(req.maxAge < 0 || time.Since(root.session.AuthTime().Time()) <= time.Duration(req.maxAge)*time.Second)

	if !reuseSSO && req.hasPrompt(oauth2PromptNone) {
		return oauth2AuthorizeErrorResponse(e, collection, req, oauth2RedirectError(oauth2ErrLoginRequired, "End-user authentication is required."))
	}

	flow, err := newOAuth2Flow(e, collection, req)
	if err != nil {
		return oauth2AuthorizeErrorResponse(e, collection, req, toOAuth2Error(err, oauth2ErrServerError))
	}

	if reuseSSO {
		return oauth2ReuseSSOSession(e, flow, root)
	}

	// prompt=create opens the hosted signup page of the same flow (the signup page links
	// back to the login page and after the signup the flow continues as after a login)
	if req.hasPrompt(oauth2PromptCreate) {
		return oauth2RedirectToStep(e, flow, "/signup")
	}

	return oauth2RedirectToStep(e, flow, "/login")
}

// newOAuth2Flow creates and persists a new pending auth session from
// the already validated authorization request and sets its browser binding cookie.
func newOAuth2Flow(e *core.RequestEvent, collection *core.Collection, req *oauth2AuthorizeRequest) (*oauth2Flow, error) {
	handle := security.RandomString(oauth2HandleLength)
	binding := security.RandomString(oauth2BindingLength)

	session := core.NewAuthSession(e.App)
	session.SetCollectionRef(collection.Id)
	session.SetClient(req.client.Id)
	session.SetHandle(handle)
	session.SetBinding(binding)
	session.SetRedirectURI(req.get("redirect_uri"))
	session.SetResponseMode(req.get("response_mode"))
	session.SetState(req.get("state"))
	session.SetNonce(req.get("nonce"))
	session.SetCodeChallenge(req.get("code_challenge"), req.get("code_challenge_method"))
	session.SetPrompt(strings.Join(req.prompts, " "))
	session.SetMaxAge(req.maxAge)
	session.SetLoginHint(req.get("login_hint"))
	session.SetUILocales(req.get("ui_locales"))
	session.SetScopesRequested(req.scopes)
	session.SetScopes([]string{})
	session.SetIP(e.RealIP())
	session.SetUserAgent(e.Request.UserAgent())
	session.SetLastUsedAt(types.NowDateTime())
	session.SetExpiresAt(types.NowDateTime().Add(core.AuthSessionFlowDuration))

	if err := e.App.Save(session); err != nil {
		return nil, err
	}

	setOAuth2Cookie(
		e,
		collection,
		oauth2ServerBindingCookiePrefix+session.Id,
		binding,
		int(core.AuthSessionFlowDuration.Seconds()),
		// Lax so that the cookie is sent with the top-level navigations
		// (incl. the redirect back from an upstream OAuth2 provider)
		http.SameSiteLaxMode,
	)

	return &oauth2Flow{
		collection: collection,
		session:    session,
		client:     req.client,
		handle:     handle,
	}, nil
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

func oauth2RedirectError(code string, description string) *oauth2Error {
	err := newOAuth2Error(http.StatusBadRequest, code, description)
	err.redirectable = true
	return err
}

// oauth2AuthorizeErrorResponse sends the authorization error response:
//   - redirect to the client redirect_uri with error, error_description, state and iss
//     query parameters if the error is redirectable
//   - otherwise renders the error page
func oauth2AuthorizeErrorResponse(e *core.RequestEvent, collection *core.Collection, req *oauth2AuthorizeRequest, oerr *oauth2Error) error {
	if oerr.Code == oauth2ErrServerError {
		e.App.Logger().Error("OAuth2 authorization server error", "error", oerr)
	}

	if !oerr.redirectable || req == nil || req.client == nil || !oauth2AllowsRedirectURI(e, req.client, req.get("redirect_uri")) {
		return oauth2RenderErrorPage(e, collection, http.StatusBadRequest, oerr)
	}

	params := url.Values{}
	params.Set("error", oerr.Code)
	if oerr.Description != "" {
		params.Set("error_description", oerr.Description)
	}
	if state := req.get("state"); state != "" {
		params.Set("state", state)
	}
	params.Set("iss", core.OAuth2Issuer(e.App, collection))

	return e.Redirect(oauth2RedirectStatus(e), oauth2BuildRedirectURL(req.get("redirect_uri"), params))
}

// oauth2BuildRedirectURL appends the provided params to the redirect URI
// (preserving its existing query parameters).
func oauth2BuildRedirectURL(redirectURI string, params url.Values) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI // shouldn't happen since the redirect uris are validated on save
	}

	query := u.Query()
	for k, v := range params {
		query[k] = v
	}
	u.RawQuery = query.Encode()

	return u.String()
}

func oauth2RedirectStatus(e *core.RequestEvent) int {
	if e.Request.Method == http.MethodGet {
		return http.StatusFound
	}

	return http.StatusSeeOther
}
