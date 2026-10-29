package apis

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/pages"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
)

// Hosted login flow
// -------------------------------------------------------------------
//
// Each authorization request creates a new pending [core.AuthSession]
// (aka. the flow) that is filled incrementally while the browser walks
// the hosted pages steps.
//
// The browser holds only:
//   - the opaque "auth_state" handle (passed as query or form parameter; only its hash is stored)
//   - the per flow binding cookie (only its hash is stored) that is checked on every step
//     with the exception of the upstream OAuth2 provider callback (it is a cross-site POST
//     for some providers) which rotates the handle and redirects to a GET continue step
//     that checks the binding cookie
//
// After each completed factor the flow checks the collection MFA requirements
// and once all factors are satisfied completes the session authentication
// (AuthRule, SuperuserIPs, OnAuthSessionCompleteRequest hook), establishes the
// root SSO session ("pb_session" cookie) and continues with the consent
// and the authorization code steps.

const (
	oauth2HandleLength    = 40
	oauth2BindingLength   = 32
	oauth2SSOSecretLength = 40
	oauth2CodeLength      = 50
)

// errInvalidOAuth2Flow is returned when the auth_state handle,
// binding cookie or session state of the current request are invalid.
var errInvalidOAuth2Flow = errors.New("missing, expired or invalid hosted login flow")

// errOAuth2FactorMismatch is returned when a factor identifies a
// different record than the already identified session actor.
var errOAuth2FactorMismatch = errors.New("the auth factor identified a different record")

// oauth2Flow holds the loaded state of a hosted login flow.
type oauth2Flow struct {
	collection *core.Collection
	session    *core.AuthSession
	client     *core.OAuth2Client

	// record is the identified actor (nil until the first factor)
	record *core.Record

	// handle is the current plain opaque auth_state handle
	handle string
}

// stepURL returns the same-origin URL of the specified hosted flow step (e.g. "/login").
func (f *oauth2Flow) stepURL(app core.App, path string) string {
	return oauth2PagesURL(app, f.collection) + path + "?auth_state=" + url.QueryEscape(f.handle)
}

// oauth2FlowHandle returns the auth_state handle from the request query or form body.
func oauth2FlowHandle(e *core.RequestEvent) string {
	if v := e.Request.URL.Query().Get("auth_state"); v != "" {
		return v
	}

	if e.Request.Method == http.MethodPost {
		return e.Request.PostFormValue("auth_state")
	}

	return ""
}

// loadOAuth2Flow loads the hosted login flow of the provided plain handle
// and checks its browser binding cookie.
//
// Only pending and authenticated (aka. waiting for consent) flows are loaded.
func loadOAuth2Flow(e *core.RequestEvent, collection *core.Collection, handle string) (*oauth2Flow, error) {
	if handle == "" || len(handle) > 255 {
		return nil, errInvalidOAuth2Flow
	}

	session, err := e.App.FindAuthSessionByHandle(handle)
	if err != nil {
		return nil, errInvalidOAuth2Flow
	}

	return loadOAuth2FlowSession(e, collection, session, handle, true)
}

func loadOAuth2FlowSession(e *core.RequestEvent, collection *core.Collection, session *core.AuthSession, handle string, checkBinding bool) (*oauth2Flow, error) {
	if session.CollectionRef() != collection.Id || session.HasExpired() {
		return nil, errInvalidOAuth2Flow
	}

	status := session.Status()
	if status != core.AuthSessionStatusPending && status != core.AuthSessionStatusAuthenticated {
		return nil, errInvalidOAuth2Flow
	}

	if checkBinding {
		cookie, err := e.Request.Cookie(oauth2ServerBindingCookiePrefix + session.Id)
		if err != nil || !session.ValidateBinding(cookie.Value) {
			return nil, errInvalidOAuth2Flow
		}
	}

	client, err := e.App.FindOAuth2ClientById(session.Client())
	if err != nil || !client.IsUsable() || client.CollectionRef() != collection.Id || !oauth2AllowsRedirectURI(e, client, session.RedirectURI()) {
		return nil, errInvalidOAuth2Flow
	}

	flow := &oauth2Flow{
		collection: collection,
		session:    session,
		client:     client,
		handle:     handle,
	}

	if recordId := session.RecordRef(); recordId != "" {
		flow.record, err = e.App.FindRecordById(collection, recordId)
		if err != nil {
			return nil, errInvalidOAuth2Flow
		}
	}

	return flow, nil
}

// loadOAuth2FlowFromRequest loads the issuer collection and
// the hosted login flow of the current request.
//
// On failure it renders the error page and handled is true.
func loadOAuth2FlowFromRequest(e *core.RequestEvent) (flow *oauth2Flow, handled bool, err error) {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return nil, true, err
	}

	flow, err = loadOAuth2Flow(e, collection, oauth2FlowHandle(e))
	if err != nil {
		return nil, true, oauth2RenderInvalidFlowPage(e, collection, err)
	}

	return flow, false, nil
}

func oauth2RenderInvalidFlowPage(e *core.RequestEvent, collection *core.Collection, err error) error {
	e.App.Logger().Debug("Invalid OAuth2 hosted login flow", "error", err)

	return oauth2RenderErrorPage(e, collection, http.StatusBadRequest, newOAuth2Error(
		http.StatusBadRequest,
		oauth2ErrInvalidRequest,
		"Missing or expired sign-in request. Please go back to the application and try again.",
	))
}

// oauth2RedirectToStep redirects to the specified hosted flow step (e.g. "/login").
func oauth2RedirectToStep(e *core.RequestEvent, flow *oauth2Flow, path string) error {
	return e.Redirect(oauth2RedirectStatus(e), flow.stepURL(e.App, path))
}

func clearOAuth2BindingCookie(e *core.RequestEvent, flow *oauth2Flow) {
	setOAuth2Cookie(e, flow.collection, oauth2ServerBindingCookiePrefix+flow.session.Id, "", -1, http.SameSiteLaxMode)
}

// oauth2FlowError fails the flow (if not already terminal) and redirects
// back to the client redirect_uri with the provided error.
func oauth2FlowError(e *core.RequestEvent, flow *oauth2Flow, oerr *oauth2Error) error {
	if oerr.Code == oauth2ErrServerError {
		e.App.Logger().Error("OAuth2 hosted login flow error", "error", oerr, "sessionId", flow.session.Id)
	}

	if !flow.session.IsTerminal() {
		if err := flow.session.Fail(); err == nil {
			if err := e.App.Save(flow.session); err != nil {
				e.App.Logger().Warn("Failed to mark the auth session as failed", "error", err, "sessionId", flow.session.Id)
			}
		}
	}

	clearOAuth2BindingCookie(e, flow)

	redirectURI := flow.session.RedirectURI()
	if !oauth2AllowsRedirectURI(e, flow.client, redirectURI) {
		return oauth2RenderErrorPage(e, flow.collection, http.StatusBadRequest, oerr)
	}

	params := url.Values{}
	params.Set("error", oerr.Code)
	if oerr.Description != "" {
		params.Set("error_description", oerr.Description)
	}
	if state := flow.session.State(); state != "" {
		params.Set("state", state)
	}
	params.Set("iss", core.OAuth2Issuer(e.App, flow.collection))

	return e.Redirect(oauth2RedirectStatus(e), oauth2BuildRedirectURL(redirectURI, params))
}

// -------------------------------------------------------------------
// Factors
// -------------------------------------------------------------------

// oauth2AddFactor triggers the OnAuthSessionStepRequest hook and registers the factor in the flow session.
//
// The first factor identifies the session actor and evaluates whether MFA is required.
func oauth2AddFactor(e *core.RequestEvent, flow *oauth2Flow, record *core.Record, method string, provider string) error {
	if flow.session.Status() != core.AuthSessionStatusPending {
		return errInvalidOAuth2Flow
	}

	if record == nil || record.Collection().Id != flow.collection.Id {
		return errors.New("missing or invalid auth factor record")
	}

	if flow.record != nil && flow.record.Id != record.Id {
		return errOAuth2FactorMismatch
	}

	event := new(core.AuthSessionStepRequestEvent)
	event.RequestEvent = e
	event.Collection = flow.collection
	event.Session = flow.session
	event.Record = record
	event.Method = method
	event.Provider = provider

	return e.App.OnAuthSessionStepRequest().Trigger(event, func(ev *core.AuthSessionStepRequestEvent) error {
		if ev.Record == nil || ev.Record.Collection().Id != flow.collection.Id || ev.Method == "" {
			return errors.New("missing or invalid auth factor record or method")
		}

		if flow.record != nil && flow.record.Id != ev.Record.Id {
			return errOAuth2FactorMismatch
		}

		if flow.record == nil {
			if err := oauth2IdentifyActor(ev.RequestEvent, flow, ev.Record); err != nil {
				return err
			}
		}

		flow.session.AddAuthMethod(ev.Method, ev.Provider)
		flow.session.SetLastUsedAt(types.NowDateTime())

		return ev.App.Save(flow.session)
	})
}

// oauth2IdentifyActor assigns the flow actor and evaluates whether MFA is required.
//
// Note that the changes are not persisted.
func oauth2IdentifyActor(e *core.RequestEvent, flow *oauth2Flow, record *core.Record) error {
	flow.record = record
	flow.session.SetRecordRef(record.Id)

	mfaRequired := false
	if flow.collection.MFA.Enabled {
		// note: returns true even on error as a safer default
		mfaRequired, _ = wantsMFA(e, record)
	}
	flow.session.SetMFARequired(mfaRequired)

	return nil
}

// oauth2RemainingMFAMethods returns the enabled factor methods that
// were not completed within the collection MFA duration.
func oauth2RemainingMFAMethods(flow *oauth2Flow) (password bool, otp bool, oauth2 bool) {
	used := flow.session.DistinctAuthMethods(oauth2MFAWindowStart(flow))

	password = flow.collection.PasswordAuth.Enabled && !slices.Contains(used, core.AuthSessionMethodPassword)
	otp = flow.collection.OTP.Enabled && !slices.Contains(used, core.AuthSessionMethodOTP)
	oauth2 = oauth2ProvidersAllowed(flow.collection) && !slices.Contains(used, core.AuthSessionMethodOAuth2)

	return
}

func oauth2MFAWindowStart(flow *oauth2Flow) time.Time {
	return time.Now().Add(-flow.collection.MFA.DurationTime())
}

// oauth2ProvidersAllowed reports whether the upstream OAuth2 providers are allowed for the collection.
func oauth2ProvidersAllowed(collection *core.Collection) bool {
	return collection.OAuth2.Enabled &&
		len(collection.OAuth2.Providers) > 0 &&
		collection.Name != core.CollectionNameSuperusers
}

// -------------------------------------------------------------------
// Continue and complete
// -------------------------------------------------------------------

// oauth2ContinueFlow redirects to the next required flow step.
func oauth2ContinueFlow(e *core.RequestEvent, flow *oauth2Flow) error {
	switch flow.session.Status() {
	case core.AuthSessionStatusAuthenticated:
		return oauth2ProceedToConsent(e, flow)
	case core.AuthSessionStatusPending:
		// continue below
	default:
		return oauth2RenderInvalidFlowPage(e, flow.collection, errInvalidOAuth2Flow)
	}

	if flow.record == nil {
		return oauth2RedirectToStep(e, flow, "/login")
	}

	if flow.session.MFARequired() && len(flow.session.DistinctAuthMethods(oauth2MFAWindowStart(flow))) < 2 {
		return oauth2RedirectToStep(e, flow, "/login/mfa")
	}

	return oauth2CompleteFlow(e, flow, false)
}

// oauth2CompleteFlow completes the flow session authentication
// (AuthRule, SuperuserIPs and the OnAuthSessionCompleteRequest hook),
// establishes the root SSO session (on interactive login) and
// continues with the consent and authorization code steps.
func oauth2CompleteFlow(e *core.RequestEvent, flow *oauth2Flow, sso bool) error {
	if err := checkRecordAuthAllowed(e, flow.record); err != nil {
		return oauth2FlowError(e, flow, oauth2RedirectError(oauth2ErrAccessDenied, "The end-user is not allowed to authenticate."))
	}

	requested := flow.session.ScopesRequested()

	event := new(core.AuthSessionCompleteRequestEvent)
	event.RequestEvent = e
	event.Collection = flow.collection
	event.Session = flow.session
	event.Client = flow.client
	event.Record = flow.record
	event.Scopes = slices.Clone(requested)
	event.SSO = sso

	err := e.App.OnAuthSessionCompleteRequest().Trigger(event, func(ev *core.AuthSessionCompleteRequestEvent) error {
		// the hook handlers could only reduce the requested scopes
		scopes := make([]string, 0, len(ev.Scopes))
		for _, s := range ev.Scopes {
			if slices.Contains(requested, s) && !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
		flow.session.SetScopes(scopes)
		flow.session.SetLastUsedAt(types.NowDateTime())

		if err := flow.session.MarkAuthenticated(); err != nil {
			return err
		}

		if !ev.SSO {
			if err := oauth2EstablishSSOSession(ev.RequestEvent, flow); err != nil {
				return err
			}
		}

		if err := ev.App.Save(flow.session); err != nil {
			return err
		}

		if !ev.SSO && flow.collection.AuthAlert.Enabled {
			if err := authAlert(ev.RequestEvent, flow.record); err != nil {
				ev.App.Logger().Warn("Failed to send login alert", "error", err)
			}
		}

		return nil
	})
	if err != nil {
		if e.Written() {
			return err
		}

		return oauth2FlowError(e, flow, oauth2RejectedError(e, err, "The authentication was rejected."))
	}

	return oauth2ProceedToConsent(e, flow)
}

// -------------------------------------------------------------------
// SSO (root session)
// -------------------------------------------------------------------

// oauth2SSO holds a loaded root SSO session and its actor.
type oauth2SSO struct {
	session *core.AuthSession
	record  *core.Record
}

// loadOAuth2SSOSession loads the active root SSO session of the specified
// issuer from the "pb_session" cookie (returns nil if missing or invalid).
func loadOAuth2SSOSession(e *core.RequestEvent, collection *core.Collection) *oauth2SSO {
	cookie, err := e.Request.Cookie(oauth2ServerSSOCookie)
	if err != nil || cookie.Value == "" || len(cookie.Value) > 255 {
		return nil
	}

	id, secret, ok := strings.Cut(cookie.Value, ".")
	if !ok || id == "" || secret == "" {
		return nil
	}

	session, err := e.App.FindAuthSessionById(id)
	if err != nil ||
		!session.IsRoot() ||
		!session.ValidateSSOSecret(secret) ||
		session.CollectionRef() != collection.Id ||
		!session.IsActive() {
		return nil
	}

	record, err := e.App.FindRecordById(collection, session.RecordRef())
	if err != nil {
		return nil
	}

	return &oauth2SSO{session: session, record: record}
}

// oauth2EstablishSSOSession creates (or refreshes) the root SSO session
// of the flow actor and links it as the flow session parent
// (aka. every interactive flow session, incl. the first one, is a child of the root).
//
// An existing root SSO session of a different actor is ended (incl. its children).
//
// Note that the flow session changes are not persisted.
func oauth2EstablishSSOSession(e *core.RequestEvent, flow *oauth2Flow) error {
	now := types.NowDateTime()

	existing := loadOAuth2SSOSession(e, flow.collection)
	if existing != nil && existing.record.Id == flow.record.Id {
		existing.session.SetAuthMethods(flow.session.AuthMethods())
		existing.session.SetAuthTime(flow.session.AuthTime())
		existing.session.SetLastUsedAt(now)
		err := e.App.Save(existing.session)
		if err == nil {
			flow.session.SetParent(existing.session.Id)
			return nil
		}

		// ended concurrently (e.g. logout) -> create a new root below
		if !errors.Is(err, core.ErrInvalidAuthSessionTransition) {
			return err
		}
		existing = nil
	}

	if existing != nil {
		if err := existing.session.End(); err != nil {
			return err
		}
		if err := e.App.Save(existing.session); err != nil {
			return err
		}
	}

	secret := security.RandomString(oauth2SSOSecretLength)
	duration := flow.collection.OAuth2Server.SessionDurationTime()

	// note: the root is a standalone browser session row that is not bound to any client
	// (the client sessions are its children)
	root := core.NewAuthSession(e.App)
	root.Set("status", core.AuthSessionStatusActive)
	root.SetCollectionRef(flow.collection.Id)
	root.SetRecordRef(flow.record.Id)
	root.SetAuthMethods(flow.session.AuthMethods())
	root.SetAuthTime(flow.session.AuthTime())
	root.SetScopesRequested([]string{})
	root.SetScopes([]string{})
	root.SetSSOSecret(secret)
	root.SetIP(e.RealIP())
	root.SetUserAgent(e.Request.UserAgent())
	root.SetLastUsedAt(now)
	root.SetExpiresAt(now.Add(duration))
	if err := e.App.Save(root); err != nil {
		return err
	}

	setOAuth2Cookie(e, flow.collection, oauth2ServerSSOCookie, root.Id+"."+secret, int(duration.Seconds()), http.SameSiteLaxMode)

	flow.session.SetParent(root.Id)

	return nil
}

// oauth2ReuseSSOSession completes the flow by reusing the actor and factors of the root SSO session.
func oauth2ReuseSSOSession(e *core.RequestEvent, flow *oauth2Flow, root *oauth2SSO) error {
	// touch the root first so that a root ended concurrently (e.g. by an in-flight logout)
	// is never reused (the stale root save is rejected by the session status transition check)
	root.session.SetLastUsedAt(types.NowDateTime())
	if err := e.App.Save(root.session); err != nil {
		if !errors.Is(err, core.ErrInvalidAuthSessionTransition) {
			return oauth2FlowError(e, flow, toOAuth2Error(err, oauth2ErrServerError))
		}

		clearOAuth2SSOCookie(e, flow.collection)

		if slices.Contains(strings.Fields(flow.session.Prompt()), oauth2PromptNone) {
			return oauth2FlowError(e, flow, oauth2RedirectError(oauth2ErrLoginRequired, "End-user authentication is required."))
		}

		return oauth2RedirectToStep(e, flow, "/login")
	}

	flow.record = root.record
	flow.session.SetRecordRef(root.record.Id)
	flow.session.SetAuthMethods(root.session.AuthMethods())
	flow.session.SetAuthTime(root.session.AuthTime())
	flow.session.SetParent(root.session.Id)

	// the reused factors must satisfy the current MFA policy
	// (e.g. MFA was enabled or its rule changed after the root login)
	mfaRequired := false
	if flow.collection.MFA.Enabled {
		// note: returns true even on error as a safer default
		mfaRequired, _ = wantsMFA(e, root.record)
	}
	flow.session.SetMFARequired(mfaRequired)

	if err := e.App.Save(flow.session); err != nil {
		return oauth2FlowError(e, flow, toOAuth2Error(err, oauth2ErrServerError))
	}

	if mfaRequired && len(flow.session.DistinctAuthMethods(oauth2MFAWindowStart(flow))) < 2 {
		if slices.Contains(strings.Fields(flow.session.Prompt()), oauth2PromptNone) {
			return oauth2FlowError(e, flow, oauth2RedirectError(oauth2ErrInteractionRequired, "End-user interaction (multi-factor authentication) is required."))
		}

		// step-up (the completed MFA factor refreshes the root factors, see oauth2EstablishSSOSession)
		return oauth2RedirectToStep(e, flow, "/login/mfa")
	}

	return oauth2CompleteFlow(e, flow, true)
}

// clearOAuth2SSOCookie removes the "pb_session" cookie of the specified issuer.
func clearOAuth2SSOCookie(e *core.RequestEvent, collection *core.Collection) {
	setOAuth2Cookie(e, collection, oauth2ServerSSOCookie, "", -1, http.SameSiteLaxMode)
}

// -------------------------------------------------------------------
// Consent and authorization code
// -------------------------------------------------------------------

// oauth2ProceedToConsent redirects to the consent page when needed
// or otherwise issues the authorization code.
func oauth2ProceedToConsent(e *core.RequestEvent, flow *oauth2Flow) error {
	needsConsent, err := oauth2NeedsConsent(e.App, flow)
	if err != nil {
		return oauth2FlowError(e, flow, toOAuth2Error(err, oauth2ErrServerError))
	}

	if needsConsent {
		if slices.Contains(strings.Fields(flow.session.Prompt()), oauth2PromptNone) {
			return oauth2FlowError(e, flow, oauth2RedirectError(oauth2ErrConsentRequired, "End-user consent is required."))
		}

		return oauth2RedirectToStep(e, flow, "/consent")
	}

	return oauth2IssueCode(e, flow)
}

// oauth2NeedsConsent reports whether the end-user consent is required for the flow.
//
// Consent is required if:
//   - prompt=consent is explicitly requested, or
//   - the collection requires consent, the client is not first-party
//     and there is no remembered consent of the client covering the granted scopes.
func oauth2NeedsConsent(app core.App, flow *oauth2Flow) (bool, error) {
	if slices.Contains(strings.Fields(flow.session.Prompt()), oauth2PromptConsent) {
		return true, nil
	}

	if !flow.collection.OAuth2Server.ConsentRequired || flow.client.FirstParty() {
		return false, nil
	}

	consent, err := app.FindOAuth2ConsentByRecordAndClient(flow.record, flow.client)
	if err != nil {
		return true, nil // no remembered consent
	}

	return !consent.Covers(flow.session.Scopes()), nil
}

// oauth2IssueCode triggers the OnOAuth2AuthorizeRequest hook, issues a new
// authorization code for the flow session and redirects back to the client redirect_uri.
func oauth2IssueCode(e *core.RequestEvent, flow *oauth2Flow) error {
	event := new(core.OAuth2AuthorizeRequestEvent)
	event.RequestEvent = e
	event.Collection = flow.collection
	event.Client = flow.client
	event.Record = flow.record
	event.Scopes = flow.session.Scopes()
	event.RedirectURI = flow.session.RedirectURI()
	event.State = flow.session.State()
	event.Nonce = flow.session.Nonce()

	hookErr := e.App.OnOAuth2AuthorizeRequest().Trigger(event, func(e *core.OAuth2AuthorizeRequestEvent) error {
		if !oauth2AllowsRedirectURI(e.RequestEvent, e.Client, e.RedirectURI) {
			return errors.New("the redirect_uri is not registered for the client")
		}

		// the hook handlers could only reduce the granted scopes
		granted := flow.session.Scopes()
		scopes := make([]string, 0, len(e.Scopes))
		for _, s := range e.Scopes {
			if slices.Contains(granted, s) && !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}

		plainCode := security.RandomString(oauth2CodeLength)

		flow.session.SetScopes(scopes)
		flow.session.SetRedirectURI(e.RedirectURI)
		flow.session.SetState(e.State)
		flow.session.SetNonce(e.Nonce)
		flow.session.SetCode(plainCode, types.NowDateTime().Add(e.Collection.OAuth2Server.CodeDurationTime()))
		flow.session.SetLastUsedAt(types.NowDateTime())
		if err := flow.session.MarkAuthorized(); err != nil {
			return err
		}
		if err := e.App.Save(flow.session); err != nil {
			return err
		}

		clearOAuth2BindingCookie(e.RequestEvent, flow)

		params := url.Values{}
		params.Set("code", plainCode)
		if e.State != "" {
			params.Set("state", e.State)
		}
		params.Set("iss", core.OAuth2Issuer(e.App, e.Collection))

		return e.Redirect(oauth2RedirectStatus(e.RequestEvent), oauth2BuildRedirectURL(e.RedirectURI, params))
	})
	if hookErr != nil {
		if e.Written() {
			return hookErr
		}

		return oauth2FlowError(e, flow, oauth2RejectedError(e, hookErr, "The authorization request was rejected."))
	}

	return nil
}

// oauth2RejectedError converts a hook (or default action) error into a redirectable access_denied error
// (the ApiErrors with status < 500 keep their message).
func oauth2RejectedError(e *core.RequestEvent, err error, fallbackDescription string) *oauth2Error {
	oerr := toOAuth2Error(err, oauth2ErrAccessDenied)
	if oerr.Code == oauth2ErrServerError || oerr.Code == oauth2ErrInvalidClient {
		e.App.Logger().Debug("Rejected OAuth2 hosted login flow", "error", err)
		oerr = newOAuth2Error(http.StatusBadRequest, oauth2ErrAccessDenied, fallbackDescription)
	}

	return oerr
}

// GET {issuer}/consent?auth_state=...
func oauth2ServerConsentPage(e *core.RequestEvent) error {
	flow, handled, err := loadOAuth2FlowFromRequest(e)
	if handled {
		return err
	}

	if flow.session.Status() != core.AuthSessionStatusAuthenticated {
		return oauth2ContinueFlow(e, flow)
	}

	return oauth2RenderConsentPage(e, flow)
}

func oauth2RenderConsentPage(e *core.RequestEvent, flow *oauth2Flow) error {
	scopes := flow.session.Scopes()

	page := pages.ConsentPage{
		Form:      oauth2PageForm(e, flow),
		Client:    oauth2PageClient(flow.client),
		Action:    oauth2PagesURL(e.App, flow.collection) + "/consent",
		UserLabel: oauth2UserLabel(flow.record),
		Scopes:    make([]string, 0, len(scopes)),
	}

	for _, s := range scopes {
		if desc, ok := oauth2ScopeDescriptions[s]; ok {
			page.Scopes = append(page.Scopes, desc)
		} else if label := core.OAuth2ScopeLabel(e.App, s); label != "" {
			page.Scopes = append(page.Scopes, label)
		} else {
			page.Scopes = append(page.Scopes, s)
		}
	}

	return oauth2RenderPage(e, flow.collection, http.StatusOK, "oauth2/consent", page)
}

type oauth2ConsentForm struct {
	AuthState string `form:"auth_state" json:"auth_state"`
	CSRF      string `form:"csrf" json:"csrf"`
	Decision  string `form:"decision" json:"decision"`
}

// POST {issuer}/consent
func oauth2ServerConsentSubmit(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	form := oauth2ConsentForm{}
	if err := oauth2BindBody(e, &form); err != nil {
		return oauth2RenderInvalidFormPage(e, collection, err)
	}

	if err := checkOAuth2FormRequest(e, form.CSRF); err != nil {
		return oauth2RenderInvalidFormPage(e, collection, err)
	}

	flow, err := loadOAuth2Flow(e, collection, form.AuthState)
	if err != nil {
		return oauth2RenderInvalidFlowPage(e, collection, err)
	}

	if flow.session.Status() != core.AuthSessionStatusAuthenticated {
		return oauth2ContinueFlow(e, flow)
	}

	if form.Decision != "allow" {
		return oauth2FlowError(e, flow, oauth2RedirectError(oauth2ErrAccessDenied, "The end-user denied the authorization request."))
	}

	if _, err := e.App.SaveOAuth2Consent(flow.record, flow.client, flow.session.Scopes()); err != nil {
		return oauth2FlowError(e, flow, toOAuth2Error(err, oauth2ErrServerError))
	}

	return oauth2IssueCode(e, flow)
}
