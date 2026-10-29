package apis

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/mails"
	"github.com/lumm2509/pocketbomb/pages"
	"github.com/lumm2509/pocketbomb/tools/auth"
	"github.com/lumm2509/pocketbomb/tools/dbutils"
	"github.com/lumm2509/pocketbomb/tools/routine"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/ozzo-validation/v4/is"
	"golang.org/x/oauth2"
)

// generic hosted login errors (intentionally vague to prevent accounts enumeration)
const (
	oauth2LoginErrInvalidCredentials = "Invalid login credentials."
	oauth2LoginErrInvalidCode        = "Invalid or expired code."
	oauth2LoginErrFailed             = "Failed to authenticate. Please try again or use another sign-in method."
	oauth2LoginErrUpstream           = "Failed to sign in with the selected provider. Please try again or use another sign-in method."
)

// the predefined (aka. non user controlled) login page errors passed as "error" query parameter
var oauth2LoginQueryErrors = map[string]string{
	"upstream": oauth2LoginErrUpstream,
}

// oauth2SignupAllowed reports whether the hosted signup page is available for the collection
// (the guests must be allowed to create records and the password auth must be enabled).
func oauth2SignupAllowed(collection *core.Collection) bool {
	return collection.CreateRule != nil &&
		collection.PasswordAuth.Enabled &&
		collection.Name != core.CollectionNameSuperusers
}

// oauth2ProviderLinks returns the sign-in links of the collection upstream OAuth2 providers.
func oauth2ProviderLinks(e *core.RequestEvent, flow *oauth2Flow) []pages.Provider {
	if !oauth2ProvidersAllowed(flow.collection) {
		return nil
	}

	issuer := oauth2PagesURL(e.App, flow.collection)

	result := make([]pages.Provider, 0, len(flow.collection.OAuth2.Providers))
	for _, config := range flow.collection.OAuth2.Providers {
		provider, err := config.InitProvider()
		if err != nil {
			e.App.Logger().Debug("Failed to setup OAuth2 provider", "name", config.Name, "error", err)
			continue
		}

		displayName := provider.DisplayName()
		if displayName == "" {
			displayName = config.Name
		}

		result = append(result, pages.Provider{
			Name:        config.Name,
			DisplayName: displayName,
			URL:         issuer + "/login/oauth2/" + url.PathEscape(config.Name) + "?auth_state=" + url.QueryEscape(flow.handle),
		})
	}

	return result
}

// -------------------------------------------------------------------
// Login page
// -------------------------------------------------------------------

// GET {issuer}/login?auth_state=...
func oauth2ServerLoginPage(e *core.RequestEvent) error {
	flow, handled, err := loadOAuth2FlowFromRequest(e)
	if handled {
		return err
	}

	if flow.session.Status() != core.AuthSessionStatusPending {
		return oauth2ContinueFlow(e, flow)
	}

	// partially authenticated (aka. MFA)
	if flow.record != nil {
		return oauth2RedirectToStep(e, flow, "/login/mfa")
	}

	return oauth2RenderLoginPage(e, flow, http.StatusOK, oauth2LoginQueryErrors[e.Request.URL.Query().Get("error")])
}

func oauth2RenderLoginPage(e *core.RequestEvent, flow *oauth2Flow, status int, errMsg string) error {
	issuer := oauth2PagesURL(e.App, flow.collection)

	page := pages.LoginPage{
		Form:          oauth2PageForm(e, flow),
		Client:        oauth2PageClient(flow.client),
		Error:         errMsg,
		IdentityLabel: oauth2IdentityLabel(flow.collection),
		LoginHint:     flow.session.LoginHint(),
		Providers:     oauth2ProviderLinks(e, flow),
	}

	if flow.collection.PasswordAuth.Enabled {
		page.PasswordAction = issuer + "/login/password"
		page.PasswordResetURL = flow.stepURL(e.App, "/password-reset")
	}

	if flow.collection.OTP.Enabled {
		page.OTPAction = issuer + "/login/otp"
	}

	if oauth2SignupAllowed(flow.collection) {
		page.SignupURL = flow.stepURL(e.App, "/signup")
	}

	if flow.collection.Name != core.CollectionNameSuperusers {
		page.VerificationRequestURL = flow.stepURL(e.App, "/verify-email/request")
	}

	return oauth2RenderPage(e, flow.collection, status, "oauth2/login", page)
}

// GET {issuer}/login/continue?auth_state=...
//
// Continues the flow after an upstream OAuth2 provider callback
// (it is a GET request so that the Lax binding cookie is checked).
//
// The pending upstream OAuth2 result (if any) is applied as factor only here,
// after the binding cookie check.
func oauth2ServerLoginContinue(e *core.RequestEvent) error {
	flow, handled, err := loadOAuth2FlowFromRequest(e)
	if handled {
		return err
	}

	if flow.session.Status() == core.AuthSessionStatusPending && flow.session.UpstreamRecordRef() != "" {
		if err := oauth2ApplyPendingUpstream(e, flow); err != nil {
			e.App.Logger().Debug("Rejected hosted login upstream OAuth2 factor", "error", err)
			return oauth2RenderFactorError(e, flow, oauth2LoginErrUpstream)
		}
	}

	return oauth2ContinueFlow(e, flow)
}

// oauth2ApplyPendingUpstream applies the pending upstream OAuth2 result of the
// (already binding checked) flow as factor and clears it.
func oauth2ApplyPendingUpstream(e *core.RequestEvent, flow *oauth2Flow) error {
	recordId := flow.session.UpstreamRecordRef()
	provider := flow.session.UpstreamProvider()

	// single use
	flow.session.SetUpstream("", "", "")

	clear := func(cause error) error {
		if err := e.App.Save(flow.session); err != nil {
			return errors.Join(cause, err)
		}
		return cause
	}

	record, err := e.App.FindRecordById(flow.collection, recordId)
	if err != nil {
		return clear(err)
	}

	e.Set(core.RequestEventKeyInfoContext, core.RequestInfoContextOAuth2)

	if err := oauth2AddFactor(e, flow, record, core.AuthSessionMethodOAuth2, provider); err != nil {
		return clear(err)
	}

	return nil
}

// -------------------------------------------------------------------
// MFA page
// -------------------------------------------------------------------

// GET {issuer}/login/mfa?auth_state=...
func oauth2ServerLoginMFAPage(e *core.RequestEvent) error {
	flow, handled, err := loadOAuth2FlowFromRequest(e)
	if handled {
		return err
	}

	if flow.session.Status() != core.AuthSessionStatusPending || flow.record == nil || !flow.session.MFARequired() {
		return oauth2ContinueFlow(e, flow)
	}

	return oauth2RenderMFAPage(e, flow, http.StatusOK, oauth2LoginQueryErrors[e.Request.URL.Query().Get("error")])
}

func oauth2RenderMFAPage(e *core.RequestEvent, flow *oauth2Flow, status int, errMsg string) error {
	issuer := oauth2PagesURL(e.App, flow.collection)

	password, otp, oauth2 := oauth2RemainingMFAMethods(flow)

	page := pages.MFAPage{
		Form:      oauth2PageForm(e, flow),
		Client:    oauth2PageClient(flow.client),
		Error:     errMsg,
		UserLabel: oauth2UserLabel(flow.record),
	}

	if password {
		page.PasswordAction = issuer + "/login/password"
	}

	if otp {
		page.OTPAction = issuer + "/login/otp"
	}

	if oauth2 {
		page.Providers = oauth2ProviderLinks(e, flow)
	}

	return oauth2RenderPage(e, flow.collection, status, "oauth2/mfa", page)
}

// oauth2RenderFactorError renders the login or the MFA page (if the actor is already identified) with the provided error.
func oauth2RenderFactorError(e *core.RequestEvent, flow *oauth2Flow, errMsg string) error {
	if flow.record != nil && flow.session.MFARequired() {
		return oauth2RenderMFAPage(e, flow, http.StatusBadRequest, errMsg)
	}

	return oauth2RenderLoginPage(e, flow, http.StatusBadRequest, errMsg)
}

// loadOAuth2FlowForm binds the submitted form, checks the CSRF and loads the pending flow.
//
// On failure it renders the error page and handled is true.
func loadOAuth2FlowForm(e *core.RequestEvent, form any, authState func() string, csrf func() string) (flow *oauth2Flow, handled bool, err error) {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return nil, true, err
	}

	if err := oauth2BindBody(e, form); err != nil {
		return nil, true, oauth2RenderInvalidFormPage(e, collection, err)
	}

	if err := checkOAuth2FormRequest(e, csrf()); err != nil {
		return nil, true, oauth2RenderInvalidFormPage(e, collection, err)
	}

	flow, err = loadOAuth2Flow(e, collection, authState())
	if err != nil {
		return nil, true, oauth2RenderInvalidFlowPage(e, collection, err)
	}

	if flow.session.Status() != core.AuthSessionStatusPending {
		return nil, true, oauth2ContinueFlow(e, flow)
	}

	return flow, false, nil
}

// -------------------------------------------------------------------
// Password factor
// -------------------------------------------------------------------

type oauth2PasswordForm struct {
	AuthState string `form:"auth_state" json:"auth_state"`
	CSRF      string `form:"csrf" json:"csrf"`
	Identity  string `form:"identity" json:"identity"`
	Password  string `form:"password" json:"password"`
}

// POST {issuer}/login/password
func oauth2ServerLoginPassword(e *core.RequestEvent) error {
	form := &oauth2PasswordForm{}

	flow, handled, err := loadOAuth2FlowForm(e, form, func() string { return form.AuthState }, func() string { return form.CSRF })
	if handled {
		return err
	}

	if !flow.collection.PasswordAuth.Enabled {
		return oauth2RenderFactorError(e, flow, oauth2LoginErrFailed)
	}

	e.Set(core.RequestEventKeyInfoContext, core.RequestInfoContextPasswordAuth)

	record := flow.record // already identified (aka. MFA)
	if record == nil && form.Identity != "" && len(form.Identity) <= 255 {
		record, err = oauth2FindRecordByIdentity(e.App, flow.collection, form.Identity)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			e.App.Logger().Error("Failed to lookup the hosted login identity", "error", err)
		}
	}

	if record == nil || form.Password == "" || len(form.Password) > 255 || !record.ValidatePassword(form.Password) {
		// dummy password check to minimize enumeration side-channel attacks
		if record == nil {
			dummyPasswordCheck(e.App, flow.collection)
		}

		return oauth2RenderFactorError(e, flow, oauth2LoginErrInvalidCredentials)
	}

	if err := oauth2AddFactor(e, flow, record, core.AuthSessionMethodPassword, ""); err != nil {
		e.App.Logger().Debug("Rejected hosted login password factor", "error", err)
		return oauth2RenderFactorError(e, flow, oauth2LoginErrFailed)
	}

	return oauth2ContinueFlow(e, flow)
}

// oauth2FindRecordByIdentity looks for an auth record by the collection password auth identity fields
// (the email field is checked first).
func oauth2FindRecordByIdentity(app core.App, collection *core.Collection, identity string) (*core.Record, error) {
	identityFields := slices.Clone(collection.PasswordAuth.IdentityFields)
	slices.SortStableFunc(identityFields, func(a, b string) int {
		if a == core.FieldNameEmail {
			return -1
		}
		if b == core.FieldNameEmail {
			return 1
		}
		return 0
	})

	var lastErr error = sql.ErrNoRows
	for _, name := range identityFields {
		if name == core.FieldNameEmail && is.EmailFormat.Validate(identity) != nil {
			continue // no need to query the database if we know that the submitted value is not an email
		}

		record, err := findRecordByIdentityField(app, collection, name, identity)
		if err == nil {
			return record, nil
		}
		lastErr = err
	}

	return nil, lastErr
}

// -------------------------------------------------------------------
// OTP factor
// -------------------------------------------------------------------

// oauth2OTPSentInfo is the (enumeration safe) info shown after an OTP request.
const oauth2OTPSentInfo = "If an account with the provided email exists, we've sent a one-time code to it."

type oauth2OTPRequestForm struct {
	AuthState string `form:"auth_state" json:"auth_state"`
	CSRF      string `form:"csrf" json:"csrf"`
	Email     string `form:"email" json:"email"`
}

// POST {issuer}/login/otp
//
// Creates a new OTP bound to the flow session and sends it to the record email.
func oauth2ServerLoginOTPRequest(e *core.RequestEvent) error {
	form := &oauth2OTPRequestForm{}

	flow, handled, err := loadOAuth2FlowForm(e, form, func() string { return form.AuthState }, func() string { return form.CSRF })
	if handled {
		return err
	}

	if !flow.collection.OTP.Enabled {
		return oauth2RenderFactorError(e, flow, oauth2LoginErrFailed)
	}

	record := flow.record // already identified (aka. MFA)
	if record == nil {
		if form.Email == "" || len(form.Email) > 255 || is.EmailFormat.Validate(form.Email) != nil {
			return oauth2RenderFactorError(e, flow, "Please enter a valid email address.")
		}

		record, err = e.App.FindAuthRecordByEmail(flow.collection, form.Email)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			e.App.Logger().Error("Failed to lookup the hosted login OTP record", "error", err)
		}
	}

	if record != nil {
		if err := oauth2SendOTP(e, flow, record); err != nil {
			e.App.Logger().Error("Failed to create hosted login OTP", "error", err, "recordId", record.Id)
		}
	}

	return oauth2RenderOTPPage(e, flow, http.StatusOK, "", oauth2OTPSentInfo)
}

// oauth2SendOTP marks the record as identified by the flow session OTP request
// (so that the session could verify the record OTPs that are not bound to any session,
// e.g. created with the "superuser otp" command) and creates and sends a new OTP bound to the flow session.
func oauth2SendOTP(e *core.RequestEvent, flow *oauth2Flow, record *core.Record) error {
	if flow.session.OTPRecordRef() != record.Id {
		flow.session.SetOTPRecordRef(record.Id)
		if err := e.App.Save(flow.session); err != nil {
			return err
		}
	}

	// limit the new OTP creations for a single record
	if !e.App.IsDev() {
		otps, err := e.App.FindAllOTPsByRecord(record)
		if err != nil {
			return err
		}

		totalRecent := 0
		for _, otp := range otps {
			if !otp.HasExpired(flow.collection.OTP.DurationTime()) {
				totalRecent++
			}
		}
		if totalRecent > 9 {
			return errors.New("too many recent OTP requests")
		}
	}

	pass := security.RandomStringWithAlphabet(flow.collection.OTP.Length, "1234567890")

	otp := core.NewOTP(e.App)
	otp.SetCollectionRef(record.Collection().Id)
	otp.SetRecordRef(record.Id)
	otp.SetSessionRef(flow.session.Id)
	otp.SetSentTo(record.Email())
	otp.SetPassword(pass)
	if err := e.App.Save(otp); err != nil {
		return err
	}

	// send in the background as a very basic timing attacks and emails enumeration protection
	app := e.App
	routine.FireAndForget(func() {
		if err := mails.SendRecordOTP(app, record, otp.Id, pass); err != nil {
			app.Logger().Error("Failed to send OTP email", "error", errors.Join(err, app.Delete(otp)))
		}
	})

	return nil
}

func oauth2RenderOTPPage(e *core.RequestEvent, flow *oauth2Flow, status int, errMsg string, sentInfo string) error {
	backPath := "/login"
	if flow.record != nil && flow.session.MFARequired() {
		backPath = "/login/mfa"
	}

	return oauth2RenderPage(e, flow.collection, status, "oauth2/otp", pages.OTPPage{
		Form:     oauth2PageForm(e, flow),
		Client:   oauth2PageClient(flow.client),
		Error:    errMsg,
		Action:   oauth2PagesURL(e.App, flow.collection) + "/login/otp/verify",
		BackURL:  flow.stepURL(e.App, backPath),
		SentInfo: sentInfo,
	})
}

type oauth2OTPVerifyForm struct {
	AuthState string `form:"auth_state" json:"auth_state"`
	CSRF      string `form:"csrf" json:"csrf"`
	Code      string `form:"code" json:"code"`
}

// the max number of the most recent session OTPs that are checked on verify
const oauth2OTPVerifyCandidates = 5

// POST {issuer}/login/otp/verify
//
// Verifies the submitted code against the OTPs bound to the flow session
// (an OTP of another session can't be used) and the OTPs that are not bound to any session
// (e.g. created with the "superuser otp" command) of the record identified by the session
// (its actor or the record of the last session OTP request).
func oauth2ServerLoginOTPVerify(e *core.RequestEvent) error {
	form := &oauth2OTPVerifyForm{}

	flow, handled, err := loadOAuth2FlowForm(e, form, func() string { return form.AuthState }, func() string { return form.CSRF })
	if handled {
		return err
	}

	if !flow.collection.OTP.Enabled {
		return oauth2RenderFactorError(e, flow, oauth2LoginErrFailed)
	}

	e.Set(core.RequestEventKeyInfoContext, core.RequestInfoContextOTP)

	code := strings.TrimSpace(form.Code)
	if code == "" || len(code) > 100 {
		return oauth2RenderOTPPage(e, flow, http.StatusBadRequest, oauth2LoginErrInvalidCode, "")
	}

	candidates, err := oauth2OTPCandidates(e.App, flow)
	if err != nil {
		return oauth2RenderOTPPage(e, flow, http.StatusBadRequest, oauth2LoginErrInvalidCode, "")
	}

	var matched *core.OTP
	limited := map[string]struct{}{}
	for _, otp := range candidates {
		if otp.HasExpired(flow.collection.OTP.DurationTime()) {
			continue
		}

		if flow.record != nil && otp.RecordRef() != flow.record.Id {
			continue
		}

		// since OTPs are usually simple digit numbers, enforce an extra per record
		// rate limit rule (once per attempt) as basic enumeration protection
		if _, ok := limited[otp.RecordRef()]; !ok {
			limited[otp.RecordRef()] = struct{}{}
			if err := checkRateLimit(e, "@pb_otp_"+otp.RecordRef(), core.RateLimitRule{MaxRequests: 5, Duration: 180}); err != nil {
				return oauth2RenderOTPPage(e, flow, http.StatusTooManyRequests, "Too many attempts, please try again later with a new code.", "")
			}
		}

		if otp.ValidatePassword(code) {
			matched = otp
			break
		}
	}

	if matched == nil {
		return oauth2RenderOTPPage(e, flow, http.StatusBadRequest, oauth2LoginErrInvalidCode, "")
	}

	record, err := e.App.FindRecordById(flow.collection, matched.RecordRef())
	if err != nil {
		return oauth2RenderOTPPage(e, flow, http.StatusBadRequest, oauth2LoginErrInvalidCode, "")
	}

	sentTo := matched.SentTo()

	// the OTPs are single use
	// (consume in a transaction so that an unbound OTP verified concurrently
	// by multiple sessions could be used only once)
	if err := oauth2ConsumeOTP(e.App, matched.Id); err != nil {
		e.App.Logger().Debug("Failed to consume the verified OTP", "error", err, "otpId", matched.Id)
		return oauth2RenderOTPPage(e, flow, http.StatusBadRequest, oauth2LoginErrInvalidCode, "")
	}

	// update the record verified state in case the OTP was sent to its current email
	if !record.Verified() && sentTo != "" && record.Email() == sentTo {
		record.SetVerified(true)

		// enforce password reset on verified upgrades in case the OTP is used
		// on its own to minimize the risk of pre-hijacking attacks
		if !flow.collection.MFA.Enabled {
			record.SetRandomPassword()
		}

		// note: the verified upgrade could rotate the record tokenKey (e.g. pre-existing external auths)
		// which ends all of its sessions except the current in-progress flow
		// (it is re-rooted on a new SSO root on completion if its root was ended)
		ctx := core.WithPreservedAuthSessions(e.Request.Context(), flow.session.Id)
		if err := e.App.SaveWithContext(ctx, record); err != nil {
			e.App.Logger().Error("Failed to update the record verified state after OTP validation", "error", err, "recordId", record.Id)
		}
	}

	if err := oauth2AddFactor(e, flow, record, core.AuthSessionMethodOTP, ""); err != nil {
		e.App.Logger().Debug("Rejected hosted login OTP factor", "error", err)
		return oauth2RenderFactorError(e, flow, oauth2LoginErrFailed)
	}

	return oauth2ContinueFlow(e, flow)
}

// oauth2OTPCandidates returns the most recent OTPs that the flow session could verify:
//   - the OTPs bound to the flow session
//   - the OTPs that are not bound to any session of the record identified by the flow session
//     (aka. its actor or the record of the last session OTP request)
func oauth2OTPCandidates(app core.App, flow *oauth2Flow) ([]*core.OTP, error) {
	candidates := []*core.OTP{}

	err := app.RecordQuery(core.CollectionNameOTPs).
		AndWhere(dbx.HashExp{
			"collectionRef": flow.collection.Id,
			"sessionRef":    flow.session.Id,
		}).
		OrderBy("created DESC").
		Limit(oauth2OTPVerifyCandidates).
		All(&candidates)
	if err != nil {
		return nil, err
	}

	identified := flow.session.OTPRecordRef()
	if flow.record != nil {
		identified = flow.record.Id
	}
	if identified == "" {
		return candidates, nil
	}

	unbound := []*core.OTP{}

	err = app.RecordQuery(core.CollectionNameOTPs).
		AndWhere(dbx.HashExp{
			"collectionRef": flow.collection.Id,
			"recordRef":     identified,
			"sessionRef":    "",
		}).
		OrderBy("created DESC").
		Limit(oauth2OTPVerifyCandidates).
		All(&unbound)
	if err != nil {
		return nil, err
	}

	return append(candidates, unbound...), nil
}

// oauth2ConsumeOTP deletes the specified OTP (returns an error if it was already consumed).
func oauth2ConsumeOTP(app core.App, otpId string) error {
	return app.RunInTransaction(func(txApp core.App) error {
		otp, err := txApp.FindOTPById(otpId)
		if err != nil {
			return err
		}

		return txApp.Delete(otp)
	})
}

// -------------------------------------------------------------------
// Upstream OAuth2 factor
// -------------------------------------------------------------------

// oauth2UpstreamStatePrefix is the prefix of the upstream OAuth2 "state" parameter of
// the hosted login flows (it is used to distinguish them in the /api/oauth2-redirect handler).
//
// The full state format is "{prefix}{authSessionId}.{secret}".
const oauth2UpstreamStatePrefix = "pbas."

// oauth2UpstreamRedirectURL returns the upstream OAuth2 providers redirect URL.
func oauth2UpstreamRedirectURL(app core.App) string {
	return strings.TrimRight(app.Settings().Meta.AppURL, "/") + "/api/oauth2-redirect"
}

// GET {issuer}/login/oauth2/{provider}?auth_state=...
//
// Starts the upstream OAuth2 authorization (with PKCE if supported by the provider).
func oauth2ServerLoginOAuth2(e *core.RequestEvent) error {
	flow, handled, err := loadOAuth2FlowFromRequest(e)
	if handled {
		return err
	}

	if flow.session.Status() != core.AuthSessionStatusPending {
		return oauth2ContinueFlow(e, flow)
	}

	name := e.Request.PathValue("provider")

	config, ok := flow.collection.OAuth2.GetProviderConfig(name)
	if !ok || !oauth2ProvidersAllowed(flow.collection) {
		return oauth2RenderFactorError(e, flow, oauth2LoginErrUpstream)
	}

	provider, err := config.InitProvider()
	if err != nil {
		e.App.Logger().Error("Failed to init the upstream OAuth2 provider", "provider", name, "error", err)
		return oauth2RenderFactorError(e, flow, oauth2LoginErrUpstream)
	}

	provider.SetRedirectURL(oauth2UpstreamRedirectURL(e.App))

	secret := security.RandomString(30)

	urlOpts := []oauth2.AuthCodeOption{}

	// custom providers url options
	switch name {
	case auth.NameApple:
		// see https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/incorporating_sign_in_with_apple_into_other_platforms#3332113
		urlOpts = append(urlOpts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}

	var codeVerifier string
	if provider.PKCE() {
		codeVerifier = security.RandomString(43)
		urlOpts = append(urlOpts,
			oauth2.SetAuthURLParam("code_challenge", security.S256Challenge(codeVerifier)),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}

	flow.session.SetUpstream(name, secret, codeVerifier)
	if err := e.App.Save(flow.session); err != nil {
		return oauth2RenderFactorError(e, flow, oauth2LoginErrUpstream)
	}

	return e.Redirect(http.StatusFound, provider.BuildAuthURL(oauth2UpstreamStatePrefix+flow.session.Id+"."+secret, urlOpts...))
}

// -------------------------------------------------------------------

// dummy password check to minimize side-channel attacks
// (performed with the collection configured field cost)
func dummyPasswordCheck(app core.App, collection *core.Collection) {
	record := &core.Record{}

	// find any random existing record
	err := app.RecordQuery(collection).Limit(1).One(record)
	if err != nil {
		return
	}

	// the value and result doesn't matter, we just need a constant-time check
	_ = record.ValidatePassword("")
}

func findRecordByIdentityField(app core.App, collection *core.Collection, field string, value any) (*core.Record, error) {
	if !slices.Contains(collection.PasswordAuth.IdentityFields, field) {
		return nil, errors.New("invalid identity field " + field)
	}

	index, ok := dbutils.FindSingleColumnUniqueIndex(collection.Indexes, field)
	if !ok {
		return nil, errors.New("missing " + field + " unique index constraint")
	}

	var expr dbx.Expression
	if strings.EqualFold(index.Columns[0].Collate, "nocase") {
		// case-insensitive search
		expr = dbx.NewExp("[["+field+"]] = {:identity} COLLATE NOCASE", dbx.Params{"identity": value})
	} else {
		expr = dbx.HashExp{field: value}
	}

	record := &core.Record{}

	err := app.RecordQuery(collection).AndWhere(expr).Limit(1).One(record)
	if err != nil {
		return nil, err
	}

	return record, nil
}
