package apis

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/mails"
	"github.com/lumm2509/pocketbomb/pages"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/routine"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/pocketbase/ozzo-validation/v4/is"
	"github.com/spf13/cast"
)

// -------------------------------------------------------------------
// Signup
// -------------------------------------------------------------------

// GET {issuer}/signup?auth_state=...
func oauth2ServerSignupPage(e *core.RequestEvent) error {
	flow, handled, err := loadOAuth2FlowFromRequest(e)
	if handled {
		return err
	}

	if !oauth2SignupAllowed(flow.collection) {
		return oauth2RenderErrorPage(e, flow.collection, http.StatusNotFound, newOAuth2Error(http.StatusNotFound, oauth2ErrInvalidRequest, "Sign up is not allowed."))
	}

	if flow.session.Status() != core.AuthSessionStatusPending || flow.record != nil {
		return oauth2ContinueFlow(e, flow)
	}

	return oauth2RenderSignupPage(e, flow, http.StatusOK, "", flow.session.LoginHint())
}

func oauth2RenderSignupPage(e *core.RequestEvent, flow *oauth2Flow, status int, errMsg string, email string) error {
	return oauth2RenderPage(e, flow.collection, status, "oauth2/signup", pages.SignupPage{
		Form:     oauth2PageForm(e, flow),
		Client:   oauth2PageClient(flow.client),
		Error:    errMsg,
		Action:   oauth2PagesURL(e.App, flow.collection) + "/signup",
		Email:    email,
		LoginURL: flow.stepURL(e.App, "/login"),
	})
}

type oauth2SignupForm struct {
	AuthState       string `form:"auth_state" json:"auth_state"`
	CSRF            string `form:"csrf" json:"csrf"`
	Email           string `form:"email" json:"email"`
	Password        string `form:"password" json:"password"`
	PasswordConfirm string `form:"passwordConfirm" json:"passwordConfirm"`
}

// POST {issuer}/signup
//
// Creates a new auth record through the regular record create API
// (the collection create rule, hooks and validations apply) as guest
// and registers it as completed password factor.
func oauth2ServerSignupSubmit(e *core.RequestEvent) error {
	form := &oauth2SignupForm{}

	flow, handled, err := loadOAuth2FlowForm(e, form, func() string { return form.AuthState }, func() string { return form.CSRF })
	if handled {
		return err
	}

	if !oauth2SignupAllowed(flow.collection) {
		return oauth2RenderErrorPage(e, flow.collection, http.StatusNotFound, newOAuth2Error(http.StatusNotFound, oauth2ErrInvalidRequest, "Sign up is not allowed."))
	}

	if flow.record != nil {
		return oauth2ContinueFlow(e, flow)
	}

	if form.Password != form.PasswordConfirm {
		return oauth2RenderSignupPage(e, flow, http.StatusBadRequest, "The passwords don't match.", form.Email)
	}

	record, err := oauth2CreateGuestRecord(e, flow.collection, map[string]any{
		core.FieldNameEmail:    form.Email,
		core.FieldNamePassword: form.Password,
		"passwordConfirm":      form.PasswordConfirm,
	})
	if err != nil {
		return oauth2RenderSignupPage(e, flow, http.StatusBadRequest, oauth2ValidationMessage(err, "Failed to create the account."), form.Email)
	}

	if !record.Verified() && record.Email() != "" {
		app := e.App
		routine.FireAndForget(func() {
			if err := mails.SendRecordVerification(app, record); err != nil {
				app.Logger().Error("Failed to send the signup verification email", "error", err, "recordId", record.Id)
			}
		})
	}

	if err := oauth2AddFactor(e, flow, record, core.AuthSessionMethodPassword, ""); err != nil {
		e.App.Logger().Debug("Rejected hosted signup password factor", "error", err)
		return oauth2RenderLoginPage(e, flow, http.StatusBadRequest, oauth2LoginErrFailed)
	}

	return oauth2ContinueFlow(e, flow)
}

// oauth2CreateGuestRecord creates a new record via the regular record create API as guest.
func oauth2CreateGuestRecord(e *core.RequestEvent, collection *core.Collection, payload map[string]any) (*core.Record, error) {
	originalAuth := e.Auth
	e.Auth = nil
	defer func() {
		e.Auth = originalAuth
	}()

	ir := &core.InternalRequest{
		Method: http.MethodPost,
		URL:    "/api/collections/" + collection.Name + "/records",
		Body:   payload,
	}

	var created *core.Record
	response, err := processInternalRequest(e.App, e, ir, core.RequestInfoContextDefault, func(data any) error {
		created, _ = data.(*core.Record)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if response.Status != http.StatusOK || created == nil {
		return nil, errors.New("failed to create the record")
	}

	return created, nil
}

// oauth2ValidationMessage returns a user friendly message from the first field validation error (if any).
func oauth2ValidationMessage(err error, fallback string) string {
	var apiErr *router.ApiError
	if !errors.As(err, &apiErr) || len(apiErr.Data) == 0 {
		return fallback
	}

	keys := make([]string, 0, len(apiErr.Data))
	for k := range apiErr.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		var msg string
		switch v := apiErr.Data[k].(type) {
		case map[string]any:
			msg = cast.ToString(v["message"])
		case interface{ Error() string }:
			msg = v.Error()
		}
		if msg != "" {
			return fallback + " " + k + ": " + msg
		}
	}

	return fallback
}

// -------------------------------------------------------------------
// Account pages helpers
// -------------------------------------------------------------------

// oauth2PageHookError renders the hosted error page for a hook (or default action)
// error if the response is not already written.
func oauth2PageHookError(e *core.RequestEvent, collection *core.Collection, err error) error {
	if err == nil || e.Written() {
		return err
	}

	e.App.Logger().Debug("Rejected hosted account page request", "error", err)

	oerr := toOAuth2Error(err, oauth2ErrInvalidRequest)
	if oerr.Code == oauth2ErrServerError || oerr.Code == oauth2ErrInvalidClient {
		oerr = newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "The request was rejected.")
	}

	return oauth2RenderErrorPage(e, collection, http.StatusBadRequest, oerr)
}

// oauth2AccountLoginURL returns the login page URL of the optional flow handle.
func oauth2AccountLoginURL(app core.App, collection *core.Collection, handle string) string {
	if handle == "" || len(handle) > 255 {
		return ""
	}

	return oauth2PagesURL(app, collection) + "/login?auth_state=" + url.QueryEscape(handle)
}

// oauth2FindAccountTokenRecord verifies the provided account mail token
// and checks whether it belongs to the issuer collection.
func oauth2FindAccountTokenRecord(e *core.RequestEvent, collection *core.Collection, token string, tokenType string) (*core.Record, error) {
	if token == "" || len(token) > 2000 {
		return nil, errors.New("missing or invalid token")
	}

	record, err := e.App.FindAuthRecordByToken(token, tokenType)
	if err != nil {
		return nil, err
	}

	if record.Collection().Id != collection.Id {
		return nil, errors.New("the token is for a different auth collection")
	}

	return record, nil
}

func oauth2RenderInvalidLinkPage(e *core.RequestEvent, collection *core.Collection, err error) error {
	e.App.Logger().Debug("Invalid hosted account page token", "error", err)

	return oauth2RenderErrorPage(e, collection, http.StatusBadRequest, newOAuth2Error(
		http.StatusBadRequest,
		oauth2ErrInvalidRequest,
		"The link is invalid or has expired.",
	))
}

type oauth2AccountTokenForm struct {
	CSRF            string `form:"csrf" json:"csrf"`
	Token           string `form:"token" json:"token"`
	Password        string `form:"password" json:"password"`
	PasswordConfirm string `form:"passwordConfirm" json:"passwordConfirm"`
}

// bindOAuth2TokenForm binds and checks the CSRF of an account token form submission.
func bindOAuth2TokenForm(e *core.RequestEvent, collection *core.Collection) (*oauth2AccountTokenForm, error) {
	form := &oauth2AccountTokenForm{}

	if err := oauth2BindBody(e, form); err != nil {
		return nil, err
	}

	if err := checkOAuth2FormRequest(e, form.CSRF); err != nil {
		return nil, err
	}

	return form, nil
}

// -------------------------------------------------------------------
// Password reset request
// -------------------------------------------------------------------

const oauth2PasswordResetNotice = "If an account with the provided email exists, we've sent a link to reset its password."

// GET {issuer}/password-reset[?auth_state=...]
func oauth2ServerPasswordResetPage(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	if !collection.PasswordAuth.Enabled {
		return oauth2RenderErrorPage(e, collection, http.StatusNotFound, newOAuth2Error(http.StatusNotFound, oauth2ErrInvalidRequest, "Password authentication is not enabled."))
	}

	handle := e.Request.URL.Query().Get("auth_state")

	return oauth2RenderPage(e, collection, http.StatusOK, "oauth2/password_reset", pages.PasswordResetPage{
		Form:     pages.Form{AuthState: handle, CSRF: oauth2CSRFToken(e, collection)},
		Action:   oauth2PagesURL(e.App, collection) + "/password-reset",
		LoginURL: oauth2AccountLoginURL(e.App, collection, handle),
	})
}

type oauth2PasswordResetForm struct {
	AuthState string `form:"auth_state" json:"auth_state"`
	CSRF      string `form:"csrf" json:"csrf"`
	Email     string `form:"email" json:"email"`
}

// POST {issuer}/password-reset
func oauth2ServerPasswordResetSubmit(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	if !collection.PasswordAuth.Enabled {
		return oauth2RenderErrorPage(e, collection, http.StatusNotFound, newOAuth2Error(http.StatusNotFound, oauth2ErrInvalidRequest, "Password authentication is not enabled."))
	}

	form := &oauth2PasswordResetForm{}
	if err := oauth2BindBody(e, form); err != nil {
		return oauth2RenderInvalidFormPage(e, collection, err)
	}

	if err := checkOAuth2FormRequest(e, form.CSRF); err != nil {
		return oauth2RenderInvalidFormPage(e, collection, err)
	}

	page := pages.PasswordResetPage{
		Form:     pages.Form{AuthState: form.AuthState, CSRF: oauth2CSRFToken(e, collection)},
		Action:   oauth2PagesURL(e.App, collection) + "/password-reset",
		Email:    form.Email,
		LoginURL: oauth2AccountLoginURL(e.App, collection, form.AuthState),
	}

	if form.Email == "" || len(form.Email) > 255 || is.EmailFormat.Validate(form.Email) != nil {
		page.Error = "Please enter a valid email address."
		return oauth2RenderPage(e, collection, http.StatusBadRequest, "oauth2/password_reset", page)
	}

	record, err := e.App.FindAuthRecordByEmail(collection, form.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		e.App.Logger().Error("Failed to lookup the password reset record", "error", err)
	}

	if record != nil {
		resendKey := getPasswordResetResendKey(record)
		if !e.App.Store().Has(resendKey) {
			event := new(core.RecordRequestPasswordResetRequestEvent)
			event.RequestEvent = e
			event.Collection = collection
			event.Record = record

			hookErr := e.App.OnRecordRequestPasswordResetRequest().Trigger(event, func(e *core.RecordRequestPasswordResetRequestEvent) error {
				// run in background as a basic timing attacks and emails enumeration protection
				app := e.App
				record := e.Record
				routine.FireAndForget(func() {
					if err := mails.SendRecordPasswordReset(app, record); err != nil {
						app.Logger().Error("Failed to send password reset email", "error", err)
						return
					}

					app.Store().Set(resendKey, struct{}{})
					time.AfterFunc(2*time.Minute, func() {
						app.Store().Remove(resendKey)
					})
				})

				return nil
			})
			if hookErr != nil {
				// note: the same notice is shown as a basic emails enumeration protection
				e.App.Logger().Debug("Rejected hosted password reset request", "error", hookErr)
			}
		}
	}

	page.Notice = oauth2PasswordResetNotice

	return oauth2RenderPage(e, collection, http.StatusOK, "oauth2/password_reset", page)
}

// -------------------------------------------------------------------
// Password reset confirm
// -------------------------------------------------------------------

// GET {issuer}/password-reset/confirm?token=...
func oauth2ServerPasswordResetConfirmPage(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	token := e.Request.URL.Query().Get("token")

	record, err := oauth2FindAccountTokenRecord(e, collection, token, core.TokenTypePasswordReset)
	if err != nil {
		return oauth2RenderInvalidLinkPage(e, collection, err)
	}

	return oauth2RenderPasswordResetConfirmPage(e, collection, http.StatusOK, token, record, "")
}

func oauth2RenderPasswordResetConfirmPage(e *core.RequestEvent, collection *core.Collection, status int, token string, record *core.Record, errMsg string) error {
	return oauth2RenderPage(e, collection, status, "oauth2/password_reset_confirm", pages.TokenFormPage{
		CSRF:   oauth2CSRFToken(e, collection),
		Error:  errMsg,
		Action: oauth2PagesURL(e.App, collection) + "/password-reset/confirm",
		Token:  token,
		Email:  record.Email(),
	})
}

// POST {issuer}/password-reset/confirm
//
// Sets the new password (which also changes the record tokenKey and therefore ends all record auth sessions).
func oauth2ServerPasswordResetConfirmSubmit(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	form, err := bindOAuth2TokenForm(e, collection)
	if err != nil {
		return oauth2RenderInvalidFormPage(e, collection, err)
	}

	record, err := oauth2FindAccountTokenRecord(e, collection, form.Token, core.TokenTypePasswordReset)
	if err != nil {
		return oauth2RenderInvalidLinkPage(e, collection, err)
	}

	if form.Password == "" || len(form.Password) > 255 {
		return oauth2RenderPasswordResetConfirmPage(e, collection, http.StatusBadRequest, form.Token, record, "Please enter a new password.")
	}

	if form.Password != form.PasswordConfirm {
		return oauth2RenderPasswordResetConfirmPage(e, collection, http.StatusBadRequest, form.Token, record, "The passwords don't match.")
	}

	event := new(core.RecordConfirmPasswordResetRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.Record = record

	hookErr := e.App.OnRecordConfirmPasswordResetRequest().Trigger(event, func(ev *core.RecordConfirmPasswordResetRequestEvent) error {
		record := ev.Record

		record.SetPassword(form.Password)

		if !record.Verified() {
			claims, err := security.ParseUnverifiedJWT(form.Token)
			if err == nil && record.Email() == cast.ToString(claims[core.TokenClaimEmail]) {
				// mark as verified if the email hasn't changed
				record.SetVerified(true)
			}
		}

		if err := ev.App.Save(record); err != nil {
			return oauth2RenderPasswordResetConfirmPage(e, collection, http.StatusBadRequest, form.Token, record, oauth2ValidationMessage(router.NewBadRequestError("", err), "Failed to set the new password."))
		}

		ev.App.Store().Remove(getPasswordResetResendKey(record))

		return oauth2RenderMessagePage(e, collection, http.StatusOK, "Password changed", "Your password has been changed. You can now sign in with your new password.")
	})

	return oauth2PageHookError(e, collection, hookErr)
}

// -------------------------------------------------------------------
// Email verification confirm
// -------------------------------------------------------------------

// GET {issuer}/verify-email?token=...
func oauth2ServerVerifyEmailPage(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	token := e.Request.URL.Query().Get("token")

	record, err := oauth2FindAccountTokenRecord(e, collection, token, core.TokenTypeVerification)
	if err != nil || collection.Name == core.CollectionNameSuperusers {
		return oauth2RenderInvalidLinkPage(e, collection, err)
	}

	if record.Verified() {
		return oauth2RenderMessagePage(e, collection, http.StatusOK, "Email verified", "Your email address is already verified.")
	}

	return oauth2RenderPage(e, collection, http.StatusOK, "oauth2/verify_email", pages.TokenFormPage{
		CSRF:   oauth2CSRFToken(e, collection),
		Action: oauth2PagesURL(e.App, collection) + "/verify-email",
		Token:  token,
		Email:  record.Email(),
	})
}

// POST {issuer}/verify-email
func oauth2ServerVerifyEmailSubmit(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	form, err := bindOAuth2TokenForm(e, collection)
	if err != nil {
		return oauth2RenderInvalidFormPage(e, collection, err)
	}

	record, err := oauth2FindAccountTokenRecord(e, collection, form.Token, core.TokenTypeVerification)
	if err != nil || collection.Name == core.CollectionNameSuperusers {
		return oauth2RenderInvalidLinkPage(e, collection, err)
	}

	// the token must be issued for the current record email
	claims, _ := security.ParseUnverifiedJWT(form.Token)
	if cast.ToString(claims[core.TokenClaimEmail]) != record.Email() {
		return oauth2RenderInvalidLinkPage(e, collection, errors.New("the verification token email doesn't match"))
	}

	event := new(core.RecordConfirmVerificationRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.Record = record

	hookErr := e.App.OnRecordConfirmVerificationRequest().Trigger(event, func(ev *core.RecordConfirmVerificationRequestEvent) error {
		record := ev.Record

		if !record.Verified() {
			record.SetVerified(true)

			// enforce an extra password reset guard as this way is less prone to
			// pre-hijacking attacks in case the password auth is eventually enabled later
			if !collection.PasswordAuth.Enabled {
				record.SetRandomPassword()
			}

			if err := ev.App.Save(record); err != nil {
				return oauth2RenderErrorPage(e, collection, http.StatusBadRequest, newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Failed to verify the email address."))
			}
		}

		ev.App.Store().Remove(getVerificationResendKey(record))

		return oauth2RenderMessagePage(e, collection, http.StatusOK, "Email verified", "Your email address has been verified.")
	})

	return oauth2PageHookError(e, collection, hookErr)
}

// -------------------------------------------------------------------
// Email verification request
// -------------------------------------------------------------------

const oauth2VerificationRequestNotice = "If an unverified account with the provided email exists, we've sent a link to verify it."

// GET {issuer}/verify-email/request[?auth_state=...]
func oauth2ServerVerifyEmailRequestPage(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	if collection.Name == core.CollectionNameSuperusers {
		return oauth2RenderErrorPage(e, collection, http.StatusNotFound, newOAuth2Error(http.StatusNotFound, oauth2ErrInvalidRequest, "All superusers are verified by default."))
	}

	handle := e.Request.URL.Query().Get("auth_state")

	return oauth2RenderPage(e, collection, http.StatusOK, "oauth2/verify_email_request", pages.PasswordResetPage{
		Form:     pages.Form{AuthState: handle, CSRF: oauth2CSRFToken(e, collection)},
		Action:   oauth2PagesURL(e.App, collection) + "/verify-email/request",
		LoginURL: oauth2AccountLoginURL(e.App, collection, handle),
	})
}

// POST {issuer}/verify-email/request
//
// Sends a new verification email (enumeration safe: the response is the same for missing accounts).
func oauth2ServerVerifyEmailRequestSubmit(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	if collection.Name == core.CollectionNameSuperusers {
		return oauth2RenderErrorPage(e, collection, http.StatusNotFound, newOAuth2Error(http.StatusNotFound, oauth2ErrInvalidRequest, "All superusers are verified by default."))
	}

	form := &oauth2PasswordResetForm{}
	if err := oauth2BindBody(e, form); err != nil {
		return oauth2RenderInvalidFormPage(e, collection, err)
	}

	if err := checkOAuth2FormRequest(e, form.CSRF); err != nil {
		return oauth2RenderInvalidFormPage(e, collection, err)
	}

	page := pages.PasswordResetPage{
		Form:     pages.Form{AuthState: form.AuthState, CSRF: oauth2CSRFToken(e, collection)},
		Action:   oauth2PagesURL(e.App, collection) + "/verify-email/request",
		Email:    form.Email,
		LoginURL: oauth2AccountLoginURL(e.App, collection, form.AuthState),
	}

	if form.Email == "" || len(form.Email) > 255 || is.EmailFormat.Validate(form.Email) != nil {
		page.Error = "Please enter a valid email address."
		return oauth2RenderPage(e, collection, http.StatusBadRequest, "oauth2/verify_email_request", page)
	}

	page.Notice = oauth2VerificationRequestNotice

	respond := func() error {
		return oauth2RenderPage(e, collection, http.StatusOK, "oauth2/verify_email_request", page)
	}

	record, err := e.App.FindAuthRecordByEmail(collection, form.Email)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			e.App.Logger().Error("Failed to lookup the verification request record", "error", err)
		}
		return respond()
	}

	err = requestRecordVerification(e, record, respond)
	if err != nil && !e.Written() {
		// note: the same notice is shown as a basic emails enumeration protection
		e.App.Logger().Debug("Rejected hosted verification request", "error", err)
		return respond()
	}

	return nil
}

// -------------------------------------------------------------------
// Email change confirm
// -------------------------------------------------------------------

// oauth2ParseEmailChangeToken verifies the email change token and returns its record and new email.
func oauth2ParseEmailChangeToken(e *core.RequestEvent, collection *core.Collection, token string) (*core.Record, string, error) {
	if collection.Name == core.CollectionNameSuperusers {
		return nil, "", errors.New("the superusers can change their emails directly")
	}

	record, err := oauth2FindAccountTokenRecord(e, collection, token, core.TokenTypeEmailChange)
	if err != nil {
		return nil, "", err
	}

	claims, _ := security.ParseUnverifiedJWT(token)
	newEmail := cast.ToString(claims[core.TokenClaimNewEmail])
	if newEmail == "" {
		return nil, "", errors.New("missing newEmail token claim")
	}

	// check if there are other records with the new email
	if _, err := e.App.FindAuthRecordByEmail(collection, newEmail); err == nil {
		return nil, "", errors.New("the new email address is already in use")
	}

	return record, newEmail, nil
}

// GET {issuer}/email-change/confirm?token=...
func oauth2ServerEmailChangeConfirmPage(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	token := e.Request.URL.Query().Get("token")

	_, newEmail, err := oauth2ParseEmailChangeToken(e, collection, token)
	if err != nil {
		return oauth2RenderInvalidLinkPage(e, collection, err)
	}

	return oauth2RenderEmailChangeConfirmPage(e, collection, http.StatusOK, token, newEmail, "")
}

func oauth2RenderEmailChangeConfirmPage(e *core.RequestEvent, collection *core.Collection, status int, token string, newEmail string, errMsg string) error {
	return oauth2RenderPage(e, collection, status, "oauth2/email_change_confirm", pages.TokenFormPage{
		CSRF:   oauth2CSRFToken(e, collection),
		Error:  errMsg,
		Action: oauth2PagesURL(e.App, collection) + "/email-change/confirm",
		Token:  token,
		Email:  newEmail,
	})
}

// POST {issuer}/email-change/confirm
func oauth2ServerEmailChangeConfirmSubmit(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	form, err := bindOAuth2TokenForm(e, collection)
	if err != nil {
		return oauth2RenderInvalidFormPage(e, collection, err)
	}

	record, newEmail, err := oauth2ParseEmailChangeToken(e, collection, form.Token)
	if err != nil {
		return oauth2RenderInvalidLinkPage(e, collection, err)
	}

	if form.Password == "" || len(form.Password) > 255 || !record.ValidatePassword(form.Password) {
		return oauth2RenderEmailChangeConfirmPage(e, collection, http.StatusBadRequest, form.Token, newEmail, "Invalid password.")
	}

	event := new(core.RecordConfirmEmailChangeRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.Record = record
	event.NewEmail = newEmail

	hookErr := e.App.OnRecordConfirmEmailChangeRequest().Trigger(event, func(ev *core.RecordConfirmEmailChangeRequestEvent) error {
		ev.Record.SetEmail(ev.NewEmail)
		ev.Record.SetVerified(true)

		if err := ev.App.Save(ev.Record); err != nil {
			return oauth2RenderEmailChangeConfirmPage(e, collection, http.StatusBadRequest, form.Token, ev.NewEmail, oauth2ValidationMessage(router.NewBadRequestError("", err), "Failed to change the email address."))
		}

		return oauth2RenderMessagePage(e, collection, http.StatusOK, "Email changed", "Your email address has been changed.")
	})

	return oauth2PageHookError(e, collection, hookErr)
}

func getPasswordResetResendKey(record *core.Record) string {
	return "@limitPasswordResetEmail_" + record.Collection().Id + record.Id
}
