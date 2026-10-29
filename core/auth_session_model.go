package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

const CollectionNameAuthSessions = "_authSessions"

// Supported auth session statuses.
//
// The regular hosted login flow transitions are:
//
//	pending -> authenticated -> authorized -> active -> ended
//
// Any non-terminal session could be ended and any session that is
// not yet active could also fail (e.g. denied consent or AuthRule failure).
const (
	// AuthSessionStatusPending is the status of a new authorization flow
	// (the actor is not identified or not all required factors are satisfied).
	AuthSessionStatusPending = "pending"

	// AuthSessionStatusAuthenticated is the status of a session whose
	// actor completed all required factors (incl. MFA) and passed the auth checks.
	AuthSessionStatusAuthenticated = "authenticated"

	// AuthSessionStatusAuthorized is the status of a session for which
	// an authorization code was issued (aka. consent was given or skipped).
	AuthSessionStatusAuthorized = "authorized"

	// AuthSessionStatusActive is the status of a session with issued tokens
	// (it is also the status of the root SSO sessions).
	AuthSessionStatusActive = "active"

	// AuthSessionStatusEnded is the terminal status of an ended (logged out, revoked, etc.) session.
	AuthSessionStatusEnded = "ended"

	// AuthSessionStatusFailed is the terminal status of a failed authorization flow.
	AuthSessionStatusFailed = "failed"
)

// AuthSessionStatuses is the list of all supported auth session statuses.
var AuthSessionStatuses = []string{
	AuthSessionStatusPending,
	AuthSessionStatusAuthenticated,
	AuthSessionStatusAuthorized,
	AuthSessionStatusActive,
	AuthSessionStatusEnded,
	AuthSessionStatusFailed,
}

// authSessionTransitions defines the allowed auth session status transitions.
var authSessionTransitions = map[string][]string{
	AuthSessionStatusPending:       {AuthSessionStatusAuthenticated, AuthSessionStatusFailed, AuthSessionStatusEnded},
	AuthSessionStatusAuthenticated: {AuthSessionStatusAuthorized, AuthSessionStatusFailed, AuthSessionStatusEnded},
	AuthSessionStatusAuthorized:    {AuthSessionStatusActive, AuthSessionStatusFailed, AuthSessionStatusEnded},
	AuthSessionStatusActive:        {AuthSessionStatusEnded},
}

// authSessionInitialStatuses is the list of the statuses that a new auth session could start with
// (active is allowed only for the root SSO and programmatically created sessions).
var authSessionInitialStatuses = []string{AuthSessionStatusPending, AuthSessionStatusActive}

// Supported auth session factor (aka. "amr") methods.
const (
	AuthSessionMethodPassword      = "password"
	AuthSessionMethodOTP           = "otp"
	AuthSessionMethodOAuth2        = "oauth2"
	AuthSessionMethodImpersonation = "impersonation"

	// AuthSessionMethodClientCredentials is the method of the application installations
	// sessions created by the client_credentials grant (root-less, no refresh token).
	AuthSessionMethodClientCredentials = "client_credentials"

	// AuthSessionMethodLaunch is the method of the application extensions "online" sessions
	// created by the token exchange of an extension launch token (actor = the staff member
	// on behalf of the installation, client = the installation managed client,
	// parent = the staff root SSO session, no refresh token; see [ApplicationLaunchClaims]).
	AuthSessionMethodLaunch = "launch"
)

// AuthSessionFlowDuration is the max time that the end-user has
// to complete the hosted login steps of a single authorization flow.
const AuthSessionFlowDuration = 1 * time.Hour

// ErrInvalidAuthSessionTransition is returned on illegal auth session status transition.
var ErrInvalidAuthSessionTransition = errors.New("invalid auth session status transition")

var (
	_ Model        = (*AuthSession)(nil)
	_ PreValidator = (*AuthSession)(nil)
	_ RecordProxy  = (*AuthSession)(nil)
)

// AuthSessionMethod defines a single auth session factor (aka. "amr" entry).
type AuthSessionMethod struct {
	// Method is the factor method name (e.g. "password", "otp", "oauth2").
	Method string `json:"method"`

	// Provider is the upstream OAuth2 provider name (oauth2 factors only).
	Provider string `json:"provider,omitempty"`

	// Time is the time when the factor was completed.
	Time types.DateTime `json:"time"`
}

// AuthSession defines a Record proxy for working with the auth sessions collection.
//
// An auth session is created for each authorization flow and it is filled
// incrementally while the browser walks the hosted login steps
// (the browser holds only an opaque handle and a binding cookie).
//
// Once tokens are issued the session id is used as "sid" claim
// and every auth token is validated against its session.
//
// Note that the session describes how/when/where/through which client
// the actor authenticated and it is not the actor itself (see [AuthSession.RecordRef]).
type AuthSession struct {
	*Record

	// cached actor and client used for generating the access tokens (see [AuthSession.AttachActor])
	actor  *Record
	client *OAuth2Client
}

// NewAuthSession instantiates and returns a new blank *AuthSession model.
//
// Use [App.NewAuthSession] if you want to create a ready to use
// active auth session for an auth record (e.g. for a custom auth method).
//
// Example usage:
//
//	session := core.NewAuthSession(app)
//	session.SetCollectionRef(users.Id)
//	session.SetClient(client.Id)
//	session.SetExpiresAt(types.NowDateTime().Add(core.AuthSessionFlowDuration))
//	app.Save(session)
func NewAuthSession(app App) *AuthSession {
	m := &AuthSession{}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameAuthSessions)
	if err != nil {
		// this is just to make tests easier since it is a system collection and it is expected to be always accessible
		// (note: the loaded record is further checked on AuthSession.PreValidate())
		c = NewBaseCollection("@__invalid__")
	}

	m.Record = NewRecord(c)
	m.Record.Set("status", AuthSessionStatusPending)
	m.Record.Set("maxAge", -1)

	return m
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *AuthSession) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameAuthSessions {
		return errors.New("missing or invalid auth session ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *AuthSession) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *AuthSession) SetProxyRecord(record *Record) {
	m.Record = record
}

// -------------------------------------------------------------------
// Status
// -------------------------------------------------------------------

// Status returns the "status" record field value.
func (m *AuthSession) Status() string {
	return m.GetString("status")
}

// CanTransitionTo reports whether the session could transition from its current status to the provided one.
func (m *AuthSession) CanTransitionTo(status string) bool {
	return canTransitionAuthSession(m.Status(), status)
}

func canTransitionAuthSession(from string, to string) bool {
	return slices.Contains(authSessionTransitions[from], to)
}

// TransitionTo changes the session status to the provided one.
//
// Returns [ErrInvalidAuthSessionTransition] if the transition is not allowed
// (see [AuthSessionStatuses] for the allowed transitions).
//
// Note that the change is not persisted.
func (m *AuthSession) TransitionTo(status string) error {
	from := m.Status()
	if !canTransitionAuthSession(from, status) {
		return fmt.Errorf("%w from %q to %q", ErrInvalidAuthSessionTransition, from, status)
	}

	m.Set("status", status)

	return nil
}

// MarkAuthenticated transitions the session to the "authenticated" status.
func (m *AuthSession) MarkAuthenticated() error {
	return m.TransitionTo(AuthSessionStatusAuthenticated)
}

// MarkAuthorized transitions the session to the "authorized" status.
func (m *AuthSession) MarkAuthorized() error {
	return m.TransitionTo(AuthSessionStatusAuthorized)
}

// MarkActive transitions the session to the "active" status.
func (m *AuthSession) MarkActive() error {
	return m.TransitionTo(AuthSessionStatusActive)
}

// End transitions the session to the terminal "ended" status.
//
// Note that ending a root SSO session also ends its children
// (except the ones with "offline_access" scope) once persisted.
func (m *AuthSession) End() error {
	return m.TransitionTo(AuthSessionStatusEnded)
}

// Fail transitions the session to the terminal "failed" status.
func (m *AuthSession) Fail() error {
	return m.TransitionTo(AuthSessionStatusFailed)
}

// IsTerminal reports whether the session is in one of the terminal (ended or failed) statuses.
func (m *AuthSession) IsTerminal() bool {
	s := m.Status()
	return s == AuthSessionStatusEnded || s == AuthSessionStatusFailed
}

// IsActive reports whether the session is active and not expired.
func (m *AuthSession) IsActive() bool {
	return m.Status() == AuthSessionStatusActive && !m.HasExpired()
}

// IsRoot reports whether the session is a root SSO session (aka. it has a SSO secret).
//
// The root SSO sessions are standalone rows that represent the browser
// login at the issuer (the "pb_session" cookie). They don't have a client,
// flow handle, authorization code or token family and every hosted flow
// session is their child (see [AuthSession.Parent]).
func (m *AuthSession) IsRoot() bool {
	return m.GetString("ssoSecretHash") != ""
}

// -------------------------------------------------------------------
// Relations
// -------------------------------------------------------------------

// CollectionRef returns the "collectionRef" record field value (aka. the issuer auth collection id).
func (m *AuthSession) CollectionRef() string {
	return m.GetString("collectionRef")
}

// SetCollectionRef updates the "collectionRef" record field value.
func (m *AuthSession) SetCollectionRef(collectionId string) {
	m.Set("collectionRef", collectionId)
}

// Client returns the "client" record field value (aka. the related OAuth2Client record id).
func (m *AuthSession) Client() string {
	return m.GetString("client")
}

// SetClient updates the "client" record field value.
func (m *AuthSession) SetClient(clientRecordId string) {
	m.Set("client", clientRecordId)
}

// RecordRef returns the "recordRef" record field value
// (aka. the actor record id; empty until the actor is identified).
func (m *AuthSession) RecordRef() string {
	return m.GetString("recordRef")
}

// SetRecordRef updates the "recordRef" record field value.
func (m *AuthSession) SetRecordRef(recordId string) {
	m.Set("recordRef", recordId)
}

// Parent returns the "parent" record field value
// (aka. the id of the root SSO session that the current flow reused).
func (m *AuthSession) Parent() string {
	return m.GetString("parent")
}

// SetParent updates the "parent" record field value.
func (m *AuthSession) SetParent(rootSessionId string) {
	m.Set("parent", rootSessionId)
}

// Impersonator returns the "impersonator" record field value
// (aka. the staff record id when the session was created via token exchange).
func (m *AuthSession) Impersonator() string {
	return m.GetString("impersonator")
}

// SetImpersonator updates the "impersonator" record field value.
//
// Note that the impersonation access tokens are accepted only if the session is also
// bound to a live impersonator session (see [AuthSession.BindImpersonator]).
func (m *AuthSession) SetImpersonator(staffRecordId string) {
	m.Set("impersonator", staffRecordId)
}

// ImpersonatorSession returns the "impersonatorSession" record field value
// (aka. the id of the impersonator auth session that the impersonation session was issued with).
func (m *AuthSession) ImpersonatorSession() string {
	return m.GetString("impersonatorSession")
}

// BindImpersonator marks the session as impersonation session of the provided staff record
// and ties it to the provided (active) staff auth session.
//
// The impersonation access tokens are rejected once the impersonator session is
// no longer active, the impersonator record is deleted or its tokenKey is changed,
// or the impersonator no longer holds the impersonate permission.
//
// Note that the change is not persisted.
func (m *AuthSession) BindImpersonator(staff *Record, staffSessionId string) {
	if staff == nil {
		m.SetImpersonator("")
		m.Set("impersonatorSession", "")
		m.Set("impersonatorKeyHash", "")
		return
	}

	m.SetImpersonator(staff.Id)
	m.Set("impersonatorSession", staffSessionId)
	m.Set("impersonatorKeyHash", hashOrEmpty(staff.TokenKey()))
}

// validateImpersonatorTokenKey reports whether the provided impersonator
// tokenKey matches with the one stored on [AuthSession.BindImpersonator].
func validateImpersonatorTokenKey(hash string, tokenKey string) bool {
	return validateHashedField(hash, tokenKey)
}

// -------------------------------------------------------------------
// Authorization request
// -------------------------------------------------------------------

// RedirectURI returns the "redirectURI" record field value.
func (m *AuthSession) RedirectURI() string {
	return m.GetString("redirectURI")
}

// SetRedirectURI updates the "redirectURI" record field value.
func (m *AuthSession) SetRedirectURI(uri string) {
	m.Set("redirectURI", uri)
}

// ResponseMode returns the "responseMode" record field value.
func (m *AuthSession) ResponseMode() string {
	return m.GetString("responseMode")
}

// SetResponseMode updates the "responseMode" record field value.
func (m *AuthSession) SetResponseMode(mode string) {
	m.Set("responseMode", mode)
}

// State returns the "state" record field value (aka. the client authorization request state).
func (m *AuthSession) State() string {
	return m.GetString("state")
}

// SetState updates the "state" record field value.
func (m *AuthSession) SetState(state string) {
	m.Set("state", state)
}

// Nonce returns the "nonce" record field value.
func (m *AuthSession) Nonce() string {
	return m.GetString("nonce")
}

// SetNonce updates the "nonce" record field value.
func (m *AuthSession) SetNonce(nonce string) {
	m.Set("nonce", nonce)
}

// CodeChallenge returns the "codeChallenge" record field value.
func (m *AuthSession) CodeChallenge() string {
	return m.GetString("codeChallenge")
}

// CodeChallengeMethod returns the "codeChallengeMethod" record field value.
func (m *AuthSession) CodeChallengeMethod() string {
	return m.GetString("codeChallengeMethod")
}

// SetCodeChallenge updates the "codeChallenge" and "codeChallengeMethod" record field values.
func (m *AuthSession) SetCodeChallenge(challenge string, method string) {
	m.Set("codeChallenge", challenge)
	m.Set("codeChallengeMethod", method)
}

// ValidateCodeVerifier reports whether the provided PKCE code verifier
// matches with the stored S256 code challenge.
func (m *AuthSession) ValidateCodeVerifier(verifier string) bool {
	challenge := m.CodeChallenge()
	if challenge == "" || verifier == "" || m.CodeChallengeMethod() != "S256" {
		return false
	}

	return security.Equal(challenge, security.S256Challenge(verifier))
}

// Prompt returns the "prompt" record field value.
func (m *AuthSession) Prompt() string {
	return m.GetString("prompt")
}

// SetPrompt updates the "prompt" record field value.
func (m *AuthSession) SetPrompt(prompt string) {
	m.Set("prompt", prompt)
}

// MaxAge returns the "maxAge" record field value (negative if not set).
func (m *AuthSession) MaxAge() int64 {
	return int64(m.GetInt("maxAge"))
}

// SetMaxAge updates the "maxAge" record field value (use -1 for not set).
func (m *AuthSession) SetMaxAge(maxAge int64) {
	if maxAge < 0 {
		maxAge = -1
	}

	m.Set("maxAge", maxAge)
}

// LoginHint returns the "loginHint" record field value.
func (m *AuthSession) LoginHint() string {
	return m.GetString("loginHint")
}

// SetLoginHint updates the "loginHint" record field value.
func (m *AuthSession) SetLoginHint(hint string) {
	m.Set("loginHint", hint)
}

// UILocales returns the "uiLocales" record field value.
func (m *AuthSession) UILocales() string {
	return m.GetString("uiLocales")
}

// SetUILocales updates the "uiLocales" record field value.
func (m *AuthSession) SetUILocales(locales string) {
	m.Set("uiLocales", locales)
}

// ScopesRequested returns the "scopesRequested" record field value.
func (m *AuthSession) ScopesRequested() []string {
	return m.GetStringSlice("scopesRequested")
}

// SetScopesRequested updates the "scopesRequested" record field value.
func (m *AuthSession) SetScopesRequested(scopes []string) {
	m.Set("scopesRequested", scopes)
}

// Scopes returns the "scopes" record field value (aka. the granted scopes).
func (m *AuthSession) Scopes() []string {
	return m.GetStringSlice("scopes")
}

// SetScopes updates the "scopes" record field value.
func (m *AuthSession) SetScopes(scopes []string) {
	m.Set("scopes", scopes)
}

// HasScope reports whether the session granted scopes contain the provided one.
func (m *AuthSession) HasScope(scope string) bool {
	return slices.Contains(m.Scopes(), scope)
}

// -------------------------------------------------------------------
// Authentication factors
// -------------------------------------------------------------------

// AuthMethods returns the "amr" record field value (aka. the completed factors).
func (m *AuthSession) AuthMethods() []AuthSessionMethod {
	result := []AuthSessionMethod{}

	_ = m.UnmarshalJSONField("amr", &result)

	return result
}

// SetAuthMethods updates the "amr" record field value.
func (m *AuthSession) SetAuthMethods(methods []AuthSessionMethod) {
	if methods == nil {
		methods = []AuthSessionMethod{}
	}

	m.Set("amr", methods)
}

// AddAuthMethod registers a new completed factor and updates the session auth time.
//
// Note that the change is not persisted.
func (m *AuthSession) AddAuthMethod(method string, provider string) {
	now := types.NowDateTime()

	methods := m.AuthMethods()
	methods = append(methods, AuthSessionMethod{Method: method, Provider: provider, Time: now})

	m.SetAuthMethods(methods)
	m.SetAuthTime(now)
}

// HasAuthMethod reports whether the session has a completed factor with the provided method.
func (m *AuthSession) HasAuthMethod(method string) bool {
	for _, am := range m.AuthMethods() {
		if am.Method == method {
			return true
		}
	}

	return false
}

// DistinctAuthMethods returns the distinct factor methods completed after the provided time.
func (m *AuthSession) DistinctAuthMethods(after time.Time) []string {
	result := []string{}

	for _, am := range m.AuthMethods() {
		if am.Time.Time().Before(after) || slices.Contains(result, am.Method) {
			continue
		}
		result = append(result, am.Method)
	}

	return result
}

// AuthTime returns the "authTime" record field value (aka. the time of the last interactive authentication).
func (m *AuthSession) AuthTime() types.DateTime {
	return m.GetDateTime("authTime")
}

// SetAuthTime updates the "authTime" record field value.
func (m *AuthSession) SetAuthTime(date types.DateTime) {
	m.Set("authTime", date)
}

// MFARequired returns the "mfaRequired" record field value.
func (m *AuthSession) MFARequired() bool {
	return m.GetBool("mfaRequired")
}

// SetMFARequired updates the "mfaRequired" record field value.
func (m *AuthSession) SetMFARequired(required bool) {
	m.Set("mfaRequired", required)
}

// -------------------------------------------------------------------
// Upstream (federated) OAuth2 login step
// -------------------------------------------------------------------

// UpstreamProvider returns the "upstreamProvider" record field value.
func (m *AuthSession) UpstreamProvider() string {
	return m.GetString("upstreamProvider")
}

// UpstreamCodeVerifier returns the "upstreamCodeVerifier" record field value.
func (m *AuthSession) UpstreamCodeVerifier() string {
	return m.GetString("upstreamCodeVerifier")
}

// SetUpstream stores the started upstream OAuth2 login step data
// (the plain state is stored hashed) and clears any previous pending upstream result.
//
// Call it with empty arguments to clear all upstream data.
func (m *AuthSession) SetUpstream(provider string, plainState string, codeVerifier string) {
	m.Set("upstreamProvider", provider)
	m.Set("upstreamState", hashOrEmpty(plainState))
	m.Set("upstreamCodeVerifier", codeVerifier)
	m.Set("upstreamRecordRef", "")
}

// SetUpstreamResult stores the resolved (but not yet applied) upstream OAuth2 login
// record id and clears the single use upstream state and code verifier.
//
// The pending result is applied as factor only by a hosted flow step that
// checked the browser binding cookie (see [AuthSession.UpstreamRecordRef]).
func (m *AuthSession) SetUpstreamResult(recordId string) {
	m.Set("upstreamState", "")
	m.Set("upstreamCodeVerifier", "")
	m.Set("upstreamRecordRef", recordId)
}

// UpstreamRecordRef returns the "upstreamRecordRef" record field value
// (aka. the pending, not yet applied, upstream OAuth2 login record id).
func (m *AuthSession) UpstreamRecordRef() string {
	return m.GetString("upstreamRecordRef")
}

// ValidateUpstreamState reports whether the provided plain upstream
// OAuth2 state matches with the stored one.
func (m *AuthSession) ValidateUpstreamState(plainState string) bool {
	return validateHashedField(m.GetString("upstreamState"), plainState)
}

// OTPRecordRef returns the "otpRecordRef" record field value
// (aka. the auth record identified by the last hosted login OTP request of the session).
//
// The session could verify the OTPs of that record that are not bound
// to any session (e.g. created with the "superuser otp" command).
func (m *AuthSession) OTPRecordRef() string {
	return m.GetString("otpRecordRef")
}

// SetOTPRecordRef updates the "otpRecordRef" record field value.
func (m *AuthSession) SetOTPRecordRef(recordId string) {
	m.Set("otpRecordRef", recordId)
}

// -------------------------------------------------------------------
// Opaque browser handle, binding and SSO secrets
// -------------------------------------------------------------------

// SetHandle stores the hash of the provided plain opaque
// "auth_state" handle (the handle is never stored plain).
func (m *AuthSession) SetHandle(plainHandle string) {
	m.Set("handleHash", hashOrEmpty(plainHandle))
}

// SetBinding stores the hash of the provided plain browser binding cookie value.
func (m *AuthSession) SetBinding(plainBinding string) {
	m.Set("bindingHash", hashOrEmpty(plainBinding))
}

// ValidateBinding reports whether the provided plain browser
// binding cookie value matches with the stored one.
func (m *AuthSession) ValidateBinding(plainBinding string) bool {
	return validateHashedField(m.GetString("bindingHash"), plainBinding)
}

// SetSSOSecret stores the hash of the provided plain root SSO session secret
// (aka. the secret part of the "pb_session" cookie value).
func (m *AuthSession) SetSSOSecret(plainSecret string) {
	m.Set("ssoSecretHash", hashOrEmpty(plainSecret))
}

// ValidateSSOSecret reports whether the provided plain SSO secret matches with the stored one.
func (m *AuthSession) ValidateSSOSecret(plainSecret string) bool {
	return validateHashedField(m.GetString("ssoSecretHash"), plainSecret)
}

// -------------------------------------------------------------------
// Authorization code
// -------------------------------------------------------------------

// SetCode stores the hash of the provided plain authorization code and its expiration date.
func (m *AuthSession) SetCode(plainCode string, expiresAt types.DateTime) {
	m.Set("codeHash", hashOrEmpty(plainCode))
	m.Set("codeExpiresAt", expiresAt)
	m.Set("codeConsumed", false)
}

// CodeExpiresAt returns the "codeExpiresAt" record field value.
func (m *AuthSession) CodeExpiresAt() types.DateTime {
	return m.GetDateTime("codeExpiresAt")
}

// HasCodeExpired reports whether the authorization code has expired.
func (m *AuthSession) HasCodeExpired() bool {
	return !m.CodeExpiresAt().Time().After(time.Now())
}

// CodeConsumed returns the "codeConsumed" record field value.
func (m *AuthSession) CodeConsumed() bool {
	return m.GetBool("codeConsumed")
}

// SetCodeConsumed updates the "codeConsumed" record field value.
func (m *AuthSession) SetCodeConsumed(consumed bool) {
	m.Set("codeConsumed", consumed)
}

// -------------------------------------------------------------------
// Refresh token family
// -------------------------------------------------------------------

// SetRefreshToken stores the hash of the provided plain refresh token
// (empty string clears the refresh token).
func (m *AuthSession) SetRefreshToken(plainToken string) {
	m.Set("refreshTokenHash", hashOrEmpty(plainToken))
}

// RotateRefreshToken moves the current refresh token hash to
// "prevRefreshTokenHash" (used for reuse detection), stores
// the hash of the new plain refresh token and the rotation time.
func (m *AuthSession) RotateRefreshToken(newPlainToken string) {
	m.Set("prevRefreshTokenHash", m.GetString("refreshTokenHash"))
	m.Set("refreshRotatedAt", types.NowDateTime())
	m.SetRefreshToken(newPlainToken)
}

// RefreshRotatedAt returns the "refreshRotatedAt" record field value
// (aka. the time of the last refresh token rotation).
func (m *AuthSession) RefreshRotatedAt() types.DateTime {
	return m.GetDateTime("refreshRotatedAt")
}

// IsWithinRefreshGrace reports whether the last refresh token rotation
// happened less than the provided grace period ago.
func (m *AuthSession) IsWithinRefreshGrace(grace time.Duration) bool {
	rotatedAt := m.RefreshRotatedAt()
	if rotatedAt.IsZero() {
		return false
	}

	elapsed := time.Since(rotatedAt.Time())

	return elapsed >= 0 && elapsed < grace
}

// ValidateRefreshToken reports whether the provided plain
// refresh token matches with the current refresh token hash.
func (m *AuthSession) ValidateRefreshToken(plainToken string) bool {
	return validateHashedField(m.GetString("refreshTokenHash"), plainToken)
}

// HasRefreshToken reports whether the session has an issued refresh token.
func (m *AuthSession) HasRefreshToken() bool {
	return m.GetString("refreshTokenHash") != ""
}

// RefreshExpiresAt returns the "refreshExpiresAt" record field value.
func (m *AuthSession) RefreshExpiresAt() types.DateTime {
	return m.GetDateTime("refreshExpiresAt")
}

// SetRefreshExpiresAt updates the "refreshExpiresAt" record field value.
func (m *AuthSession) SetRefreshExpiresAt(date types.DateTime) {
	m.Set("refreshExpiresAt", date)
}

// HasRefreshExpired reports whether the refresh token family has expired.
func (m *AuthSession) HasRefreshExpired() bool {
	return !m.RefreshExpiresAt().Time().After(time.Now())
}

// -------------------------------------------------------------------
// Application extension launch
// -------------------------------------------------------------------

// LaunchJti returns the "launchJti" record field value (the jti of the exchanged
// extension launch token of an online session; unique, aka. single use).
func (m *AuthSession) LaunchJti() string {
	return m.GetString("launchJti")
}

// SetLaunchJti updates the "launchJti" record field value.
func (m *AuthSession) SetLaunchJti(jti string) {
	m.Set("launchJti", jti)
}

// IsLaunch reports whether the session is an application extension online session
// (see [AuthSessionMethodLaunch]).
func (m *AuthSession) IsLaunch() bool {
	return m.HasAuthMethod(AuthSessionMethodLaunch)
}

// -------------------------------------------------------------------
// Client info and timestamps
// -------------------------------------------------------------------

// IP returns the "ip" record field value.
func (m *AuthSession) IP() string {
	return m.GetString("ip")
}

// SetIP updates the "ip" record field value.
func (m *AuthSession) SetIP(ip string) {
	m.Set("ip", ip)
}

// UserAgent returns the "userAgent" record field value.
func (m *AuthSession) UserAgent() string {
	return m.GetString("userAgent")
}

// SetUserAgent updates the "userAgent" record field value (truncated to 255 chars).
func (m *AuthSession) SetUserAgent(userAgent string) {
	if len(userAgent) > 255 {
		userAgent = userAgent[:255]
	}

	m.Set("userAgent", userAgent)
}

// LastUsedAt returns the "lastUsedAt" record field value.
func (m *AuthSession) LastUsedAt() types.DateTime {
	return m.GetDateTime("lastUsedAt")
}

// SetLastUsedAt updates the "lastUsedAt" record field value.
func (m *AuthSession) SetLastUsedAt(date types.DateTime) {
	m.Set("lastUsedAt", date)
}

// ExpiresAt returns the "expiresAt" record field value.
func (m *AuthSession) ExpiresAt() types.DateTime {
	return m.GetDateTime("expiresAt")
}

// SetExpiresAt updates the "expiresAt" record field value.
func (m *AuthSession) SetExpiresAt(date types.DateTime) {
	m.Set("expiresAt", date)
}

// HasExpired reports whether the session has expired.
func (m *AuthSession) HasExpired() bool {
	return !m.ExpiresAt().Time().After(time.Now())
}

// Created returns the "created" record field value.
func (m *AuthSession) Created() types.DateTime {
	return m.GetDateTime("created")
}

// Updated returns the "updated" record field value.
func (m *AuthSession) Updated() types.DateTime {
	return m.GetDateTime("updated")
}

// -------------------------------------------------------------------
// Tokens
// -------------------------------------------------------------------

// AttachActor caches the session actor record and client so that
// they could be used for generating the session access tokens.
//
// Returns an error if the provided record or client don't belong to the session.
func (m *AuthSession) AttachActor(record *Record, client *OAuth2Client) error {
	if record == nil || client == nil {
		return errors.New("missing auth session actor or client")
	}

	if m.RecordRef() == "" || record.Id != m.RecordRef() || record.Collection().Id != m.CollectionRef() {
		return errors.New("the record is not the auth session actor")
	}

	// note: the cross-issuer sessions are the dashboard client impersonations and
	// the application extensions online sessions (staff actor, installation managed client)
	crossIssuer := (client.IsDashboard() && m.Impersonator() != "") ||
		(client.IsManaged() && m.IsLaunch() && record.IsSuperuser())

	if m.IsRoot() || client.Id != m.Client() || (client.CollectionRef() != m.CollectionRef() && !crossIssuer) {
		return errors.New("the client is not the auth session client")
	}

	m.actor = record
	m.client = client

	return nil
}

// Actor returns the attached session actor record (see [AuthSession.AttachActor]).
func (m *AuthSession) Actor() *Record {
	return m.actor
}

// NewAccessToken generates and returns a new access token for the
// attached actor and client (see [AuthSession.AttachActor]).
//
// The access token is a HS256 record auth token (signed with the record
// tokenKey and the collection AuthToken.Secret) with the following claims:
//   - "type"         - always "auth"
//   - "id"           - the actor record id
//   - "collectionId" - the actor collection id
//   - "cid"          - the public client_id of the session client
//   - "scope"        - space-delimited list of the session granted scopes
//   - "sid"          - the session id (checked on each [App.FindAuthRecordByToken] call)
//   - "act"          - the impersonator (only for impersonation sessions, RFC 8693)
//
// The token duration is based on the collection AuthToken.Duration option.
func (m *AuthSession) NewAccessToken() (string, error) {
	if m.Id == "" || m.Record.IsNew() {
		return "", errors.New("the auth session must be saved before issuing tokens")
	}

	if m.Status() != AuthSessionStatusActive {
		return "", errors.New("the auth session is not active")
	}

	if m.actor == nil || m.client == nil {
		return "", errors.New("missing attached auth session actor and client")
	}

	if !m.actor.Collection().IsAuth() {
		return "", ErrNotAuthRecord
	}

	key := m.actor.TokenKey() + m.actor.Collection().AuthToken.Secret
	if key == "" {
		return "", ErrMissingSigningKey
	}

	claims := jwt.MapClaims{
		TokenClaimType:            TokenTypeAuth,
		TokenClaimId:              m.actor.Id,
		TokenClaimCollectionId:    m.actor.Collection().Id,
		TokenClaimOAuth2ClientId:  m.client.ClientId(),
		TokenClaimOAuth2Scope:     strings.Join(m.Scopes(), " "),
		TokenClaimOAuth2SessionId: m.Id,
	}

	if impersonator := m.Impersonator(); impersonator != "" {
		claims[TokenClaimOAuth2Actor] = map[string]any{"sub": impersonator}
	}

	return security.NewJWT(claims, key, m.actor.Collection().AuthToken.DurationTime())
}

// -------------------------------------------------------------------

func hashOrEmpty(plain string) string {
	if plain == "" {
		return ""
	}

	return security.SHA256(plain)
}

// validateHashedField performs a constant-time comparison of the provided plain value hash.
func validateHashedField(hash string, plain string) bool {
	if hash == "" || plain == "" {
		return false
	}

	return security.Equal(hash, security.SHA256(plain))
}

// -------------------------------------------------------------------
// Hooks
// -------------------------------------------------------------------

func (app *BaseApp) registerAuthSessionHooks() {
	app.OnRecordValidate(CollectionNameAuthSessions).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if err := validateAuthSession(e.App, e.Record); err != nil {
				return err
			}

			return e.Next()
		},
		Priority: 99,
	})

	// sync the original model state after each successful persist so that the status
	// transitions of an already saved (but not refetched) session are properly validated
	syncOriginal := &hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if err := e.Next(); err != nil {
				return err
			}

			return e.Record.PostScan()
		},
		Priority: 98, // wraps the cascade handler below
	}
	app.OnRecordCreateExecute(CollectionNameAuthSessions).Bind(syncOriginal)
	app.OnRecordUpdateExecute(CollectionNameAuthSessions).Bind(syncOriginal)

	// validate the status transition against the persisted (aka. current db) state
	// and write in the same transaction so that a stale session model
	// (e.g. a root SSO session loaded before a concurrent logout) can't
	// overwrite a newer status (e.g. "resurrect" an ended session)
	app.OnRecordUpdateExecute(CollectionNameAuthSessions).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			originalApp := e.App
			defer func() {
				e.App = originalApp
			}()

			return e.App.RunInTransaction(func(txApp App) error {
				var current string

				err := txApp.DB().Select("status").
					From(CollectionNameAuthSessions).
					Where(dbx.HashExp{"id": e.Record.LastSavedPK()}).
					Limit(1).
					Row(&current)
				if err != nil {
					return err
				}

				status := e.Record.GetString("status")
				if current != status && !canTransitionAuthSession(current, status) {
					return fmt.Errorf(
						"%w from the persisted %q to %q (the auth session was changed concurrently)",
						ErrInvalidAuthSessionTransition,
						current,
						status,
					)
				}

				e.App = txApp

				return e.Next()
			})
		},
		Priority: 97, // wraps the original sync and cascade handlers
	})

	// cascade the ending of a root SSO session to its children
	// (with the exception of the children with "offline_access" scope)
	// and the ending of any session to the impersonation sessions issued with it
	app.OnRecordUpdateExecute(CollectionNameAuthSessions).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if err := e.Next(); err != nil {
				return err
			}

			if e.Record.GetString("status") != AuthSessionStatusEnded ||
				e.Record.Original().GetString("status") == AuthSessionStatusEnded {
				return nil
			}

			if err := endAuthSessionChildren(e.Context, e.App, e.Record.Id); err != nil {
				return err
			}

			return endAuthSessionsByExpr(e.Context, e.App, dbx.HashExp{"impersonatorSession": e.Record.Id})
		},
		Priority: 99,
	})

	// run on every hour to cleanup the ended, failed and expired auth sessions
	// (and the stale pending application installations)
	app.Cron().Add("__pbAuthSessionsCleanup__", "0 * * * *", func() {
		if err := app.DeleteExpiredAuthSessions(); err != nil {
			app.Logger().Warn("Failed to delete expired auth sessions", "error", err)
		}

		if err := app.deleteStalePendingApplicationInstallations(); err != nil {
			app.Logger().Warn("Failed to delete the stale pending application installations", "error", err)
		}
	})

	// end all record auth sessions on tokenKey change (e.g. on password change)
	app.OnRecordUpdateExecute().Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			err := e.Next()
			if err != nil || !e.Record.Collection().IsAuth() {
				return err
			}

			if !e.Record.Original().IsNew() && e.Record.Original().TokenKey() != e.Record.TokenKey() {
				// note: the sessions preserved in the save context (e.g. the in-progress
				// hosted login flow that caused a verified upgrade) are not ended
				err = endAuthSessionsByExpr(e.Context, e.App, dbx.HashExp{
					"collectionRef": e.Record.Collection().Id,
					"recordRef":     e.Record.Id,
				})
				if err != nil {
					return fmt.Errorf(
						"[%s] failed to end all previous auth sessions for record %q: %w",
						e.Record.Collection().Name,
						e.Record.Id,
						err,
					)
				}
			}

			return nil
		},
		Priority: 99,
	})

	// end all client auth sessions when the client is disabled
	// (on client delete the sessions are deleted by the relation cascade)
	app.OnRecordUpdateExecute(CollectionNameOAuth2Clients).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if err := e.Next(); err != nil {
				return err
			}

			if !e.Record.GetBool("disabled") || e.Record.Original().GetBool("disabled") {
				return nil
			}

			return e.App.EndAllAuthSessionsByClient(&OAuth2Client{e.Record})
		},
		Priority: 99,
	})

	// delete all record auth sessions on auth record delete
	app.OnRecordDeleteExecute().Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if !e.Record.Collection().IsAuth() {
				return e.Next()
			}

			return e.App.RunInTransaction(func(txApp App) error {
				originalApp := e.App
				e.App = txApp
				err := e.Next()
				e.App = originalApp
				if err != nil {
					return err
				}

				err = deleteAuthSessionsByExpr(txApp, map[string]any{
					"collectionRef": e.Record.Collection().Id,
					"recordRef":     e.Record.Id,
				})
				if err != nil {
					return err
				}

				// end the impersonation sessions of the deleted staff record
				if e.Record.IsSuperuser() {
					return endAuthSessionsByExpr(e.Context, txApp, dbx.HashExp{"impersonator": e.Record.Id})
				}

				return nil
			})
		},
		Priority: 99,
	})

	// delete all collection auth sessions on auth collection delete
	app.OnCollectionDeleteExecute().Bind(&hook.Handler[*CollectionEvent]{
		Func: func(e *CollectionEvent) error {
			if !e.Collection.IsAuth() {
				return e.Next()
			}

			return e.App.RunInTransaction(func(txApp App) error {
				originalApp := e.App
				e.App = txApp
				err := e.Next()
				e.App = originalApp
				if err != nil {
					return err
				}

				return deleteAuthSessionsByExpr(txApp, map[string]any{"collectionRef": e.Collection.Id})
			})
		},
		Priority: 99,
	})
}

// validateAuthSession validates the auth session relations and status transition.
func validateAuthSession(app App, record *Record) error {
	errs := validation.Errors{}

	collectionId := record.GetString("collectionRef")
	err := validation.Validate(collectionId, validation.Required, validation.By(validateCollectionId(app, CollectionTypeAuth)))
	if err != nil {
		errs["collectionRef"] = err
	}

	if recordId := record.GetString("recordRef"); recordId != "" && errs["collectionRef"] == nil {
		if err := validation.Validate(recordId, validation.By(validateRecordId(app, collectionId))); err != nil {
			errs["recordRef"] = err
		}
	}

	for _, field := range []string{"upstreamRecordRef", "otpRecordRef"} {
		if recordId := record.GetString(field); recordId != "" && errs["collectionRef"] == nil {
			if err := validation.Validate(recordId, validation.By(validateRecordId(app, collectionId))); err != nil {
				errs[field] = err
			}
		}
	}

	// the root SSO sessions are not bound to any client
	// (all other sessions must have a client)
	if record.GetString("ssoSecretHash") != "" {
		if record.GetString("client") != "" {
			errs["client"] = validation.NewError(
				"validation_auth_session_root_client",
				"The root SSO sessions must not have a client.",
			)
		}

		for _, field := range []string{"parent", "handleHash", "codeHash", "refreshTokenHash", "prevRefreshTokenHash", "impersonatorSession"} {
			if record.GetString(field) != "" {
				errs[field] = validation.NewError(
					"validation_auth_session_root_field",
					"The root SSO sessions must not have a parent, flow handle, authorization code or token family.",
				)
			}
		}
	} else if record.GetString("client") == "" {
		errs["client"] = validation.ErrRequired
	}

	// note: the dashboard client impersonation sessions are allowed
	// to be issued for the records of any auth collection (aka. cross-issuer)
	isDashboardImpersonation := record.GetString("impersonator") != "" && isDashboardClientId(app, record.GetString("client"))

	// the application extensions online sessions (method launch) are the only sessions of a staff
	// actor with an installation managed client (aka. cross-issuer) and they are always:
	// children of a root SSO session, single use launch token jti, no refresh token, code or impersonation
	isLaunch := slices.ContainsFunc(parseAuthSessionMethods(record), func(m AuthSessionMethod) bool {
		return m.Method == AuthSessionMethodLaunch
	})
	isManagedClient := isManagedClientId(app, record.GetString("client"))
	if isLaunch || record.GetString("launchJti") != "" {
		if !isLaunch ||
			!isManagedClient ||
			!isSuperusersCollectionId(app, collectionId) ||
			record.GetString("launchJti") == "" ||
			record.GetString("parent") == "" ||
			record.GetString("ssoSecretHash") != "" ||
			record.GetString("impersonator") != "" ||
			record.GetString("refreshTokenHash") != "" ||
			record.GetString("codeHash") != "" ||
			record.GetString("handleHash") != "" {
			errs["amr"] = validation.NewError(
				"validation_launch_session",
				"The launch sessions could be created only with the token exchange of an application extension launch token.",
			)
		}
	}

	if err := validateOAuth2ClientCollectionRef(app, record); err != nil && !isDashboardImpersonation && !(isLaunch && isManagedClient) {
		var verrs validation.Errors
		if errors.As(err, &verrs) {
			for k, v := range verrs {
				errs[k] = v
			}
		} else {
			return err
		}
	}

	// the application installations sessions are created only by the client_credentials
	// grant (root-less, without refresh token) and the client_credentials method
	// is available only for the application installations
	isClientCredentials := slices.ContainsFunc(parseAuthSessionMethods(record), func(m AuthSessionMethod) bool {
		return m.Method == AuthSessionMethodClientCredentials
	})
	if isApplicationInstallationsCollectionId(app, collectionId) {
		if !isClientCredentials ||
			record.GetString("ssoSecretHash") != "" ||
			record.GetString("parent") != "" ||
			record.GetString("impersonator") != "" ||
			record.GetString("refreshTokenHash") != "" ||
			record.GetString("codeHash") != "" {
			errs["amr"] = validation.NewError(
				"validation_installation_session",
				"The application installations sessions could be created only with the client_credentials grant.",
			)
		}
	} else if isClientCredentials {
		errs["amr"] = validation.NewError(
			"validation_client_credentials_session",
			"The client_credentials sessions are available only for the application installations.",
		)
	}

	status := record.GetString("status")
	original := record.Original()
	if record.IsNew() {
		if !slices.Contains(authSessionInitialStatuses, status) {
			errs["status"] = validation.NewError(
				"validation_invalid_auth_session_status",
				"A new auth session must start with pending or active status.",
			)
		}
	} else {
		originalStatus := original.GetString("status")
		if originalStatus != status && !canTransitionAuthSession(originalStatus, status) {
			errs["status"] = validation.NewError(
				"validation_invalid_auth_session_transition",
				"Invalid auth session status transition from {{.from}} to {{.to}}.",
			).SetParams(map[string]any{"from": originalStatus, "to": status})
		}

		// the actor of an already identified session cannot be changed
		if originalRecordRef := original.GetString("recordRef"); originalRecordRef != "" &&
			originalRecordRef != record.GetString("recordRef") {
			errs["recordRef"] = validation.NewError(
				"validation_auth_session_actor_change",
				"The auth session actor cannot be changed.",
			)
		}
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}

// endAuthSessionChildren ends all non-terminal children of the specified root session
// except the ones with "offline_access" scope (they survive the SSO logout)
// and the ones preserved in the provided context (see [WithPreservedAuthSessions]).
func endAuthSessionChildren(ctx context.Context, app App, rootId string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	children := []*AuthSession{}

	err := app.RecordQuery(CollectionNameAuthSessions).
		AndWhere(dbx.HashExp{"parent": rootId}).
		AndWhere(dbx.NotIn("status", AuthSessionStatusEnded, AuthSessionStatusFailed)).
		All(&children)
	if err != nil {
		return err
	}

	preserved := preservedAuthSessions(ctx)

	for _, child := range children {
		if child.HasScope(OAuth2ScopeOfflineAccess) || slices.Contains(preserved, child.Id) {
			continue
		}

		if err := child.End(); err != nil {
			return err
		}

		if err := app.SaveWithContext(ctx, child); err != nil {
			return err
		}
	}

	return nil
}

// parseAuthSessionMethods returns the "amr" field value of the provided auth session record.
func parseAuthSessionMethods(record *Record) []AuthSessionMethod {
	result := []AuthSessionMethod{}

	_ = record.UnmarshalJSONField("amr", &result)

	return result
}

// isApplicationInstallationsCollectionId reports whether the provided collection id is the installations collection.
func isApplicationInstallationsCollectionId(app App, collectionId string) bool {
	if collectionId == "" {
		return false
	}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameApplicationInstallations)

	return err == nil && c.Id == collectionId
}

// isSuperusersCollectionId reports whether the provided collection id is the _superusers collection.
func isSuperusersCollectionId(app App, collectionId string) bool {
	if collectionId == "" {
		return false
	}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameSuperusers)

	return err == nil && c.Id == collectionId
}

// isManagedClientId reports whether the provided client record id is an application installation managed client.
func isManagedClientId(app App, clientRecordId string) bool {
	if clientRecordId == "" {
		return false
	}

	client, err := app.FindOAuth2ClientById(clientRecordId)

	return err == nil && client.IsManaged()
}

// isDashboardClientId reports whether the provided client record id is the built-in dashboard client.
func isDashboardClientId(app App, clientRecordId string) bool {
	if clientRecordId == "" {
		return false
	}

	client, err := app.FindOAuth2ClientById(clientRecordId)

	return err == nil && client.IsDashboard()
}
