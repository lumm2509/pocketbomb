package apis

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

// RFC 8693 (token exchange) token types.
const (
	oauth2TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

	// oauth2TokenTypeRecordId is a custom subject token type that identifies
	// the impersonated auth record by its id (the subject is not required
	// to have a token since the impersonation is authorized by the actor token).
	oauth2TokenTypeRecordId = "urn:pocketbase:params:oauth:token-type:record_id"

	// oauth2TokenTypeLaunchToken is a custom subject token type of the application
	// extensions launch tokens (exchanged by the installation managed client for
	// a staff online access token, see [oauth2TokenExchangeLaunch]).
	oauth2TokenTypeLaunchToken = "urn:pocketbase:params:oauth:token-type:launch_token"
)

type oauth2TokenForm struct {
	oauth2ClientCredentials

	GrantType    string `form:"grant_type" json:"grant_type"`
	Code         string `form:"code" json:"code"`
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri"`
	CodeVerifier string `form:"code_verifier" json:"code_verifier"`
	RefreshToken string `form:"refresh_token" json:"refresh_token"`
	Scope        string `form:"scope" json:"scope"`

	// token exchange (RFC 8693)
	SubjectToken       string `form:"subject_token" json:"subject_token"`
	SubjectTokenType   string `form:"subject_token_type" json:"subject_token_type"`
	ActorToken         string `form:"actor_token" json:"actor_token"`
	ActorTokenType     string `form:"actor_token_type" json:"actor_token_type"`
	RequestedTokenType string `form:"requested_token_type" json:"requested_token_type"`
}

type oauth2TokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
	IdToken         string `json:"id_token,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`

	// AssociatedUser is the staff member of an application extension online token.
	AssociatedUser *oauth2AssociatedUser `json:"associated_user,omitempty"`
}

// oauth2AssociatedUser defines the staff member of an online token (id and role names only).
type oauth2AssociatedUser struct {
	Id    string   `json:"id"`
	Roles []string `json:"roles"`
}

// POST {issuer}/token
//
// The only HTTP endpoint that issues OAuth2 server access tokens.
func oauth2ServerToken(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	form := oauth2TokenForm{}
	if err := oauth2BindBody(e, &form); err != nil {
		return oauth2JSONError(e, newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Failed to read the request body."))
	}

	// the built-in dashboard client (of the _superusers issuer) is allowed
	// to perform token exchange (impersonation) with any issuer
	clientCollection := collection
	if form.GrantType == oauth2GrantTypeTokenExchange && oauth2RequestClientId(e, form.oauth2ClientCredentials) == core.OAuth2DashboardClientId {
		clientCollection, err = e.App.FindCachedCollectionByNameOrId(core.CollectionNameSuperusers)
		if err != nil {
			return oauth2JSONError(e, newOAuth2Error(http.StatusInternalServerError, oauth2ErrServerError, ""))
		}
	}

	client, err := oauth2AuthenticateClient(e, clientCollection, form.oauth2ClientCredentials)
	if err != nil {
		return oauth2JSONError(e, err)
	}

	// the client must be allowed to use the requested grant type (RFC 6749 section 5.2)
	if grantType := oauth2ClientGrantType(form.GrantType); grantType != "" && !client.AllowsGrantType(grantType) {
		return oauth2JSONError(e, newOAuth2Error(http.StatusBadRequest, oauth2ErrUnauthorizedClient, "The client is not allowed to use this grant_type."))
	}

	switch form.GrantType {
	case oauth2GrantTypeAuthorizationCode:
		err = oauth2TokenAuthorizationCode(e, collection, client, form)
	case oauth2GrantTypeRefreshToken:
		err = oauth2TokenRefresh(e, collection, client, form)
	case oauth2GrantTypeTokenExchange:
		err = oauth2TokenExchange(e, collection, client, form)
	case oauth2GrantTypeClientCredentials:
		err = oauth2TokenClientCredentials(e, collection, client, form)
	case "":
		err = newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Missing grant_type parameter.")
	default:
		err = newOAuth2Error(http.StatusBadRequest, oauth2ErrUnsupportedGrantType, "Unsupported grant_type.")
	}

	if err != nil && !e.Written() {
		return oauth2JSONError(e, err)
	}

	return err
}

// oauth2ClientGrantType returns the client "grantTypes" value of the provided
// wire grant_type (empty string for the unsupported grant types).
func oauth2ClientGrantType(grantType string) string {
	switch grantType {
	case oauth2GrantTypeAuthorizationCode:
		return core.OAuth2GrantTypeAuthorizationCode
	case oauth2GrantTypeRefreshToken:
		return core.OAuth2GrantTypeRefreshToken
	case oauth2GrantTypeTokenExchange:
		return core.OAuth2GrantTypeTokenExchange
	case oauth2GrantTypeClientCredentials:
		return core.OAuth2GrantTypeClientCredentials
	}

	return ""
}

func oauth2InvalidGrantError(description string) *oauth2Error {
	return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidGrant, description)
}

// oauth2TokenAuthorizationCode handles the authorization_code grant (RFC 6749 section 4.1.3 + RFC 7636).
func oauth2TokenAuthorizationCode(e *core.RequestEvent, collection *core.Collection, client *core.OAuth2Client, form oauth2TokenForm) error {
	if form.Code == "" {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Missing code parameter.")
	}

	if form.RedirectURI == "" {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Missing redirect_uri parameter.")
	}

	invalidCodeErr := oauth2InvalidGrantError("Invalid or expired authorization code.")

	// find, validate and consume the code in a single transaction
	// to guarantee that it could be exchanged only once
	var session *core.AuthSession
	var reused bool
	txErr := e.App.RunInTransaction(func(txApp core.App) error {
		found, err := txApp.FindAuthSessionByCode(form.Code)
		if err != nil || found.Client() != client.Id || found.CollectionRef() != collection.Id {
			return invalidCodeErr
		}

		session = found

		if found.CodeConsumed() {
			reused = true
			return nil
		}

		if found.Status() != core.AuthSessionStatusAuthorized || found.HasCodeExpired() || found.HasExpired() {
			return invalidCodeErr
		}

		if found.RedirectURI() != form.RedirectURI {
			return oauth2InvalidGrantError("The redirect_uri doesn't match with the one from the authorization request.")
		}

		// PKCE (RFC 7636 section 4.6; it is always required by the authorization endpoint)
		if !found.ValidateCodeVerifier(form.CodeVerifier) {
			return oauth2InvalidGrantError("Invalid code_verifier.")
		}

		found.SetCodeConsumed(true)

		return txApp.Save(found)
	})
	if txErr != nil {
		return txErr
	}

	// the code was already exchanged -> end the related session (RFC 6749 section 4.1.2)
	if reused {
		oauth2EndSession(e.App, session, "authorization code reuse")
		return invalidCodeErr
	}

	record, err := e.App.FindRecordById(collection, session.RecordRef())
	if err != nil {
		return oauth2InvalidGrantError("The authorization code auth record is missing.")
	}

	now := types.NowDateTime()
	scopes := session.Scopes()

	// every session has a rotating refresh token family:
	//   - offline_access sessions have their own RefreshTokenDuration and survive the SSO logout
	//   - the other sessions are bounded by their root SSO session (they end with it)
	refreshExpiresAt := now.Add(collection.OAuth2Server.RefreshTokenDurationTime())
	if !session.HasScope(core.OAuth2ScopeOfflineAccess) && session.Parent() != "" {
		root, err := e.App.FindAuthSessionById(session.Parent())
		if err != nil || !root.IsRoot() || !root.IsActive() {
			oauth2EndSession(e.App, session, "authorization code exchange of an ended SSO session")
			return invalidCodeErr
		}
		if root.ExpiresAt().Time().Before(refreshExpiresAt.Time()) {
			refreshExpiresAt = root.ExpiresAt()
		}
	}

	refreshToken := newOAuth2RefreshToken()
	session.SetRefreshToken(refreshToken)
	session.SetRefreshExpiresAt(refreshExpiresAt)
	session.SetExpiresAt(refreshExpiresAt)
	session.SetLastUsedAt(now)
	session.SetIP(e.RealIP())
	session.SetUserAgent(e.Request.UserAgent())
	if err := session.MarkActive(); err != nil {
		return invalidCodeErr
	}

	event := new(core.OAuth2TokenRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.GrantType = oauth2GrantTypeAuthorizationCode
	event.Client = client
	event.Record = record
	event.Session = session
	event.Scopes = scopes
	event.IdTokenClaims = map[string]any{}

	return e.App.OnOAuth2TokenRequest().Trigger(event, func(e *core.OAuth2TokenRequestEvent) error {
		if err := e.App.Save(e.Session); err != nil {
			// e.g. ended concurrently by a logout or revocation
			if errors.Is(err, core.ErrInvalidAuthSessionTransition) {
				return invalidCodeErr
			}
			return err
		}

		return oauth2WriteTokenResponse(e, refreshToken, e.Session.Nonce())
	})
}

// oauth2TokenRefresh handles the refresh_token grant (RFC 6749 section 6)
// with refresh token rotation and reuse detection (RFC 9700 section 4.14.2).
func oauth2TokenRefresh(e *core.RequestEvent, collection *core.Collection, client *core.OAuth2Client, form oauth2TokenForm) error {
	if form.RefreshToken == "" {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Missing refresh_token parameter.")
	}

	invalidTokenErr := oauth2InvalidGrantError("Invalid or expired refresh token.")

	session, err := e.App.FindAuthSessionByRefreshToken(form.RefreshToken)
	if err != nil {
		oauth2DetectRefreshTokenReuse(e.App, collection, client, form.RefreshToken, "")
		return invalidTokenErr
	}

	if session.Client() != client.Id ||
		session.CollectionRef() != collection.Id ||
		!session.IsActive() ||
		session.HasRefreshExpired() ||
		!e.App.IsAuthSessionRootAlive(session) {
		return invalidTokenErr
	}

	scopes := session.Scopes()

	// the requested scope (if any) must not exceed the originally granted scopes
	// (note: the issued tokens always have the original session scopes)
	for _, s := range strings.Fields(form.Scope) {
		if !slices.Contains(scopes, s) {
			return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidScope, "The requested scope exceeds the originally granted scopes.")
		}
	}

	record, err := e.App.FindRecordById(collection, session.RecordRef())
	if err != nil {
		return oauth2InvalidGrantError("The refresh token auth record is missing.")
	}

	newRefreshToken := newOAuth2RefreshToken()

	event := new(core.OAuth2TokenRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.GrantType = oauth2GrantTypeRefreshToken
	event.Client = client
	event.Record = record
	event.Session = session
	event.Scopes = scopes
	event.IdTokenClaims = map[string]any{}

	return e.App.OnOAuth2TokenRequest().Trigger(event, func(e *core.OAuth2TokenRequestEvent) error {
		// rotate in a transaction to ensure that concurrent requests
		// with the same refresh token can't both succeed
		txErr := e.App.RunInTransaction(func(txApp core.App) error {
			fresh, err := txApp.FindAuthSessionByRefreshToken(form.RefreshToken)
			if err != nil || fresh.Id != e.Session.Id || !fresh.IsActive() {
				return invalidTokenErr
			}

			fresh.RotateRefreshToken(newRefreshToken)
			fresh.SetLastUsedAt(types.NowDateTime())
			if err := txApp.Save(fresh); err != nil {
				return err
			}

			e.Session = fresh

			return nil
		})
		if txErr != nil {
			oauth2DetectRefreshTokenReuse(e.App, collection, client, form.RefreshToken, e.Session.Id)
			return txErr
		}

		return oauth2WriteTokenResponse(e, newRefreshToken, "")
	})
}

// oauth2RefreshGracePeriod is the max time after a refresh token rotation within which the
// previous refresh token of the same client and session is rejected without ending the session
// (e.g. concurrent refresh requests from multiple browser tabs).
const oauth2RefreshGracePeriod = 10 * time.Second

// oauth2DetectRefreshTokenReuse ends the auth session of an already rotated
// refresh token (aka. a possibly stolen refresh token was used).
//
// The previous refresh token presented within [oauth2RefreshGracePeriod] after its rotation
// by the same client (and for the same session if expectedSessionId is set) is only rejected
// (the session is not ended) because it is most likely a concurrent refresh request
// of the legitimate client.
func oauth2DetectRefreshTokenReuse(app core.App, collection *core.Collection, client *core.OAuth2Client, refreshToken string, expectedSessionId string) {
	session, err := app.FindAuthSessionByPrevRefreshToken(refreshToken)
	if err != nil || session.IsTerminal() {
		return
	}

	if session.Client() == client.Id &&
		session.CollectionRef() == collection.Id &&
		(expectedSessionId == "" || session.Id == expectedSessionId) &&
		session.IsWithinRefreshGrace(oauth2RefreshGracePeriod) {
		app.Logger().Debug(
			"OAuth2 previous refresh token used within the rotation grace period (concurrent refresh)",
			"sessionId", session.Id,
			"clientId", session.Client(),
		)
		return
	}

	oauth2EndSession(app, session, "refresh token reuse")
}

// oauth2TokenExchange handles the RFC 8693 token exchange grant used for impersonation
// and for the application extensions launch tokens (see [oauth2TokenExchangeLaunch]).
//
// The subject is the impersonated auth record of the issuer collection (subject_token_type
// "urn:pocketbase:params:oauth:token-type:record_id") and the actor_token must be a valid
// _superusers access token with the RBAC "impersonate" permission (see [core.CheckImpersonation]).
//
// The issued access token has an "act" claim and its new auth session has the impersonator set.
// No refresh or id tokens are issued.
func oauth2TokenExchange(e *core.RequestEvent, collection *core.Collection, client *core.OAuth2Client, form oauth2TokenForm) error {
	if form.SubjectToken == "" || form.SubjectTokenType == "" {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Missing subject_token or subject_token_type parameter.")
	}

	if form.SubjectTokenType == oauth2TokenTypeLaunchToken {
		return oauth2TokenExchangeLaunch(e, collection, client, form)
	}

	if form.SubjectTokenType != oauth2TokenTypeRecordId {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Unsupported subject_token_type.")
	}

	// the installations managed clients exchange only the launch tokens
	if client.IsManaged() {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrUnauthorizedClient, "The client is not allowed to use this subject_token_type.")
	}

	if form.ActorToken == "" || form.ActorTokenType != oauth2TokenTypeAccessToken {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Missing or invalid actor_token or actor_token_type parameter.")
	}

	if form.RequestedTokenType != "" && form.RequestedTokenType != oauth2TokenTypeAccessToken {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Unsupported requested_token_type.")
	}

	actor, err := e.App.FindAuthRecordByToken(form.ActorToken, core.TokenTypeAuth)
	if err != nil || !actor.IsSuperuser() {
		return oauth2InvalidGrantError("The actor token is invalid or not allowed to impersonate.")
	}

	actorInfo := &core.RequestInfo{Auth: actor}
	if oauth2Info := newAuthTokenOAuth2Info(e.App, actor, form.ActorToken); oauth2Info != nil {
		actorInfo.OAuth2 = *oauth2Info
	}

	// no impersonation chains (an impersonation token can't be used as actor)
	// so that the "act" claim always identifies the real staff member
	actorClaims, _ := security.ParseUnverifiedJWT(form.ActorToken)
	if actorClaims[core.TokenClaimOAuth2Actor] != nil {
		return oauth2InvalidGrantError("The actor token is invalid or not allowed to impersonate.")
	}

	// the impersonation session is tied to the (already validated) actor token session
	actorSessionId, _ := actorClaims[core.TokenClaimOAuth2SessionId].(string)
	if actorSessionId == "" {
		return oauth2InvalidGrantError("The actor token is invalid or not allowed to impersonate.")
	}

	target, err := e.App.FindRecordById(collection, form.SubjectToken)
	if err != nil {
		return oauth2InvalidGrantError("Invalid subject_token.")
	}

	if err := core.CheckImpersonation(e.App, actorInfo, target); err != nil {
		return oauth2InvalidGrantError("The actor token is invalid or not allowed to impersonate.")
	}

	scopes := list.ToUniqueStringSlice(strings.Fields(form.Scope))
	if len(scopes) == 0 {
		scopes = client.Scopes()
	}

	allowed := core.OAuth2AllowedScopes(e.App, collection)
	clientScopes := client.Scopes()
	for _, s := range scopes {
		if !slices.Contains(allowed, s) || !slices.Contains(clientScopes, s) {
			return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidScope, "The scope "+s+" is not allowed for the client.")
		}
	}

	// the impersonation sessions of the dashboard client are not bound to the subject issuer clients
	// (only the dashboard client could be used cross-issuer and only for impersonation)
	if client.CollectionRef() != collection.Id && !client.IsDashboard() {
		return newOAuth2Error(http.StatusUnauthorized, oauth2ErrInvalidClient, "Client authentication failed.")
	}

	now := types.NowDateTime()

	session := core.NewAuthSession(e.App)
	session.Set("status", core.AuthSessionStatusActive)
	session.SetCollectionRef(collection.Id)
	session.SetClient(client.Id)
	session.SetRecordRef(target.Id)
	session.BindImpersonator(actor, actorSessionId)
	session.SetScopesRequested(scopes)
	session.SetScopes(scopes)
	session.SetAuthMethods([]core.AuthSessionMethod{{
		Method:   core.AuthSessionMethodImpersonation,
		Provider: actor.Collection().Name,
		Time:     now,
	}})
	session.SetAuthTime(now)
	session.SetIP(e.RealIP())
	session.SetUserAgent(e.Request.UserAgent())
	session.SetLastUsedAt(now)
	session.SetExpiresAt(now.Add(collection.AuthToken.DurationTime()))

	event := new(core.OAuth2TokenRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.GrantType = oauth2GrantTypeTokenExchange
	event.Client = client
	event.Record = target
	event.Session = session
	event.Scopes = scopes
	event.IdTokenClaims = map[string]any{}

	return e.App.OnOAuth2TokenRequest().Trigger(event, func(e *core.OAuth2TokenRequestEvent) error {
		if err := e.App.Save(e.Session); err != nil {
			return err
		}

		return oauth2WriteTokenResponse(e, "", "")
	})
}

// oauth2TokenExchangeLaunch handles the token exchange of an application extension launch token
// (subject_token_type "urn:pocketbase:params:oauth:token-type:launch_token", see [core.ApplicationLaunchClaims])
// for a staff online access token.
//
// The client must be the managed client of the installation of the launch token (aud) and:
//   - the launch token is verified (signature/kid with the issuer JWKS, typ, iss, exp) and single use (jti)
//   - the installation must be active
//   - the staff dashboard session (sid) and its root SSO session must be active
//
// A new launch session is created (actor = the staff member, client = the managed client,
// parent = the staff root SSO session so that the staff logout ends it, the launch token jti
// stored with a unique index, no refresh token, expiration bounded by the root session).
// The scopes are derived from the effective staff permissions ∩ installation grant
// (the optional "scope" could only narrow them).
//
// No refresh or id tokens are issued.
func oauth2TokenExchangeLaunch(e *core.RequestEvent, collection *core.Collection, client *core.OAuth2Client, form oauth2TokenForm) error {
	if collection.Name != core.CollectionNameApplicationInstallations || !client.IsManaged() || !client.IsConfidential() {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrUnauthorizedClient, "The client is not allowed to use this subject_token_type.")
	}

	if form.ActorToken != "" || form.ActorTokenType != "" {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "The actor_token is not supported with the launch tokens.")
	}

	if form.RequestedTokenType != "" && form.RequestedTokenType != oauth2TokenTypeAccessToken {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Unsupported requested_token_type.")
	}

	invalidLaunchErr := oauth2InvalidGrantError("Invalid, expired or already used launch token.")

	claims, err := core.ParseApplicationLaunchToken(e.App, form.SubjectToken)
	if err != nil {
		return invalidLaunchErr
	}

	// the launch token must be issued to the authenticated client and its installation
	if !security.Equal(claims.ClientId, client.ClientId()) || claims.InstallationId != client.ApplicationInstallationRef() {
		return invalidLaunchErr
	}

	installation, err := e.App.FindApplicationInstallationById(claims.InstallationId)
	if err != nil || !installation.IsActive() {
		return invalidLaunchErr
	}

	staff, err := e.App.FindRecordById(core.CollectionNameSuperusers, claims.StaffId)
	if err != nil {
		return invalidLaunchErr
	}

	// the staff dashboard session (and its root SSO session) must be still active
	staffSession, err := e.App.FindAuthSessionById(claims.StaffSessionId)
	if err != nil ||
		!staffSession.IsActive() ||
		staffSession.HasExpired() ||
		staffSession.IsRoot() ||
		staffSession.Impersonator() != "" ||
		staffSession.RecordRef() != staff.Id ||
		staffSession.CollectionRef() != staff.Collection().Id ||
		staffSession.Parent() == "" {
		return invalidLaunchErr
	}

	root, err := e.App.FindAuthSessionById(staffSession.Parent())
	if err != nil ||
		!root.IsRoot() ||
		!root.IsActive() ||
		root.HasExpired() ||
		root.RecordRef() != staff.Id ||
		root.CollectionRef() != staff.Collection().Id {
		return invalidLaunchErr
	}

	// single use (also guaranteed by the launchJti unique index on save)
	if total, err := e.App.CountRecords(core.CollectionNameAuthSessions, dbx.HashExp{"launchJti": claims.Jti}); err != nil || total > 0 {
		return invalidLaunchErr
	}

	scopes, err := core.ApplicationOnBehalfOfScopes(e.App, staff, installation)
	if err != nil {
		return invalidLaunchErr
	}

	if requested := list.ToUniqueStringSlice(strings.Fields(form.Scope)); len(requested) > 0 {
		for _, s := range requested {
			if !slices.Contains(scopes, s) {
				return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidScope, "The scope "+s+" is not allowed for the staff member and the application installation.")
			}
		}
		scopes = requested
	}

	now := types.NowDateTime()

	expiresAt := now.Add(staff.Collection().AuthToken.DurationTime())
	if root.ExpiresAt().Time().Before(expiresAt.Time()) {
		expiresAt = root.ExpiresAt()
	}

	session := core.NewAuthSession(e.App)
	session.Set("status", core.AuthSessionStatusActive)
	session.SetCollectionRef(staff.Collection().Id)
	session.SetClient(client.Id)
	session.SetRecordRef(staff.Id)
	session.SetParent(root.Id)
	session.SetLaunchJti(claims.Jti)
	session.SetScopesRequested(scopes)
	session.SetScopes(scopes)
	session.SetAuthMethods([]core.AuthSessionMethod{{Method: core.AuthSessionMethodLaunch, Time: now}})
	session.SetAuthTime(root.AuthTime())
	session.SetIP(e.RealIP())
	session.SetUserAgent(e.Request.UserAgent())
	session.SetLastUsedAt(now)
	session.SetExpiresAt(expiresAt)

	event := new(core.OAuth2TokenRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.GrantType = oauth2GrantTypeTokenExchange
	event.Client = client
	event.Record = staff
	event.Session = session
	event.Scopes = scopes
	event.IdTokenClaims = map[string]any{}

	return e.App.OnOAuth2TokenRequest().Trigger(event, func(e *core.OAuth2TokenRequestEvent) error {
		// note: a concurrent exchange of the same launch token fails on the launchJti unique index
		if err := e.App.Save(e.Session); err != nil {
			return invalidLaunchErr
		}

		return oauth2WriteTokenResponse(e, "", "")
	})
}

// oauth2TokenClientCredentials handles the client_credentials grant (RFC 6749 section 4.4)
// of the application installations managed clients.
//
// The client must be the managed client of an existing installation (only the
// _applicationInstallations issuer) and the optional "scope" could only narrow
// the scopes derived from the installation grant (the default is the full grant).
//
// A new root-less active auth session (method client_credentials, actor = installation,
// no refresh token) is created for each access token. No refresh or id tokens are issued.
func oauth2TokenClientCredentials(e *core.RequestEvent, collection *core.Collection, client *core.OAuth2Client, form oauth2TokenForm) error {
	unauthorizedErr := newOAuth2Error(http.StatusBadRequest, oauth2ErrUnauthorizedClient, "The client is not allowed to use this grant_type.")

	if collection.Name != core.CollectionNameApplicationInstallations || !client.IsManaged() || !client.IsConfidential() {
		return unauthorizedErr
	}

	installation, err := e.App.FindApplicationInstallationById(client.ApplicationInstallationRef())
	if err != nil || installation.Collection().Id != collection.Id {
		return unauthorizedErr
	}

	// the pending installations (not acknowledged install notification) can't obtain tokens
	if !installation.IsActive() {
		return newOAuth2Error(http.StatusBadRequest, oauth2ErrUnauthorizedClient, "The application installation is not active.")
	}

	scopes := core.ApplicationGrantScopes(e.App, installation.Permissions())

	if requested := list.ToUniqueStringSlice(strings.Fields(form.Scope)); len(requested) > 0 {
		for _, s := range requested {
			if !slices.Contains(scopes, s) {
				return newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidScope, "The scope "+s+" is not granted to the application installation.")
			}
		}
		scopes = requested
	}

	now := types.NowDateTime()

	session := core.NewAuthSession(e.App)
	session.Set("status", core.AuthSessionStatusActive)
	session.SetCollectionRef(collection.Id)
	session.SetClient(client.Id)
	session.SetRecordRef(installation.Id)
	session.SetScopesRequested(scopes)
	session.SetScopes(scopes)
	session.SetAuthMethods([]core.AuthSessionMethod{{Method: core.AuthSessionMethodClientCredentials, Time: now}})
	session.SetAuthTime(now)
	session.SetIP(e.RealIP())
	session.SetUserAgent(e.Request.UserAgent())
	session.SetLastUsedAt(now)
	session.SetExpiresAt(now.Add(collection.AuthToken.DurationTime()))

	event := new(core.OAuth2TokenRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.GrantType = oauth2GrantTypeClientCredentials
	event.Client = client
	event.Record = installation.Record
	event.Session = session
	event.Scopes = scopes
	event.IdTokenClaims = map[string]any{}

	return e.App.OnOAuth2TokenRequest().Trigger(event, func(e *core.OAuth2TokenRequestEvent) error {
		if err := e.App.Save(e.Session); err != nil {
			return err
		}

		return oauth2WriteTokenResponse(e, "", "")
	})
}

func oauth2WriteTokenResponse(e *core.OAuth2TokenRequestEvent, refreshToken string, nonce string) error {
	if err := e.Session.AttachActor(e.Record, e.Client); err != nil {
		return err
	}

	accessToken, err := e.Session.NewAccessToken()
	if err != nil {
		return err
	}

	scopes := e.Session.Scopes()

	result := oauth2TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		// note: the access token duration of the actor collection
		// (it differs from the issuer collection only for the online tokens)
		ExpiresIn:    e.Record.Collection().AuthToken.Duration,
		Scope:        strings.Join(scopes, " "),
		RefreshToken: refreshToken,
	}

	if e.GrantType == oauth2GrantTypeTokenExchange {
		result.IssuedTokenType = oauth2TokenTypeAccessToken

		if e.Session.IsLaunch() {
			result.AssociatedUser = &oauth2AssociatedUser{Id: e.Record.Id, Roles: []string{}}
			roles, err := e.App.FindRecordRoles(e.Record)
			if err != nil {
				return err
			}
			for _, r := range roles {
				result.AssociatedUser.Roles = append(result.AssociatedUser.Roles, r.Name())
			}
		}
	} else if e.GrantType != oauth2GrantTypeClientCredentials && slices.Contains(scopes, core.OAuth2ScopeOpenId) {
		result.IdToken, err = e.Record.NewOIDCIdToken(core.OIDCIdTokenOptions{
			Issuer:      core.OAuth2Issuer(e.App, e.Collection),
			Client:      e.Client,
			Session:     e.Session,
			Scopes:      scopes,
			Nonce:       nonce,
			AuthTime:    e.Session.AuthTime(),
			ExtraClaims: e.IdTokenClaims,
		})
		if err != nil {
			return err
		}
	}

	setOAuth2NoStoreHeaders(e.RequestEvent)

	return e.JSON(http.StatusOK, result)
}

func newOAuth2RefreshToken() string {
	return security.RandomString(64)
}

// oauth2EndSession ends the provided auth session (and its children) because of a detected security issue.
func oauth2EndSession(app core.App, session *core.AuthSession, reason string) {
	if err := app.EndAuthSession(session, "OAuth2 "+reason); err != nil {
		app.Logger().Error("Failed to end the OAuth2 auth session", "error", err, "sessionId", session.Id)
	}
}
