package apis

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/security"
)

// OAuth2 server (aka. OpenID Connect provider) cookie names.
//
// All cookies are HttpOnly and scoped to the issuer path (/oauth2/{collection}).
const (
	// oauth2ServerSSOCookie stores the root SSO session reference
	// in the format "{rootSessionId}.{ssoSecret}" (only the secret hash is stored in the session).
	oauth2ServerSSOCookie = "pb_session"

	// oauth2ServerBindingCookiePrefix is the prefix of the per flow browser
	// binding cookie (the full name is the prefix + the auth session id).
	oauth2ServerBindingCookiePrefix = "pb_binding_"

	// oauth2ServerCSRFCookie stores the double-submit CSRF token
	// used by all hosted pages forms.
	oauth2ServerCSRFCookie = "pb_oauth2_csrf"
)

// Standard OAuth2 error codes (RFC 6749, RFC 7009, RFC 6750 and OpenID Connect Core).
const (
	oauth2ErrInvalidRequest          = "invalid_request"
	oauth2ErrInvalidClient           = "invalid_client"
	oauth2ErrInvalidGrant            = "invalid_grant"
	oauth2ErrInvalidScope            = "invalid_scope"
	oauth2ErrInvalidToken            = "invalid_token"
	oauth2ErrInsufficientScope       = "insufficient_scope"
	oauth2ErrUnauthorizedClient      = "unauthorized_client"
	oauth2ErrUnsupportedGrantType    = "unsupported_grant_type"
	oauth2ErrUnsupportedResponseType = "unsupported_response_type"
	oauth2ErrAccessDenied            = "access_denied"
	oauth2ErrServerError             = "server_error"
	oauth2ErrLoginRequired           = "login_required"
	oauth2ErrInteractionRequired     = "interaction_required"
	oauth2ErrConsentRequired         = "consent_required"
	oauth2ErrRequestNotSupported     = "request_not_supported"
	oauth2ErrRequestURINotSupported  = "request_uri_not_supported"
)

// bindOAuth2ServerApi registers the OAuth2 server (aka. OpenID Connect provider) endpoints.
//
// Every auth collection acts as separate issuer served under
// /oauth2/{collectionName} (see [core.OAuth2Issuer]).
func bindOAuth2ServerApi(app core.App, r *router.Router[*core.RequestEvent]) {
	// root discovery documents (for the Settings.OAuth2Server.DefaultCollection issuer)
	r.GET("/.well-known/openid-configuration", oauth2ServerRootDiscovery)
	r.GET("/.well-known/oauth-authorization-server", oauth2ServerRootDiscovery)
	r.GET("/.well-known/oauth-protected-resource", oauth2ServerProtectedResource)

	// upstream OAuth2 providers callback of the hosted login flows
	// (registered at the providers; GET + POST for response_mode=form_post)
	r.GET("/api/oauth2-redirect", oauth2ServerUpstreamRedirect).Bind(
		SkipSuccessActivityLog(), // skip success log as it could contain sensitive information in the url
	)
	r.POST("/api/oauth2-redirect", oauth2ServerUpstreamRedirect).Bind(
		SkipSuccessActivityLog(), // skip success log as it could contain sensitive information in the url
	)

	sub := r.Group("/oauth2/{collection}")
	sub.Bind(oauth2ApplicationsIssuerGuard())

	sub.GET("/.well-known/openid-configuration", oauth2ServerDiscovery)
	sub.GET("/.well-known/oauth-authorization-server", oauth2ServerDiscovery)
	sub.GET("/jwks.json", oauth2ServerJWKS)

	sub.GET("/authorize", oauth2ServerAuthorize).Bind(
		collectionPathRateLimit("", "oauth2Authorize"),
	)
	sub.POST("/authorize", oauth2ServerAuthorize).Bind(
		collectionPathRateLimit("", "oauth2Authorize"),
	)

	// hosted login steps
	sub.GET("/login", oauth2ServerLoginPage).Bind(
		collectionPathRateLimit("", "oauth2Login"),
	)
	sub.GET("/login/continue", oauth2ServerLoginContinue).Bind(
		collectionPathRateLimit("", "oauth2Login"),
	)
	sub.GET("/login/mfa", oauth2ServerLoginMFAPage).Bind(
		collectionPathRateLimit("", "oauth2Login"),
	)
	sub.POST("/login/password", oauth2ServerLoginPassword).Bind(
		collectionPathRateLimit("", "oauth2LoginPassword", "auth"),
	)
	sub.POST("/login/otp", oauth2ServerLoginOTPRequest).Bind(
		collectionPathRateLimit("", "oauth2LoginOTP"),
	)
	sub.POST("/login/otp/verify", oauth2ServerLoginOTPVerify).Bind(
		collectionPathRateLimit("", "oauth2LoginOTPVerify", "auth"),
	)
	sub.GET("/login/oauth2/{provider}", oauth2ServerLoginOAuth2).Bind(
		collectionPathRateLimit("", "oauth2LoginOAuth2", "auth"),
	)

	sub.GET("/signup", oauth2ServerSignupPage).Bind(
		collectionPathRateLimit("", "oauth2Signup"),
	)
	sub.POST("/signup", oauth2ServerSignupSubmit).Bind(
		collectionPathRateLimit("", "oauth2Signup", "create"),
	)

	sub.GET("/consent", oauth2ServerConsentPage).Bind(
		collectionPathRateLimit("", "oauth2Consent"),
	)
	sub.POST("/consent", oauth2ServerConsentSubmit).Bind(
		collectionPathRateLimit("", "oauth2Consent"),
	)

	// hosted account pages
	sub.GET("/password-reset", oauth2ServerPasswordResetPage).Bind(
		collectionPathRateLimit("", "oauth2PasswordReset"),
	)
	sub.POST("/password-reset", oauth2ServerPasswordResetSubmit).Bind(
		collectionPathRateLimit("", "oauth2PasswordReset"),
	)
	sub.GET("/password-reset/confirm", oauth2ServerPasswordResetConfirmPage).Bind(
		collectionPathRateLimit("", "oauth2PasswordResetConfirm"),
	)
	sub.POST("/password-reset/confirm", oauth2ServerPasswordResetConfirmSubmit).Bind(
		collectionPathRateLimit("", "oauth2PasswordResetConfirm"),
	)
	sub.GET("/verify-email", oauth2ServerVerifyEmailPage).Bind(
		collectionPathRateLimit("", "oauth2VerifyEmail"),
	)
	sub.POST("/verify-email", oauth2ServerVerifyEmailSubmit).Bind(
		collectionPathRateLimit("", "oauth2VerifyEmail"),
	)
	sub.GET("/verify-email/request", oauth2ServerVerifyEmailRequestPage).Bind(
		collectionPathRateLimit("", "oauth2VerifyEmailRequest"),
	)
	sub.POST("/verify-email/request", oauth2ServerVerifyEmailRequestSubmit).Bind(
		collectionPathRateLimit("", "oauth2VerifyEmailRequest"),
	)
	sub.GET("/email-change/confirm", oauth2ServerEmailChangeConfirmPage).Bind(
		collectionPathRateLimit("", "oauth2EmailChangeConfirm"),
	)
	sub.POST("/email-change/confirm", oauth2ServerEmailChangeConfirmSubmit).Bind(
		collectionPathRateLimit("", "oauth2EmailChangeConfirm"),
	)

	sub.POST("/token", oauth2ServerToken).Bind(
		collectionPathRateLimit("", "oauth2Token"),
	)

	sub.GET("/userinfo", oauth2ServerUserinfo).Bind(
		collectionPathRateLimit("", "oauth2Userinfo"),
	)
	sub.POST("/userinfo", oauth2ServerUserinfo).Bind(
		collectionPathRateLimit("", "oauth2Userinfo"),
	)

	sub.POST("/revoke", oauth2ServerRevoke).Bind(
		collectionPathRateLimit("", "oauth2Revoke"),
	)

	sub.POST("/introspect", oauth2ServerIntrospect).Bind(
		collectionPathRateLimit("", "oauth2Introspect"),
	)

	sub.GET("/logout", oauth2ServerLogout).Bind(
		collectionPathRateLimit("", "oauth2Logout"),
	)
	sub.POST("/logout", oauth2ServerLogout).Bind(
		collectionPathRateLimit("", "oauth2Logout"),
	)

	// superuser only management endpoints (client secret, keys rotation)
	bindOAuth2ServerManagementApi(app, r)

}

// oauth2ApplicationsIssuerAllowedRoutes is the list of the issuer routes (relative to
// /oauth2/{collection}) available for the _applicationInstallations issuer.
var oauth2ApplicationsIssuerAllowedRoutes = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/jwks.json",
	"/token",
	"/revoke",
	"/introspect",
}

// oauth2ApplicationsIssuerGuard rejects the hosted pages and the interactive flow endpoints
// (authorize, login, signup, consent, account pages, userinfo, logout) of the
// _applicationInstallations issuer (the installations authenticate only with the
// client_credentials grant of their managed OAuth2 client).
func oauth2ApplicationsIssuerGuard() *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Func: func(e *core.RequestEvent) error {
			if e.Request.PathValue("collection") != core.CollectionNameApplicationInstallations {
				return e.Next()
			}

			_, route, _ := strings.Cut(e.Request.Pattern, "/oauth2/{collection}")
			if !slices.Contains(oauth2ApplicationsIssuerAllowedRoutes, route) {
				return e.NotFoundError("The application installations issuer supports only the client_credentials token endpoint.", nil)
			}

			return e.Next()
		},
	}
}

// findOAuth2ServerCollection returns the issuer auth collection from the "collection" path parameter.
//
// Note that the collection is matched only by its name (aka. the issuer path segment).
func findOAuth2ServerCollection(e *core.RequestEvent) (*core.Collection, error) {
	name := e.Request.PathValue("collection")

	collection, err := e.App.FindCachedCollectionByNameOrId(name)
	if err != nil || collection.Name != name || !collection.IsAuth() {
		return nil, e.NotFoundError("Missing or invalid OAuth2 server collection.", err)
	}

	return collection, nil
}

// findOAuth2ServerDefaultCollection returns the auth collection
// configured as Settings.OAuth2Server.DefaultCollection.
func findOAuth2ServerDefaultCollection(e *core.RequestEvent) (*core.Collection, error) {
	nameOrId := e.App.Settings().OAuth2Server.DefaultCollection
	if nameOrId == "" {
		return nil, e.NotFoundError("", errors.New("missing default OAuth2 server collection"))
	}

	collection, err := e.App.FindCachedCollectionByNameOrId(nameOrId)
	if err != nil || !collection.IsAuth() {
		return nil, e.NotFoundError("", err)
	}

	return collection, nil
}

// oauth2AllowsRedirectURI reports whether the provided uri is an allowed client redirect URI
// in the context of the current request (see [core.OAuth2Client.AllowsRedirectURI]).
func oauth2AllowsRedirectURI(e *core.RequestEvent, client *core.OAuth2Client, uri string) bool {
	return client.AllowsRedirectURI(uri, e.App.Settings().Meta.AppURL, e.RequestOrigin())
}

// oauth2PagesURL returns the base URL of the collection issuer hosted pages
// used for the browser navigations within a flow (step redirects, form actions and links).
//
// It is the same-origin issuer path (without the AppURL scheme and host)
// so that the browser stays on the host of the authorization request
// and the flow binding cookies work even when the AppURL is empty or differs
// from the request host (e.g. the default dashboard setup).
//
// Note that the issuer identifier ("iss" claim and parameter) is still [core.OAuth2Issuer].
func oauth2PagesURL(app core.App, collection *core.Collection) string {
	return oauth2IssuerPath(app, collection)
}

// oauth2IssuerPath returns the URL path of the collection issuer
// (it is used as cookies path).
func oauth2IssuerPath(app core.App, collection *core.Collection) string {
	u, err := url.Parse(core.OAuth2Issuer(app, collection))
	if err != nil || u.Path == "" {
		return "/oauth2/" + url.PathEscape(collection.Name)
	}

	return u.EscapedPath()
}

// -------------------------------------------------------------------
// OAuth2 errors
// -------------------------------------------------------------------

// oauth2Error defines an OAuth2 protocol error.
type oauth2Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`

	// status is the HTTP status code used for the JSON responses.
	status int

	// redirectable indicates whether the error could be sent
	// back to the client redirect_uri (authorization endpoint only).
	redirectable bool
}

func (err *oauth2Error) Error() string {
	if err.Description != "" {
		return err.Code + ": " + err.Description
	}
	return err.Code
}

func newOAuth2Error(status int, code string, description string) *oauth2Error {
	return &oauth2Error{status: status, Code: code, Description: description}
}

// toOAuth2Error converts an arbitrary error (e.g. returned from a hook handler)
// into an OAuth2 protocol error.
func toOAuth2Error(err error, fallbackCode string) *oauth2Error {
	var oerr *oauth2Error
	if errors.As(err, &oerr) {
		return oerr
	}

	var apiErr *router.ApiError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.Status >= 500:
			return newOAuth2Error(http.StatusInternalServerError, oauth2ErrServerError, "")
		case apiErr.Status == http.StatusUnauthorized:
			return newOAuth2Error(http.StatusUnauthorized, oauth2ErrInvalidClient, apiErr.Message)
		default:
			return newOAuth2Error(http.StatusBadRequest, fallbackCode, apiErr.Message)
		}
	}

	return newOAuth2Error(http.StatusInternalServerError, oauth2ErrServerError, "")
}

// oauth2JSONError writes an OAuth2 JSON error response
// (RFC 6749 section 5.2) instead of the default PocketBase ApiError shape.
func oauth2JSONError(e *core.RequestEvent, err error) error {
	oerr := toOAuth2Error(err, oauth2ErrInvalidRequest)
	if oerr.Code == oauth2ErrServerError {
		e.App.Logger().Error("OAuth2 server error", "error", err, "url", e.Request.URL.Path)
	}

	status := oerr.status
	if status == 0 {
		status = http.StatusBadRequest
	}

	if status == http.StatusUnauthorized && oerr.Code == oauth2ErrInvalidClient {
		e.Response.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
	}

	setOAuth2NoStoreHeaders(e)

	return e.JSON(status, oerr)
}

func setOAuth2NoStoreHeaders(e *core.RequestEvent) {
	e.Response.Header().Set("Cache-Control", "no-store")
	e.Response.Header().Set("Pragma", "no-cache")
}

// -------------------------------------------------------------------
// Request body
// -------------------------------------------------------------------

// oauth2BindBody binds the request body into dst similar to [core.RequestEvent.BindBody]
// but the form submissions are read ONLY from the request body (aka. the URL query
// parameters are ignored) so that credentials, codes, tokens and passwords
// are never accepted from the URL (RFC 6749 section 2.3.1 and 3.2).
func oauth2BindBody(e *core.RequestEvent, dst any) error {
	contentType := e.Request.Header.Get("Content-Type")

	switch {
	case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
		if err := e.Request.ParseForm(); err != nil {
			return err
		}
	case strings.HasPrefix(contentType, "multipart/form-data"):
		if err := e.Request.ParseMultipartForm(router.DefaultMaxMemory); err != nil {
			return err
		}
	default:
		return e.BindBody(dst)
	}

	return router.UnmarshalRequestData(e.Request.PostForm, dst, "", "")
}

// -------------------------------------------------------------------
// Client authentication
// -------------------------------------------------------------------

// oauth2ClientCredentials holds the submitted client authentication data.
type oauth2ClientCredentials struct {
	ClientId     string `form:"client_id" json:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret"`
}

// oauth2RequestClientId returns the client_id of the current token request
// (from the basic auth header or the submitted credentials).
func oauth2RequestClientId(e *core.RequestEvent, creds oauth2ClientCredentials) string {
	if basicId, _, ok := e.Request.BasicAuth(); ok {
		id, _ := url.QueryUnescape(basicId)
		return id
	}

	return creds.ClientId
}

// oauth2AuthenticateClient authenticates the OAuth2 client of the current
// token/revoke/introspect request using one of the supported
// token_endpoint_auth_methods (none, client_secret_basic, client_secret_post).
func oauth2AuthenticateClient(e *core.RequestEvent, collection *core.Collection, creds oauth2ClientCredentials) (*core.OAuth2Client, error) {
	clientId := creds.ClientId
	clientSecret := creds.ClientSecret

	if basicId, basicSecret, ok := e.Request.BasicAuth(); ok {
		// using more than one authentication method is not allowed (RFC 6749 section 2.3)
		if clientSecret != "" {
			return nil, newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Multiple client authentication methods are not allowed.")
		}

		// the credentials are form-urlencoded (RFC 6749 section 2.3.1)
		basicId, _ = url.QueryUnescape(basicId)
		basicSecret, _ = url.QueryUnescape(basicSecret)

		if clientId != "" && clientId != basicId {
			return nil, newOAuth2Error(http.StatusUnauthorized, oauth2ErrInvalidClient, "Mismatched client_id.")
		}

		clientId = basicId
		clientSecret = basicSecret
	}

	invalidClientErr := newOAuth2Error(http.StatusUnauthorized, oauth2ErrInvalidClient, "Client authentication failed.")

	if clientId == "" {
		return nil, invalidClientErr
	}

	client, err := e.App.FindOAuth2ClientByClientId(clientId)
	if err != nil || client.Disabled() || client.CollectionRef() != collection.Id {
		return nil, invalidClientErr
	}

	if client.IsConfidential() {
		if !client.ValidateClientSecret(clientSecret) {
			return nil, invalidClientErr
		}
	} else if clientSecret != "" {
		// public clients are not issued with secrets
		return nil, invalidClientErr
	}

	return client, nil
}

// -------------------------------------------------------------------
// Cookies
// -------------------------------------------------------------------

// setOAuth2Cookie sets a HttpOnly issuer path scoped cookie
// (maxAge < 0 removes the cookie).
func setOAuth2Cookie(e *core.RequestEvent, collection *core.Collection, name string, value string, maxAge int, sameSite http.SameSite) {
	if maxAge < 0 {
		value = ""
	}

	e.SetCookie(&http.Cookie{
		Name:     name,
		Value:    value,
		Path:     oauth2IssuerPath(e.App, collection),
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   oauth2SecureCookies(e, collection),
		SameSite: sameSite,
	})
}

func oauth2SecureCookies(e *core.RequestEvent, collection *core.Collection) bool {
	return e.IsTLS() || strings.HasPrefix(core.OAuth2Issuer(e.App, collection), "https://")
}

// -------------------------------------------------------------------
// CSRF protection (hosted pages forms)
// -------------------------------------------------------------------

const oauth2CSRFTokenLength = 32

// oauth2CSRFToken returns the current CSRF token from the CSRF cookie
// or generates a new one (double-submit cookie pattern).
func oauth2CSRFToken(e *core.RequestEvent, collection *core.Collection) string {
	cookie, err := e.Request.Cookie(oauth2ServerCSRFCookie)
	if err == nil && len(cookie.Value) == oauth2CSRFTokenLength {
		return cookie.Value
	}

	token := security.RandomString(oauth2CSRFTokenLength)

	e.SetCookie(&http.Cookie{
		Name:     oauth2ServerCSRFCookie,
		Value:    token,
		Path:     oauth2IssuerPath(e.App, collection),
		HttpOnly: true,
		Secure:   oauth2SecureCookies(e, collection),
		SameSite: http.SameSiteStrictMode,
	})

	return token
}

// checkOAuth2FormRequest performs CSRF checks for the hosted pages form submissions:
//   - the request must not be cross-site (Sec-Fetch-Site, Origin and Referer headers checks)
//   - the submitted csrf value must match with the CSRF cookie
func checkOAuth2FormRequest(e *core.RequestEvent, submittedCSRF string) error {
	invalidErr := errors.New("invalid or expired form submission, please go back and try again")

	if site := e.Request.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return invalidErr
	}

	allowedOrigins := oauth2AllowedOrigins(e)

	if origin := e.Request.Header.Get("Origin"); origin != "" {
		if !slices.Contains(allowedOrigins, strings.ToLower(origin)) {
			return invalidErr
		}
	} else if referer := e.Request.Header.Get("Referer"); referer != "" {
		u, err := url.Parse(referer)
		if err != nil || !slices.Contains(allowedOrigins, strings.ToLower(u.Scheme+"://"+u.Host)) {
			return invalidErr
		}
	}

	cookie, err := e.Request.Cookie(oauth2ServerCSRFCookie)
	if err != nil || len(cookie.Value) != oauth2CSRFTokenLength || !security.Equal(cookie.Value, submittedCSRF) {
		return invalidErr
	}

	return nil
}

// oauth2AllowedOrigins returns the list of the allowed hosted pages origins
// (the Settings.Meta.AppURL origin and the current request host).
func oauth2AllowedOrigins(e *core.RequestEvent) []string {
	result := make([]string, 0, 2)

	if u, err := url.Parse(e.App.Settings().Meta.AppURL); err == nil && u.Host != "" {
		result = append(result, strings.ToLower(u.Scheme+"://"+u.Host))
	}

	// the scheme of the current request host is not checked because
	// the app could be behind a TLS terminating proxy
	// (the Origin header cannot be forged by a cross-site browser request anyway)
	host := strings.ToLower(e.Request.Host)
	result = append(result, "https://"+host, "http://"+host)

	return result
}
