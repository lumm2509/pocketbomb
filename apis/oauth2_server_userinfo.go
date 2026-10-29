package apis

import (
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/security"
)

// oauth2AccessToken holds the data of a verified OAuth2 server access token.
type oauth2AccessToken struct {
	Record    *core.Record
	Claims    jwt.MapClaims
	ClientId  string
	SessionId string
	Scopes    []string
}

// loadOAuth2AccessToken verifies the provided OAuth2 server access token
// and checks whether it was issued by the specified issuer collection
// (both the token actor and the token client must belong to the issuer).
//
// The token is verified with [core.App.FindAuthRecordByToken] which
// also checks whether the token auth session is still active.
func loadOAuth2AccessToken(app core.App, collection *core.Collection, token string) (*oauth2AccessToken, error) {
	result, err := loadOAuth2ClientAccessToken(app, collection, token)
	if err != nil {
		return nil, err
	}

	if result.Record.Collection().Id != collection.Id {
		return nil, errors.New("the access token is issued by another collection")
	}

	return result, nil
}

// loadOAuth2ClientAccessToken is similar to [loadOAuth2AccessToken] but only the token client must
// belong to the issuer collection (the actor could be of another collection, e.g. the staff actor
// of an application extension online token issued to an installation managed client).
//
// It is used by the token client own endpoints (introspection and revocation) where
// the authenticated client must be the token client.
func loadOAuth2ClientAccessToken(app core.App, collection *core.Collection, token string) (*oauth2AccessToken, error) {
	if token == "" {
		return nil, errors.New("missing access token")
	}

	record, err := app.FindAuthRecordByToken(token, core.TokenTypeAuth)
	if err != nil {
		return nil, err
	}

	// the signature is already verified by FindAuthRecordByToken
	claims, err := security.ParseUnverifiedJWT(token)
	if err != nil {
		return nil, err
	}

	result := &oauth2AccessToken{Record: record, Claims: claims}
	result.ClientId, _ = claims[core.TokenClaimOAuth2ClientId].(string)
	result.SessionId, _ = claims[core.TokenClaimOAuth2SessionId].(string)
	scope, _ := claims[core.TokenClaimOAuth2Scope].(string)
	result.Scopes = strings.Fields(scope)

	if result.ClientId == "" || result.SessionId == "" {
		return nil, errors.New("not an OAuth2 access token")
	}

	client, err := app.FindOAuth2ClientByClientId(result.ClientId)
	if err != nil || client.Disabled() || client.CollectionRef() != collection.Id {
		return nil, errors.New("missing or disabled OAuth2 client")
	}

	return result, nil
}

// oauth2BearerError writes a RFC 6750 bearer token error response.
func oauth2BearerError(e *core.RequestEvent, status int, code string, description string) error {
	e.Response.Header().Set(
		"WWW-Authenticate",
		`Bearer error="`+code+`", error_description="`+strings.ReplaceAll(description, `"`, `'`)+`"`,
	)

	return oauth2JSONError(e, newOAuth2Error(status, code, description))
}

// GET|POST {issuer}/userinfo (OpenID Connect Core section 5.3)
func oauth2ServerUserinfo(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	token := getAuthTokenFromRequest(e)

	// RFC 6750 section 2.2 (form-encoded body parameter)
	if token == "" && e.Request.Method == http.MethodPost &&
		strings.HasPrefix(e.Request.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		token = e.Request.PostFormValue("access_token")
	}

	accessToken, err := loadOAuth2AccessToken(e.App, collection, token)
	if err != nil {
		return oauth2BearerError(e, http.StatusUnauthorized, oauth2ErrInvalidToken, "Invalid or expired access token.")
	}

	hasOpenId := false
	for _, s := range accessToken.Scopes {
		if s == core.OAuth2ScopeOpenId {
			hasOpenId = true
			break
		}
	}
	if !hasOpenId {
		return oauth2BearerError(e, http.StatusForbidden, oauth2ErrInsufficientScope, "The access token doesn't have the openid scope.")
	}

	setOAuth2NoStoreHeaders(e)

	return e.JSON(http.StatusOK, accessToken.Record.OIDCStandardClaims(accessToken.Scopes))
}
