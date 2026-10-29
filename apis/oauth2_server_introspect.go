package apis

import (
	"net/http"
	"strings"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/security"
)

// POST {issuer}/introspect (RFC 7662)
//
// Only confidential clients of the same issuer are allowed to introspect tokens
// and only their own tokens (the tokens of the other clients are reported as inactive).
func oauth2ServerIntrospect(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	form := oauth2TokenRevokeForm{}
	if err := oauth2BindBody(e, &form); err != nil {
		return oauth2JSONError(e, newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Failed to read the request body."))
	}

	client, err := oauth2AuthenticateClient(e, collection, form.oauth2ClientCredentials)
	if err != nil {
		return oauth2JSONError(e, err)
	}

	if !client.IsConfidential() {
		return oauth2JSONError(e, newOAuth2Error(http.StatusUnauthorized, oauth2ErrInvalidClient, "Only confidential clients are allowed to introspect tokens."))
	}

	if form.Token == "" {
		return oauth2JSONError(e, newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Missing token parameter."))
	}

	setOAuth2NoStoreHeaders(e)

	inactive := map[string]any{"active": false}

	session, accessToken := findOAuth2TokenSession(e.App, collection, form.Token, form.TokenTypeHint)
	if session == nil || !session.IsActive() {
		return e.JSON(http.StatusOK, inactive)
	}

	// a client could introspect only its own tokens
	// (aka. the token cid must match the authenticated client)
	if session.Client() != client.Id ||
		(accessToken != nil && !security.Equal(accessToken.ClientId, client.ClientId())) {
		return e.JSON(http.StatusOK, inactive)
	}

	sessionClient, err := e.App.FindOAuth2ClientById(session.Client())
	if err != nil || sessionClient.Disabled() {
		return e.JSON(http.StatusOK, inactive)
	}

	result := map[string]any{
		"active":    true,
		"client_id": sessionClient.ClientId(),
		"sub":       session.RecordRef(),
		"aud":       sessionClient.ClientId(),
		"iss":       core.OAuth2Issuer(e.App, collection),
		"sid":       session.Id,
	}

	if impersonator := session.Impersonator(); impersonator != "" {
		result["act"] = map[string]any{"sub": impersonator}
	}

	if accessToken != nil {
		result["token_type"] = "Bearer"
		result["scope"] = accessToken.Claims[core.TokenClaimOAuth2Scope]
		if exp, err := accessToken.Claims.GetExpirationTime(); err == nil && exp != nil {
			result["exp"] = exp.Unix()
		}
	} else {
		result["token_type"] = oauth2TokenTypeHintRefreshToken
		result["scope"] = strings.Join(session.Scopes(), " ")
		if !session.RefreshExpiresAt().IsZero() {
			result["exp"] = session.RefreshExpiresAt().Time().Unix()
		}
	}

	return e.JSON(http.StatusOK, result)
}
