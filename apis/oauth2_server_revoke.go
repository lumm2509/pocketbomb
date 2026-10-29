package apis

import (
	"net/http"

	"github.com/lumm2509/pocketbomb/core"
)

const (
	oauth2TokenTypeHintAccessToken  = "access_token"
	oauth2TokenTypeHintRefreshToken = "refresh_token"
)

type oauth2TokenRevokeForm struct {
	oauth2ClientCredentials

	Token         string `form:"token" json:"token"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint"`
}

// findOAuth2TokenSession finds the auth session of the provided access or refresh token.
//
// Returns nil if the token is invalid, expired, its session is not active or issued to a client of another
// issuer collection (the access token actor could be of another collection, e.g. an online token).
func findOAuth2TokenSession(app core.App, collection *core.Collection, token string, hint string) (*core.AuthSession, *oauth2AccessToken) {
	findByRefreshToken := func() *core.AuthSession {
		session, err := app.FindAuthSessionByRefreshToken(token)
		if err != nil ||
			session.CollectionRef() != collection.Id ||
			!session.IsActive() ||
			session.HasRefreshExpired() ||
			!app.IsAuthSessionRootAlive(session) {
			return nil
		}
		return session
	}

	findByAccessToken := func() (*core.AuthSession, *oauth2AccessToken) {
		// note: the session state is already checked by the token validation
		// note: the token client must belong to the issuer (the callers check that it is the authenticated client)
		accessToken, err := loadOAuth2ClientAccessToken(app, collection, token)
		if err != nil {
			return nil, nil
		}

		session, err := app.FindAuthSessionById(accessToken.SessionId)
		if err != nil {
			return nil, nil
		}

		return session, accessToken
	}

	// the hint is used only to determine the lookup order (RFC 7009 section 2.1)
	if hint == oauth2TokenTypeHintAccessToken {
		if session, accessToken := findByAccessToken(); session != nil {
			return session, accessToken
		}
		return findByRefreshToken(), nil
	}

	if session := findByRefreshToken(); session != nil {
		return session, nil
	}

	return findByAccessToken()
}

// POST {issuer}/revoke (RFC 7009)
//
// Revoking either the access or the refresh token ends the entire
// auth session (and therefore all access and refresh tokens issued within it).
func oauth2ServerRevoke(e *core.RequestEvent) error {
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

	if form.Token == "" {
		return oauth2JSONError(e, newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, "Missing token parameter."))
	}

	setOAuth2NoStoreHeaders(e)

	session, _ := findOAuth2TokenSession(e.App, collection, form.Token, form.TokenTypeHint)

	// invalid, already revoked or tokens issued to another client are silently ignored
	// (RFC 7009 section 2.2) to avoid leaking the token state to other clients
	if session == nil || session.Client() != client.Id {
		return e.NoContent(http.StatusOK)
	}

	event := new(core.OAuth2RevokeRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.Client = client
	event.Session = session
	event.TokenTypeHint = form.TokenTypeHint

	err = e.App.OnOAuth2RevokeRequest().Trigger(event, func(e *core.OAuth2RevokeRequestEvent) error {
		if !e.Session.IsTerminal() {
			if err := e.Session.End(); err != nil {
				return err
			}
			if err := e.App.Save(e.Session); err != nil {
				return err
			}
		}

		return e.NoContent(http.StatusOK)
	})
	if err != nil && !e.Written() {
		return oauth2JSONError(e, err)
	}

	return err
}
