package apis

import (
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/pages"
	"github.com/lumm2509/pocketbomb/tools/security"
)

type oauth2LogoutForm struct {
	IdTokenHint           string `form:"id_token_hint" json:"id_token_hint"`
	PostLogoutRedirectURI string `form:"post_logout_redirect_uri" json:"post_logout_redirect_uri"`
	State                 string `form:"state" json:"state"`
	ClientId              string `form:"client_id" json:"client_id"`
	CSRF                  string `form:"csrf" json:"csrf"`
}

// GET|POST {issuer}/logout (OpenID Connect RP-Initiated Logout 1.0)
//
// Ends the root SSO session (and its children without "offline_access"
// scope), clears the "pb_session" cookie and, if a valid id_token_hint
// is provided, also ends the auth session of the id_token "sid" claim.
//
// Without a valid id_token_hint the end-user is asked to confirm the logout
// (to prevent logout CSRF).
func oauth2ServerLogout(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	form := oauth2LogoutForm{}
	if e.Request.Method == http.MethodPost {
		if err := oauth2BindBody(e, &form); err != nil {
			return oauth2RenderInvalidFormPage(e, collection, err)
		}
	} else {
		query := e.Request.URL.Query()
		form.IdTokenHint = query.Get("id_token_hint")
		form.PostLogoutRedirectURI = query.Get("post_logout_redirect_uri")
		form.State = query.Get("state")
		form.ClientId = query.Get("client_id")
	}

	logoutErr := func(description string) error {
		return oauth2RenderErrorPage(e, collection, http.StatusBadRequest, newOAuth2Error(http.StatusBadRequest, oauth2ErrInvalidRequest, description))
	}

	issuer := core.OAuth2Issuer(e.App, collection)

	// verify the id_token_hint (expired tokens are allowed)
	var hintClaims jwt.MapClaims
	if form.IdTokenHint != "" {
		jwks, err := collection.OAuth2Server.JWKS()
		if err != nil {
			return e.InternalServerError("Failed to load the signing keys.", err)
		}

		claims, err := security.ParseSignedJWT(form.IdTokenHint, jwks, jwt.WithoutClaimsValidation())
		if err != nil || claims["iss"] != issuer {
			return logoutErr("Invalid id_token_hint.")
		}

		hintClaims = claims
	}

	// resolve the client
	clientId := form.ClientId
	if hintClaims != nil {
		aud, _ := hintClaims.GetAudience()
		if len(aud) != 1 || (clientId != "" && clientId != aud[0]) {
			return logoutErr("The id_token_hint audience doesn't match with the client_id.")
		}
		clientId = aud[0]
	}

	var client *core.OAuth2Client
	if clientId != "" {
		client, err = e.App.FindOAuth2ClientByClientId(clientId)
		if err != nil || client.Disabled() || client.CollectionRef() != collection.Id {
			return logoutErr("Unknown or disabled client.")
		}
	}

	if form.PostLogoutRedirectURI != "" && (client == nil || !client.AllowsPostLogoutRedirectURI(form.PostLogoutRedirectURI, e.App.Settings().Meta.AppURL, e.RequestOrigin())) {
		return logoutErr("The post_logout_redirect_uri is not registered for the client.")
	}

	root := loadOAuth2SSOSession(e, collection)

	// the logout is confirmed only by an id_token_hint of the current SSO actor
	// (an attacker could otherwise use an id_token of its own account to end
	// the victim's SSO session with a top-level cross-site navigation)
	confirmed := false
	if hintClaims != nil {
		sub, _ := hintClaims.GetSubject()
		confirmed = root == nil || (sub != "" && root.record.Id == sub)
	}

	// ask for confirmation
	if !confirmed {
		if e.Request.Method != http.MethodPost {
			params := map[string]string{}
			if form.IdTokenHint != "" {
				params["id_token_hint"] = form.IdTokenHint
			}
			if form.PostLogoutRedirectURI != "" {
				params["post_logout_redirect_uri"] = form.PostLogoutRedirectURI
			}
			if form.State != "" {
				params["state"] = form.State
			}
			if clientId != "" {
				params["client_id"] = clientId
			}

			return oauth2RenderPage(e, collection, http.StatusOK, "oauth2/message", pages.MessagePage{
				Heading:     "Sign out",
				Message:     "Do you want to sign out?",
				Action:      oauth2PagesURL(e.App, collection) + "/logout",
				ActionLabel: "Sign out",
				CSRF:        oauth2CSRFToken(e, collection),
				Params:      params,
			})
		}

		if err := checkOAuth2FormRequest(e, form.CSRF); err != nil {
			return oauth2RenderInvalidFormPage(e, collection, err)
		}
	}

	// end the root SSO session (the children are ended by the cascade)
	if root != nil {
		if err := root.session.End(); err == nil {
			if err := e.App.Save(root.session); err != nil {
				e.App.Logger().Warn("Failed to end the root SSO session on logout", "error", err, "sessionId", root.session.Id)
			}
		}
	}
	clearOAuth2SSOCookie(e, collection)

	// end the id_token_hint session
	if hintClaims != nil && client != nil {
		sid, _ := hintClaims["sid"].(string)
		sub, _ := hintClaims.GetSubject()
		if sid != "" {
			session, err := e.App.FindAuthSessionById(sid)
			if err == nil &&
				!session.IsTerminal() &&
				session.Client() == client.Id &&
				session.RecordRef() == sub &&
				session.CollectionRef() == collection.Id {
				if err := session.End(); err == nil {
					if err := e.App.Save(session); err != nil {
						e.App.Logger().Warn("Failed to end the auth session on logout", "error", err, "sessionId", session.Id)
					}
				}
			}
		}
	}

	if form.PostLogoutRedirectURI != "" {
		params := url.Values{}
		if form.State != "" {
			params.Set("state", form.State)
		}

		return e.Redirect(oauth2RedirectStatus(e), oauth2BuildRedirectURL(form.PostLogoutRedirectURI, params))
	}

	return oauth2RenderMessagePage(e, collection, http.StatusOK, "Signed out", "You have been signed out. You can close this window.")
}
