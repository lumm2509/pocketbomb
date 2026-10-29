package apis

import (
	"net/http"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/security"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// oauth2ClientSecretLength is the length of the generated OAuth2 client secrets
// (~297 bits of entropy with the default alphanumeric alphabet).
const oauth2ClientSecretLength = 50

// bindOAuth2ServerManagementApi registers the superuser only
// OAuth2 server (aka. OpenID Connect provider) management endpoints.
//
// Note that the clients and grants CRUD is handled by the regular
// records API (the system collections have superusers only rules).
func bindOAuth2ServerManagementApi(app core.App, r *router.Router[*core.RequestEvent]) {
	sub := r.Group("/api/oauth2")

	sub.POST("/clients/{id}/rotate-secret", oauth2ClientRotateSecret).Bind(
		RequirePermission(core.PermissionResourceOAuth2Clients, core.PermissionLevelWrite),
	)
	// note: the signing keys are part of the auth collection options
	sub.POST("/{collection}/keys/rotate", oauth2ServerRotateSigningKey).Bind(RequirePermission(
		core.PermissionResourceOAuth2Clients, core.PermissionLevelWrite,
		core.PermissionResourceCollections, core.PermissionLevelWrite,
	))

	bindOAuth2ClientAPIKeysApi(sub)

	// the internal secret fields are hidden by bindRecordAccessHooks,
	// return only whether the client has a secret
	app.OnRecordEnrich(core.CollectionNameOAuth2Clients).Bind(&hook.Handler[*core.RecordEnrichEvent]{
		Id: "__pbOAuth2ClientEnrich__",
		Func: func(e *core.RecordEnrichEvent) error {
			if e.RequestInfo != nil && e.RequestInfo.Can(e.App, core.PermissionResourceOAuth2Clients, core.PermissionLevelRead) {
				e.Record.WithCustomData(true)
				e.Record.Set("hasClientSecret", e.Record.GetString("clientSecretHash") != "")
			}

			return e.Next()
		},
	})

	// return only whether the session is a root SSO session
	app.OnRecordEnrich(core.CollectionNameAuthSessions).Bind(&hook.Handler[*core.RecordEnrichEvent]{
		Id: "__pbAuthSessionEnrich__",
		Func: func(e *core.RecordEnrichEvent) error {
			e.Record.WithCustomData(true)
			e.Record.Set("sso", e.Record.GetString("ssoSecretHash") != "")

			return e.Next()
		},
	})
}

type oauth2ClientSecretResponse struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// POST /api/oauth2/clients/{id}/rotate-secret
//
// Generates a new client secret for the specified confidential client
// and replaces the old one (if any).
//
// The plain secret is returned only once (only its hash is stored).
func oauth2ClientRotateSecret(e *core.RequestEvent) error {
	client, err := e.App.FindOAuth2ClientById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("Missing or invalid OAuth2 client.", err)
	}

	// the clients of the _superusers issuer are Owner only
	if err := core.CheckOAuth2ClientChange(e.App, e.ActorInfo(), client.Record); err != nil {
		return e.ForbiddenError("Only the Owners could manage the _superusers OAuth2 clients.", err)
	}

	if !client.IsConfidential() {
		return e.BadRequestError("Only confidential clients can have a client secret.", nil)
	}

	secret := security.RandomString(oauth2ClientSecretLength)

	client.SetClientSecret(secret)

	if err := e.App.Save(client); err != nil {
		return e.BadRequestError("Failed to save the OAuth2 client secret.", err)
	}

	return e.JSON(http.StatusOK, oauth2ClientSecretResponse{
		ClientId:     client.ClientId(),
		ClientSecret: secret,
	})
}

type oauth2RotateSigningKeyForm struct {
	Alg string `form:"alg" json:"alg"`
}

func (form *oauth2RotateSigningKeyForm) validate() error {
	return validation.ValidateStruct(form,
		validation.Field(&form.Alg, validation.In(security.JWTAlgRS256, security.JWTAlgES256)),
	)
}

// POST /api/oauth2/{collection}/keys/rotate
//
// Generates a new active signing key for the specified auth collection OAuth2 server
// and marks the existing keys as inactive (they are still published in the JWKS
// so that the previously issued tokens could be verified).
//
// Returns the updated (redacted) collection.
func oauth2ServerRotateSigningKey(e *core.RequestEvent) error {
	collection, err := e.App.FindCollectionByNameOrId(e.Request.PathValue("collection"))
	if err != nil || !collection.IsAuth() {
		return e.NotFoundError("Missing or invalid auth collection.", err)
	}

	form := &oauth2RotateSigningKeyForm{}
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}
	if err := form.validate(); err != nil {
		return e.BadRequestError("An error occurred while validating the submitted data.", err)
	}

	alg := form.Alg
	if alg == "" {
		alg = security.JWTAlgRS256
	}

	key, err := core.NewOAuth2SigningKey(alg)
	if err != nil {
		return e.InternalServerError("Failed to generate a new signing key.", err)
	}

	for i := range collection.OAuth2Server.SigningKeys {
		collection.OAuth2Server.SigningKeys[i].Active = false
	}
	collection.OAuth2Server.SigningKeys = append(collection.OAuth2Server.SigningKeys, key)

	if err := e.App.Save(collection); err != nil {
		return e.BadRequestError("Failed to rotate the signing key.", err)
	}

	return e.JSON(http.StatusOK, collection)
}
