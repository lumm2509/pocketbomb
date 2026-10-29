package apis

import (
	"net/http"
	"strings"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/security"
)

// oauth2DiscoveryDocument defines the OpenID Connect Discovery 1.0
// and OAuth 2.0 Authorization Server Metadata (RFC 8414) document.
type oauth2DiscoveryDocument struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported  []string `json:"introspection_endpoint_auth_methods_supported"`
	IdTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	PromptValuesSupported                      []string `json:"prompt_values_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
}

const (
	oauth2GrantTypeAuthorizationCode = "authorization_code"
	oauth2GrantTypeRefreshToken      = "refresh_token"
	oauth2GrantTypeTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"

	// the application installations managed clients only (see oauth2TokenClientCredentials)
	oauth2GrantTypeClientCredentials = "client_credentials"
)

const (
	oauth2AuthMethodNone              = "none"
	oauth2AuthMethodClientSecretBasic = "client_secret_basic"
	oauth2AuthMethodClientSecretPost  = "client_secret_post"
)

var oauth2SupportedClaims = []string{
	"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "sid", "act",
	"email", "email_verified",
	"name", "preferred_username", "picture", "updated_at",
}

func newOAuth2DiscoveryDocument(app core.App, collection *core.Collection) *oauth2DiscoveryDocument {
	issuer := core.OAuth2Issuer(app, collection)

	algs := make([]string, 0, len(collection.OAuth2Server.SigningKeys))
	for _, k := range collection.OAuth2Server.SigningKeys {
		algs = append(algs, k.Alg)
	}
	algs = list.ToUniqueStringSlice(algs)
	if len(algs) == 0 {
		algs = []string{security.JWTAlgRS256}
	}

	grantTypes := []string{oauth2GrantTypeAuthorizationCode, oauth2GrantTypeRefreshToken, oauth2GrantTypeTokenExchange}
	if collection.Name == core.CollectionNameApplicationInstallations {
		// the application installations issuer supports only the client_credentials grant
		// and the token exchange of the extensions launch tokens (managed clients only)
		grantTypes = []string{oauth2GrantTypeClientCredentials, oauth2GrantTypeTokenExchange}
	}

	promptValues := []string{oauth2PromptNone, oauth2PromptLogin, oauth2PromptConsent}
	if oauth2SignupAllowed(collection) {
		promptValues = append(promptValues, oauth2PromptCreate)
	}

	return &oauth2DiscoveryDocument{
		Issuer:                                 issuer,
		AuthorizationEndpoint:                  issuer + "/authorize",
		TokenEndpoint:                          issuer + "/token",
		UserinfoEndpoint:                       issuer + "/userinfo",
		JWKSURI:                                issuer + "/jwks.json",
		RevocationEndpoint:                     issuer + "/revoke",
		IntrospectionEndpoint:                  issuer + "/introspect",
		EndSessionEndpoint:                     issuer + "/logout",
		ScopesSupported:                        core.OAuth2AllowedScopes(app, collection),
		ResponseTypesSupported:                 []string{"code"},
		ResponseModesSupported:                 []string{"query"},
		GrantTypesSupported:                    grantTypes,
		CodeChallengeMethodsSupported:          []string{"S256"},
		TokenEndpointAuthMethodsSupported:      []string{oauth2AuthMethodNone, oauth2AuthMethodClientSecretBasic, oauth2AuthMethodClientSecretPost},
		RevocationEndpointAuthMethodsSupported: []string{oauth2AuthMethodNone, oauth2AuthMethodClientSecretBasic, oauth2AuthMethodClientSecretPost},
		// introspection is allowed only for confidential clients
		IntrospectionEndpointAuthMethodsSupported:  []string{oauth2AuthMethodClientSecretBasic, oauth2AuthMethodClientSecretPost},
		IdTokenSigningAlgValuesSupported:           algs,
		SubjectTypesSupported:                      []string{"public"},
		ClaimsSupported:                            oauth2SupportedClaims,
		PromptValuesSupported:                      promptValues,
		AuthorizationResponseIssParameterSupported: true,
		ClaimsParameterSupported:                   false,
		RequestParameterSupported:                  false,
		RequestURIParameterSupported:               false,
	}
}

func setOAuth2PublicCacheHeaders(e *core.RequestEvent) {
	e.Response.Header().Set("Cache-Control", "public, max-age=300")
}

// GET {issuer}/.well-known/openid-configuration
// GET {issuer}/.well-known/oauth-authorization-server
func oauth2ServerDiscovery(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	setOAuth2PublicCacheHeaders(e)

	return e.JSON(http.StatusOK, newOAuth2DiscoveryDocument(e.App, collection))
}

// GET /.well-known/openid-configuration
// GET /.well-known/oauth-authorization-server
func oauth2ServerRootDiscovery(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerDefaultCollection(e)
	if err != nil {
		return err
	}

	setOAuth2PublicCacheHeaders(e)

	return e.JSON(http.StatusOK, newOAuth2DiscoveryDocument(e.App, collection))
}

// GET /.well-known/oauth-protected-resource (RFC 9728)
func oauth2ServerProtectedResource(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerDefaultCollection(e)
	if err != nil {
		return err
	}

	setOAuth2PublicCacheHeaders(e)

	return e.JSON(http.StatusOK, map[string]any{
		"resource":                 strings.TrimRight(e.App.Settings().Meta.AppURL, "/"),
		"resource_name":            e.App.Settings().Meta.AppName,
		"authorization_servers":    []string{core.OAuth2Issuer(e.App, collection)},
		"scopes_supported":         core.OAuth2AllowedScopes(e.App, collection),
		"bearer_methods_supported": []string{"header"},
	})
}

// GET {issuer}/jwks.json
func oauth2ServerJWKS(e *core.RequestEvent) error {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return err
	}

	jwks, err := collection.OAuth2Server.JWKS()
	if err != nil {
		return e.InternalServerError("Failed to load the signing keys.", err)
	}

	setOAuth2PublicCacheHeaders(e)

	return e.JSON(http.StatusOK, jwks)
}
