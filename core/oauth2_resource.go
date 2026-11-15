package core

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/tools/security"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// OAuth2ResourceAccessTokenType is the explicit "typ" header of the resource access tokens
// (JWT Profile for OAuth 2.0 Access Tokens, RFC 9068 section 2.1).
//
// The resource servers must reject the tokens without it, so that an id_token or any other
// token signed with the same issuer keys can't be used as an access token.
const OAuth2ResourceAccessTokenType = "at+jwt"

// OAuth2ResourceDefaultAccessTokenDuration is the suggested lifetime (in seconds) of the
// resource access tokens: they are verified offline by the resource servers, so a revoked
// session (logout, password change, reuse detection) is cut off only when they expire.
const OAuth2ResourceDefaultAccessTokenDuration = 300

// OAuth2ResourceRegisteredClaims are the resource access token claims set by the server
// that the [OAuth2TokenRequestEvent.AccessTokenClaims] can't replace.
var OAuth2ResourceRegisteredClaims = []string{
	"iss", "sub", "aud", "exp", "iat", "nbf", "jti",
	"client_id", "scope", "sid", "auth_time", TokenClaimOAuth2Actor,
}

// OAuth2Resource defines a protected resource (aka. a resource server, e.g. another
// service of the platform) of an auth collection OAuth2 server.
//
// A client allowed to use it (see [OAuth2Client.Resources]) can request an access token
// for it with the "resource" token request parameter (Resource Indicators, RFC 8707).
// The issued token is a JWT access token (RFC 9068) with the resource identifier as
// "aud", signed with the collection signing keys, so that the resource server can
// verify it offline with the issuer JWKS.
type OAuth2Resource struct {
	// Identifier is the resource indicator: an absolute URI without query and fragment
	// (e.g. "https://api.example.com" or "urn:example:payments").
	Identifier string `form:"identifier" json:"identifier"`

	// Name is an optional human friendly name of the resource.
	Name string `form:"name" json:"name"`

	// AccessTokenDuration is the lifetime of the issued access tokens in seconds.
	AccessTokenDuration int64 `form:"accessTokenDuration" json:"accessTokenDuration"`
}

// AccessTokenDurationTime returns the resource AccessTokenDuration as time.Duration.
func (r OAuth2Resource) AccessTokenDurationTime() time.Duration {
	return time.Duration(r.AccessTokenDuration) * time.Second
}

// Validate makes OAuth2Resource validatable by implementing [validation.Validatable] interface.
func (r OAuth2Resource) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.Identifier, validation.Required, validation.Length(1, 255), validation.By(CheckOAuth2ResourceIdentifier)),
		validation.Field(&r.Name, validation.Length(0, 255)),
		validation.Field(&r.AccessTokenDuration, validation.Required, validation.Min(10), validation.Max(86400)),
	)
}

// CheckOAuth2ResourceIdentifier checks whether the provided value is a valid resource
// indicator: an absolute URI without query and fragment (RFC 8707 section 2).
func CheckOAuth2ResourceIdentifier(value any) error {
	v, _ := value.(string)

	invalidErr := validation.NewError(
		"validation_invalid_resource_identifier",
		"Must be an absolute URI without query and fragment.",
	)

	u, err := url.Parse(v)
	if v == "" || err != nil || u.Scheme == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(v, "#") {
		return invalidErr
	}

	if (u.Scheme == "http" || u.Scheme == "https") && u.Host == "" {
		return invalidErr
	}

	if u.Opaque == "" && u.Host == "" && u.Path == "" {
		return invalidErr
	}

	return nil
}

func checkForDuplicatedOAuth2Resources(value any) error {
	resources, _ := value.([]OAuth2Resource)

	existing := make(map[string]struct{}, len(resources))
	for i, r := range resources {
		if _, ok := existing[r.Identifier]; ok {
			return validation.Errors{
				strconv.Itoa(i): validation.Errors{
					"identifier": validation.NewError("validation_duplicated_resource", "The resource {{.resource}} is already registered.").
						SetParams(map[string]any{"resource": r.Identifier}),
				},
			}
		}
		existing[r.Identifier] = struct{}{}
	}

	return nil
}

// FindResource returns the registered resource with the provided identifier.
func (c OAuth2ServerConfig) FindResource(identifier string) (OAuth2Resource, bool) {
	for _, r := range c.Resources {
		if r.Identifier == identifier {
			return r, true
		}
	}

	return OAuth2Resource{}, false
}

// OAuth2ResourceAccessTokenOptions defines the options of [AuthSession.NewResourceAccessToken].
type OAuth2ResourceAccessTokenOptions struct {
	// Issuer is the OAuth2 server issuer identifier ("iss" claim, see [OAuth2Issuer]).
	Issuer string

	// Resource is the resource the token is issued for ("aud" claim and lifetime).
	Resource OAuth2Resource

	// ExtraClaims are additional custom claims (see [OAuth2TokenRequestEvent.AccessTokenClaims]).
	//
	// They can't replace any of the [OAuth2ResourceRegisteredClaims].
	ExtraClaims map[string]any
}

// NewResourceAccessToken issues a JWT access token (RFC 9068) of the session for a
// protected resource of its collection, signed with the active collection signing key.
//
// The claims are the registered "iss", "sub", "aud" (the resource identifier),
// "client_id", "scope", "sid", "jti", "iat", "exp", "auth_time" (when known),
// "act" (the staff member of an impersonation session) and the custom extra claims.
//
// The session must be active and with attached actor and client (see [AuthSession.AttachActor]).
func (m *AuthSession) NewResourceAccessToken(opts OAuth2ResourceAccessTokenOptions) (string, error) {
	if m.Id == "" || m.Record.IsNew() {
		return "", errors.New("the auth session must be saved before issuing tokens")
	}

	if m.Status() != AuthSessionStatusActive {
		return "", errors.New("the auth session is not active")
	}

	if m.actor == nil || m.client == nil {
		return "", errors.New("missing attached auth session actor and client")
	}

	collection := m.actor.Collection()
	if !collection.IsAuth() {
		return "", ErrNotAuthRecord
	}

	if opts.Issuer == "" {
		return "", errors.New("missing issuer")
	}

	if opts.Resource.Identifier == "" || opts.Resource.AccessTokenDuration <= 0 {
		return "", errors.New("missing or invalid resource")
	}

	signingKey, ok := collection.OAuth2Server.ActiveSigningKey()
	if !ok {
		return "", ErrMissingSigningKey
	}

	signer, err := signingKey.Signer()
	if err != nil {
		return "", err
	}

	now := time.Now()
	duration := opts.Resource.AccessTokenDurationTime()

	claims := jwt.MapClaims{}
	for k, v := range opts.ExtraClaims {
		claims[k] = v
	}
	for _, registered := range OAuth2ResourceRegisteredClaims {
		delete(claims, registered)
	}

	claims["iss"] = opts.Issuer
	claims["sub"] = m.actor.Id
	claims["aud"] = opts.Resource.Identifier
	claims["client_id"] = m.client.ClientId()
	claims["scope"] = strings.Join(m.Scopes(), " ")
	claims["sid"] = m.Id
	claims["jti"] = security.RandomString(32)
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(duration).Unix()

	if authTime := m.AuthTime(); !authTime.IsZero() {
		claims["auth_time"] = authTime.Time().Unix()
	}

	if impersonator := m.Impersonator(); impersonator != "" {
		claims[TokenClaimOAuth2Actor] = map[string]any{"sub": impersonator}
	}

	return security.NewSignedJWTWithType(claims, signer, duration, OAuth2ResourceAccessTokenType)
}
