package core

import (
	"encoding/json/v2"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	validation "github.com/pocketbase/ozzo-validation/v4"
	"github.com/pocketbase/ozzo-validation/v4/is"
)

// Built-in OAuth2 server (aka. OpenID Connect provider) scopes.
const (
	OAuth2ScopeOpenId        = "openid"
	OAuth2ScopeEmail         = "email"
	OAuth2ScopeProfile       = "profile"
	OAuth2ScopeOfflineAccess = "offline_access"
)

// OAuth2BuiltinScopes is the list with the always available OAuth2 server scopes.
var OAuth2BuiltinScopes = []string{
	OAuth2ScopeOpenId,
	OAuth2ScopeEmail,
	OAuth2ScopeProfile,
	OAuth2ScopeOfflineAccess,
}

// scope-token as defined in RFC 6749 (section 3.3)
var oauth2ScopeRegex = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)

var oauth2KidRegex = regexp.MustCompile(`^[\w\-\.]+$`)

// OAuth2Issuer returns the OAuth2 server (aka. OpenID Connect provider)
// issuer identifier of the provided auth collection in the format:
//
//	{settings.Meta.AppURL}/oauth2/{collectionName}
func OAuth2Issuer(app App, collection *Collection) string {
	return strings.TrimRight(app.Settings().Meta.AppURL, "/") + "/oauth2/" + url.PathEscape(collection.Name)
}

// OAuth2ServerConfig defines the options for an auth collection acting
// as OAuth2/OpenID Connect provider (aka. authorization server).
//
// Every auth collection is an issuer with its own
// issuer identifier (see [OAuth2Issuer]) and signing keys.
//
// Note that the issued access tokens duration is controlled by
// the collection AuthToken.Duration option and the enabled hosted
// login page methods by the collection PasswordAuth, OTP and OAuth2 options.
type OAuth2ServerConfig struct {
	// LoginPage defines the hosted login page branding options.
	LoginPage OAuth2ServerLoginPageConfig `form:"loginPage" json:"loginPage"`

	// Scopes is an optional list with extra custom scopes that
	// clients can request in addition to the [OAuth2BuiltinScopes].
	Scopes []string `form:"scopes" json:"scopes"`

	// SigningKeys is a list of the asymmetric keys used for signing the OpenID Connect id_tokens.
	//
	// The latest created active key is used for signing new tokens.
	// The inactive keys are still published in the JWKS so that
	// previously issued tokens can be verified (aka. key rotation).
	SigningKeys []OAuth2SigningKey `form:"signingKeys" json:"signingKeys"`

	// SessionDuration specifies how long the issuer root SSO session
	// (aka. the "pb_session" browser cookie) to be valid (in seconds).
	SessionDuration int64 `form:"sessionDuration" json:"sessionDuration"`

	// RefreshTokenDuration specifies the max lifetime of an auth session
	// refresh token family (in seconds).
	//
	// Every hosted flow session has a rotating refresh token. The family of
	// a session without the "offline_access" scope is additionally bounded by
	// its root SSO session (it ends with it, e.g. on logout), while the
	// "offline_access" sessions survive the SSO logout.
	RefreshTokenDuration int64 `form:"refreshTokenDuration" json:"refreshTokenDuration"`

	// CodeDuration specifies how long an issued OAuth2 authorization code to be valid (in seconds).
	CodeDuration int64 `form:"codeDuration" json:"codeDuration"`

	// ConsentRequired specifies whether to ask the user for consent
	// before authorizing a client (first-party clients always skip it).
	ConsentRequired bool `form:"consentRequired" json:"consentRequired"`
}

// UnmarshalJSON implements the [json.Unmarshaler] interface.
//
// Similar to [OAuth2Config.UnmarshalJSON], instead of replacing the entire
// signing keys slice, we ensure that partially submitted key data
// (e.g. without privateKey) is merged on per key level based on the key kid.
func (c *OAuth2ServerConfig) UnmarshalJSON(b []byte) error {
	originalKeys := slices.Clone(c.SigningKeys)

	type alias OAuth2ServerConfig
	err := json.Unmarshal(b, (*alias)(c))
	if err != nil {
		return err
	}

	if len(c.SigningKeys) == 0 || len(originalKeys) == 0 {
		return nil
	}

	// unmarshal again but this time into a plain array of objects
	// so that we have only the submitted fields and no zero defaults
	plain := struct {
		SigningKeys []map[string]any `json:"signingKeys"`
	}{}
	err = json.Unmarshal(b, &plain)
	if err != nil {
		return err
	}

	// no keys were submitted
	if len(plain.SigningKeys) == 0 {
		return nil
	}

	if len(c.SigningKeys) != len(plain.SigningKeys) {
		return errors.New("the length of the plain unmarshalized signing keys and the ones from the config doesn't match")
	}

KeysMergeLoop:
	for i, plain := range plain.SigningKeys {
		for _, original := range originalKeys {
			if original.Kid == plain["kid"] {
				raw, err := json.Marshal(plain)
				if err != nil {
					return err
				}

				// unmarshal the new plain data on top of the original one
				err = json.Unmarshal(raw, &original)
				if err != nil {
					return err
				}

				c.SigningKeys[i] = original

				continue KeysMergeLoop
			}
		}
	}

	return nil
}

// Validate makes OAuth2ServerConfig validatable by implementing [validation.Validatable] interface.
func (c OAuth2ServerConfig) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.SessionDuration, validation.Required, validation.Min(10), validation.Max(94670856)), // ~3y max
		validation.Field(&c.RefreshTokenDuration, validation.Required, validation.Min(10), validation.Max(94670856)),
		validation.Field(&c.CodeDuration, validation.Required, validation.Min(10), validation.Max(600)),
		validation.Field(
			&c.Scopes,
			validation.Each(validation.Required, validation.Length(1, 100), validation.Match(oauth2ScopeRegex)),
			validation.By(checkForDuplicatedOAuth2Scopes),
			// note: the reserved scope prefixes are checked by the collection validator
			// only for the newly added scopes (see [CheckNewOAuth2ReservedScopes])
		),
		validation.Field(&c.LoginPage),
		// note: the keys are not required because a new active key is
		// auto generated on collection save if there is none
		validation.Field(
			&c.SigningKeys,
			validation.By(checkForDuplicatedOAuth2SigningKeys),
			validation.When(len(c.SigningKeys) > 0, validation.By(checkForActiveOAuth2SigningKey)),
		),
	)
}

func checkForDuplicatedOAuth2Scopes(value any) error {
	scopes, _ := value.([]string)

	existing := make(map[string]struct{}, len(scopes)+len(OAuth2BuiltinScopes))
	for _, s := range OAuth2BuiltinScopes {
		existing[s] = struct{}{}
	}

	for i, s := range scopes {
		if _, ok := existing[s]; ok {
			return validation.Errors{
				strconv.Itoa(i): validation.NewError("validation_duplicated_scope", "The scope {{.scope}} is already registered.").
					SetParams(map[string]any{"scope": s}),
			}
		}
		existing[s] = struct{}{}
	}

	return nil
}

// IsReservedOAuth2CustomScope reports whether the provided custom scope uses one of the reserved
// collection or system scopes prefixes (read_*, write_*, system:*).
//
// The read_ and write_ prefixed scopes are interpreted as RBAC collection scopes (e.g. a custom
// "write_orders" scope would grant write access to an "orders" collection created later)
// and the system: namespace is reserved for the system resources scopes.
func IsReservedOAuth2CustomScope(scope string) bool {
	return IsOAuth2CollectionScope(scope) || IsOAuth2SystemScope(scope)
}

// CheckNewOAuth2ReservedScopes checks that the newly added custom scopes
// (aka. the ones that are not part of the old scopes list) don't use
// the reserved collection and system scopes prefixes (see [IsReservedOAuth2CustomScope]).
//
// The already stored conflicting scopes are tolerated so that the collections
// created before the prefixes reservation could still be saved
// (the system migration logs a warning for each of them).
func CheckNewOAuth2ReservedScopes(newScopes []string, oldScopes []string) error {
	for i, s := range newScopes {
		if !IsReservedOAuth2CustomScope(s) || slices.Contains(oldScopes, s) {
			continue
		}

		return validation.Errors{
			strconv.Itoa(i): validation.NewError(
				"validation_reserved_scope",
				"The read_, write_ and system: scope prefixes are reserved for the collection and system scopes.",
			).SetParams(map[string]any{"scope": s}),
		}
	}

	return nil
}

func checkForDuplicatedOAuth2SigningKeys(value any) error {
	keys, _ := value.([]OAuth2SigningKey)

	existing := make(map[string]struct{}, len(keys))

	for i, k := range keys {
		if k.Kid == "" {
			continue // the kid nonempty state is validated separately
		}
		if _, ok := existing[k.Kid]; ok {
			return validation.Errors{
				strconv.Itoa(i): validation.Errors{
					"kid": validation.NewError("validation_duplicated_kid", "The kid {{.kid}} is already registered.").
						SetParams(map[string]any{"kid": k.Kid}),
				},
			}
		}
		existing[k.Kid] = struct{}{}
	}

	return nil
}

func checkForActiveOAuth2SigningKey(value any) error {
	keys, _ := value.([]OAuth2SigningKey)

	for _, k := range keys {
		if k.Active {
			return nil
		}
	}

	return validation.NewError("validation_missing_active_key", "At least one active signing key is required.")
}

// AllowedScopes returns the list of all builtin and custom scopes supported by the server.
func (c OAuth2ServerConfig) AllowedScopes() []string {
	return list.ToUniqueStringSlice(append(slices.Clone(OAuth2BuiltinScopes), c.Scopes...))
}

// ActiveSigningKey returns the latest created active signing key.
//
// Returns false and zero key if there is no active signing key.
func (c OAuth2ServerConfig) ActiveSigningKey() (key OAuth2SigningKey, exists bool) {
	for _, k := range c.SigningKeys {
		if !k.Active {
			continue
		}

		if !exists || k.CreatedAt.After(key.CreatedAt) {
			key = k
			exists = true
		}
	}

	return
}

// JWKS returns the public JSON Web Key Set of all configured signing keys
// (both active and inactive).
func (c OAuth2ServerConfig) JWKS() (*security.JWKSet, error) {
	result := &security.JWKSet{Keys: make([]*security.JWK, 0, len(c.SigningKeys))}

	for _, k := range c.SigningKeys {
		jwk, err := k.JWK()
		if err != nil {
			return nil, err
		}
		result.Keys = append(result.Keys, jwk)
	}

	return result, nil
}

// SessionDurationTime returns the current SessionDuration as [time.Duration].
func (c OAuth2ServerConfig) SessionDurationTime() time.Duration {
	return time.Duration(c.SessionDuration) * time.Second
}

// RefreshTokenDurationTime returns the current RefreshTokenDuration as [time.Duration].
func (c OAuth2ServerConfig) RefreshTokenDurationTime() time.Duration {
	return time.Duration(c.RefreshTokenDuration) * time.Second
}

// CodeDurationTime returns the current CodeDuration as [time.Duration].
func (c OAuth2ServerConfig) CodeDurationTime() time.Duration {
	return time.Duration(c.CodeDuration) * time.Second
}

// normalizeSigningKeys removes the keys without private key
// (e.g. from a redacted collection export) and auto generates
// a new active key if there is none (every auth collection is an issuer).
func (c *OAuth2ServerConfig) normalizeSigningKeys() error {
	c.SigningKeys = slices.DeleteFunc(slices.Clone(c.SigningKeys), func(k OAuth2SigningKey) bool {
		return k.PrivateKey == ""
	})

	if _, ok := c.ActiveSigningKey(); ok {
		return nil
	}

	key, err := NewOAuth2SigningKey(security.JWTAlgRS256)
	if err != nil {
		return err
	}

	c.SigningKeys = append(c.SigningKeys, key)

	return nil
}

// -------------------------------------------------------------------

// OAuth2ServerLoginPageConfig defines the hosted pages branding options.
type OAuth2ServerLoginPageConfig struct {
	// Title is an optional hosted login page title (fallbacks to the app name).
	Title string `form:"title" json:"title"`

	// LogoURL is an optional hosted login page logo image url.
	LogoURL string `form:"logoURL" json:"logoURL"`

	// PrimaryColor is an optional hosted login page accent color in hex format (e.g. "#1055c9").
	PrimaryColor string `form:"primaryColor" json:"primaryColor"`
}

// Validate makes OAuth2ServerLoginPageConfig validatable by implementing [validation.Validatable] interface.
func (c OAuth2ServerLoginPageConfig) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.Title, validation.Length(0, 255)),
		validation.Field(&c.LogoURL, is.URL),
		validation.Field(&c.PrimaryColor, is.HexColor),
	)
}

// -------------------------------------------------------------------

// OAuth2SigningKey defines a single OAuth2 server (OpenID Connect) asymmetric signing key.
type OAuth2SigningKey struct {
	// Kid is the unique key identifier (used as JWT "kid" header).
	Kid string `form:"kid" json:"kid"`

	// Alg is the key signing algorithm (RS256 or ES256).
	Alg string `form:"alg" json:"alg"`

	// PrivateKey is the PEM encoded private key.
	//
	// Similar to the other collection secrets it is never serialized
	// with the collection JSON.
	PrivateKey string `form:"privateKey" json:"privateKey,omitempty"`

	// CreatedAt is the key creation date.
	CreatedAt types.DateTime `form:"createdAt" json:"createdAt"`

	// Active indicates whether the key could be used for signing new tokens
	// (inactive keys are used only for verification).
	Active bool `form:"active" json:"active"`
}

// NewOAuth2SigningKey generates a new active OAuth2SigningKey for the specified alg (RS256 or ES256).
func NewOAuth2SigningKey(alg string) (OAuth2SigningKey, error) {
	privateKey, err := security.GeneratePrivateKeyPEM(alg)
	if err != nil {
		return OAuth2SigningKey{}, err
	}

	return OAuth2SigningKey{
		Kid:        security.RandomString(20),
		Alg:        alg,
		PrivateKey: privateKey,
		CreatedAt:  types.NowDateTime(),
		Active:     true,
	}, nil
}

// Validate makes OAuth2SigningKey validatable by implementing [validation.Validatable] interface.
func (k OAuth2SigningKey) Validate() error {
	return validation.ValidateStruct(&k,
		validation.Field(&k.Kid, validation.Required, validation.Length(1, 100), validation.Match(oauth2KidRegex)),
		validation.Field(&k.Alg, validation.Required, validation.In(security.JWTAlgRS256, security.JWTAlgES256)),
		validation.Field(&k.PrivateKey, validation.Required, validation.By(func(value any) error {
			v, _ := value.(string)
			if v == "" {
				return nil // nonempty state is validated separately
			}

			if k.Alg != security.JWTAlgRS256 && k.Alg != security.JWTAlgES256 {
				return nil // the alg is validated separately
			}

			key, err := security.ParsePrivateKeyPEM(v)
			if err != nil {
				return validation.NewError("validation_invalid_private_key", "Invalid or unsupported PEM private key.")
			}

			if err := security.CheckPrivateKeyAlg(key, k.Alg); err != nil {
				return validation.NewError("validation_private_key_alg_mismatch", "The private key is not compatible with the selected alg.")
			}

			return nil
		})),
	)
}

// Signer parses the key PrivateKey and returns a new [security.JWTSigner] instance.
func (k OAuth2SigningKey) Signer() (*security.JWTSigner, error) {
	privateKey, err := security.ParsePrivateKeyPEM(k.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &security.JWTSigner{Kid: k.Kid, Alg: k.Alg, Key: privateKey}, nil
}

// JWK returns the public JWK representation of the current signing key.
func (k OAuth2SigningKey) JWK() (*security.JWK, error) {
	signer, err := k.Signer()
	if err != nil {
		return nil, err
	}

	return security.NewJWK(k.Kid, k.Alg, signer.Key.Public())
}
