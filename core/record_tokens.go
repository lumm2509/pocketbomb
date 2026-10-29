package core

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
)

// Supported record token types
const (
	TokenTypeAuth          = "auth"
	TokenTypeFile          = "file"
	TokenTypeVerification  = "verification"
	TokenTypePasswordReset = "passwordReset"
	TokenTypeEmailChange   = "emailChange"
	TokenTypeInstaller     = "installer"
)

// List with commonly used record token claims
const (
	TokenClaimId           = "id"
	TokenClaimType         = "type"
	TokenClaimCollectionId = "collectionId"
	TokenClaimEmail        = "email"
	TokenClaimNewEmail     = "newEmail"

	// OAuth2 server access token claims
	TokenClaimOAuth2ClientId  = "cid"
	TokenClaimOAuth2Scope     = "scope"
	TokenClaimOAuth2SessionId = "sid"
	TokenClaimOAuth2Actor     = "act"
)

// Common token related errors
var (
	ErrNotAuthRecord     = errors.New("not an auth collection record")
	ErrMissingSigningKey = errors.New("missing or invalid signing key")
)

// NewInstallerToken generates and returns a new short-lived installer token
// for the provided (system installer) superuser record.
//
// The installer token is a dedicated token type that is never accepted
// as auth token and it could be used only with the installer API
// (e.g. to create the first superuser).
func (m *Record) NewInstallerToken(duration time.Duration) (string, error) {
	if !m.Collection().IsAuth() || m.Collection().Name != CollectionNameSuperusers {
		return "", errors.New("the installer token could be issued only for a superuser record")
	}

	key := m.TokenKey() + m.Collection().AuthToken.Secret + installerTokenKeySuffix
	if key == installerTokenKeySuffix {
		return "", ErrMissingSigningKey
	}

	return security.NewJWT(
		jwt.MapClaims{
			TokenClaimType:         TokenTypeInstaller,
			TokenClaimId:           m.Id,
			TokenClaimCollectionId: m.Collection().Id,
		},
		key,
		duration,
	)
}

// installerTokenKeySuffix is appended to the auth token secret so that the
// installer tokens are never valid with the auth tokens signing key (and vice versa).
const installerTokenKeySuffix = ".installer"

// OIDCIdTokenOptions defines the options for generating an OpenID Connect id_token.
type OIDCIdTokenOptions struct {
	// Issuer is the OAuth2 server issuer identifier ("iss" claim, see [OAuth2Issuer]).
	Issuer string

	// Client is the OAuth2 client the token is issued to ("aud" claim).
	Client *OAuth2Client

	// Session is the optional auth session the token is issued within ("sid" claim).
	//
	// If set, the session scopes and auth time are used as fallback.
	Session *AuthSession

	// Scopes is the list of granted scopes based on which the standard
	// claims are populated (e.g. "email" and "email_verified" for the "email" scope).
	Scopes []string

	// Nonce is the authorization request nonce value ("nonce" claim).
	Nonce string

	// AuthTime is the time when the end-user authentication occurred ("auth_time" claim).
	AuthTime types.DateTime

	// Duration is the token duration (fallbacks to the auth collection AuthToken.Duration option).
	Duration time.Duration

	// ExtraClaims is an optional map with custom claims to add to the token.
	//
	// Note that they cannot replace the registered "iss", "sub", "aud", "exp", "iat",
	// "auth_time", "nonce" and "sid" claims.
	ExtraClaims map[string]any
}

// NewOIDCIdToken generates and returns a new OpenID Connect id_token
// signed with the active auth collection OAuth2Server signing key.
func (m *Record) NewOIDCIdToken(opts OIDCIdTokenOptions) (string, error) {
	if !m.Collection().IsAuth() {
		return "", ErrNotAuthRecord
	}

	if opts.Issuer == "" {
		return "", errors.New("missing issuer")
	}

	if opts.Client == nil || opts.Client.ClientId() == "" {
		return "", errors.New("missing OAuth2 client")
	}

	signingKey, ok := m.Collection().OAuth2Server.ActiveSigningKey()
	if !ok {
		return "", ErrMissingSigningKey
	}

	signer, err := signingKey.Signer()
	if err != nil {
		return "", err
	}

	scopes := opts.Scopes
	authTime := opts.AuthTime
	if opts.Session != nil {
		if len(scopes) == 0 {
			scopes = opts.Session.Scopes()
		}
		if authTime.IsZero() {
			authTime = opts.Session.AuthTime()
		}
	}

	duration := opts.Duration
	if duration <= 0 {
		duration = m.Collection().AuthToken.DurationTime()
	}

	claims := jwt.MapClaims{}

	for k, v := range opts.ExtraClaims {
		claims[k] = v
	}

	for k, v := range m.OIDCStandardClaims(scopes) {
		claims[k] = v
	}

	// registered claims
	claims["iss"] = opts.Issuer
	claims["sub"] = m.Id
	claims["aud"] = opts.Client.ClientId()
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(duration).Unix()
	delete(claims, "auth_time")
	if !authTime.IsZero() {
		claims["auth_time"] = authTime.Unix()
	}
	delete(claims, "nonce")
	if opts.Nonce != "" {
		claims["nonce"] = opts.Nonce
	}
	delete(claims, "sid")
	if opts.Session != nil && opts.Session.Id != "" {
		claims["sid"] = opts.Session.Id
	}

	return security.NewSignedJWT(claims, signer, duration)
}

// OIDCStandardClaims returns the OpenID Connect standard claims of the
// current auth record that are allowed by the provided scopes
// (used both for the id_token and the userinfo endpoint response):
//   - "sub" (always)
//   - "email", "email_verified" (email scope)
//   - "name", "preferred_username", "picture", "updated_at" (profile scope;
//     based on the collection OAuth2 mapped fields)
func (m *Record) OIDCStandardClaims(scopes []string) map[string]any {
	claims := map[string]any{"sub": m.Id}

	for _, scope := range scopes {
		switch scope {
		case OAuth2ScopeEmail:
			claims["email"] = m.Email()
			claims["email_verified"] = m.Verified()
		case OAuth2ScopeProfile:
			mapped := m.Collection().OAuth2.MappedFields
			if mapped.Name != "" {
				claims["name"] = m.GetString(mapped.Name)
			}
			if mapped.Username != "" {
				claims["preferred_username"] = m.GetString(mapped.Username)
			}
			if mapped.AvatarURL != "" {
				if v := m.GetString(mapped.AvatarURL); strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
					claims["picture"] = v
				}
			}
			if updated := m.GetDateTime("updated"); !updated.IsZero() {
				claims["updated_at"] = updated.Unix()
			}
		}
	}

	return claims
}

// NewVerificationToken generates and returns a new record verification token.
func (m *Record) NewVerificationToken() (string, error) {
	if !m.Collection().IsAuth() {
		return "", ErrNotAuthRecord
	}

	key := (m.TokenKey() + m.Collection().VerificationToken.Secret)
	if key == "" {
		return "", ErrMissingSigningKey
	}

	return security.NewJWT(
		jwt.MapClaims{
			TokenClaimType:         TokenTypeVerification,
			TokenClaimId:           m.Id,
			TokenClaimCollectionId: m.Collection().Id,
			TokenClaimEmail:        m.Email(),
		},
		key,
		m.Collection().VerificationToken.DurationTime(),
	)
}

// NewPasswordResetToken generates and returns a new auth record password reset request token.
func (m *Record) NewPasswordResetToken() (string, error) {
	if !m.Collection().IsAuth() {
		return "", ErrNotAuthRecord
	}

	key := (m.TokenKey() + m.Collection().PasswordResetToken.Secret)
	if key == "" {
		return "", ErrMissingSigningKey
	}

	return security.NewJWT(
		jwt.MapClaims{
			TokenClaimType:         TokenTypePasswordReset,
			TokenClaimId:           m.Id,
			TokenClaimCollectionId: m.Collection().Id,
			TokenClaimEmail:        m.Email(),
		},
		key,
		m.Collection().PasswordResetToken.DurationTime(),
	)
}

// NewEmailChangeToken generates and returns a new auth record change email request token.
func (m *Record) NewEmailChangeToken(newEmail string) (string, error) {
	if !m.Collection().IsAuth() {
		return "", ErrNotAuthRecord
	}

	key := (m.TokenKey() + m.Collection().EmailChangeToken.Secret)
	if key == "" {
		return "", ErrMissingSigningKey
	}

	return security.NewJWT(
		jwt.MapClaims{
			TokenClaimType:         TokenTypeEmailChange,
			TokenClaimId:           m.Id,
			TokenClaimCollectionId: m.Collection().Id,
			TokenClaimEmail:        m.Email(),
			TokenClaimNewEmail:     newEmail,
		},
		key,
		m.Collection().EmailChangeToken.DurationTime(),
	)
}

// NewFileToken generates and returns a new record private file access token.
func (m *Record) NewFileToken() (string, error) {
	if !m.Collection().IsAuth() {
		return "", ErrNotAuthRecord
	}

	key := (m.TokenKey() + m.Collection().FileToken.Secret)
	if key == "" {
		return "", ErrMissingSigningKey
	}

	return security.NewJWT(
		jwt.MapClaims{
			TokenClaimType:         TokenTypeFile,
			TokenClaimId:           m.Id,
			TokenClaimCollectionId: m.Collection().Id,
		},
		key,
		m.Collection().FileToken.DurationTime(),
	)
}
