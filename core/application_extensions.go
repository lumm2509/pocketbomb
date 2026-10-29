package core

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/tools/security"
)

// Applications extensions (declarative; no application code runs inside PocketBase)
// -------------------------------------------------------------------
//
// The manifest [[extensions]] are dashboard navigation links and record panel actions
// (see [ApplicationExtensionTypes]). A staff member launches an extension from the dashboard:
//
//  1. the dashboard requests a launch token (POST /api/applications/installations/{id}/launch,
//     first-party dashboard token only, see [CheckApplicationExtensionAccess])
//  2. the launch token (a short-lived JWS signed with the active signing key of the
//     _applicationInstallations issuer, "typ": [ApplicationLaunchTokenType]) is POSTed by the
//     dashboard to the extension URL with an auto-submitted form (it never travels in a URL)
//  3. the application exchanges it at the issuer token endpoint (token exchange authenticated with its
//     managed client credentials) for an "online" access token: the actor is the staff member on behalf
//     of the installation (effective = staff permissions ∩ installation grant, see [Authorize]);
//     the online session is a child of the staff root SSO session (the staff logout ends it)
//
// The launch token is never accepted as an auth token (it has none of the record auth token claims
// and it is signed with the issuer asymmetric key instead of a record token secret).

// ApplicationLaunchTokenType is the explicit "typ" header of the extension launch tokens.
const ApplicationLaunchTokenType = "pb-launch+jwt"

// ApplicationLaunchTokenDuration is the extension launch token expiration duration.
const ApplicationLaunchTokenDuration = 60 * time.Second

// applicationLaunchJtiRetention is the min time after the creation of a launch (online) session
// before it could be deleted by the cleanup (its persisted launch token jti is the replay protection
// and therefore it must outlive the launch token; the extra time covers the clock skew).
const applicationLaunchJtiRetention = 5 * time.Minute

// ApplicationLaunchRecord defines the record of a record action launch token.
type ApplicationLaunchRecord struct {
	Collection string `json:"collection"`
	Id         string `json:"id"`
}

// ApplicationLaunchClaims defines the claims of an extension launch token.
type ApplicationLaunchClaims struct {
	// Issuer is the _applicationInstallations issuer identifier ("iss").
	Issuer string

	// ClientId is the public client_id of the installation managed OAuth2 client ("aud").
	ClientId string

	// StaffId is the id of the staff member that launched the extension ("sub").
	StaffId string

	// StaffSessionId is the id of the staff dashboard auth session ("sid").
	StaffSessionId string

	// InstallationId is the id of the application installation ("installation_id").
	InstallationId string

	// Extension is the launched manifest extension handle ("extension").
	Extension string

	// Record is the record of a record action launch ("record", optional).
	Record *ApplicationLaunchRecord

	// Jti is the unique (single use) token identifier ("jti").
	Jti string

	// ExpiresAt is the token expiration time ("exp").
	ExpiresAt time.Time
}

// NewApplicationLaunchToken generates a new extension launch token (see [ApplicationLaunchClaims])
// signed with the active signing key of the _applicationInstallations issuer
// (the Issuer, Jti and ExpiresAt claims are always generated).
//
// The access checks are the caller responsibility (see [CheckApplicationExtensionAccess]).
func NewApplicationLaunchToken(app App, claims ApplicationLaunchClaims) (string, error) {
	if claims.ClientId == "" || claims.StaffId == "" || claims.StaffSessionId == "" ||
		claims.InstallationId == "" || claims.Extension == "" {
		return "", errors.New("missing required launch token claims")
	}

	signer, issuer, err := applicationIssuerSigner(app)
	if err != nil {
		return "", err
	}

	now := time.Now()

	payload := jwt.MapClaims{
		"iss":             issuer,
		"aud":             claims.ClientId,
		"sub":             claims.StaffId,
		"sid":             claims.StaffSessionId,
		"installation_id": claims.InstallationId,
		"extension":       claims.Extension,
		"iat":             now.Unix(),
		"exp":             now.Add(ApplicationLaunchTokenDuration).Unix(),
		"jti":             security.RandomString(32),
	}

	if claims.Record != nil {
		payload["record"] = map[string]any{
			"collection": claims.Record.Collection,
			"id":         claims.Record.Id,
		}
	}

	return security.NewSignedJWTWithType(payload, signer, ApplicationLaunchTokenDuration, ApplicationLaunchTokenType)
}

// ParseApplicationLaunchToken verifies the provided extension launch token (signature and kid with the
// _applicationInstallations issuer JWKS, "typ" header, iss, exp and the required claims) and returns its claims.
//
// The caller must still check the audience against the authenticated client, the installation,
// the staff session and the jti single use (see the token endpoint token exchange grant).
func ParseApplicationLaunchToken(app App, token string) (*ApplicationLaunchClaims, error) {
	collection, err := app.FindCachedCollectionByNameOrId(CollectionNameApplicationInstallations)
	if err != nil {
		return nil, err
	}

	jwks, err := collection.OAuth2Server.JWKS()
	if err != nil {
		return nil, err
	}

	raw, err := security.ParseSignedJWTWithType(
		token,
		jwks,
		ApplicationLaunchTokenType,
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(OAuth2Issuer(app, collection)),
	)
	if err != nil {
		return nil, err
	}

	claims := &ApplicationLaunchClaims{}
	claims.Issuer, _ = raw["iss"].(string)
	claims.ClientId, _ = raw["aud"].(string)
	claims.StaffId, _ = raw["sub"].(string)
	claims.StaffSessionId, _ = raw["sid"].(string)
	claims.InstallationId, _ = raw["installation_id"].(string)
	claims.Extension, _ = raw["extension"].(string)
	claims.Jti, _ = raw["jti"].(string)

	if exp, err := raw.GetExpirationTime(); err == nil && exp != nil {
		claims.ExpiresAt = exp.Time
	}

	if record, ok := raw["record"].(map[string]any); ok {
		claims.Record = &ApplicationLaunchRecord{}
		claims.Record.Collection, _ = record["collection"].(string)
		claims.Record.Id, _ = record["id"].(string)
	}

	if claims.ClientId == "" || claims.StaffId == "" || claims.StaffSessionId == "" ||
		claims.InstallationId == "" || claims.Extension == "" || claims.Jti == "" {
		return nil, errors.New("missing required launch token claims")
	}

	return claims, nil
}

// applicationOnBehalfOfPermissions returns the effective permissions of a staff member acting on behalf
// of the provided installation: staff permissions ∩ installation grant (application grantable only)
// with at most the webhooks read level (see [resolveOnBehalfOfPermissions]).
func applicationOnBehalfOfPermissions(staffPermissions Permissions, installation *ApplicationInstallation) Permissions {
	result := staffPermissions.Intersect(ApplicationGrantPermissions(installation.Permissions()))

	if result.System[PermissionResourceWebhooks] == PermissionLevelWrite {
		result.System[PermissionResourceWebhooks] = PermissionLevelRead
	}

	return result
}

// ApplicationOnBehalfOfScopes returns the scopes of an extension online token of the provided staff member
// (the scopes derived from the effective staff permissions ∩ installation grant, see [ApplicationGrantScopes]).
func ApplicationOnBehalfOfScopes(app App, staff *Record, installation *ApplicationInstallation) ([]string, error) {
	if staff == nil || !staff.IsSuperuser() || installation == nil {
		return nil, errors.New("the online tokens could be issued only for a staff member and an installation")
	}

	// note: the staff own permissions (without any token restriction)
	perms, err := ResolveActorPermissions(app, &RequestInfo{Auth: staff})
	if err != nil {
		return nil, err
	}

	staffPermissions := perms.Permissions
	if perms.Owner {
		staffPermissions = AllPermissions()
	}

	return ApplicationGrantScopes(app, applicationOnBehalfOfPermissions(staffPermissions, installation)), nil
}

// ErrApplicationExtensionNotAllowed is returned by [CheckApplicationExtensionAccess].
var ErrApplicationExtensionNotAllowed = errors.New("the application extension is not available")

// CheckApplicationExtensionAccess checks whether the request actor could see and launch the provided
// extension of the provided installation (manifest = the installed version manifest):
//   - the actor must be a staff member with the applications read permission (never the third-party
//     or application tokens; the dashboard first-party token check is done by the launch endpoint)
//   - the installation must be active
//   - record actions: the collection must be a regular collection that both the staff member
//     and the installation grant could view (see [Authorize]) and, if record is set, it must
//     belong to the collection and it must be visible to the staff member
//
// Returns the record action collection (nil for the navigation extensions).
func CheckApplicationExtensionAccess(
	app App,
	info *RequestInfo,
	installation *ApplicationInstallation,
	ext ApplicationManifestExtension,
	record *Record,
) (*Collection, error) {
	if info == nil || !info.IsStaff() || installation == nil {
		return nil, ErrApplicationExtensionNotAllowed
	}

	perms := info.Permissions(app)
	if perms.ThirdParty || !info.Can(app, PermissionResourceApplications, PermissionLevelRead) {
		return nil, ErrApplicationExtensionNotAllowed
	}

	if !installation.IsActive() {
		return nil, fmt.Errorf("%w: the installation is not active", ErrApplicationExtensionNotAllowed)
	}

	switch ext.Type {
	case ApplicationExtensionTypeNavigation:
		if record != nil {
			return nil, fmt.Errorf("%w: the navigation extensions have no record", ErrApplicationExtensionNotAllowed)
		}
		return nil, nil
	case ApplicationExtensionTypeRecordAction:
		// handled below
	default:
		return nil, ErrApplicationExtensionNotAllowed
	}

	collection, err := app.FindCachedCollectionByNameOrId(ext.Collection)
	if err != nil || collection.Name != ext.Collection || collection.System {
		return nil, fmt.Errorf("%w: missing or invalid record action collection", ErrApplicationExtensionNotAllowed)
	}

	access := info.CollectionAccess(app, collection, PermissionActionView)
	if !access.Allowed {
		return nil, fmt.Errorf("%w: the staff member can't view the collection", ErrApplicationExtensionNotAllowed)
	}

	grant := ApplicationGrantPermissions(installation.Permissions())
	if !grant.CanCollection(collection.Id, PermissionActionView) {
		return nil, fmt.Errorf("%w: the installation grant doesn't cover the collection view", ErrApplicationExtensionNotAllowed)
	}

	if record != nil {
		if record.Collection().Id != collection.Id {
			return nil, fmt.Errorf("%w: the record doesn't belong to the collection", ErrApplicationExtensionNotAllowed)
		}

		if !access.BypassRules {
			ok, _ := app.CanAccessRecord(record, info, collection.ViewRule)
			if !ok {
				return nil, fmt.Errorf("%w: the record is not visible", ErrApplicationExtensionNotAllowed)
			}
		}
	}

	return collection, nil
}
