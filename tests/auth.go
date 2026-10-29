package tests

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
)

// testClientIdPrefix is the client_id prefix of the auto created first-party test OAuth2 clients.
const testClientIdPrefix = "pb_test_"

// NewSessionAuthToken creates a new real session-backed auth (aka. OAuth2 access) token
// for the provided auth record.
//
// It creates a root SSO session and an active child session issued through
// a first-party OAuth2 client (the built-in pb_dashboard client for the superusers
// and an auto created "pb_test_{collection}" client for the other auth collections).
//
// The optional scopes default to all client scopes.
func NewSessionAuthToken(app core.App, record *core.Record, optScopes ...string) (string, error) {
	session, err := CreateAuthSession(app, record, optScopes...)
	if err != nil {
		return "", err
	}

	return session.NewAccessToken()
}

// CreateAuthSession creates a root SSO session and an active child session
// (see [NewSessionAuthToken]) for the provided auth record.
func CreateAuthSession(app core.App, record *core.Record, optScopes ...string) (*core.AuthSession, error) {
	if record == nil || !record.Collection().IsAuth() {
		return nil, core.ErrNotAuthRecord
	}

	client, err := testClient(app, record.Collection())
	if err != nil {
		return nil, err
	}

	now := types.NowDateTime()

	root := core.NewAuthSession(app)
	root.Set("status", core.AuthSessionStatusActive)
	root.SetCollectionRef(record.Collection().Id)
	root.SetRecordRef(record.Id)
	root.SetSSOSecret(security.RandomString(40))
	root.SetAuthMethods([]core.AuthSessionMethod{{Method: core.AuthSessionMethodPassword, Time: now}})
	root.SetAuthTime(now)
	root.SetExpiresAt(now.Add(record.Collection().OAuth2Server.SessionDurationTime()))
	if err := app.Save(root); err != nil {
		return nil, fmt.Errorf("failed to create the test root session: %w", err)
	}

	scopes := optScopes
	if len(scopes) == 0 {
		scopes = client.Scopes()
	}

	return app.CreateAuthSession(record, client, core.AuthSessionOptions{
		Scopes:      scopes,
		Parent:      root.Id,
		AuthMethods: root.AuthMethods(),
	})
}

// testClient returns (and creates if missing) the first-party test OAuth2 client of the provided collection.
func testClient(app core.App, collection *core.Collection) (*core.OAuth2Client, error) {
	clientId := ClientIdForCollection(collection.Name)

	client, err := app.FindOAuth2ClientByClientId(clientId)
	if err == nil {
		return client, nil
	}

	if collection.Name == core.CollectionNameSuperusers {
		return nil, errors.New("missing built-in pb_dashboard client")
	}

	client = core.NewOAuth2Client(app)
	client.SetName("Test " + collection.Name)
	client.SetClientId(clientId)
	client.SetType(core.OAuth2ClientTypePublic)
	client.SetFirstParty(true)
	client.SetCollectionRef(collection.Id)
	client.SetRedirectURIs([]string{"https://example.com/pb_test_callback"})
	client.SetScopes(collection.OAuth2Server.AllowedScopes())
	if err := app.Save(client); err != nil {
		return nil, fmt.Errorf("failed to create the test OAuth2 client: %w", err)
	}

	return client, nil
}

// -------------------------------------------------------------------
// Scenario token placeholders
// -------------------------------------------------------------------

// The token placeholders could be used in the static [ApiScenario] fields
// (URL and Headers) and they are resolved to real tokens right before
// the scenario request is sent (after BeforeTestFunc).

var tokenPlaceholderRegex = regexp.MustCompile(`__pbtesttoken\[([^|\]]+)\|([^|\]]+)\|([^|\]]+)\|(valid|expired)\]__`)

// AuthToken returns a scenario placeholder that is resolved to a new
// real session-backed auth token (see [NewSessionAuthToken]) of the specified
// record (collection name or id + record id or email).
func AuthToken(collectionNameOrId string, recordIdOrEmail string) string {
	return tokenPlaceholder(core.TokenTypeAuth, collectionNameOrId, recordIdOrEmail, false)
}

// ExpiredAuthToken is similar to [AuthToken] but the resolved token is expired
// (the related auth session is still active).
func ExpiredAuthToken(collectionNameOrId string, recordIdOrEmail string) string {
	return tokenPlaceholder(core.TokenTypeAuth, collectionNameOrId, recordIdOrEmail, true)
}

// RecordToken returns a scenario placeholder that is resolved to a new
// record token of the specified non-auth type (file, verification, passwordReset, emailChange).
//
// For the emailChange tokens the new email is always "change@example.com".
func RecordToken(tokenType string, collectionNameOrId string, recordIdOrEmail string, expired bool) string {
	return tokenPlaceholder(tokenType, collectionNameOrId, recordIdOrEmail, expired)
}

func tokenPlaceholder(tokenType, collection, record string, expired bool) string {
	state := "valid"
	if expired {
		state = "expired"
	}

	return "__pbtesttoken[" + tokenType + "|" + collection + "|" + record + "|" + state + "]__"
}

// ResolveTokenPlaceholders replaces all token placeholders in the provided string with real tokens.
//
// The same placeholder within a single cache map is resolved to the same token.
func ResolveTokenPlaceholders(app core.App, str string, cache map[string]string) (string, error) {
	var resolveErr error

	result := tokenPlaceholderRegex.ReplaceAllStringFunc(str, func(match string) string {
		if token, ok := cache[match]; ok {
			return token
		}

		parts := tokenPlaceholderRegex.FindStringSubmatch(match)

		token, err := newPlaceholderToken(app, parts[1], parts[2], parts[3], parts[4] == "expired")
		if err != nil {
			resolveErr = errors.Join(resolveErr, err)
			return match
		}

		cache[match] = token

		return token
	})

	return result, resolveErr
}

func newPlaceholderToken(app core.App, tokenType, collectionNameOrId, recordIdOrEmail string, expired bool) (string, error) {
	if tokenType == apiKeyPlaceholderType {
		_, token, err := NewAPIKey(app, collectionNameOrId, core.APIKeyKindPublic, AllCollectionsActions)
		return token, err
	}

	record, err := app.FindRecordById(collectionNameOrId, recordIdOrEmail)
	if err != nil {
		record, err = app.FindAuthRecordByEmail(collectionNameOrId, recordIdOrEmail)
		if err != nil {
			return "", fmt.Errorf("failed to find the token placeholder record %s/%s: %w", collectionNameOrId, recordIdOrEmail, err)
		}
	}

	if !expired {
		switch tokenType {
		case core.TokenTypeAuth:
			return NewSessionAuthToken(app, record)
		case core.TokenTypeFile:
			return record.NewFileToken()
		case core.TokenTypeVerification:
			return record.NewVerificationToken()
		case core.TokenTypePasswordReset:
			return record.NewPasswordResetToken()
		case core.TokenTypeEmailChange:
			return record.NewEmailChangeToken("change@example.com")
		}

		return "", errors.New("unsupported token placeholder type " + tokenType)
	}

	// expired tokens with otherwise valid claims and signature
	claims := jwt.MapClaims{
		core.TokenClaimType:         tokenType,
		core.TokenClaimId:           record.Id,
		core.TokenClaimCollectionId: record.Collection().Id,
	}

	var secret string
	switch tokenType {
	case core.TokenTypeAuth:
		session, err := CreateAuthSession(app, record)
		if err != nil {
			return "", err
		}
		client, err := app.FindOAuth2ClientById(session.Client())
		if err != nil {
			return "", err
		}
		claims[core.TokenClaimOAuth2ClientId] = client.ClientId()
		claims[core.TokenClaimOAuth2Scope] = strings.Join(session.Scopes(), " ")
		claims[core.TokenClaimOAuth2SessionId] = session.Id
		secret = record.Collection().AuthToken.Secret
	case core.TokenTypeFile:
		secret = record.Collection().FileToken.Secret
	case core.TokenTypeVerification:
		claims[core.TokenClaimEmail] = record.Email()
		secret = record.Collection().VerificationToken.Secret
	case core.TokenTypePasswordReset:
		claims[core.TokenClaimEmail] = record.Email()
		secret = record.Collection().PasswordResetToken.Secret
	case core.TokenTypeEmailChange:
		claims[core.TokenClaimEmail] = record.Email()
		claims[core.TokenClaimNewEmail] = "change@example.com"
		secret = record.Collection().EmailChangeToken.Secret
	default:
		return "", errors.New("unsupported token placeholder type " + tokenType)
	}

	return security.NewJWT(claims, record.TokenKey()+secret, -1*time.Hour)
}

// resolveScenarioPlaceholders resolves the token placeholders of the scenario URL and headers.
func resolveScenarioPlaceholders(app core.App, url string, headers map[string]string) (string, map[string]string, error) {
	if !strings.Contains(url, "__pbtesttoken[") && !slices.ContainsFunc(mapValues(headers), func(v string) bool {
		return strings.Contains(v, "__pbtesttoken[")
	}) {
		return url, headers, nil
	}

	cache := map[string]string{}

	resolvedURL, err := ResolveTokenPlaceholders(app, url, cache)
	if err != nil {
		return "", nil, err
	}

	resolvedHeaders := make(map[string]string, len(headers))
	for k, v := range headers {
		resolvedHeaders[k], err = ResolveTokenPlaceholders(app, v, cache)
		if err != nil {
			return "", nil, err
		}
	}

	return resolvedURL, resolvedHeaders, nil
}

func mapValues(m map[string]string) []string {
	result := make([]string, 0, len(m))
	for _, v := range m {
		result = append(result, v)
	}
	return result
}
