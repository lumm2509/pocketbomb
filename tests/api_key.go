package tests

import (
	"fmt"

	"github.com/lumm2509/pocketbomb/core"
)

// apiKeyPlaceholderType is the token placeholder type of the [PublicAPIKey] placeholders.
const apiKeyPlaceholderType = "publicAPIKey"

// AllCollectionsActions is a key permissions ceiling allowing all actions of all regular collections.
var AllCollectionsActions = core.Permissions{
	Collections: map[string][]string{
		core.PermissionAllCollections: {
			core.PermissionActionList,
			core.PermissionActionView,
			core.PermissionActionCreate,
			core.PermissionActionUpdate,
			core.PermissionActionDelete,
		},
	},
}

// PublicAPIKey returns a scenario placeholder that is resolved to a new public API key
// of the first-party "pb_test_users" OAuth2 client (aka. the client of the users test auth tokens)
// with an all regular collections actions ceiling and without allowed origins.
//
// It is meant for the guest scenarios of the deny by default APIs (records, batch, realtime)
// so that they are still governed only by the collection rules.
func PublicAPIKey() string {
	return tokenPlaceholder(apiKeyPlaceholderType, "users", "-", false)
}

// PublicAPIKeyHeaders returns the scenario headers with a [PublicAPIKey] placeholder.
func PublicAPIKeyHeaders() map[string]string {
	return map[string]string{"X-PB-Public-Key": PublicAPIKey()}
}

// NewAPIKey creates and persists a new API key of the first-party test OAuth2 client
// of the provided auth collection (see [NewSessionAuthToken]) and returns it with its plain token.
//
// The private keys are created with "none" buyer context
// (change it with key.SetBuyerContext and save the key if needed).
func NewAPIKey(app core.App, clientCollectionNameOrId string, kind string, permissions core.Permissions) (*core.APIKey, string, error) {
	collection, err := app.FindCachedCollectionByNameOrId(clientCollectionNameOrId)
	if err != nil {
		return nil, "", err
	}

	client, err := testClient(app, collection)
	if err != nil {
		return nil, "", err
	}

	return NewClientAPIKey(app, client, kind, permissions)
}

// NewClientAPIKey creates and persists a new API key of the provided OAuth2 client
// and returns it with its plain token (see [NewAPIKey]).
func NewClientAPIKey(app core.App, client *core.OAuth2Client, kind string, permissions core.Permissions) (*core.APIKey, string, error) {
	key := core.NewAPIKey(app)
	key.SetName("Test " + kind + " key")
	key.SetClientRef(client.Id)
	key.SetKind(kind)
	if kind == core.APIKeyKindPrivate {
		key.SetBuyerContext(core.APIKeyBuyerContextNone)
	}
	key.SetPermissions(permissions)
	token := key.GenerateToken()

	if err := app.Save(key); err != nil {
		return nil, "", fmt.Errorf("failed to create the test API key: %w", err)
	}

	return key, token, nil
}

// ClientIdForCollection returns the client_id of the first-party test OAuth2 client
// of the provided auth collection (see [NewSessionAuthToken] and [NewAPIKey]).
func ClientIdForCollection(collectionName string) string {
	if collectionName == core.CollectionNameSuperusers {
		return core.OAuth2DashboardClientId
	}

	return testClientIdPrefix + collectionName
}
