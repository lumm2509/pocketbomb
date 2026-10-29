package core

import (
	"errors"

	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

// FindAPIKeyById returns a single APIKey model by its record id.
func (app *BaseApp) FindAPIKeyById(id string) (*APIKey, error) {
	result := &APIKey{}

	err := app.RecordQuery(CollectionNameAPIKeys).
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindAPIKeyByToken returns the APIKey model of the provided plain token
// (looked up by its sha256 hash; the key and client state are not checked).
func (app *BaseApp) FindAPIKeyByToken(plainToken string) (*APIKey, error) {
	if plainToken == "" {
		return nil, errors.New("missing API key token")
	}

	result := &APIKey{}

	err := app.RecordQuery(CollectionNameAPIKeys).
		AndWhere(dbx.HashExp{"tokenHash": security.SHA256(plainToken)}).
		Limit(1).
		One(result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindAllAPIKeysByClient returns all APIKey models of the specified OAuth2 client record id (newest first).
func (app *BaseApp) FindAllAPIKeysByClient(clientId string) ([]*APIKey, error) {
	result := []*APIKey{}

	err := app.RecordQuery(CollectionNameAPIKeys).
		AndWhere(dbx.HashExp{"clientRef": clientId}).
		OrderBy("created DESC", "rowid DESC").
		All(&result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// HasPublicAPIKeyForOrigin reports whether at least one enabled and not expired
// public API key has the provided origin in its allowed origins.
func (app *BaseApp) HasPublicAPIKeyForOrigin(origin string) bool {
	normalized, err := NormalizeAPIKeyOrigin(origin)
	if err != nil {
		return false
	}

	var exists int

	err = app.RecordQuery(CollectionNameAPIKeys).
		Select("(1)").
		AndWhere(dbx.HashExp{"kind": APIKeyKindPublic, "disabled": false}).
		AndWhere(dbx.NewExp("([[expiresAt]] = '' OR [[expiresAt]] > {:now})", dbx.Params{"now": types.NowDateTime().String()})).
		AndWhere(dbx.NewExp(
			"EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid([[allowedOrigins]]) THEN [[allowedOrigins]] ELSE '[]' END) WHERE [[json_each.value]] = {:origin})",
			dbx.Params{"origin": normalized},
		)).
		Limit(1).
		Row(&exists)

	return err == nil && exists == 1
}
