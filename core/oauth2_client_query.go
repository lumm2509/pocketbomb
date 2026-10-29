package core

import (
	"github.com/pocketbase/dbx"
)

// FindAllOAuth2ClientsByCollection returns all OAuth2Client models
// registered for the provided auth collection.
func (app *BaseApp) FindAllOAuth2ClientsByCollection(collection *Collection) ([]*OAuth2Client, error) {
	result := []*OAuth2Client{}

	err := app.RecordQuery(CollectionNameOAuth2Clients).
		AndWhere(dbx.HashExp{"collectionRef": collection.Id}).
		OrderBy("created DESC").
		All(&result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindOAuth2ClientById returns a single OAuth2Client model by its record id.
func (app *BaseApp) FindOAuth2ClientById(id string) (*OAuth2Client, error) {
	result := &OAuth2Client{}

	err := app.RecordQuery(CollectionNameOAuth2Clients).
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindOAuth2ClientByClientId returns a single OAuth2Client model by its public client_id.
func (app *BaseApp) FindOAuth2ClientByClientId(clientId string) (*OAuth2Client, error) {
	result := &OAuth2Client{}

	err := app.RecordQuery(CollectionNameOAuth2Clients).
		AndWhere(dbx.HashExp{"clientId": clientId}).
		Limit(1).
		One(result)

	if err != nil {
		return nil, err
	}

	return result, nil
}
