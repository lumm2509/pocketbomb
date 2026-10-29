package core

import (
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/pocketbase/dbx"
)

// FindOAuth2ConsentByRecordAndClient returns the remembered consent of the provided auth record for the specified client.
func (app *BaseApp) FindOAuth2ConsentByRecordAndClient(authRecord *Record, client *OAuth2Client) (*OAuth2Consent, error) {
	result := &OAuth2Consent{}

	err := app.RecordQuery(CollectionNameOAuth2Consents).
		AndWhere(dbx.HashExp{
			"collectionRef": authRecord.Collection().Id,
			"recordRef":     authRecord.Id,
			"client":        client.Id,
		}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindAllOAuth2ConsentsByRecord returns all OAuth2Consent models of the provided auth record.
func (app *BaseApp) FindAllOAuth2ConsentsByRecord(authRecord *Record) ([]*OAuth2Consent, error) {
	result := []*OAuth2Consent{}

	err := app.RecordQuery(CollectionNameOAuth2Consents).
		AndWhere(dbx.HashExp{
			"collectionRef": authRecord.Collection().Id,
			"recordRef":     authRecord.Id,
		}).
		OrderBy("created DESC").
		All(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// SaveOAuth2Consent creates or updates the remembered consent of the provided
// auth record for the specified client by merging the provided scopes.
func (app *BaseApp) SaveOAuth2Consent(authRecord *Record, client *OAuth2Client, scopes []string) (*OAuth2Consent, error) {
	consent, err := app.FindOAuth2ConsentByRecordAndClient(authRecord, client)
	if err != nil {
		consent = NewOAuth2Consent(app)
		consent.SetCollectionRef(authRecord.Collection().Id)
		consent.SetRecordRef(authRecord.Id)
		consent.SetClient(client.Id)
	}

	consent.SetScopes(list.ToUniqueStringSlice(append(consent.Scopes(), scopes...)))

	if err := app.Save(consent); err != nil {
		return nil, err
	}

	return consent, nil
}
