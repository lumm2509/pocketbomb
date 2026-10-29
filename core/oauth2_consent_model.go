package core

import (
	"context"
	"errors"
	"slices"

	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/types"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

const CollectionNameOAuth2Consents = "_oauth2Consents"

var (
	_ Model        = (*OAuth2Consent)(nil)
	_ PreValidator = (*OAuth2Consent)(nil)
	_ RecordProxy  = (*OAuth2Consent)(nil)
)

// OAuth2Consent defines a Record proxy for working with the OAuth2 server consents collection.
//
// A consent is only the remembered end-user decision to authorize
// an OAuth2 client for a set of scopes (the issued tokens are part of the [AuthSession]).
type OAuth2Consent struct {
	*Record
}

// NewOAuth2Consent instantiates and returns a new blank *OAuth2Consent model.
//
// Example usage:
//
//	consent := core.NewOAuth2Consent(app)
//	consent.SetRecordRef(user.Id)
//	consent.SetCollectionRef(user.Collection().Id)
//	consent.SetClient(client.Id)
//	consent.SetScopes([]string{"openid", "email"})
//	app.Save(consent)
func NewOAuth2Consent(app App) *OAuth2Consent {
	m := &OAuth2Consent{}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameOAuth2Consents)
	if err != nil {
		// this is just to make tests easier since it is a system collection and it is expected to be always accessible
		// (note: the loaded record is further checked on OAuth2Consent.PreValidate())
		c = NewBaseCollection("@__invalid__")
	}

	m.Record = NewRecord(c)

	return m
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *OAuth2Consent) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameOAuth2Consents {
		return errors.New("missing or invalid oauth2 consent ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *OAuth2Consent) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *OAuth2Consent) SetProxyRecord(record *Record) {
	m.Record = record
}

// CollectionRef returns the "collectionRef" record field value.
func (m *OAuth2Consent) CollectionRef() string {
	return m.GetString("collectionRef")
}

// SetCollectionRef updates the "collectionRef" record field value.
func (m *OAuth2Consent) SetCollectionRef(collectionId string) {
	m.Set("collectionRef", collectionId)
}

// RecordRef returns the "recordRef" record field value.
func (m *OAuth2Consent) RecordRef() string {
	return m.GetString("recordRef")
}

// SetRecordRef updates the "recordRef" record field value.
func (m *OAuth2Consent) SetRecordRef(recordId string) {
	m.Set("recordRef", recordId)
}

// Client returns the "client" record field value (aka. the related OAuth2Client record id).
func (m *OAuth2Consent) Client() string {
	return m.GetString("client")
}

// SetClient updates the "client" record field value.
func (m *OAuth2Consent) SetClient(clientRecordId string) {
	m.Set("client", clientRecordId)
}

// Scopes returns the "scopes" record field value (aka. the consented scopes).
func (m *OAuth2Consent) Scopes() []string {
	return m.GetStringSlice("scopes")
}

// SetScopes updates the "scopes" record field value.
func (m *OAuth2Consent) SetScopes(scopes []string) {
	m.Set("scopes", scopes)
}

// Covers reports whether the consent scopes include all of the provided scopes.
func (m *OAuth2Consent) Covers(scopes []string) bool {
	consented := m.Scopes()

	for _, s := range scopes {
		if !slices.Contains(consented, s) {
			return false
		}
	}

	return true
}

// Created returns the "created" record field value.
func (m *OAuth2Consent) Created() types.DateTime {
	return m.GetDateTime("created")
}

// Updated returns the "updated" record field value.
func (m *OAuth2Consent) Updated() types.DateTime {
	return m.GetDateTime("updated")
}

func (app *BaseApp) registerOAuth2ConsentHooks() {
	recordRefHooks[*OAuth2Consent](app, CollectionNameOAuth2Consents, CollectionTypeAuth)

	// ensure that the consent client belongs to the same auth collection
	app.OnRecordValidate(CollectionNameOAuth2Consents).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if err := validateOAuth2ClientCollectionRef(e.App, e.Record); err != nil {
				return err
			}

			return e.Next()
		},
		Priority: 99,
	})
}

// validateOAuth2ClientCollectionRef checks whether the record "client"
// relation points to a client registered for the record "collectionRef".
func validateOAuth2ClientCollectionRef(app App, record *Record) error {
	clientId := record.GetString("client")
	if clientId == "" {
		return nil // the nonempty state is validated by the field
	}

	client, err := app.FindRecordById(CollectionNameOAuth2Clients, clientId)
	if err != nil {
		return nil // the relation existence is validated by the field
	}

	if client.GetString("collectionRef") != record.GetString("collectionRef") {
		return validation.Errors{
			"client": validation.NewError("validation_invalid_client_collection", "The client is not registered for the specified auth collection."),
		}
	}

	return nil
}
