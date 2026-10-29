package core

import (
	"github.com/pocketbase/dbx"
)

// FindApplicationById returns the application with the specified id.
func (app *BaseApp) FindApplicationById(id string) (*Application, error) {
	result := &Application{}

	err := app.RecordQuery(CollectionNameApplications).
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindApplicationByHandle returns the application with the specified handle.
func (app *BaseApp) FindApplicationByHandle(handle string) (*Application, error) {
	result := &Application{}

	err := app.RecordQuery(CollectionNameApplications).
		AndWhere(dbx.HashExp{"handle": handle}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindAllApplications returns all applications ordered by name.
func (app *BaseApp) FindAllApplications() ([]*Application, error) {
	result := []*Application{}

	err := app.RecordQuery(CollectionNameApplications).
		OrderBy("name ASC", "handle ASC").
		All(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindApplicationVersionById returns the application version with the specified id.
func (app *BaseApp) FindApplicationVersionById(id string) (*ApplicationVersion, error) {
	result := &ApplicationVersion{}

	err := app.RecordQuery(CollectionNameApplicationVersions).
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindAllApplicationVersionsByApplication returns all versions of the provided application (newest first).
func (app *BaseApp) FindAllApplicationVersionsByApplication(applicationId string) ([]*ApplicationVersion, error) {
	result := []*ApplicationVersion{}

	err := app.RecordQuery(CollectionNameApplicationVersions).
		AndWhere(dbx.HashExp{"applicationRef": applicationId}).
		OrderBy("created DESC", "rowid DESC").
		All(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindApplicationInstallationById returns the application installation with the specified id.
func (app *BaseApp) FindApplicationInstallationById(id string) (*ApplicationInstallation, error) {
	result := &ApplicationInstallation{}

	err := app.RecordQuery(CollectionNameApplicationInstallations).
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindApplicationInstallationByApplication returns the installation of the specified application.
func (app *BaseApp) FindApplicationInstallationByApplication(applicationId string) (*ApplicationInstallation, error) {
	result := &ApplicationInstallation{}

	err := app.RecordQuery(CollectionNameApplicationInstallations).
		AndWhere(dbx.HashExp{"applicationRef": applicationId}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindApplicationInstallationClient returns the managed OAuth2 client of the provided installation.
func (app *BaseApp) FindApplicationInstallationClient(installationId string) (*OAuth2Client, error) {
	result := &OAuth2Client{}

	err := app.RecordQuery(CollectionNameOAuth2Clients).
		AndWhere(dbx.HashExp{"applicationInstallationRef": installationId}).
		Limit(1).
		One(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindAllWebhooksByApplicationInstallation returns the managed webhooks of the provided installation
// (in the manifest subscriptions order).
func (app *BaseApp) FindAllWebhooksByApplicationInstallation(installationId string) ([]*Webhook, error) {
	result := []*Webhook{}

	err := app.RecordQuery(CollectionNameWebhooks).
		AndWhere(dbx.HashExp{"applicationInstallationRef": installationId}).
		OrderBy("created ASC", "rowid ASC").
		All(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
