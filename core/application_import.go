package core

import (
	"context"
	"errors"

	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// ErrApplicationVersionExists is returned when importing an already existing
// application version with a different manifest (the versions are immutable).
var ErrApplicationVersionExists = validation.NewError(
	"validation_application_version_exists",
	"The application version already exists with a different manifest (the versions are immutable, bump the version).",
)

// ApplicationManifestImportResult defines the [App.ImportApplicationManifest] result.
type ApplicationManifestImportResult struct {
	Application *Application
	Version     *ApplicationVersion

	// Created indicates whether the application was created by the import.
	Created bool

	// Unchanged indicates that the same version with the same manifest
	// digest already existed (idempotent import, nothing was changed).
	Unchanged bool
}

// ImportApplicationManifest creates a custom application (or a new version of an existing
// custom application with the same handle) from the provided validated manifest.
//
// The version must be new (the versions are immutable) unless its stored manifest digest
// is the same (idempotent import). The application metadata and latestVersionRef are
// updated from the imported manifest.
//
// createdBy is the optional staff record id that imported the manifest.
//
// The manifest icon_url (if any) is fetched and inlined as data: URI (a failure only drops the icon).
func (app *BaseApp) ImportApplicationManifest(manifest *ApplicationManifest, sourceFormat string, createdBy string) (*ApplicationManifestImportResult, error) {
	origin := applicationOrigin{source: ApplicationSourceCustom}

	if manifest != nil && manifest.IconURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), applicationCatalogTimeout)
		defer cancel()

		origin.iconURL = app.applicationCatalogs.InlineIcon(ctx, manifest.IconURL)
	}

	return app.importApplicationManifest(manifest, sourceFormat, createdBy, origin)
}

// applicationOrigin describes where an imported manifest comes from.
type applicationOrigin struct {
	source string

	// catalog applications only
	catalogURL  string
	manifestURL string
	iconURL     string
}

// importApplicationManifest imports the manifest as a new application or as a new version of
// the existing application with the same handle and source (the versions of the catalog
// applications are imported only from the catalog and the custom ones only by deploy).
func (app *BaseApp) importApplicationManifest(manifest *ApplicationManifest, sourceFormat string, createdBy string, origin applicationOrigin) (*ApplicationManifestImportResult, error) {
	event := new(ApplicationManifestImportEvent)
	event.App = app
	event.Manifest = manifest
	event.SourceFormat = sourceFormat
	event.CreatedBy = createdBy

	err := app.OnApplicationManifestImport().Trigger(event, func(e *ApplicationManifestImportEvent) error {
		result, err := app.saveApplicationManifest(e.Manifest, e.SourceFormat, e.CreatedBy, origin)
		e.Result = result
		return err
	})

	return event.Result, err
}

func (app *BaseApp) saveApplicationManifest(manifest *ApplicationManifest, sourceFormat string, createdBy string, origin applicationOrigin) (*ApplicationManifestImportResult, error) {
	if manifest == nil {
		return nil, errors.New("missing application manifest")
	}

	manifest.Normalize()
	if err := manifest.Validate(); err != nil {
		return nil, err
	}

	digest, err := manifest.Digest()
	if err != nil {
		return nil, err
	}

	raw, err := manifest.JSON()
	if err != nil {
		return nil, err
	}

	result := &ApplicationManifestImportResult{}

	txErr := app.RunInTransaction(func(txApp App) error {
		application, err := txApp.FindApplicationByHandle(manifest.Handle)
		if err != nil {
			application = NewApplication(txApp)
			application.Set("source", origin.source)
			result.Created = true
		} else if application.Source() != origin.source {
			if origin.source == ApplicationSourceCatalog {
				return validation.Errors{"handle": validation.NewError(
					"validation_application_not_catalog",
					"The handle belongs to a custom application (a catalog application with the same handle cannot be installed).",
				)}
			}
			return validation.Errors{"handle": validation.NewError(
				"validation_application_not_custom",
				"The handle belongs to a catalog application (only the custom applications could be deployed).",
			)}
		}

		if !result.Created {
			existing := &ApplicationVersion{}
			err := txApp.RecordQuery(CollectionNameApplicationVersions).
				AndWhere(dbx.HashExp{"applicationRef": application.Id, "version": manifest.Version}).
				Limit(1).
				One(existing)
			if err == nil {
				if existing.ManifestDigest() != digest {
					return validation.Errors{"version": ErrApplicationVersionExists}
				}

				result.Application = application
				result.Version = existing
				result.Unchanged = true

				return nil
			}
		}

		application.loadManifest(manifest)
		if origin.source == ApplicationSourceCatalog {
			application.Set("catalogURL", origin.catalogURL)
			application.Set("manifestURL", origin.manifestURL)
		}
		// note: only the inlined data: icons are stored
		application.Set("iconURL", SafeApplicationIconURL(origin.iconURL))
		if err := txApp.Save(application); err != nil {
			return err
		}

		version := NewApplicationVersion(txApp)
		version.Set("applicationRef", application.Id)
		version.Set("version", manifest.Version)
		version.Set("manifest", types.JSONRaw(raw))
		version.Set("sourceFormat", sourceFormat)
		version.Set("createdBy", createdBy)
		if err := txApp.Save(version); err != nil {
			return err
		}

		// reload so that the original state is the persisted one
		application, err = txApp.FindApplicationById(application.Id)
		if err != nil {
			return err
		}

		application.Set("latestVersionRef", version.Id)
		if err := txApp.Save(application); err != nil {
			return err
		}

		result.Application = application
		result.Version = version

		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	return result, nil
}
