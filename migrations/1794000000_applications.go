package migrations

import (
	"fmt"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

// Applications:
//   - creates the _applications, _applicationVersions and _applicationInstallations
//     (auth; aka. the application actors) system collections
//   - adds _oauth2Clients.applicationInstallationRef and _oauth2Clients.grantTypes
//     (the existing clients keep their behavior: authorization_code, refresh_token and token_exchange)
//   - adds _webhooks.applicationInstallationRef (the installation managed webhooks)
//   - adds _authSessions.launchJti (the single use extension launch tokens)
//     and launchSession (the dashboard session that an online session ends with)
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		applications, err := createApplicationsCollection(txApp)
		if err != nil {
			return fmt.Errorf("_applications error: %w", err)
		}

		versions, err := createApplicationVersionsCollection(txApp, applications)
		if err != nil {
			return fmt.Errorf("_applicationVersions error: %w", err)
		}

		// note: added after the versions collection is created (circular reference)
		applications.Fields.Add(&core.RelationField{
			Name:         "latestVersionRef",
			System:       true,
			MaxSelect:    1,
			CollectionId: versions.Id,
		})
		// note: only the server inlined data: icons (so that the dashboard CSP doesn't have to allow remote images)
		applications.Fields.Add(&core.TextField{Name: "iconURL", System: true, Max: 100000})
		if err := txApp.Save(applications); err != nil {
			return fmt.Errorf("_applications error: %w", err)
		}

		installations, err := createApplicationInstallationsCollection(txApp, applications, versions)
		if err != nil {
			return fmt.Errorf("_applicationInstallations error: %w", err)
		}

		if err := addOAuth2ClientsApplicationFields(txApp, installations); err != nil {
			return fmt.Errorf("_oauth2Clients error: %w", err)
		}

		webhooks, err := txApp.FindCollectionByNameOrId(core.CollectionNameWebhooks)
		if err != nil {
			return err
		}
		webhooks.Fields.Add(&core.RelationField{
			Name:          "applicationInstallationRef",
			System:        true,
			MaxSelect:     1,
			CollectionId:  installations.Id,
			CascadeDelete: true,
		})
		webhooks.AddIndex("idx_webhooks_applicationInstallationRef", false, "applicationInstallationRef", "")
		if err := txApp.Save(webhooks); err != nil {
			return fmt.Errorf("_webhooks error: %w", err)
		}

		sessions, err := txApp.FindCollectionByNameOrId(core.CollectionNameAuthSessions)
		if err != nil {
			return err
		}
		sessions.Fields.Add(&core.TextField{Name: "launchJti", System: true, Hidden: true})
		sessions.Fields.Add(&core.TextField{Name: "launchSession", System: true, Hidden: true})
		sessions.AddIndex("idx_authSessions_launchJti", true, "launchJti", "launchJti != ''")
		sessions.AddIndex("idx_authSessions_launchSession", false, "launchSession", "launchSession != ''")
		if err := txApp.Save(sessions); err != nil {
			return fmt.Errorf("_authSessions error: %w", err)
		}

		return nil
	}, func(txApp core.App) error {
		sessions, err := txApp.FindCollectionByNameOrId(core.CollectionNameAuthSessions)
		if err != nil {
			return err
		}
		if _, err := txApp.DB().Delete(core.CollectionNameAuthSessions, dbx.NewExp("[[launchJti]] != ''")).Execute(); err != nil {
			return err
		}
		sessions.RemoveIndex("idx_authSessions_launchJti")
		sessions.RemoveIndex("idx_authSessions_launchSession")
		sessions.Fields.RemoveByName("launchJti")
		sessions.Fields.RemoveByName("launchSession")
		// note: without validation because the system fields can't be removed otherwise
		if err := txApp.SaveNoValidate(sessions); err != nil {
			return err
		}

		// the managed clients and webhooks can't exist without their installations
		for _, name := range []string{core.CollectionNameWebhooks, core.CollectionNameOAuth2Clients} {
			col, err := txApp.FindCollectionByNameOrId(name)
			if err != nil {
				return err
			}
			if _, err := txApp.DB().Delete(name, dbx.NewExp("[[applicationInstallationRef]] != ''")).Execute(); err != nil {
				return err
			}
			col.Fields.RemoveByName("applicationInstallationRef")
			col.Fields.RemoveByName("grantTypes")
			col.RemoveIndex("idx_webhooks_applicationInstallationRef")
			col.RemoveIndex("idx_oauth2Clients_applicationInstallationRef")
			if err := txApp.SaveNoValidate(col); err != nil {
				return err
			}
		}

		for _, name := range []string{
			core.CollectionNameApplicationInstallations,
			core.CollectionNameApplicationVersions,
			core.CollectionNameApplications,
		} {
			if err := dropRawCollection(txApp, name); err != nil {
				return err
			}
		}

		return nil
	})
}

func createApplicationsCollection(txApp core.App) (*core.Collection, error) {
	col := core.NewBaseCollection(core.CollectionNameApplications)
	col.System = true

	// note: all API rules are nil (the records are managed through the /api/applications endpoints)

	col.Fields.Add(&core.TextField{Name: "handle", System: true, Required: true, Max: 63})
	col.Fields.Add(&core.TextField{Name: "name", System: true, Required: true, Max: 100})
	col.Fields.Add(&core.TextField{Name: "description", System: true, Max: 1000})
	col.Fields.Add(&core.TextField{Name: "developerName", System: true, Max: 100})
	col.Fields.Add(&core.URLField{Name: "developerURL", System: true})
	col.Fields.Add(&core.URLField{Name: "applicationURL", System: true})
	col.Fields.Add(&core.SelectField{
		Name:      "source",
		System:    true,
		Required:  true,
		MaxSelect: 1,
		Values:    []string{core.ApplicationSourceCustom, core.ApplicationSourceCatalog},
	})
	col.Fields.Add(&core.URLField{Name: "catalogURL", System: true})
	col.Fields.Add(&core.URLField{Name: "manifestURL", System: true})
	col.Fields.Add(&core.AutodateField{Name: "created", System: true, OnCreate: true})
	col.Fields.Add(&core.AutodateField{Name: "updated", System: true, OnCreate: true, OnUpdate: true})

	col.AddIndex("idx_applications_handle", true, "handle", "")

	if err := txApp.Save(col); err != nil {
		return nil, err
	}

	return col, nil
}

func createApplicationVersionsCollection(txApp core.App, applications *core.Collection) (*core.Collection, error) {
	col := core.NewBaseCollection(core.CollectionNameApplicationVersions)
	col.System = true

	col.Fields.Add(&core.RelationField{
		Name:          "applicationRef",
		System:        true,
		Required:      true,
		MaxSelect:     1,
		CollectionId:  applications.Id,
		CascadeDelete: true,
	})
	col.Fields.Add(&core.TextField{Name: "version", System: true, Required: true, Max: 50})
	col.Fields.Add(&core.JSONField{Name: "manifest", System: true, Required: true})
	col.Fields.Add(&core.TextField{Name: "manifestDigest", System: true, Required: true})
	col.Fields.Add(&core.SelectField{
		Name:      "sourceFormat",
		System:    true,
		Required:  true,
		MaxSelect: 1,
		Values:    []string{core.ApplicationManifestFormatTOML, core.ApplicationManifestFormatJSON},
	})
	// the importer staff record id (if any; it is a plain ref so that the
	// immutable versions are not changed when the staff record is deleted)
	col.Fields.Add(&core.TextField{Name: "createdBy", System: true})
	col.Fields.Add(&core.AutodateField{Name: "created", System: true, OnCreate: true})

	col.AddIndex("idx_applicationVersions_version", true, "applicationRef,version", "")

	if err := txApp.Save(col); err != nil {
		return nil, err
	}

	return col, nil
}

func createApplicationInstallationsCollection(txApp core.App, applications *core.Collection, versions *core.Collection) (*core.Collection, error) {
	col := core.NewAuthCollection(core.CollectionNameApplicationInstallations)
	col.System = true

	// the installations authenticate only with their managed OAuth2 client (client_credentials)
	col.PasswordAuth.Enabled = false
	col.OTP.Enabled = false
	col.OAuth2.Enabled = false
	col.MFA.Enabled = false
	col.AuthAlert.Enabled = false
	col.AuthToken.Duration = core.ApplicationInstallationTokenDuration
	col.DefaultRoles = []string{} // never roles (non-nil to skip the default Customer role)

	// all API rules are nil (aka. records API access only with the applications permission)
	col.ListRule = nil
	col.ViewRule = nil
	col.CreateRule = nil
	col.UpdateRule = nil
	col.DeleteRule = nil
	col.AuthRule = nil
	col.ManageRule = nil

	if email, ok := col.Fields.GetByName(core.FieldNameEmail).(*core.EmailField); ok {
		email.Required = false
	}

	col.Fields.Add(&core.RelationField{
		Name:          "applicationRef",
		System:        true,
		Required:      true,
		MaxSelect:     1,
		CollectionId:  applications.Id,
		CascadeDelete: true,
	})
	col.Fields.Add(&core.RelationField{
		Name:         "versionRef",
		System:       true,
		Required:     true,
		MaxSelect:    1,
		CollectionId: versions.Id,
	})
	col.Fields.Add(&core.JSONField{Name: "permissions", System: true})
	// the installer staff record id (if any)
	col.Fields.Add(&core.TextField{Name: "installedBy", System: true})
	col.Fields.Add(&core.DateField{Name: "secretRotatedAt", System: true})
	// pending until the application acknowledged the install notification
	col.Fields.Add(&core.SelectField{
		Name:      "status",
		System:    true,
		Required:  true,
		MaxSelect: 1,
		Values:    []string{core.ApplicationInstallationStatusPending, core.ApplicationInstallationStatusActive},
	})
	// the signing secret shared by the installation managed webhooks
	col.Fields.Add(&core.TextField{Name: "webhookSecret", System: true, Hidden: true})
	col.Fields.Add(&core.AutodateField{Name: "created", System: true, OnCreate: true})
	col.Fields.Add(&core.AutodateField{Name: "updated", System: true, OnCreate: true, OnUpdate: true})

	// one installation per application (single tenant)
	col.AddIndex("idx_applicationInstallations_application", true, "applicationRef", "")
	col.AddIndex("idx_applicationInstallations_status", false, "status", "")

	if err := txApp.Save(col); err != nil {
		return nil, err
	}

	return col, nil
}

func addOAuth2ClientsApplicationFields(txApp core.App, installations *core.Collection) error {
	clients, err := txApp.FindCollectionByNameOrId(core.CollectionNameOAuth2Clients)
	if err != nil {
		return err
	}

	clients.Fields.Add(&core.RelationField{
		Name:          "applicationInstallationRef",
		System:        true,
		MaxSelect:     1,
		CollectionId:  installations.Id,
		CascadeDelete: true,
	})
	clients.Fields.Add(&core.SelectField{
		Name:      "grantTypes",
		System:    true,
		MaxSelect: len(core.OAuth2GrantTypes),
		Values:    core.OAuth2GrantTypes,
	})
	clients.AddIndex("idx_oauth2Clients_applicationInstallationRef", false, "applicationInstallationRef", "")

	if err := txApp.Save(clients); err != nil {
		return err
	}

	// the existing clients keep exactly their current behavior
	_, err = txApp.DB().Update(
		core.CollectionNameOAuth2Clients,
		dbx.Params{"grantTypes": types.JSONArray[string](core.OAuth2DefaultGrantTypes)},
		nil,
	).Execute()

	return err
}
