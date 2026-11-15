package migrations

import (
	"github.com/lumm2509/pocketbomb/core"
)

// OAuth2 protected resources (Resource Indicators, RFC 8707):
//   - adds _oauth2Clients.resources (the identifiers of the issuer resources, see
//     [core.OAuth2ServerConfig.Resources], the client could request JWT access tokens for;
//     the existing clients get none)
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		col, err := txApp.FindCollectionByNameOrId(core.CollectionNameOAuth2Clients)
		if err != nil {
			return err
		}

		col.Fields.Add(&core.JSONField{Name: "resources", System: true})

		return txApp.Save(col)
	}, func(txApp core.App) error {
		col, err := txApp.FindCollectionByNameOrId(core.CollectionNameOAuth2Clients)
		if err != nil {
			return err
		}

		col.Fields.RemoveByName("resources")

		// the regular validation doesn't allow removing system fields
		return txApp.SaveNoValidate(col)
	})
}
