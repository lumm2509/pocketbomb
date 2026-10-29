package migrations

import (
	"github.com/lumm2509/pocketbomb/core"
)

// API keys (phase K):
//   - creates the _apiKeys system collection (the OAuth2 clients credentials identifying
//     the client/channel, never an actor; public browser-safe keys and private server-only keys)
//
// The keys are managed through the /api/oauth2/clients/{id}/api-keys endpoints
// (all API rules are nil; the staff access is mapped to the oauth2_clients resource).
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		clients, err := txApp.FindCollectionByNameOrId(core.CollectionNameOAuth2Clients)
		if err != nil {
			return err
		}

		col := core.NewBaseCollection(core.CollectionNameAPIKeys)
		col.System = true

		col.Fields.Add(&core.TextField{Name: "name", System: true, Required: true, Max: 100})
		col.Fields.Add(&core.RelationField{
			Name:          "clientRef",
			System:        true,
			Required:      true,
			MaxSelect:     1,
			CollectionId:  clients.Id,
			CascadeDelete: true,
		})
		col.Fields.Add(&core.SelectField{
			Name:      "kind",
			System:    true,
			Required:  true,
			MaxSelect: 1,
			Values:    []string{core.APIKeyKindPublic, core.APIKeyKindPrivate},
		})
		// private keys only
		col.Fields.Add(&core.SelectField{
			Name:      "buyerContext",
			System:    true,
			MaxSelect: 1,
			Values:    []string{core.APIKeyBuyerContextRequired, core.APIKeyBuyerContextNone},
		})
		col.Fields.Add(&core.TextField{Name: "tokenHash", System: true, Required: true, Hidden: true})
		col.Fields.Add(&core.TextField{Name: "tokenPrefix", System: true, Required: true, Max: 20})
		// the plain value of the public keys (they are public; always empty for the private keys)
		col.Fields.Add(&core.TextField{Name: "token", System: true, Max: 100})
		col.Fields.Add(&core.JSONField{Name: "permissions", System: true})
		// public keys only
		col.Fields.Add(&core.JSONField{Name: "allowedOrigins", System: true})
		col.Fields.Add(&core.BoolField{Name: "disabled", System: true})
		col.Fields.Add(&core.DateField{Name: "expiresAt", System: true})
		col.Fields.Add(&core.DateField{Name: "lastUsedAt", System: true})
		// the creator staff record id (a plain ref so that the key is not changed when the staff record is deleted)
		col.Fields.Add(&core.TextField{Name: "createdBy", System: true})
		col.Fields.Add(&core.AutodateField{Name: "created", System: true, OnCreate: true})
		col.Fields.Add(&core.AutodateField{Name: "updated", System: true, OnCreate: true, OnUpdate: true})

		col.AddIndex("idx_apiKeys_tokenHash", true, "tokenHash", "")
		col.AddIndex("idx_apiKeys_clientRef", false, "clientRef", "")

		return txApp.Save(col)
	}, func(txApp core.App) error {
		return dropRawCollection(txApp, core.CollectionNameAPIKeys)
	})
}
