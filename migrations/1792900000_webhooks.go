package migrations

import (
	"github.com/lumm2509/pocketbomb/core"
)

// creates the webhook subscriptions system collection.
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		clients, err := txApp.FindCollectionByNameOrId(core.CollectionNameOAuth2Clients)
		if err != nil {
			return err
		}

		col := core.NewBaseCollection(core.CollectionNameWebhooks)
		col.System = true

		col.Fields.Add(&core.TextField{
			Name:     "name",
			System:   true,
			Required: true,
			Max:      255,
		})
		col.Fields.Add(&core.BoolField{
			Name:   "active",
			System: true,
		})
		col.Fields.Add(&core.TextField{
			Name:     "uri",
			System:   true,
			Required: true,
			Max:      2048,
		})
		// note: stored in plain text because it is required for the HMAC signatures
		col.Fields.Add(&core.TextField{
			Name:   "secret",
			System: true,
			Hidden: true,
			Max:    255,
		})
		col.Fields.Add(&core.JSONField{
			Name:   "topics",
			System: true,
		})
		col.Fields.Add(&core.TextField{
			Name:   "filter",
			System: true,
			Max:    3000,
		})
		col.Fields.Add(&core.JSONField{
			Name:   "fields",
			System: true,
		})
		col.Fields.Add(&core.TextField{
			Name:   "apiVersion",
			System: true,
			Max:    50,
		})
		col.Fields.Add(&core.RelationField{
			Name:          "client",
			System:        true,
			MaxSelect:     1,
			CollectionId:  clients.Id,
			CascadeDelete: true,
		})
		col.Fields.Add(&core.NumberField{
			Name:    "failureCount",
			System:  true,
			OnlyInt: true,
		})
		col.Fields.Add(&core.TextField{
			Name:   "disabledReason",
			System: true,
		})
		col.Fields.Add(&core.DateField{
			Name:   "lastSuccessAt",
			System: true,
		})
		col.Fields.Add(&core.DateField{
			Name:   "lastFailureAt",
			System: true,
		})
		col.Fields.Add(&core.AutodateField{
			Name:     "created",
			System:   true,
			OnCreate: true,
		})
		col.Fields.Add(&core.AutodateField{
			Name:     "updated",
			System:   true,
			OnCreate: true,
			OnUpdate: true,
		})
		// the non-Owner actor ("{collectionId}:{recordId}") that last created or changed the subscription
		col.Fields.Add(&core.TextField{Name: "actorRef", System: true})

		col.AddIndex("idx_webhooks_active", false, "active", "")
		col.AddIndex("idx_webhooks_client", false, "client", "client != ''")

		return txApp.Save(col)
	}, func(txApp core.App) error {
		return dropRawCollection(txApp, core.CollectionNameWebhooks)
	})
}
