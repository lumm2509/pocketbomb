package migrations

import (
	"github.com/lumm2509/pocketbomb/core"
)

// creates the auxiliary db webhook deliveries (queue + log) table.
func init() {
	core.SystemMigrations.Add(&core.Migration{
		Up: func(txApp core.App) error {
			_, execErr := txApp.AuxDB().NewQuery(`
				CREATE TABLE IF NOT EXISTS {{_webhookDeliveries}} (
					[[id]]              TEXT PRIMARY KEY DEFAULT ('r'||lower(hex(randomblob(7)))) NOT NULL,
					[[webhook]]         TEXT DEFAULT "" NOT NULL,
					[[eventId]]         TEXT DEFAULT "" NOT NULL,
					[[topic]]           TEXT DEFAULT "" NOT NULL,
					[[apiVersion]]      TEXT DEFAULT "" NOT NULL,
					[[triggeredAt]]     TEXT DEFAULT "" NOT NULL,
					[[status]]          TEXT DEFAULT "pending" NOT NULL,
					[[attempts]]        INTEGER DEFAULT 0 NOT NULL,
					[[nextAttemptAt]]   TEXT DEFAULT "" NOT NULL,
					[[leaseUntil]]      TEXT DEFAULT "" NOT NULL,
					[[leaseToken]]      TEXT DEFAULT "" NOT NULL,
					[[payload]]         JSON DEFAULT NULL,
					[[requestHeaders]]  JSON DEFAULT "{}" NOT NULL,
					[[requestBody]]     TEXT DEFAULT "" NOT NULL,
					[[responseStatus]]  INTEGER DEFAULT 0 NOT NULL,
					[[responseHeaders]] JSON DEFAULT "{}" NOT NULL,
					[[responseBody]]    TEXT DEFAULT "" NOT NULL,
					[[error]]           TEXT DEFAULT "" NOT NULL,
					[[durationMs]]      INTEGER DEFAULT 0 NOT NULL,
					[[test]]            BOOLEAN DEFAULT FALSE NOT NULL,
					[[redeliveryOf]]    TEXT DEFAULT "" NOT NULL,
					[[created]]         TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%fZ')) NOT NULL,
					[[updated]]         TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%fZ')) NOT NULL
				);

				CREATE INDEX IF NOT EXISTS idx_webhookDeliveries_due on {{_webhookDeliveries}} ([[status]], [[nextAttemptAt]]);
				CREATE INDEX IF NOT EXISTS idx_webhookDeliveries_created on {{_webhookDeliveries}} ([[created]]);
				CREATE INDEX IF NOT EXISTS idx_webhookDeliveries_webhook_created on {{_webhookDeliveries}} ([[webhook]], [[created]]);
				CREATE INDEX IF NOT EXISTS idx_webhookDeliveries_topic_created on {{_webhookDeliveries}} ([[topic]], [[created]]);
				CREATE INDEX IF NOT EXISTS idx_webhookDeliveries_status_created on {{_webhookDeliveries}} ([[status]], [[created]]);
				CREATE INDEX IF NOT EXISTS idx_webhookDeliveries_eventId on {{_webhookDeliveries}} ([[eventId]]);
				CREATE INDEX IF NOT EXISTS idx_webhookDeliveries_leaseToken on {{_webhookDeliveries}} ([[leaseToken]]) WHERE [[leaseToken]] != '';
			`).Execute()

			return execErr
		},
		Down: func(txApp core.App) error {
			_, err := txApp.AuxDB().DropTable(core.WebhookDeliveriesTableName).Execute()
			return err
		},
		ReapplyCondition: func(txApp core.App, runner *core.MigrationsRunner, fileName string) (bool, error) {
			// reapply only if the _webhookDeliveries table doesn't exist
			exists := txApp.AuxHasTable(core.WebhookDeliveriesTableName)
			return !exists, nil
		},
	})
}
