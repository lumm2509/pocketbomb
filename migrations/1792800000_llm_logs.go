package migrations

import (
	"github.com/lumm2509/pocketbomb/core"
)

// creates the auxiliary db LLM usage logs table.
func init() {
	core.SystemMigrations.Add(&core.Migration{
		Up: func(txApp core.App) error {
			_, execErr := txApp.AuxDB().NewQuery(`
				CREATE TABLE IF NOT EXISTS {{_llmLogs}} (
					[[id]]             TEXT PRIMARY KEY DEFAULT ('r'||lower(hex(randomblob(7)))) NOT NULL,
					[[provider]]       TEXT DEFAULT "" NOT NULL,
					[[model]]          TEXT DEFAULT "" NOT NULL,
					[[profile]]        TEXT DEFAULT "" NOT NULL,
					[[stream]]         BOOLEAN DEFAULT FALSE NOT NULL,
					[[status]]         TEXT DEFAULT "" NOT NULL,
					[[error]]          TEXT DEFAULT "" NOT NULL,
					[[inputTokens]]    INTEGER DEFAULT 0 NOT NULL,
					[[outputTokens]]   INTEGER DEFAULT 0 NOT NULL,
					[[durationMs]]     INTEGER DEFAULT 0 NOT NULL,
					[[request]]        JSON DEFAULT NULL,
					[[response]]       JSON DEFAULT NULL,
					[[authCollection]] TEXT DEFAULT "" NOT NULL,
					[[authRecord]]     TEXT DEFAULT "" NOT NULL,
					[[ip]]             TEXT DEFAULT "" NOT NULL,
					[[meta]]           JSON DEFAULT "{}" NOT NULL,
					[[created]]        TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%fZ')) NOT NULL
				);

				CREATE INDEX IF NOT EXISTS idx_llmLogs_created on {{_llmLogs}} ([[created]]);
				CREATE INDEX IF NOT EXISTS idx_llmLogs_profile_auth_created on {{_llmLogs}} ([[profile]], [[authCollection]], [[authRecord]], [[created]]);
				CREATE INDEX IF NOT EXISTS idx_llmLogs_profile_ip_created on {{_llmLogs}} ([[profile]], [[ip]], [[created]]);
				CREATE INDEX IF NOT EXISTS idx_llmLogs_auth_created on {{_llmLogs}} ([[authRecord]], [[created]]);
				CREATE INDEX IF NOT EXISTS idx_llmLogs_model_created on {{_llmLogs}} ([[model]], [[created]]);
				CREATE INDEX IF NOT EXISTS idx_llmLogs_status on {{_llmLogs}} ([[status]]);
			`).Execute()

			return execErr
		},
		Down: func(txApp core.App) error {
			_, err := txApp.AuxDB().DropTable("_llmLogs").Execute()
			return err
		},
		ReapplyCondition: func(txApp core.App, runner *core.MigrationsRunner, fileName string) (bool, error) {
			// reapply only if the _llmLogs table doesn't exist
			exists := txApp.AuxHasTable("_llmLogs")
			return !exists, nil
		},
	})
}
