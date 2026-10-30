package migrations

import (
	"github.com/lumm2509/pocketbomb/core"
)

// Adds the effective app proxy path of the application installations
// (unique among the installations that have one).
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		col, err := txApp.FindCollectionByNameOrId(core.CollectionNameApplicationInstallations)
		if err != nil {
			return err
		}

		col.Fields.Add(&core.TextField{Name: "proxyPrefix", System: true})
		col.Fields.Add(&core.TextField{Name: "proxySubpath", System: true})
		col.AddIndex("idx_applicationInstallations_proxy", true, "proxyPrefix, proxySubpath", "proxySubpath != ''")

		return txApp.Save(col)
	}, func(txApp core.App) error {
		col, err := txApp.FindCollectionByNameOrId(core.CollectionNameApplicationInstallations)
		if err != nil {
			return err
		}

		col.RemoveIndex("idx_applicationInstallations_proxy")
		col.Fields.RemoveByName("proxyPrefix")
		col.Fields.RemoveByName("proxySubpath")

		// the regular validation doesn't allow removing system fields
		return txApp.SaveNoValidate(col)
	})
}
