package apis

import (
	"errors"
	"net/http"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/router"
)

// graphqlSchemaMaxSize is the max size of a submitted schema (in bytes).
const graphqlSchemaMaxSize = 1 << 20

var errGraphQLSchemaDryRun = errors.New("graphql schema dry run")

func bindGraphQLSchemaApi(rg *router.RouterGroup[*core.RequestEvent]) {
	write := RequirePermission(core.PermissionResourceCollections, core.PermissionLevelWrite)

	sub := rg.Group("/graphql/schema")
	sub.GET("", graphqlSchemaGet).Bind(write)
	sub.POST("/plan", graphqlSchemaPlanCreate).Bind(write)
	sub.POST("/apply", graphqlSchemaApply).Bind(write)
}

// graphqlSchemaCanApply reports whether a migrations writer is available (see [core.StoreKeyGraphQLSchemaMigrationWriter]).
func graphqlSchemaCanApply(app core.App) bool {
	return app.Store().Has(core.StoreKeyGraphQLSchemaMigrationWriter)
}

const graphqlSchemaNoWriterMessage = "The schema can't be applied because the migrations can't be generated (the migratecmd plugin with automigrate enabled is required)."

// GET /api/graphql/schema
//
// With ?source=derived it returns the schema of the current collections instead of the stored one.
//
// drifted reports whether the stored schema no longer describes the current
// collections (applying it as it is would change them).
func graphqlSchemaGet(e *core.RequestEvent) error {
	stored := e.App.Settings().GraphQL.Schema

	if stored == "" || e.Request.URL.Query().Get("source") == "derived" {
		derived, err := graphqlDeriveSchema(e.App)
		if err != nil {
			return e.InternalServerError("Failed to derive the schema.", err)
		}

		return e.JSON(http.StatusOK, map[string]any{
			"schema":   derived,
			"source":   "derived",
			"canApply": graphqlSchemaCanApply(e.App),
			"drifted":  false,
		})
	}

	plan, err := newGraphQLSchemaPlan(e.App, stored)
	if err != nil {
		return e.InternalServerError("Failed to compare the schema.", err)
	}

	return e.JSON(http.StatusOK, map[string]any{
		"schema":   stored,
		"source":   "stored",
		"canApply": graphqlSchemaCanApply(e.App),
		"drifted":  len(plan.Changes) > 0 || len(plan.Errors) > 0,
	})
}

type graphqlSchemaForm struct {
	Schema           string `json:"schema"`
	PlanHash         string `json:"planHash"`
	AllowDestructive bool   `json:"allowDestructive"`
}

func bindGraphQLSchemaForm(e *core.RequestEvent) (*graphqlSchemaForm, error) {
	form := &graphqlSchemaForm{}
	if err := e.BindBody(form); err != nil {
		return nil, e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	if len(form.Schema) > graphqlSchemaMaxSize {
		return nil, e.BadRequestError("The schema is too large.", nil)
	}

	return form, nil
}

// POST /api/graphql/schema/plan
//
// The target collections are also saved (and always rolled back)
// so that the plan reports the regular collection validation errors.
func graphqlSchemaPlanCreate(e *core.RequestEvent) error {
	form, err := bindGraphQLSchemaForm(e)
	if err != nil {
		return err
	}

	plan, err := newGraphQLSchemaPlan(e.App, form.Schema)
	if err != nil {
		return e.InternalServerError("Failed to create the plan.", err)
	}

	if len(plan.Errors) == 0 && (len(plan.upsert) > 0 || len(plan.remove) > 0) {
		txErr := e.App.RunInTransaction(func(txApp core.App) error {
			if err := txApp.ApplyCollectionChanges(plan.upsert, plan.remove); err != nil {
				return err
			}
			return errGraphQLSchemaDryRun
		})
		if reloadErr := e.App.ReloadCachedCollections(); reloadErr != nil {
			return e.InternalServerError("Failed to reload the collections.", reloadErr)
		}
		if txErr != nil && !errors.Is(txErr, errGraphQLSchemaDryRun) {
			plan.Errors = append(plan.Errors, graphqlSchemaError{Message: txErr.Error()})
		}
	}

	if len(plan.Errors) > 0 {
		plan.PlanHash = ""
	}

	return e.JSON(http.StatusOK, plan)
}

// POST /api/graphql/schema/apply
func graphqlSchemaApply(e *core.RequestEvent) error {
	form, err := bindGraphQLSchemaForm(e)
	if err != nil {
		return err
	}

	// nothing is changed without a migrations writer
	if !graphqlSchemaCanApply(e.App) {
		return e.Error(http.StatusConflict, graphqlSchemaNoWriterMessage, nil)
	}

	plan, err := newGraphQLSchemaPlan(e.App, form.Schema)
	if err != nil {
		return e.InternalServerError("Failed to create the plan.", err)
	}

	if len(plan.Errors) > 0 {
		return e.BadRequestError("Invalid schema.", map[string]any{"schema": plan.Errors})
	}

	if form.PlanHash == "" || form.PlanHash != plan.PlanHash {
		return e.Error(http.StatusConflict, "The collections or the schema have changed since the preview (preview the changes again).", nil)
	}

	if plan.isDestructive() && !form.AllowDestructive {
		return e.BadRequestError("The plan has destructive changes that must be explicitly allowed.", nil)
	}

	old := make(map[string]*core.Collection, len(plan.upsert))
	for _, c := range plan.upsert {
		if existing, err := e.App.FindCollectionByNameOrId(c.Id); err == nil {
			old[c.Id] = existing
		}
	}

	originalApp := e.App
	defer func() {
		e.App = originalApp
	}()

	event := new(core.GraphQLSchemaApplyRequestEvent)
	event.RequestEvent = e
	event.Schema = form.Schema
	event.PlanHash = plan.PlanHash
	event.AllowDestructive = form.AllowDestructive

	txErr := e.App.RunInTransaction(func(txApp core.App) error {
		e.App = txApp

		err := txApp.OnGraphQLSchemaApplyRequest().Trigger(event, func(ev *core.GraphQLSchemaApplyRequestEvent) error {
			if err := ev.App.ApplyCollectionChanges(plan.upsert, plan.remove); err != nil {
				return err
			}

			for _, c := range plan.upsert {
				fresh, err := ev.App.FindCollectionByNameOrId(c.Id)
				if err != nil {
					return err
				}
				ev.Changes = append(ev.Changes, core.GraphQLSchemaCollectionChange{Old: old[c.Id], New: fresh})
			}
			for _, c := range plan.remove {
				ev.Changes = append(ev.Changes, core.GraphQLSchemaCollectionChange{Old: c})
			}

			settings, err := ev.App.Settings().Clone()
			if err != nil {
				return err
			}
			settings.GraphQL.Schema = ev.Schema

			return ev.App.Save(settings)
		})
		if err != nil {
			return err
		}

		if len(event.Changes) > 0 && event.MigrationFile == "" {
			return errors.New(graphqlSchemaNoWriterMessage)
		}

		return nil
	})
	e.App = originalApp
	if txErr != nil {
		if reloadErr := e.App.ReloadCachedCollections(); reloadErr != nil {
			return e.InternalServerError("Failed to reload the collections.", reloadErr)
		}
		_ = e.App.ReloadSettings()

		return firstApiError(txErr, e.BadRequestError("Failed to apply the schema.", txErr))
	}

	return e.JSON(http.StatusOK, map[string]any{
		"changes":       plan.Changes,
		"migrationFile": event.MigrationFile,
	})
}
