package apis

import (
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/hook"
)

// bindRecordAccessHooks registers the actor dependent checks of the system
// collections records API (incl. the batch API subrequests) and the
// enrich hook that hides the internal secret fields.
//
// The checks are bound with late priority so that they are applied on the
// final record state right before the save. They don't apply to the
// programmatic app.Save calls (the model invariants are enforced in core).
func bindRecordAccessHooks(app core.App) {
	bindRecordRequestCheck(app, core.CollectionNameRoles, recordRequestCreate|recordRequestUpdate, func(e *core.RecordRequestEvent) error {
		if err := core.CheckRoleChange(e.App, e.ActorInfo(), e.Record, false); err != nil {
			return e.ForbiddenError("You are not allowed to perform this role change.", err)
		}
		return nil
	})
	bindRecordRequestCheck(app, core.CollectionNameRoles, recordRequestDelete, func(e *core.RecordRequestEvent) error {
		if err := core.CheckRoleChange(e.App, e.ActorInfo(), e.Record, true); err != nil {
			return e.ForbiddenError("You are not allowed to perform this role change.", err)
		}
		return nil
	})

	bindRecordRequestCheck(app, core.CollectionNameRoleAssignments, recordRequestCreate|recordRequestUpdate|recordRequestDelete, func(e *core.RecordRequestEvent) error {
		if err := core.CheckRoleAssignmentChange(e.App, e.ActorInfo(), e.Record); err != nil {
			return e.ForbiddenError("You are not allowed to perform this role assignment change.", err)
		}
		return nil
	})

	bindRecordRequestCheck(app, core.CollectionNameSuperusers, recordRequestUpdate|recordRequestDelete, func(e *core.RecordRequestEvent) error {
		if err := core.CheckStaffRecordChange(e.App, e.ActorInfo(), e.Record); err != nil {
			return e.ForbiddenError("You are not allowed to change this staff member.", err)
		}
		return nil
	})

	bindRecordRequestCheck(app, core.CollectionNameOAuth2Clients, recordRequestCreate|recordRequestUpdate|recordRequestDelete, func(e *core.RecordRequestEvent) error {
		if err := core.CheckOAuth2ClientChange(e.App, e.ActorInfo(), e.Record); err != nil {
			return e.ForbiddenError("Only the Owners could manage the _superusers OAuth2 clients and the first-party clients.", err)
		}
		return nil
	})

	bindRecordRequestCheck(app, core.CollectionNameWebhooks, recordRequestCreate|recordRequestUpdate, func(e *core.RecordRequestEvent) error {
		info := e.ActorInfo()

		if err := core.CheckWebhookChange(e.App, info, e.Record); err != nil {
			return e.ForbiddenError("Only the Owners could subscribe to the system collections topics.", err)
		}

		// a subscription with topics the actor can't view (or a filter it can't use) can't be changed (no hijacking)
		if !e.Record.IsNew() && !core.CanAccessWebhook(e.App, info, e.Record.Original()) {
			return e.ForbiddenError("You are not allowed to change a subscription with topics you can't view or a filter you can't use.", nil)
		}

		if err := core.CheckWebhookTopicsAccess(e.App, info, e.Record.GetStringSlice("topics")); err != nil {
			return e.BadRequestError("You are not allowed to subscribe to the records you can't view.", err)
		}

		if err := core.CheckWebhookFilterAccess(e.App, info, e.Record); err != nil {
			return e.BadRequestError("You are not allowed to filter by the fields or collections you can't access.", err)
		}

		// the actor of the subscription (never from the request body)
		e.Record.Set("actorRef", core.WebhookChangeActorRef(e.App, info, e.Record))

		return nil
	})

	// note: create/update of the applications collections via the records API are Owner only (see [core.Authorize])
	bindRecordRequestCheck(app, core.CollectionNameApplicationInstallations, recordRequestDelete, func(e *core.RecordRequestEvent) error {
		if err := core.CheckApplicationInstallationChange(e.App, e.ActorInfo(), e.Record); err != nil {
			return e.ForbiddenError("You are not allowed to uninstall this application (you must hold every permission of its grant).", err)
		}
		return nil
	})
	bindRecordRequestCheck(app, core.CollectionNameApplications, recordRequestDelete, func(e *core.RecordRequestEvent) error {
		installation, err := e.App.FindApplicationInstallationByApplication(e.Record.Id)
		if err != nil {
			return nil
		}
		if err := core.CheckApplicationInstallationChange(e.App, e.ActorInfo(), installation.Record); err != nil {
			return e.ForbiddenError("You are not allowed to delete this installed application (you must hold every permission of its grant).", err)
		}
		return nil
	})

	// never expose the internal secret fields (e.g. hashes), not even to the Owners
	app.OnRecordEnrich().Bind(&hook.Handler[*core.RecordEnrichEvent]{
		Id: "__pbInternalFieldsEnrich__",
		Func: func(e *core.RecordEnrichEvent) error {
			err := e.Next()

			// hide after the default enrich finalizer (it unhides all fields for the rules bypass)
			if fields := core.InternalFieldNames(e.Record.Collection()); len(fields) > 0 {
				e.Record.Hide(fields...)
			}

			return err
		},
	})
}

const (
	recordRequestCreate = 1 << iota
	recordRequestUpdate
	recordRequestDelete
)

func bindRecordRequestCheck(app core.App, collection string, actions int, check func(e *core.RecordRequestEvent) error) {
	handler := func() *hook.Handler[*core.RecordRequestEvent] {
		return &hook.Handler[*core.RecordRequestEvent]{
			Id: "__pbAccessCheck" + collection + "__",
			Func: func(e *core.RecordRequestEvent) error {
				if err := check(e); err != nil {
					return err
				}
				return e.Next()
			},
			Priority: 9999,
		}
	}

	if actions&recordRequestCreate != 0 {
		app.OnRecordCreateRequest(collection).Bind(handler())
	}
	if actions&recordRequestUpdate != 0 {
		app.OnRecordUpdateRequest(collection).Bind(handler())
	}
	if actions&recordRequestDelete != 0 {
		app.OnRecordDeleteRequest(collection).Bind(handler())
	}
}
