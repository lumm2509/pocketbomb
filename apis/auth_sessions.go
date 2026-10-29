package apis

import (
	"net/http"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/router"
)

// bindAuthSessionsApi registers the staff auth sessions management endpoints.
//
// The sessions are listed through the regular records API of the _authSessions
// system collection; changing them through the records API is Owner only (it could
// allow taking over an account) but ending (aka. revoking) a session isn't an account
// takeover and therefore it is allowed with the sessions write permission.
func bindAuthSessionsApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	sub := rg.Group("/sessions")
	sub.POST("/{id}/end", authSessionEnd).Bind(
		RequirePermission(core.PermissionResourceSessions, core.PermissionLevelWrite),
	)
}

// POST /api/sessions/{id}/end
//
// Ends the specified auth session (with the regular cascade: ending a root SSO session
// ends its non-offline children and ending any session ends the impersonations issued with it).
//
// The sessions of the staff members are subject to the no-escalation staff checks
// (a non-Owner can't end the sessions of an Owner or of a more privileged staff member).
func authSessionEnd(e *core.RequestEvent) error {
	session, err := e.App.FindAuthSessionById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("", err)
	}

	// note: a session without an existing actor record (e.g. a pending flow
	// session without an identified record) has no staff checks to apply
	if actor, err := e.App.FindRecordById(session.CollectionRef(), session.RecordRef()); err == nil {
		if err := core.CheckStaffRecordChange(e.App, e.ActorInfo(), actor); err != nil {
			return e.ForbiddenError("You are not allowed to end the sessions of this staff member.", err)
		}
	}

	if err := e.App.EndAuthSession(session, "Staff session end request"); err != nil {
		return e.BadRequestError("Failed to end the auth session.", err)
	}

	return e.NoContent(http.StatusNoContent)
}
