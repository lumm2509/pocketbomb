package apis

import (
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/search"
	"github.com/pocketbase/dbx"
)

// The records read path shared by the records list/view API, the GraphQL API and the expand:
//   - [core.Authorize] (incl. the API key ceiling and the third-party token scopes)
//   - the collection List/View API rule (unless bypassed)
//   - the client filter/sort restrictions (superuser only rule fields, hidden, secret and joined collection fields)
//   - the OnRecordEnrich hooks and the visibility flags (hidden fields and email visibility)

// recordsListProvider returns the records list search provider of the request actor
// with the collection ListRule and the client filter/sort restrictions applied to the provided query.
//
// The client filter and sort are only checked; the caller adds them to the provider.
func recordsListProvider(
	e *core.RequestEvent,
	requestInfo *core.RequestInfo,
	collection *core.Collection,
	query *dbx.SelectQuery,
	clientFilter string,
	clientSort string,
) (*search.Provider, core.Access, error) {
	access, err := recordCollectionAccess(e, requestInfo, collection, core.PermissionActionList)
	if err != nil {
		return nil, access, err
	}
	bypassRules := access.BypassRules

	if collection.ListRule == nil && !bypassRules {
		return nil, access, e.ForbiddenError("Only superusers can perform this action.", nil)
	}

	// forbid users and guests to query special filter/sort fields
	err = checkForSuperuserOnlyRuleFields(bypassRules, clientFilter, clientSort)
	if err != nil {
		return nil, access, err
	}

	fieldsResolver := core.NewRecordFieldResolver(e.App, collection, requestInfo, true)

	if !bypassRules && collection.ListRule != nil && *collection.ListRule != "" {
		expr, err := search.FilterData(*collection.ListRule).BuildExpr(fieldsResolver)
		if err != nil {
			return nil, access, err
		}
		query.AndWhere(expr)

		// will be applied by the search provider right before executing the query
		// fieldsResolver.UpdateQuery(query)
	}

	// hidden fields are searchable only by the actors with bypass permission (e.g. Owners)
	// and the secret fields (e.g. tokenKey) only by the Owners
	fieldsResolver.SetAllowHiddenFields(bypassRules)
	fieldsResolver.SetDenySecretFields(!requestInfo.IsOwner(e.App))

	// the client-side filter/sort can't reference collections that the actor can't access
	// (note: set after the ListRule expression is built so that the rule joins are not restricted)
	if !requestInfo.IsOwner(e.App) {
		fieldsResolver.SetJoinCollectionCheck(core.ClientFilterJoinCheck(e.App, requestInfo))
	}

	searchProvider := search.NewProvider(fieldsResolver).Query(query)

	// use rowid when available to minimize the need of a covering index with the "id" field
	if !collection.IsView() {
		searchProvider.CountCol("_rowid_")
	}

	return searchProvider, access, nil
}

// throttleEmptyFilteredList adds a randomized throttle in case of too many empty search filter attempts.
//
// This is just for extra precaution since security researches raised concern regarding the possibility of eventual
// timing attacks because the List API rule acts also as filter and executes in a single run with the client-side filters.
// This is by design and it is an accepted trade off between performance, usability and correctness.
//
// While technically the below doesn't fully guarantee protection against filter timing attacks, in practice combined with the network latency it makes them even less feasible.
// A properly configured rate limiter or individual fields Hidden checks are better suited if you are really concerned about eventual information disclosure by side-channel attacks.
//
// In all cases it doesn't really matter that much because it doesn't affect the builtin PocketBase security sensitive fields (e.g. password and tokenKey) since they
// are not client-side filterable and in the few places where they need to be compared against an external value, a constant time check is used.
func throttleEmptyFilteredList(e *core.RequestEvent, collection *core.Collection, bypassRules bool, clientFilter string, totalRecords int) {
	if !bypassRules &&
		(collection.ListRule != nil && *collection.ListRule != "") &&
		clientFilter != "" &&
		totalRecords == 0 &&
		checkRateLimit(e, "@pb_list_timing_check_"+collection.Id, listTimingRateLimitRule) != nil {
		e.App.Logger().Debug("Randomized throttle because of too many failed searches", "collectionId", collection.Id)
		randomizedThrottle(500)
	}
}

// recordViewRuleFunc returns the records query filter of the view API of the request actor
// (the collection ViewRule unless bypassed).
func recordViewRuleFunc(e *core.RequestEvent, requestInfo *core.RequestInfo, collection *core.Collection) (func(q *dbx.SelectQuery) error, error) {
	access, err := recordCollectionAccess(e, requestInfo, collection, core.PermissionActionView)
	if err != nil {
		return nil, err
	}

	if collection.ViewRule == nil && !access.BypassRules {
		return nil, e.ForbiddenError("Only superusers can perform this action.", nil)
	}

	return func(q *dbx.SelectQuery) error {
		if !access.BypassRules && collection.ViewRule != nil && *collection.ViewRule != "" {
			resolver := core.NewRecordFieldResolver(e.App, collection, requestInfo, true)

			expr, err := search.FilterData(*collection.ViewRule).BuildExpr(resolver)
			if err != nil {
				return err
			}

			q.AndWhere(expr)

			err = resolver.UpdateQuery(q)
			if err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// enrichRecords triggers the OnRecordEnrich hooks and then applies the default
// visibility flags and the provided expands to the records (see [EnrichRecords]).
//
// Note: Expects all records to be from the same collection!
func enrichRecords(app core.App, requestInfo *core.RequestInfo, records []*core.Record, expands ...string) error {
	if len(records) == 0 {
		return nil
	}

	return triggerRecordEnrichHooks(app, requestInfo, records, func() error {
		err := defaultEnrichRecords(app, requestInfo, records, expands...)
		if err != nil {
			// only log because it is not critical
			app.Logger().Warn("failed to apply default enriching", "error", err)
		}

		return nil
	})
}
