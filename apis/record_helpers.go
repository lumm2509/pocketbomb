package apis

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/mails"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/routine"
	"github.com/lumm2509/pocketbomb/tools/search"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

const (
	expandQueryParam = "expand"
	fieldsQueryParam = "fields"
)

// checkRecordAuthAllowed checks whether the specified auth record
// is allowed to authenticate in the current request context
// (superuser IPs whitelist and collection AuthRule).
func checkRecordAuthAllowed(e *core.RequestEvent, authRecord *core.Record) error {
	if authRecord.IsSuperuser() {
		allowedIPs := e.App.Settings().SuperuserIPs
		if len(allowedIPs) > 0 && !isIPInList(allowedIPs, e.RealIP()) {
			return e.ForbiddenError("", errors.New("superuser IP is not whitelisted"))
		}
	}

	requestInfo, err := e.RequestInfo()
	if err != nil {
		return err
	}

	ok, err := e.App.CanAccessRecord(authRecord, requestInfo, authRecord.Collection().AuthRule)
	if !ok {
		return firstApiError(err, e.ForbiddenError("The request doesn't satisfy the collection requirements to authenticate.", err))
	}

	return nil
}

// wantsMFA checks whether to enable MFA for the specified auth record based on its MFA rule
// (note: returns true even in case of an error as a safer default).
func wantsMFA(e *core.RequestEvent, record *core.Record) (bool, error) {
	rule := record.Collection().MFA.Rule
	if rule == "" {
		return true, nil
	}

	requestInfo, err := e.RequestInfo()
	if err != nil {
		return true, err
	}

	var exists int

	query := e.App.RecordQuery(record.Collection()).
		Select("(1)").
		AndWhere(dbx.HashExp{record.Collection().Name + ".id": record.Id})

	// parse and apply the access rule filter
	resolver := core.NewRecordFieldResolver(e.App, record.Collection(), requestInfo, true)
	expr, err := search.FilterData(rule).BuildExpr(resolver)
	if err != nil {
		return true, err
	}

	err = resolver.UpdateQuery(query)
	if err != nil {
		return true, err
	}

	err = query.AndWhere(expr).Limit(1).Row(&exists)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return true, err
	}

	return exists > 0, nil
}

// EnrichRecord parses the request context and enrich the provided record:
//   - expands relations (if defaultExpands and/or ?expand query param is set)
//   - ensures that the emails of the auth record and its expanded auth relations
//     are visible only for the current logged superuser, record owner or record with manage access
func EnrichRecord(e *core.RequestEvent, record *core.Record, defaultExpands ...string) error {
	return EnrichRecords(e, []*core.Record{record}, defaultExpands...)
}

// EnrichRecords parses the request context and enriches the provided records:
//   - expands relations (if defaultExpands and/or ?expand query param is set)
//   - ensures that the emails of the auth records and their expanded auth relations
//     are visible only for the current logged superuser, record owner or record with manage access
//
// Note: Expects all records to be from the same collection!
func EnrichRecords(e *core.RequestEvent, records []*core.Record, defaultExpands ...string) error {
	if len(records) == 0 {
		return nil
	}

	info, err := e.RequestInfo()
	if err != nil {
		return err
	}

	expands := defaultExpands
	if param := info.Query[expandQueryParam]; param != "" {
		expands = append(expands, strings.Split(param, ",")...)
	}

	return enrichRecords(e.App, info, records, expands...)
}

type iterator[T any] struct {
	items []T
	index int
}

func (ri *iterator[T]) next() T {
	var item T

	if ri.index < len(ri.items) {
		item = ri.items[ri.index]
		ri.index++
	}

	return item
}

func triggerRecordEnrichHooks(app core.App, requestInfo *core.RequestInfo, records []*core.Record, finalizer func() error) error {
	it := iterator[*core.Record]{items: records}

	enrichHook := app.OnRecordEnrich()

	event := new(core.RecordEnrichEvent)
	event.App = app
	event.RequestInfo = requestInfo

	var iterate func(record *core.Record) error
	iterate = func(record *core.Record) error {
		if record == nil {
			return nil
		}

		event.Record = record

		return enrichHook.Trigger(event, func(ee *core.RecordEnrichEvent) error {
			next := it.next()
			if next == nil {
				if finalizer != nil {
					return finalizer()
				}
				return nil
			}

			event.App = ee.App // in case it was replaced with a transaction
			event.Record = next

			err := iterate(next)

			event.App = app
			event.Record = record

			return err
		})
	}

	return iterate(it.next())
}

func defaultEnrichRecords(app core.App, requestInfo *core.RequestInfo, records []*core.Record, expands ...string) error {
	err := autoResolveRecordsFlags(app, records, requestInfo)
	if err != nil {
		return fmt.Errorf("failed to resolve records flags: %w", err)
	}

	if len(expands) > 0 {
		expandErrs := app.ExpandRecords(records, expands, expandFetch(app, requestInfo))
		if len(expandErrs) > 0 {
			errsSlice := make([]error, 0, len(expandErrs))
			for key, err := range expandErrs {
				errsSlice = append(errsSlice, fmt.Errorf("failed to expand %q: %w", key, err))
			}
			return fmt.Errorf("failed to expand records: %w", errors.Join(errsSlice...))
		}
	}

	return nil
}

// expandFetch is the records fetch function that is used to expand related records.
func expandFetch(app core.App, originalRequestInfo *core.RequestInfo) core.ExpandFetchFunc {
	// shallow clone the provided request info to set an "expand" context
	requestInfoClone := *originalRequestInfo
	requestInfoPtr := &requestInfoClone
	requestInfoPtr.Context = core.RequestInfoContextExpand

	return func(relCollection *core.Collection, relIds []string) ([]*core.Record, error) {
		records, findErr := app.FindRecordsByIds(relCollection.Id, relIds, func(q *dbx.SelectQuery) error {
			access := requestInfoPtr.CollectionAccess(app, relCollection, core.PermissionActionView)
			if !access.Allowed {
				return fmt.Errorf("insufficient permissions to view collection %q records", relCollection.Name)
			}

			if access.BypassRules {
				return nil // e.g. Owners can access everything
			}

			if relCollection.ViewRule == nil {
				return fmt.Errorf("only superusers can view collection %q records", relCollection.Name)
			}

			if *relCollection.ViewRule != "" {
				resolver := core.NewRecordFieldResolver(app, relCollection, requestInfoPtr, true)

				expr, err := search.FilterData(*(relCollection.ViewRule)).BuildExpr(resolver)
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
		})
		if findErr != nil {
			return nil, findErr
		}

		enrichErr := triggerRecordEnrichHooks(app, requestInfoPtr, records, func() error {
			if err := autoResolveRecordsFlags(app, records, requestInfoPtr); err != nil {
				// non-critical error
				app.Logger().Warn("Failed to apply autoResolveRecordsFlags for the expanded records", "error", err)
			}

			return nil
		})
		if enrichErr != nil {
			return nil, enrichErr
		}

		return records, nil
	}
}

// autoResolveRecordsFlags resolves various visibility flags of the provided records.
//
// Currently it enables:
// - export of hidden fields if the current auth model is a superuser
// - email export ignoring the emailVisibity checks if the current auth model is superuser, owner or a "manager".
//
// Note: Expects all records to be from the same collection!
func autoResolveRecordsFlags(app core.App, records []*core.Record, requestInfo *core.RequestInfo) error {
	if len(records) == 0 {
		return nil // nothing to resolve
	}

	if requestInfo.CollectionAccess(app, records[0].Collection(), core.PermissionActionView).BypassRules {
		hiddenFields := records[0].Collection().Fields.FieldNames()

		// the secret fields (e.g. tokenKey) are exported only for the Owners
		if !requestInfo.IsOwner(app) {
			secrets := core.SecretFieldNames(records[0].Collection())
			hiddenFields = slices.DeleteFunc(hiddenFields, func(name string) bool {
				return slices.Contains(secrets, name)
			})
		}

		for _, rec := range records {
			rec.Unhide(hiddenFields...)
			rec.IgnoreEmailVisibility(true)
		}
	}

	// additional emailVisibility checks
	// ---------------------------------------------------------------
	if !records[0].Collection().IsAuth() {
		return nil // not auth collection records
	}

	collection := records[0].Collection()

	mappedRecords := make(map[string]*core.Record, len(records))
	recordIds := make([]any, len(records))
	for i, rec := range records {
		mappedRecords[rec.Id] = rec
		recordIds[i] = rec.Id
	}

	if requestInfo.Auth != nil && mappedRecords[requestInfo.Auth.Id] != nil {
		mappedRecords[requestInfo.Auth.Id].IgnoreEmailVisibility(true)
	}

	if collection.ManageRule == nil || *collection.ManageRule == "" {
		return nil // no manage rule to check
	}

	// fetch the ids of the managed records
	// ---
	managedIds := []string{}

	query := app.RecordQuery(collection).
		Select(app.ConcurrentDB().QuoteSimpleColumnName(collection.Name) + ".id").
		AndWhere(dbx.In(app.ConcurrentDB().QuoteSimpleColumnName(collection.Name)+".id", recordIds...))

	resolver := core.NewRecordFieldResolver(app, collection, requestInfo, true)
	expr, err := search.FilterData(*collection.ManageRule).BuildExpr(resolver)
	if err != nil {
		return err
	}

	query.AndWhere(expr)

	err = resolver.UpdateQuery(query)
	if err != nil {
		return err
	}

	err = query.Column(&managedIds)
	if err != nil {
		return err
	}
	// ---

	// ignore the email visibility check for the managed records
	for _, id := range managedIds {
		if rec, ok := mappedRecords[id]; ok {
			rec.IgnoreEmailVisibility(true)
		}
	}

	return nil
}

var superuserOnlyRuleFields = []string{"@collection.", "@request."}

// checkForSuperuserOnlyRuleFields loosely checks and returns an error if
// the provided client filter/sort expressions contain rule fields that only
// the actors with bypass permission (e.g. Owners) can use.
func checkForSuperuserOnlyRuleFields(bypassRules bool, filterOrSortExprs ...string) error {
	if bypassRules {
		return nil
	}

	for _, v := range filterOrSortExprs {
		if v == "" {
			continue
		}

		for _, field := range superuserOnlyRuleFields {
			if strings.Contains(v, field) {
				return router.NewForbiddenError("Only superusers can filter by "+field, nil)
			}
		}
	}

	return nil
}

// firstApiError returns the first ApiError from the errors list
// (this is used usually to prevent unnecessary wraping and to allow bubling ApiError from nested hooks)
//
// If no ApiError is found, returns a default "Internal server" error.
func firstApiError(errs ...error) *router.ApiError {
	var apiErr *router.ApiError
	var ok bool

	for _, err := range errs {
		if err == nil {
			continue
		}

		// quick assert to avoid the reflection checks
		apiErr, ok = err.(*router.ApiError)
		if ok {
			return apiErr
		}

		// nested/wrapped errors
		if errors.As(err, &apiErr) {
			return apiErr
		}
	}

	return router.NewInternalServerError("", errors.Join(errs...))
}

// execAfterSuccessTx ensures that fn is executed only after a successful transaction.
//
// If the current app instance is not a transactional or checkTx is false,
// then fn is directly executed.
//
// It could be usually used to allow propagating an error or writing
// custom response from within the wrapped transaction block.
func execAfterSuccessTx(checkTx bool, app core.App, fn func() error) error {
	if txInfo := app.TxInfo(); txInfo != nil && checkTx {
		txInfo.OnComplete(func(txErr error) error {
			if txErr == nil {
				return fn()
			}
			return nil
		})
		return nil
	}

	return fn()
}

// -------------------------------------------------------------------

const maxAuthOrigins = 5

func authAlert(e *core.RequestEvent, authRecord *core.Record) error {
	// generate fingerprint
	// ---
	ip := e.RealIP()

	userAgent := e.Request.UserAgent()
	if len(userAgent) > 200 {
		userAgent = userAgent[:200] + "..."
	}

	fingerprint := security.MD5(ip + userAgent)
	alertInfo := fmt.Sprintf("%s - %s %s", types.NowDateTime().String(), ip, userAgent)
	// ---

	origins, err := e.App.FindAllAuthOriginsByRecord(authRecord)
	if err != nil {
		return err
	}

	isFirstLogin := len(origins) == 0

	var currentOrigin *core.AuthOrigin
	for _, origin := range origins {
		if origin.Fingerprint() == fingerprint {
			currentOrigin = origin
			break
		}
	}
	if currentOrigin == nil {
		currentOrigin = core.NewAuthOrigin(e.App)
		currentOrigin.SetCollectionRef(authRecord.Collection().Id)
		currentOrigin.SetRecordRef(authRecord.Id)
		currentOrigin.SetFingerprint(fingerprint)
	}

	// send email alert for the new origin auth (skip first login)
	//
	// Note: The "fake" timeout is a temp solution to avoid blocking
	//       for too long when the SMTP server is not accessible, due
	//       to the lack of context cancellation support in the underlying
	//       mailer and net/smtp package.
	//       The goroutine technically "leaks" but we assume that the OS will
	//       terminate the connection after some time (usually after 3-4 mins).
	if !isFirstLogin && currentOrigin.IsNew() && authRecord.Email() != "" {
		mailSent := make(chan error, 1)

		timer := time.AfterFunc(15*time.Second, func() {
			mailSent <- errors.New("auth alert mail send wait timeout reached")
		})

		routine.FireAndForget(func() {
			err := mails.SendRecordAuthAlert(e.App, authRecord, alertInfo)
			timer.Stop()
			mailSent <- err
		})

		err = <-mailSent
		if err != nil {
			return err
		}
	}

	// try to keep only up to maxAuthOrigins
	// (pop the last used ones; it is not executed in a transaction to avoid unnecessary locks)
	if currentOrigin.IsNew() && len(origins) >= maxAuthOrigins {
		for i := len(origins) - 1; i >= maxAuthOrigins-1; i-- {
			if err := e.App.Delete(origins[i]); err != nil {
				// treat as non-critical error, just log for now
				e.App.Logger().Warn("Failed to delete old AuthOrigin record", "error", err, "authOriginId", origins[i].Id)
			}
		}
	}

	// create/update the origin fingerprint
	return e.App.Save(currentOrigin)
}
