package apis

import (
	cryptoRand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/forms"
	"github.com/lumm2509/pocketbomb/tools/filesystem"
	"github.com/lumm2509/pocketbomb/tools/inflector"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/search"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/pocketbase/dbx"
)

// bindRecordCrudApi registers the record crud api endpoints and
// the corresponding handlers.
//
// note: the rate limiter is "inlined" because some of the crud actions are also used in the batch APIs
func bindRecordCrudApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	// note: deny by default - the records API requests must identify their client
	// with an API key or an OAuth2 access token (the collection rules still apply)
	subGroup := rg.Group("/collections/{collection}/records").
		Unbind(DefaultRateLimitMiddlewareId).
		Bind(requireClientCredentials())
	subGroup.GET("", recordsList)
	subGroup.GET("/{id}", recordView)
	subGroup.POST("", recordCreate(true, nil)).Bind(dynamicCollectionBodyLimit(""))
	subGroup.PATCH("/{id}", recordUpdate(true, nil)).Bind(dynamicCollectionBodyLimit(""))
	subGroup.DELETE("/{id}", recordDelete(true, nil))
}

func recordsList(e *core.RequestEvent) error {
	collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue("collection"))
	if err != nil || collection == nil {
		return e.NotFoundError("Missing collection context.", err)
	}

	err = checkCollectionRateLimit(e, collection, "list")
	if err != nil {
		return err
	}

	requestInfo, err := e.RequestInfo()
	if err != nil {
		return firstApiError(err, e.BadRequestError("", err))
	}

	searchProvider, access, err := recordsListProvider(
		e,
		requestInfo,
		collection,
		e.App.RecordQuery(collection),
		requestInfo.Query[search.FilterQueryParam],
		requestInfo.Query[search.SortQueryParam],
	)
	if err != nil {
		return err
	}

	records := []*core.Record{}
	result, err := searchProvider.ParseAndExec(e.Request.URL.Query().Encode(), &records)
	if err != nil {
		return firstApiError(err, e.BadRequestError("", err))
	}

	event := new(core.RecordsListRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.Records = records
	event.Result = result

	return e.App.OnRecordsListRequest().Trigger(event, func(e *core.RecordsListRequestEvent) error {
		if err := EnrichRecords(e.RequestEvent, e.Records); err != nil {
			return firstApiError(err, e.InternalServerError("Failed to enrich records", err))
		}

		throttleEmptyFilteredList(e.RequestEvent, collection, access.BypassRules, requestInfo.Query[search.FilterQueryParam], len(e.Records))

		return execAfterSuccessTx(true, e.App, func() error {
			return e.JSON(http.StatusOK, e.Result)
		})
	})
}

var listTimingRateLimitRule = core.RateLimitRule{MaxRequests: 3, Duration: 3}

func randomizedThrottle(softMax int64) {
	var timeout int64
	randRange, err := cryptoRand.Int(cryptoRand.Reader, big.NewInt(softMax))
	if err == nil {
		timeout = randRange.Int64()
	} else {
		timeout = softMax
	}

	time.Sleep(time.Duration(timeout) * time.Millisecond)
}

func recordView(e *core.RequestEvent) error {
	collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue("collection"))
	if err != nil || collection == nil {
		return e.NotFoundError("Missing collection context.", err)
	}

	err = checkCollectionRateLimit(e, collection, "view")
	if err != nil {
		return err
	}

	recordId := e.Request.PathValue("id")
	if recordId == "" {
		return e.NotFoundError("", nil)
	}

	requestInfo, err := e.RequestInfo()
	if err != nil {
		return firstApiError(err, e.BadRequestError("", err))
	}

	ruleFunc, err := recordViewRuleFunc(e, requestInfo, collection)
	if err != nil {
		return err
	}

	record, fetchErr := e.App.FindRecordById(collection, recordId, ruleFunc)
	if fetchErr != nil || record == nil {
		return firstApiError(err, e.NotFoundError("", fetchErr))
	}

	event := new(core.RecordRequestEvent)
	event.RequestEvent = e
	event.Collection = collection
	event.Record = record

	return e.App.OnRecordViewRequest().Trigger(event, func(e *core.RecordRequestEvent) error {
		if err := EnrichRecord(e.RequestEvent, e.Record); err != nil {
			return firstApiError(err, e.InternalServerError("Failed to enrich record", err))
		}

		return execAfterSuccessTx(true, e.App, func() error {
			return e.JSON(http.StatusOK, e.Record)
		})
	})
}

func recordCreate(responseWriteAfterTx bool, optFinalizer func(data any) error) func(e *core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue("collection"))
		if err != nil || collection == nil {
			return e.NotFoundError("Missing collection context.", err)
		}

		if collection.IsView() {
			return e.BadRequestError("Unsupported collection type.", nil)
		}

		err = checkCollectionRateLimit(e, collection, "create")
		if err != nil {
			return err
		}

		requestInfo, err := e.RequestInfo()
		if err != nil {
			return firstApiError(err, e.BadRequestError("", err))
		}

		access, err := recordCollectionAccess(e, requestInfo, collection, core.PermissionActionCreate)
		if err != nil {
			return err
		}

		hasSuperuserAuth := access.BypassRules
		if !hasSuperuserAuth && collection.CreateRule == nil {
			return e.ForbiddenError("Only superusers can perform this action.", nil)
		}

		record := core.NewRecord(collection)

		data, err := recordDataFromRequest(e, record)
		if err != nil {
			return firstApiError(err, e.BadRequestError("Failed to read the submitted data.", err))
		}

		// set a random password for the OAuth2 ignoring its plain password validators
		var skipPlainPasswordRecordValidators bool
		if requestInfo.Context == core.RequestInfoContextOAuth2 {
			if _, ok := data[core.FieldNamePassword]; !ok {
				data[core.FieldNamePassword] = security.RandomString(30)
				data[core.FieldNamePassword+"Confirm"] = data[core.FieldNamePassword]
				skipPlainPasswordRecordValidators = true
			}
		}

		// replace modifiers fields so that the resolved value is always
		// available when accessing requestInfo.Body
		requestInfo.Body = data

		form := forms.NewRecordUpsert(e.App, record)
		if hasSuperuserAuth {
			form.GrantSuperuserAccess()
		}
		form.Load(data)

		if skipPlainPasswordRecordValidators {
			// unset the plain value to skip the plain password field validators
			if raw, ok := record.GetRaw(core.FieldNamePassword).(*core.PasswordFieldValue); ok {
				raw.Plain = ""
			}
		}

		// check the request and record data against the create and manage rules
		if !hasSuperuserAuth && collection.CreateRule != nil {
			dummyRecord := record.Clone()

			dummyRandomPart := "__pb_create__" + security.PseudorandomString(6)

			// set an id if it doesn't have already
			// (the value doesn't matter; it is used only to minimize the breaking changes with earlier versions)
			if dummyRecord.Id == "" {
				dummyRecord.Id = "__temp_id__" + dummyRandomPart
			}

			// unset the verified field to prevent manage API rule misuse in case the rule relies on it
			dummyRecord.SetVerified(false)

			// export the dummy record data into db params
			dummyExport, err := dummyRecord.DBExport(e.App)
			if err != nil {
				return e.BadRequestError("Failed to create record", fmt.Errorf("dummy DBExport error: %w", err))
			}

			dummyParams := make(dbx.Params, len(dummyExport))
			selects := make([]string, 0, len(dummyExport))
			var param string
			for k, v := range dummyExport {
				k = inflector.Columnify(k) // columnify is just as extra measure in case of custom fields
				param = "__pb_create__" + k
				dummyParams[param] = v
				selects = append(selects, "{:"+param+"} AS [["+k+"]]")
			}

			// shallow clone the current collection
			dummyCollection := *collection
			dummyCollection.Id += dummyRandomPart
			dummyCollection.Name += inflector.Columnify(dummyRandomPart)

			withFrom := fmt.Sprintf("WITH {{%s}} as (SELECT %s)", dummyCollection.Name, strings.Join(selects, ","))

			// check non-empty create rule
			if *dummyCollection.CreateRule != "" {
				ruleQuery := e.App.ConcurrentDB().Select("(1)").PreFragment(withFrom).From(dummyCollection.Name).AndBind(dummyParams)

				resolver := core.NewRecordFieldResolver(e.App, &dummyCollection, requestInfo, true)

				expr, err := search.FilterData(*dummyCollection.CreateRule).BuildExpr(resolver)
				if err != nil {
					return e.BadRequestError("Failed to create record", fmt.Errorf("create rule build expression failure: %w", err))
				}
				ruleQuery.AndWhere(expr)

				err = resolver.UpdateQuery(ruleQuery)
				if err != nil {
					return e.BadRequestError("Failed to create record", fmt.Errorf("create rule update query failure: %w", err))
				}

				var exists int
				err = ruleQuery.Limit(1).Row(&exists)
				if err != nil || exists == 0 {
					return e.BadRequestError("Failed to create record", fmt.Errorf("create rule failure: %w", err))
				}
			}

			// check for manage rule access
			manageRuleQuery := e.App.ConcurrentDB().Select("(1)").PreFragment(withFrom).From(dummyCollection.Name).AndBind(dummyParams)
			if !form.HasManageAccess() &&
				hasAuthManageAccess(e.App, requestInfo, &dummyCollection, manageRuleQuery) {
				form.GrantManagerAccess()
			}
		}

		var isOptFinalizerCalled bool

		event := new(core.RecordRequestEvent)
		event.RequestEvent = e
		event.Collection = collection
		event.Record = record

		hookErr := e.App.OnRecordCreateRequest().Trigger(event, func(e *core.RecordRequestEvent) error {
			form.SetApp(e.App)
			form.SetRecord(e.Record)

			err := form.Submit()
			if err != nil {
				return firstApiError(err, e.BadRequestError("Failed to create record", err))
			}

			err = EnrichRecord(e.RequestEvent, e.Record)
			if err != nil {
				return firstApiError(err, e.InternalServerError("Failed to enrich record", err))
			}

			err = execAfterSuccessTx(responseWriteAfterTx, e.App, func() error {
				return e.JSON(http.StatusOK, e.Record)
			})
			if err != nil {
				return err
			}

			if optFinalizer != nil {
				isOptFinalizerCalled = true
				err = optFinalizer(e.Record)
				if err != nil {
					return firstApiError(err, e.InternalServerError("", err))
				}
			}

			return nil
		})
		if hookErr != nil {
			return hookErr
		}

		// e.g. in case the regular hook chain was stopped and the finalizer cannot be executed as part of the last e.Next() task
		if !isOptFinalizerCalled && optFinalizer != nil {
			if err := optFinalizer(event.Record); err != nil {
				return firstApiError(err, e.InternalServerError("", err))
			}
		}

		return nil
	}
}

func recordUpdate(responseWriteAfterTx bool, optFinalizer func(data any) error) func(e *core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue("collection"))
		if err != nil || collection == nil {
			return e.NotFoundError("Missing collection context.", err)
		}

		if collection.IsView() {
			return e.BadRequestError("Unsupported collection type.", nil)
		}

		err = checkCollectionRateLimit(e, collection, "update")
		if err != nil {
			return err
		}

		recordId := e.Request.PathValue("id")
		if recordId == "" {
			return e.NotFoundError("", nil)
		}

		requestInfo, err := e.RequestInfo()
		if err != nil {
			return firstApiError(err, e.BadRequestError("", err))
		}

		access, err := recordCollectionAccess(e, requestInfo, collection, core.PermissionActionUpdate)
		if err != nil {
			return err
		}

		hasSuperuserAuth := access.BypassRules

		if !hasSuperuserAuth && collection.UpdateRule == nil {
			return firstApiError(err, e.ForbiddenError("Only superusers can perform this action.", nil))
		}

		// eager fetch the record so that the modifiers field values can be resolved
		record, err := e.App.FindRecordById(collection, recordId)
		if err != nil {
			return firstApiError(err, e.NotFoundError("", err))
		}

		data, err := recordDataFromRequest(e, record)
		if err != nil {
			return firstApiError(err, e.BadRequestError("Failed to read the submitted data.", err))
		}

		// replace modifiers fields so that the resolved value is always
		// available when accessing requestInfo.Body
		requestInfo.Body = data

		ruleFunc := func(q *dbx.SelectQuery) error {
			if !hasSuperuserAuth && collection.UpdateRule != nil && *collection.UpdateRule != "" {
				resolver := core.NewRecordFieldResolver(e.App, collection, requestInfo, true)

				expr, err := search.FilterData(*collection.UpdateRule).BuildExpr(resolver)
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
		}

		// refetch with access checks
		record, err = e.App.FindRecordById(collection, recordId, ruleFunc)
		if err != nil {
			return firstApiError(err, e.NotFoundError("", err))
		}

		form := forms.NewRecordUpsert(e.App, record)
		if hasSuperuserAuth {
			form.GrantSuperuserAccess()
		}
		form.Load(data)

		manageRuleQuery := e.App.ConcurrentDB().Select("(1)").From(collection.Name).AndWhere(dbx.HashExp{
			collection.Name + ".id": record.Id,
		})
		if !form.HasManageAccess() &&
			hasAuthManageAccess(e.App, requestInfo, collection, manageRuleQuery) {
			form.GrantManagerAccess()
		}

		for _, field := range access.ReadOnlyFields {
			if record.Original().Get(field) != record.Get(field) {
				return e.ForbiddenError(thirdPartyTokenForbiddenMessage, errors.New("restricted_field"))
			}
		}

		var isOptFinalizerCalled bool

		event := new(core.RecordRequestEvent)
		event.RequestEvent = e
		event.Collection = collection
		event.Record = record

		hookErr := e.App.OnRecordUpdateRequest().Trigger(event, func(e *core.RecordRequestEvent) error {
			form.SetApp(e.App)
			form.SetRecord(e.Record)

			err := form.Submit()
			if err != nil {
				return firstApiError(err, e.BadRequestError("Failed to update record.", err))
			}

			err = EnrichRecord(e.RequestEvent, e.Record)
			if err != nil {
				return firstApiError(err, e.InternalServerError("Failed to enrich record", err))
			}

			err = execAfterSuccessTx(responseWriteAfterTx, e.App, func() error {
				return e.JSON(http.StatusOK, e.Record)
			})
			if err != nil {
				return err
			}

			if optFinalizer != nil {
				isOptFinalizerCalled = true
				err = optFinalizer(e.Record)
				if err != nil {
					return firstApiError(err, e.InternalServerError("", fmt.Errorf("update optFinalizer error: %w", err)))
				}
			}

			return nil
		})
		if hookErr != nil {
			return hookErr
		}

		// e.g. in case the regular hook chain was stopped and the finalizer cannot be executed as part of the last e.Next() task
		if !isOptFinalizerCalled && optFinalizer != nil {
			if err := optFinalizer(event.Record); err != nil {
				return firstApiError(err, e.InternalServerError("", fmt.Errorf("update optFinalizer error: %w", err)))
			}
		}

		return nil
	}
}

func recordDelete(responseWriteAfterTx bool, optFinalizer func(data any) error) func(e *core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue("collection"))
		if err != nil || collection == nil {
			return e.NotFoundError("Missing collection context.", err)
		}

		if collection.IsView() {
			return e.BadRequestError("Unsupported collection type.", nil)
		}

		err = checkCollectionRateLimit(e, collection, "delete")
		if err != nil {
			return err
		}

		recordId := e.Request.PathValue("id")
		if recordId == "" {
			return e.NotFoundError("", nil)
		}

		requestInfo, err := e.RequestInfo()
		if err != nil {
			return firstApiError(err, e.BadRequestError("", err))
		}

		access, err := recordCollectionAccess(e, requestInfo, collection, core.PermissionActionDelete)
		if err != nil {
			return err
		}

		if !access.BypassRules && collection.DeleteRule == nil {
			return e.ForbiddenError("Only superusers can perform this action.", nil)
		}

		ruleFunc := func(q *dbx.SelectQuery) error {
			if !access.BypassRules && collection.DeleteRule != nil && *collection.DeleteRule != "" {
				resolver := core.NewRecordFieldResolver(e.App, collection, requestInfo, true)

				expr, err := search.FilterData(*collection.DeleteRule).BuildExpr(resolver)
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
		}

		record, err := e.App.FindRecordById(collection, recordId, ruleFunc)
		if err != nil || record == nil {
			return e.NotFoundError("", err)
		}

		var isOptFinalizerCalled bool

		event := new(core.RecordRequestEvent)
		event.RequestEvent = e
		event.Collection = collection
		event.Record = record

		hookErr := e.App.OnRecordDeleteRequest().Trigger(event, func(e *core.RecordRequestEvent) error {
			if err := e.App.Delete(e.Record); err != nil {
				return firstApiError(err, e.BadRequestError("Failed to delete record. Make sure that the record is not part of a required relation reference.", err))
			}

			err = execAfterSuccessTx(responseWriteAfterTx, e.App, func() error {
				return e.NoContent(http.StatusNoContent)
			})
			if err != nil {
				return err
			}

			if optFinalizer != nil {
				isOptFinalizerCalled = true
				err = optFinalizer(e.Record)
				if err != nil {
					return firstApiError(err, e.InternalServerError("", fmt.Errorf("delete optFinalizer error: %w", err)))
				}
			}

			return nil
		})
		if hookErr != nil {
			return hookErr
		}

		// e.g. in case the regular hook chain was stopped and the finalizer cannot be executed as part of the last e.Next() task
		if !isOptFinalizerCalled && optFinalizer != nil {
			if err := optFinalizer(event.Record); err != nil {
				return firstApiError(err, e.InternalServerError("", fmt.Errorf("delete optFinalizer error: %w", err)))
			}
		}

		return nil
	}
}

// -------------------------------------------------------------------

// recordCollectionAccess resolves the RBAC access of the request actor
// for the specified collection action (see [core.Authorize]) and
// returns a forbidden error if the action is not allowed.
func recordCollectionAccess(e *core.RequestEvent, requestInfo *core.RequestInfo, collection *core.Collection, action string) (core.Access, error) {
	access := requestInfo.CollectionAccess(e.App, collection, action)
	if !access.Allowed {
		return access, e.ForbiddenError("The authorized record is not allowed to perform this action.", nil)
	}

	return access, nil
}

func recordDataFromRequest(e *core.RequestEvent, record *core.Record) (map[string]any, error) {
	info, err := e.RequestInfo()
	if err != nil {
		return nil, err
	}

	// resolve regular fields
	result := record.ReplaceModifiers(info.Body)

	// resolve uploaded files
	uploadedFiles, err := extractUploadedFiles(e, record.Collection(), "")
	if err != nil {
		return nil, err
	}
	if len(uploadedFiles) > 0 {
		for k, files := range uploadedFiles {
			uploaded := make([]any, 0, len(files))

			// if not remove/prepend/append -> merge with the submitted
			// info.Body values to prevent accidental old files deletion
			if info.Body[k] != nil &&
				!strings.HasPrefix(k, "+") &&
				!strings.HasSuffix(k, "+") &&
				!strings.HasSuffix(k, "-") {
				existing := list.ToUniqueStringSlice(info.Body[k])
				for _, name := range existing {
					uploaded = append(uploaded, name)
				}
			}

			for _, file := range files {
				uploaded = append(uploaded, file)
			}

			result[k] = uploaded
		}

		result = record.ReplaceModifiers(result)
	}

	isAuth := record.Collection().IsAuth()

	action := core.PermissionActionUpdate
	if record.IsNew() {
		action = core.PermissionActionCreate
	}

	// unset the secret fields (e.g. tokenKey) for the non-Owners
	if !info.IsOwner(e.App) {
		for _, name := range core.SecretFieldNames(record.Collection()) {
			// exception for the auth collection "password" field (it is validated by the API rules or the bypass)
			if isAuth && name == core.FieldNamePassword {
				continue
			}

			delete(result, name)
		}
	}

	// unset hidden fields for the actors without bypass permission (e.g. non-Owners customers)
	if !info.CollectionAccess(e.App, record.Collection(), action).BypassRules {
		for _, f := range record.Collection().Fields {
			if f.GetHidden() {
				// exception for the auth collection "password" field
				if isAuth && f.GetName() == core.FieldNamePassword {
					continue
				}

				delete(result, f.GetName())
			}
		}
	}

	return result, nil
}

func extractUploadedFiles(re *core.RequestEvent, collection *core.Collection, prefix string) (map[string][]*filesystem.File, error) {
	contentType := re.Request.Header.Get("content-type")
	if !strings.HasPrefix(contentType, "multipart/form-data") {
		return nil, nil // not multipart/form-data request
	}

	result := map[string][]*filesystem.File{}

	for _, field := range collection.Fields {
		if field.Type() != core.FieldTypeFile {
			continue
		}

		baseKey := field.GetName()

		keys := []string{
			baseKey,
			// prepend and append modifiers
			"+" + baseKey,
			baseKey + "+",
		}

		for _, k := range keys {
			if prefix != "" {
				k = prefix + "." + k
			}
			files, err := re.FindUploadedFiles(k)
			if err != nil && !errors.Is(err, http.ErrMissingFile) {
				return nil, err
			}
			if len(files) > 0 {
				result[k] = files
			}
		}
	}

	return result, nil
}

// hasAuthManageAccess checks whether the client is allowed to have
// [forms.RecordUpsert] auth management permissions
// (e.g. allowing to change system auth fields without oldPassword).
func hasAuthManageAccess(app core.App, requestInfo *core.RequestInfo, collection *core.Collection, query *dbx.SelectQuery) bool {
	if !collection.IsAuth() {
		return false
	}

	manageRule := collection.ManageRule

	if manageRule == nil || *manageRule == "" {
		return false // only for superusers (manageRule can't be empty)
	}

	if requestInfo == nil || requestInfo.Auth == nil {
		return false // no auth record
	}

	resolver := core.NewRecordFieldResolver(app, collection, requestInfo, true)

	expr, err := search.FilterData(*manageRule).BuildExpr(resolver)
	if err != nil {
		app.Logger().Error("Manage rule build expression error", "error", err, "collectionId", collection.Id)
		return false
	}
	query.AndWhere(expr)

	err = resolver.UpdateQuery(query)
	if err != nil {
		return false
	}

	var exists int

	err = query.Limit(1).Row(&exists)

	return err == nil && exists > 0
}
