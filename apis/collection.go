package apis

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/auth"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/search"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// bindCollectionApi registers the collection api endpoints and the corresponding handlers.
func bindCollectionApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	read := RequirePermission(core.PermissionResourceCollections, core.PermissionLevelRead)
	write := RequirePermission(core.PermissionResourceCollections, core.PermissionLevelWrite)

	subGroup := rg.Group("/collections")
	// note: the list and view are also available for the staff members with collection permissions
	// (filtered to the collections they could access; see collectionsList and collectionView)
	// (and for the applications with collections read grant)
	subGroup.GET("", collectionsList).Bind(RequireAuth(core.CollectionNameSuperusers, core.CollectionNameApplicationInstallations))
	subGroup.POST("", collectionCreate).Bind(write)
	subGroup.GET("/{collection}", collectionView).Bind(RequireAuth(core.CollectionNameSuperusers, core.CollectionNameApplicationInstallations))
	subGroup.PATCH("/{collection}", collectionUpdate).Bind(write)
	subGroup.DELETE("/{collection}", collectionDelete).Bind(write)
	subGroup.DELETE("/{collection}/truncate", collectionTruncate).Bind(write)
	subGroup.PUT("/import", collectionsImport).Bind(write)
	subGroup.GET("/meta/scaffolds", collectionScaffolds).Bind(read)

	// @todo experimental
	subGroup.GET("/meta/oauth2-providers", collectionListOAuth2Providers).Bind(read)
	// note: the dry-run view query could select from any table (same as creating a view collection)
	subGroup.POST("/meta/dry-run-view", collectionDryRunView).Bind(write)
}

func collectionsList(e *core.RequestEvent) error {
	fieldResolver := search.NewSimpleFieldResolver(
		"id", "created", "updated", "name", "system", "type",
	)

	collections := []*core.Collection{}

	query := e.App.CollectionQuery()

	// limit the collections of the staff members without collections read permission
	// to the ones they could access (see [core.FilterCollectionsByAccess])
	allowedIds, all, err := staffAllowedCollectionIds(e)
	if err != nil {
		return err
	}
	if !all {
		query.AndWhere(dbx.In("id", list.ToInterfaceSlice(allowedIds)...))
	}

	result, err := search.NewProvider(fieldResolver).
		Query(query).
		ParseAndExec(e.Request.URL.Query().Encode(), &collections)

	if err != nil {
		return e.BadRequestError("", err)
	}

	event := new(core.CollectionsListRequestEvent)
	event.RequestEvent = e
	event.Collections = collections
	event.Result = result

	return event.App.OnCollectionsListRequest().Trigger(event, func(e *core.CollectionsListRequestEvent) error {
		return execAfterSuccessTx(true, e.App, func() error {
			return e.JSON(http.StatusOK, e.Result)
		})
	})
}

// staffAllowedCollectionIds returns the ids of the collections that the request staff
// actor could see (all is true for the actors with collections read permission).
//
// Returns a forbidden error if the actor is not a staff member (or an application,
// or a staff member on behalf of an application) or it can't see any collection
// (the access of the applications and online tokens is evaluated by [core.Authorize]).
func staffAllowedCollectionIds(e *core.RequestEvent) ([]string, bool, error) {
	if !e.IsStaff() && !e.IsApplication() && !e.ActorInfo().Permissions(e.App).IsOnBehalfOfApplication() {
		return nil, false, e.ForbiddenError("The authorized record is not allowed to perform this action.", nil)
	}

	info := e.ActorInfo()

	if info.Can(e.App, core.PermissionResourceCollections, core.PermissionLevelRead) {
		return nil, true, nil
	}

	collections, err := e.App.FindAllCollections()
	if err != nil {
		return nil, false, e.InternalServerError("", err)
	}

	allowed := core.FilterCollectionsByAccess(e.App, info, collections)
	if len(allowed) == 0 {
		return nil, false, e.ForbiddenError("The authorized record is not allowed to perform this action.", nil)
	}

	ids := make([]string, len(allowed))
	for i, c := range allowed {
		ids[i] = c.Id
	}

	return ids, false, nil
}

func collectionView(e *core.RequestEvent) error {
	collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue("collection"))
	if err != nil || collection == nil {
		return e.NotFoundError("", err)
	}

	allowedIds, all, err := staffAllowedCollectionIds(e)
	if err != nil {
		return err
	}
	if !all && !slices.Contains(allowedIds, collection.Id) {
		return e.ForbiddenError("The authorized record is not allowed to perform this action.", nil)
	}

	event := new(core.CollectionRequestEvent)
	event.RequestEvent = e
	event.Collection = collection

	return e.App.OnCollectionViewRequest().Trigger(event, func(e *core.CollectionRequestEvent) error {
		return execAfterSuccessTx(true, e.App, func() error {
			return e.JSON(http.StatusOK, e.Collection)
		})
	})
}

func collectionCreate(e *core.RequestEvent) error {
	// populate the minimal required factory collection data (if any)
	factoryExtract := struct {
		Type string `form:"type" json:"type"`
		Name string `form:"name" json:"name"`
	}{}
	if err := e.BindBody(&factoryExtract); err != nil {
		return e.BadRequestError("Failed to load the collection type data due to invalid formatting.", err)
	}

	// create scaffold
	collection := core.NewCollection(factoryExtract.Type, factoryExtract.Name)

	// merge the scaffold with the submitted request data
	if err := e.BindBody(collection); err != nil {
		return e.BadRequestError("Failed to load the submitted data due to invalid formatting.", err)
	}

	event := new(core.CollectionRequestEvent)
	event.RequestEvent = e
	event.Collection = collection

	return e.App.OnCollectionCreateRequest().Trigger(event, func(e *core.CollectionRequestEvent) error {
		if err := e.App.Save(e.Collection); err != nil {
			// validation failure
			var validationErrors validation.Errors
			if errors.As(err, &validationErrors) {
				return e.BadRequestError("Failed to create collection.", validationErrors)
			}

			// other generic db error
			return e.BadRequestError("Failed to create collection. Raw error: \n"+err.Error(), nil)
		}

		return execAfterSuccessTx(true, e.App, func() error {
			return e.JSON(http.StatusOK, e.Collection)
		})
	})
}

func collectionUpdate(e *core.RequestEvent) error {
	collection, err := e.App.FindCollectionByNameOrId(e.Request.PathValue("collection"))
	if err != nil || collection == nil {
		return e.NotFoundError("", err)
	}

	if err := e.BindBody(collection); err != nil {
		return e.BadRequestError("Failed to load the submitted data due to invalid formatting.", err)
	}

	event := new(core.CollectionRequestEvent)
	event.RequestEvent = e
	event.Collection = collection

	return event.App.OnCollectionUpdateRequest().Trigger(event, func(e *core.CollectionRequestEvent) error {
		if err := e.App.Save(e.Collection); err != nil {
			// validation failure
			var validationErrors validation.Errors
			if errors.As(err, &validationErrors) {
				return e.BadRequestError("Failed to update collection.", validationErrors)
			}

			// other generic db error
			return e.BadRequestError("Failed to update collection. Raw error: \n"+err.Error(), nil)
		}

		return execAfterSuccessTx(true, e.App, func() error {
			return e.JSON(http.StatusOK, e.Collection)
		})
	})
}

func collectionDelete(e *core.RequestEvent) error {
	collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue("collection"))
	if err != nil || collection == nil {
		return e.NotFoundError("", err)
	}

	event := new(core.CollectionRequestEvent)
	event.RequestEvent = e
	event.Collection = collection

	return e.App.OnCollectionDeleteRequest().Trigger(event, func(e *core.CollectionRequestEvent) error {
		if err := e.App.Delete(e.Collection); err != nil {
			msg := "Failed to delete collection"

			// check fo references
			refs, _ := e.App.FindCollectionReferences(e.Collection, e.Collection.Id)
			if len(refs) > 0 {
				names := make([]string, 0, len(refs))
				for ref := range refs {
					names = append(names, ref.Name)
				}
				msg += " probably due to existing reference in " + strings.Join(names, ", ")
			}

			return e.BadRequestError(msg, err)
		}

		return execAfterSuccessTx(true, e.App, func() error {
			return e.NoContent(http.StatusNoContent)
		})
	})
}

func collectionTruncate(e *core.RequestEvent) error {
	collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue("collection"))
	if err != nil || collection == nil {
		return e.NotFoundError("", err)
	}

	if collection.IsView() {
		return e.BadRequestError("View collections cannot be truncated since they don't store their own records.", nil)
	}

	err = e.App.TruncateCollection(collection)
	if err != nil {
		return e.BadRequestError("Failed to truncate collection (most likely due to required cascade delete record references).", err)
	}

	return e.NoContent(http.StatusNoContent)
}

func collectionScaffolds(e *core.RequestEvent) error {
	randomId := security.RandomStringWithAlphabet(10, core.DefaultIdAlphabet) // could be used as part of the default indexes name

	collections := map[string]*core.Collection{
		core.CollectionTypeBase: core.NewBaseCollection("", randomId),
		core.CollectionTypeAuth: core.NewAuthCollection("", randomId),
		core.CollectionTypeView: core.NewViewCollection("", randomId),
	}

	for _, c := range collections {
		c.Id = "" // clear random id
	}

	return e.JSON(http.StatusOK, collections)
}

type providerListItem struct {
	order int

	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Logo        string `json:"logo"`
}

func collectionListOAuth2Providers(e *core.RequestEvent) error {
	providers := make([]*providerListItem, 0, len(auth.Providers))

	for name, factory := range auth.Providers {
		p := factory()

		providers = append(providers, &providerListItem{
			order:       p.Order(),
			Name:        name,
			DisplayName: p.DisplayName(),
			Logo:        p.Logo(),
		})
	}

	slices.SortStableFunc(providers, func(a, b *providerListItem) int {
		// sort by order
		if a.order < b.order {
			return -1
		}
		if a.order > b.order {
			return 1
		}

		// fallback sort by name
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}

		return 0
	})

	return e.JSON(http.StatusOK, providers)
}

func collectionDryRunView(e *core.RequestEvent) error {
	// extra precaution in case reused in custom route group
	if !e.Can(core.PermissionResourceCollections, core.PermissionLevelWrite) {
		return e.ForbiddenError("", nil)
	}

	form := dryRunViewForm{}

	err := e.BindBody(&form)
	if err != nil {
		return firstApiError(err, e.BadRequestError("An error occurred while loading the submitted data.", err))
	}

	err = form.validate()
	if err != nil {
		return firstApiError(err, e.BadRequestError("An error occurred while validating the submitted data.", err))
	}

	result, err := e.App.DryRunView(form.Query, 10)
	if err != nil {
		return firstApiError(err, e.BadRequestError("Invalid view query. Raw error: \n"+err.Error(), nil))
	}

	return e.JSON(http.StatusOK, result)
}

type dryRunViewForm struct {
	Query string `form:"query" json:"query"`
}

func (form *dryRunViewForm) validate() error {
	return validation.ValidateStruct(form,
		validation.Field(&form.Query, validation.Required, validation.Length(0, 5000)),
	)
}
