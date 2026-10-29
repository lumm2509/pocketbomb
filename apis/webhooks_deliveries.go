package apis

import (
	"errors"
	"net/http"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/search"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

var webhookDeliveryFilterFields = []string{
	"id", "created", "updated", "webhook", "eventId", "topic", "apiVersion", "triggeredAt",
	"status", "attempts", "nextAttemptAt", "responseStatus", "error", "durationMs", "test", "redeliveryOf",
}

// webhookDeliveryResponse extends the delivery with the human friendly topic name.
type webhookDeliveryResponse struct {
	*core.WebhookDelivery

	// TopicName is the human friendly topic (e.g. "posts.create").
	TopicName string `json:"topicName"`
}

func newWebhookDeliveryResponse(app core.App, d *core.WebhookDelivery) *webhookDeliveryResponse {
	return &webhookDeliveryResponse{
		WebhookDelivery: d,
		TopicName:       core.RenderWebhookTopic(app, d.Topic),
	}
}

// webhookDeliveriesAccessExpr returns the deliveries query expression of the deliveries that
// the request actor could access (nil when all deliveries are accessible, aka. for the Owners):
//   - only the deliveries of the subscriptions whose current topics the actor could view
//     (see [core.CanAccessWebhook]; the deliveries payloads contain the event records)
//   - excluding the deliveries of the collections that the actor can't view
//     (e.g. the deliveries of a previous subscription topic)
//
// The deliveries are in the auxiliary db so the subscriptions and the collections
// (both small tables) are checked in Go and the deliveries are filtered by the
// allowed subscription ids and the excluded topic namespaces.
func webhookDeliveriesAccessExpr(e *core.RequestEvent) (dbx.Expression, error) {
	info := e.ActorInfo()
	if info.IsOwner(e.App) {
		return nil, nil
	}

	webhooks, err := e.App.FindAllRecords(core.CollectionNameWebhooks)
	if err != nil {
		return nil, err
	}

	ids := make([]any, 0, len(webhooks))
	for _, r := range webhooks {
		if core.CanAccessWebhook(e.App, info, r) {
			ids = append(ids, r.Id)
		}
	}

	if len(ids) == 0 {
		return dbx.NewExp("1=0"), nil
	}

	collections, err := e.App.FindAllCollections()
	if err != nil {
		return nil, err
	}

	exprs := []dbx.Expression{dbx.In("webhook", ids...)}
	for _, c := range collections {
		if c.System || !info.CollectionAccess(e.App, c, core.PermissionActionView).BypassRules {
			// the stored delivery topics are always in the "{collectionId}.{op}" format
			exprs = append(exprs, dbx.NotLike("topic", c.Id+".").Match(false, true))
		}
	}

	return dbx.And(exprs...), nil
}

// findAccessibleWebhookDelivery returns the specified delivery if the request actor could access it.
func findAccessibleWebhookDelivery(e *core.RequestEvent, id string) (*core.WebhookDelivery, error) {
	accessExpr, err := webhookDeliveriesAccessExpr(e)
	if err != nil {
		return nil, err
	}

	query := e.App.WebhookDeliveryQuery().AndWhere(dbx.HashExp{"id": id}).Limit(1)
	if accessExpr != nil {
		query.AndWhere(accessExpr)
	}

	delivery := &core.WebhookDelivery{}
	if err := query.One(delivery); err != nil {
		return nil, err
	}

	return delivery, nil
}

// GET /api/webhooks/deliveries
func webhookDeliveriesList(e *core.RequestEvent) error {
	fieldResolver := search.NewSimpleFieldResolver(webhookDeliveryFilterFields...)

	items := []*core.WebhookDelivery{}

	query := e.App.WebhookDeliveryQuery()

	accessExpr, err := webhookDeliveriesAccessExpr(e)
	if err != nil {
		return e.InternalServerError("", err)
	}
	if accessExpr != nil {
		query.AndWhere(accessExpr)
	}

	result, err := search.NewProvider(fieldResolver).
		Query(query).
		ParseAndExec(e.Request.URL.Query().Encode(), &items)
	if err != nil {
		return e.BadRequestError("", err)
	}

	responseItems := make([]*webhookDeliveryResponse, len(items))
	for i, item := range items {
		responseItems[i] = newWebhookDeliveryResponse(e.App, item)
	}
	result.Items = responseItems

	return e.JSON(http.StatusOK, result)
}

// DELETE /api/webhooks/deliveries
//
// Deletes all completed deliveries (the pending and retrying ones are kept since they are part of the queue).
//
// The non-Owners delete only the deliveries that they could access.
func webhookDeliveriesTruncate(e *core.RequestEvent) error {
	where := dbx.NotIn("status", core.WebhookDeliveryStatusPending, core.WebhookDeliveryStatusRetrying)

	accessExpr, err := webhookDeliveriesAccessExpr(e)
	if err != nil {
		return e.InternalServerError("", err)
	}
	if accessExpr != nil {
		where = dbx.And(where, accessExpr)
	}

	// delete the rows directly (aka. no model hooks will be fired)
	_, err = e.App.AuxNonconcurrentDB().Delete(core.WebhookDeliveriesTableName, where).Execute()
	if err != nil {
		return e.InternalServerError("Failed to truncate the webhook deliveries.", err)
	}

	// try to free the unused disk space
	err = e.App.AuxVacuum()
	if err != nil {
		e.App.Logger().Warn("Failed to VACUUM aux database", "error", err)
	}

	return e.NoContent(http.StatusNoContent)
}

// GET /api/webhooks/deliveries/{id}
func webhookDeliveriesView(e *core.RequestEvent) error {
	id := e.Request.PathValue("id")
	if id == "" {
		return e.NotFoundError("", nil)
	}

	delivery, err := findAccessibleWebhookDelivery(e, id)
	if err != nil || delivery == nil {
		return e.NotFoundError("", err)
	}

	return e.JSON(http.StatusOK, newWebhookDeliveryResponse(e.App, delivery))
}

// GET /api/webhooks/deliveries/stats?interval=minute|hour|day&groupBy=status|topic|webhook&filter=...
func webhookDeliveriesStats(e *core.RequestEvent) error {
	query := e.Request.URL.Query()

	params := core.WebhookDeliveriesStatsParams{
		Interval: query.Get("interval"),
		GroupBy:  query.Get("groupBy"),
	}

	err := validation.Errors{
		"interval": validation.Validate(params.Interval, validation.In(
			core.WebhookDeliveriesStatsIntervalMinute,
			core.WebhookDeliveriesStatsIntervalHour,
			core.WebhookDeliveriesStatsIntervalDay,
		)),
		"groupBy": validation.Validate(params.GroupBy, validation.In(
			core.WebhookDeliveriesStatsGroupByStatus,
			core.WebhookDeliveriesStatsGroupByTopic,
			core.WebhookDeliveriesStatsGroupByWebhook,
		)),
	}.Filter()
	if err != nil {
		return e.BadRequestError("Invalid stats parameters.", err)
	}

	if filter := query.Get(search.FilterQueryParam); filter != "" {
		params.Filter, err = search.FilterData(filter).BuildExpr(search.NewSimpleFieldResolver(webhookDeliveryFilterFields...))
		if err != nil {
			return e.BadRequestError("Invalid filter format.", err)
		}
	}

	accessExpr, err := webhookDeliveriesAccessExpr(e)
	if err != nil {
		return e.InternalServerError("", err)
	}
	if accessExpr != nil {
		if params.Filter != nil {
			params.Filter = dbx.And(params.Filter, accessExpr)
		} else {
			params.Filter = accessExpr
		}
	}

	stats, err := e.App.WebhookDeliveriesStats(params)
	if err != nil {
		return e.BadRequestError("Failed to generate the webhook deliveries stats.", err)
	}

	return e.JSON(http.StatusOK, stats)
}

// POST /api/webhooks/deliveries/{id}/redeliver
//
// Creates a new delivery of the same event (same event id and payload),
// sends it synchronously and returns it.
func webhookDeliveriesRedeliver(e *core.RequestEvent) error {
	delivery, err := findAccessibleWebhookDelivery(e, e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("", err)
	}

	if !e.App.Settings().Webhooks.Enabled {
		return e.BadRequestError("Webhooks are disabled.", nil)
	}

	result, err := e.App.Webhooks().Redeliver(e.Request.Context(), delivery.Id)
	if err != nil {
		if errors.Is(err, core.ErrWebhookNotRedeliverable) {
			return e.BadRequestError("Only completed non-test deliveries can be redelivered.", nil)
		}
		return e.InternalServerError("Failed to redeliver the webhook.", err)
	}

	return e.JSON(http.StatusOK, newWebhookDeliveryResponse(e.App, result))
}
