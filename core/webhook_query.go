package core

import (
	"time"

	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

// FindWebhookById returns a single Webhook subscription model by its id.
func (app *BaseApp) FindWebhookById(id string) (*Webhook, error) {
	result := &Webhook{}

	err := app.RecordQuery(CollectionNameWebhooks).
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// -------------------------------------------------------------------

// Webhook deliveries stats intervals.
const (
	WebhookDeliveriesStatsIntervalMinute = "minute"
	WebhookDeliveriesStatsIntervalHour   = "hour"
	WebhookDeliveriesStatsIntervalDay    = "day"
)

// Webhook deliveries stats group by options.
const (
	WebhookDeliveriesStatsGroupByStatus  = "status"
	WebhookDeliveriesStatsGroupByTopic   = "topic"
	WebhookDeliveriesStatsGroupByWebhook = "webhook"
)

var webhookDeliveriesStatsIntervalFormats = map[string]string{
	WebhookDeliveriesStatsIntervalMinute: "%Y-%m-%d %H:%M:00",
	WebhookDeliveriesStatsIntervalHour:   "%Y-%m-%d %H:00:00",
	WebhookDeliveriesStatsIntervalDay:    "%Y-%m-%d 00:00:00",
}

var webhookDeliveriesStatsGroupExprs = map[string]string{
	"":                                   "''",
	WebhookDeliveriesStatsGroupByStatus:  "[[status]]",
	WebhookDeliveriesStatsGroupByTopic:   "[[topic]]",
	WebhookDeliveriesStatsGroupByWebhook: "[[webhook]]",
}

// WebhookDeliveryQuery returns a new WebhookDelivery select query.
func (app *BaseApp) WebhookDeliveryQuery() *dbx.SelectQuery {
	return app.AuxModelQuery(&WebhookDelivery{})
}

// FindWebhookDeliveryById finds a single WebhookDelivery entry by its id.
func (app *BaseApp) FindWebhookDeliveryById(id string) (*WebhookDelivery, error) {
	model := &WebhookDelivery{}

	err := app.WebhookDeliveryQuery().
		AndWhere(dbx.HashExp{"id": id}).
		Limit(1).
		One(model)

	if err != nil {
		return nil, err
	}

	return model, nil
}

// DeleteOldWebhookDeliveries deletes all completed (success, failed or disabled)
// webhook deliveries created before createdBefore.
//
// The pending and retrying deliveries are never deleted.
//
// For better performance the delete is executed as plain SQL statement,
// aka. no delete model hook events will be fired.
func (app *BaseApp) DeleteOldWebhookDeliveries(createdBefore time.Time) error {
	formattedDate := createdBefore.UTC().Format(types.DefaultDateLayout)

	expr := dbx.And(
		dbx.NewExp("[[created]] <= {:date}", dbx.Params{"date": formattedDate}),
		dbx.In("status", WebhookDeliveryStatusSuccess, WebhookDeliveryStatusFailed, WebhookDeliveryStatusDisabled),
	)

	_, err := app.auxNonconcurrentDB.Delete(WebhookDeliveriesTableName, expr).Execute()

	return err
}

// WebhookDeliveriesStatsParams defines the [App.WebhookDeliveriesStats] parameters.
type WebhookDeliveriesStatsParams struct {
	// Filter is an optional deliveries filter expression.
	Filter dbx.Expression

	// Interval is the time bucket size - minute, hour (default), day.
	Interval string

	// GroupBy is an optional extra grouping - status, topic, webhook.
	GroupBy string
}

// WebhookDeliveriesStatsItem defines a single time bucket (and group) webhook deliveries statistic.
type WebhookDeliveriesStatsItem struct {
	Date types.DateTime `db:"date" json:"date"`

	// Group is the group value (empty if no GroupBy is set).
	Group string `db:"grp" json:"group"`

	Total    int `db:"total" json:"total"`
	Success  int `db:"success" json:"success"`
	Failed   int `db:"failed" json:"failed"`
	Retrying int `db:"retrying" json:"retrying"`
	Pending  int `db:"pending" json:"pending"`
	Disabled int `db:"disabled" json:"disabled"`

	// Attempts is the total number of the made attempts.
	Attempts int `db:"attempts" json:"attempts"`

	// AvgDurationMs is the average last attempt duration (only for the deliveries with at least 1 attempt).
	AvgDurationMs float64 `db:"avgDurationMs" json:"avgDurationMs"`
}

// WebhookDeliveriesStats returns time bucketed (by created date and
// optionally grouped) webhook deliveries statistics sorted by date and group in ASC order.
func (app *BaseApp) WebhookDeliveriesStats(params WebhookDeliveriesStatsParams) ([]*WebhookDeliveriesStatsItem, error) {
	format, ok := webhookDeliveriesStatsIntervalFormats[params.Interval]
	if !ok {
		format = webhookDeliveriesStatsIntervalFormats[WebhookDeliveriesStatsIntervalHour]
	}

	groupExpr, ok := webhookDeliveriesStatsGroupExprs[params.GroupBy]
	if !ok {
		groupExpr = webhookDeliveriesStatsGroupExprs[""]
	}

	countStatus := func(status string) string {
		return "COALESCE(SUM(CASE WHEN [[status]] = '" + status + "' THEN 1 ELSE 0 END), 0)"
	}

	query := app.AuxDB().
		Select(
			"strftime('"+format+"', [[created]]) AS [[date]]",
			groupExpr+" AS [[grp]]",
			"COUNT(*) AS [[total]]",
			countStatus(WebhookDeliveryStatusSuccess)+" AS [[success]]",
			countStatus(WebhookDeliveryStatusFailed)+" AS [[failed]]",
			countStatus(WebhookDeliveryStatusRetrying)+" AS [[retrying]]",
			countStatus(WebhookDeliveryStatusPending)+" AS [[pending]]",
			countStatus(WebhookDeliveryStatusDisabled)+" AS [[disabled]]",
			"COALESCE(SUM([[attempts]]), 0) AS [[attempts]]",
			"COALESCE(AVG(CASE WHEN [[attempts]] > 0 THEN [[durationMs]] END), 0) AS [[avgDurationMs]]",
		).
		From(WebhookDeliveriesTableName).
		GroupBy("date", "grp").
		OrderBy("date ASC", "grp ASC")

	if params.Filter != nil {
		query.AndWhere(params.Filter)
	}

	result := []*WebhookDeliveriesStatsItem{}

	err := query.All(&result)

	return result, err
}
