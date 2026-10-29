package core

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/lumm2509/pocketbomb/tools/webhooks"
	"github.com/pocketbase/dbx"
)

var _ webhooks.Store = (*webhookDeliveriesStore)(nil)

// webhookDeliveriesStore is a [webhooks.Store] implementation backed by
// the auxiliary db "_webhookDeliveries" table.
//
// The queries are executed directly (aka. without model hooks).
type webhookDeliveriesStore struct {
	app *BaseApp
}

func (s *webhookDeliveriesStore) insert(ctx context.Context, rows ...*WebhookDelivery) error {
	if len(rows) == 0 {
		return nil
	}

	return s.app.AuxRunInTransaction(func(txApp App) error {
		for _, row := range rows {
			if row.Id == "" {
				row.Id = GenerateDefaultRandomId()
			}
			if row.Created.IsZero() {
				row.Created = types.NowDateTime()
			}
			if row.Updated.IsZero() {
				row.Updated = row.Created
			}
			if row.Status == "" {
				row.Status = WebhookDeliveryStatusPending
			}
			if row.RequestHeaders == nil {
				row.RequestHeaders = types.JSONMap[string]{}
			}
			if row.ResponseHeaders == nil {
				row.ResponseHeaders = types.JSONMap[string]{}
			}

			if err := txApp.AuxNonconcurrentDB().Model(row).WithContext(ctx).Insert(); err != nil {
				return err
			}
			row.MarkAsNotNew()
		}

		return nil
	})
}

// Enqueue implements [webhooks.Store.Enqueue].
func (s *webhookDeliveriesStore) Enqueue(ctx context.Context, deliveries ...*webhooks.Delivery) error {
	rows := make([]*WebhookDelivery, len(deliveries))

	for i, d := range deliveries {
		row := &WebhookDelivery{
			Webhook:       d.SubscriptionId,
			EventId:       d.Event.Id,
			Topic:         d.Event.Topic,
			ApiVersion:    d.Event.ApiVersion,
			TriggeredAt:   toDateTime(d.Event.TriggeredAt),
			Status:        d.Status,
			Attempts:      d.Attempts,
			NextAttemptAt: toDateTime(d.NextAttemptAt),
			Payload:       types.JSONRaw(d.Event.Payload),
			Created:       toDateTime(d.Created),
			Updated:       toDateTime(d.Updated),
		}
		row.Id = d.Id
		rows[i] = row
	}

	return s.insert(ctx, rows...)
}

// ClaimDue implements [webhooks.Store.ClaimDue].
func (s *webhookDeliveriesStore) ClaimDue(ctx context.Context, now time.Time, limit int, leaseFor time.Duration) ([]*webhooks.Delivery, error) {
	result := []*webhooks.Delivery{}

	if limit <= 0 {
		return result, nil
	}

	nowStr := toDateTime(now).String()
	token := webhooks.NewLeaseToken()

	rows := []*WebhookDelivery{}

	err := s.app.AuxRunInTransaction(func(txApp App) error {
		db := txApp.AuxNonconcurrentDB()

		dueExpr := dbx.And(
			dbx.In("status", WebhookDeliveryStatusPending, WebhookDeliveryStatusRetrying),
			dbx.NewExp("[[nextAttemptAt]] <= {:now}", dbx.Params{"now": nowStr}),
			dbx.NewExp("[[leaseUntil]] <= {:now}", dbx.Params{"now": nowStr}),
		)

		ids := []string{}
		err := db.Select("id").
			From(WebhookDeliveriesTableName).
			Where(dueExpr).
			OrderBy("nextAttemptAt ASC", "created ASC").
			Limit(int64(limit)).
			WithContext(ctx).
			Column(&ids)
		if err != nil || len(ids) == 0 {
			return err
		}

		_, err = db.Update(
			WebhookDeliveriesTableName,
			dbx.Params{
				"leaseUntil": toDateTime(now.Add(leaseFor)).String(),
				"leaseToken": token,
			},
			dbx.And(dbx.In("id", list.ToInterfaceSlice(ids)...), dueExpr),
		).WithContext(ctx).Execute()
		if err != nil {
			return err
		}

		return db.Select("*").
			From(WebhookDeliveriesTableName).
			Where(dbx.HashExp{"leaseToken": token}).
			OrderBy("nextAttemptAt ASC", "created ASC").
			WithContext(ctx).
			All(&rows)
	})
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		result = append(result, row.toDelivery())
	}

	return result, nil
}

func webhookHeadersToMap(h http.Header) types.JSONMap[string] {
	result := make(types.JSONMap[string], len(h))
	for k, v := range h {
		result[k] = strings.ToValidUTF8(strings.Join(v, ", "), "�")
	}
	return result
}

func capWebhookLogBody(body []byte, max int) string {
	if len(body) > max {
		body = body[:max]
	}
	return strings.ToValidUTF8(string(body), "�")
}

func (s *webhookDeliveriesStore) markAttempt(ctx context.Context, d *webhooks.Delivery, a *webhooks.Attempt) error {
	if a == nil {
		a = &webhooks.Attempt{}
	}

	data := dbx.Params{
		"status":          d.Status,
		"attempts":        d.Attempts,
		"nextAttemptAt":   toDateTime(d.NextAttemptAt).String(),
		"leaseUntil":      "",
		"leaseToken":      "",
		"requestHeaders":  webhookHeadersToMap(a.RequestHeaders),
		"requestBody":     capWebhookLogBody(a.RequestBody, maxWebhookLogBodySize),
		"responseStatus":  a.StatusCode,
		"responseHeaders": webhookHeadersToMap(a.ResponseHeaders),
		"responseBody":    capWebhookLogBody(a.ResponseBody, maxWebhookLogBodySize),
		"error":           a.Error,
		"durationMs":      a.Duration.Milliseconds(),
		"updated":         types.NowDateTime().String(),
	}

	return s.update(ctx, d, data)
}

func (s *webhookDeliveriesStore) update(ctx context.Context, d *webhooks.Delivery, data dbx.Params) error {
	res, err := s.app.AuxNonconcurrentDB().Update(
		WebhookDeliveriesTableName,
		data,
		dbx.HashExp{"id": d.Id, "leaseToken": d.LeaseToken},
	).WithContext(ctx).Execute()
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return webhooks.ErrLeaseLost
	}

	d.LeaseToken = ""
	d.LeaseUntil = time.Time{}

	return nil
}

// MarkSuccess implements [webhooks.Store.MarkSuccess].
func (s *webhookDeliveriesStore) MarkSuccess(ctx context.Context, d *webhooks.Delivery, a *webhooks.Attempt) error {
	return s.markAttempt(ctx, d, a)
}

// MarkFailure implements [webhooks.Store.MarkFailure].
func (s *webhookDeliveriesStore) MarkFailure(ctx context.Context, d *webhooks.Delivery, a *webhooks.Attempt) error {
	return s.markAttempt(ctx, d, a)
}

// MarkDisabled implements [webhooks.Store.MarkDisabled].
func (s *webhookDeliveriesStore) MarkDisabled(ctx context.Context, d *webhooks.Delivery, reason string) error {
	return s.update(ctx, d, dbx.Params{
		"status":        d.Status,
		"nextAttemptAt": "",
		"leaseUntil":    "",
		"leaseToken":    "",
		"error":         reason,
		"updated":       types.NowDateTime().String(),
	})
}
