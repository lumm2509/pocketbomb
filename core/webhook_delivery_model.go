package core

import (
	"time"

	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/lumm2509/pocketbomb/tools/webhooks"
)

var _ Model = (*WebhookDelivery)(nil)

// WebhookDeliveriesTableName is the auxiliary db table name of the
// webhook deliveries (it acts both as delivery queue and log).
const WebhookDeliveriesTableName = "_webhookDeliveries"

// Webhook delivery statuses.
const (
	WebhookDeliveryStatusPending  = webhooks.StatusPending
	WebhookDeliveryStatusRetrying = webhooks.StatusRetrying
	WebhookDeliveryStatusSuccess  = webhooks.StatusSuccess
	WebhookDeliveryStatusFailed   = webhooks.StatusFailed
	WebhookDeliveryStatusDisabled = webhooks.StatusDisabled
)

const (
	// maxWebhookPayloadSize is the max allowed size of a single webhook event payload.
	maxWebhookPayloadSize = 1 << 20 // 1MB

	// maxWebhookLogBodySize is the max stored size of the delivery log request body.
	maxWebhookLogBodySize = 64 << 10 // 64KB
)

// WebhookDelivery defines a single webhook event delivery to a single subscription.
//
// The model is stored in the auxiliary db and it serves both as delivery queue
// and as log of the last delivery attempt.
type WebhookDelivery struct {
	BaseModel

	// Webhook is the related webhook subscription id.
	Webhook string `db:"webhook" json:"webhook"`

	// EventId is the event identifier (the same across retries and redeliveries).
	EventId string `db:"eventId" json:"eventId"`

	// Topic is the event topic in its storage format
	// (aka. "{collectionId}.{op}" for the collection topics).
	Topic string `db:"topic" json:"topic"`

	ApiVersion  string         `db:"apiVersion" json:"apiVersion"`
	TriggeredAt types.DateTime `db:"triggeredAt" json:"triggeredAt"`

	Status   string `db:"status" json:"status"`
	Attempts int    `db:"attempts" json:"attempts"`

	NextAttemptAt types.DateTime `db:"nextAttemptAt" json:"nextAttemptAt"`
	LeaseUntil    types.DateTime `db:"leaseUntil" json:"leaseUntil"`
	LeaseToken    string         `db:"leaseToken" json:"-"`

	// Payload is the original event payload (aka. the request body before any hook modifications).
	Payload types.JSONRaw `db:"payload" json:"payload"`

	// The last attempt request and response data.
	RequestHeaders  types.JSONMap[string] `db:"requestHeaders" json:"requestHeaders"`
	RequestBody     string                `db:"requestBody" json:"requestBody"` // capped
	ResponseStatus  int                   `db:"responseStatus" json:"responseStatus"`
	ResponseHeaders types.JSONMap[string] `db:"responseHeaders" json:"responseHeaders"`
	ResponseBody    string                `db:"responseBody" json:"responseBody"` // capped
	Error           string                `db:"error" json:"error"`
	DurationMs      int                   `db:"durationMs" json:"durationMs"`

	// Test indicates a manually triggered test delivery (it is never retried).
	Test bool `db:"test" json:"test"`

	// RedeliveryOf is the id of the original delivery in case of a manual redelivery.
	RedeliveryOf string `db:"redeliveryOf" json:"redeliveryOf"`

	Created types.DateTime `db:"created" json:"created"`
	Updated types.DateTime `db:"updated" json:"updated"`
}

// TableName implements [Model.TableName] interface method.
func (m *WebhookDelivery) TableName() string {
	return WebhookDeliveriesTableName
}

// IsDone reports whether the delivery is in a final state (success, failed or disabled).
func (m *WebhookDelivery) IsDone() bool {
	return m.Status == WebhookDeliveryStatusSuccess ||
		m.Status == WebhookDeliveryStatusFailed ||
		m.Status == WebhookDeliveryStatusDisabled
}

// toDelivery converts the model to [webhooks.Delivery].
func (m *WebhookDelivery) toDelivery() *webhooks.Delivery {
	return &webhooks.Delivery{
		Id:             m.Id,
		SubscriptionId: m.Webhook,
		Event: webhooks.Event{
			Id:          m.EventId,
			Topic:       m.Topic,
			ApiVersion:  m.ApiVersion,
			TriggeredAt: m.TriggeredAt.Time(),
			Payload:     []byte(m.Payload),
		},
		Status:        m.Status,
		Attempts:      m.Attempts,
		NextAttemptAt: m.NextAttemptAt.Time(),
		LeaseUntil:    m.LeaseUntil.Time(),
		LeaseToken:    m.LeaseToken,
		Created:       m.Created.Time(),
		Updated:       m.Updated.Time(),
	}
}

func toDateTime(t time.Time) types.DateTime {
	if t.IsZero() {
		return types.DateTime{}
	}

	dt, _ := types.ParseDateTime(t)

	return dt
}
