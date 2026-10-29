package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lumm2509/pocketbomb/tools/routine"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/lumm2509/pocketbomb/tools/webhooks"
	"github.com/pocketbase/dbx"
)

// Outgoing webhooks
// -------------------------------------------------------------------
//
// Flow:
//  1. The record model hooks (OnRecordAfter{Create,Update,Delete}Success,
//     OnAuthSessionCompleteRequest and the verified state change) check in-memory whether there is
//     at least one active subscription matching the event topic and if so a
//     snapshot of the record is queued for async processing (nothing else is
//     done in the request path and errors are never propagated to the originating request).
//  2. The async processor evaluates the subscriptions filter, builds the
//     payload of each matched subscription and inserts the deliveries in the
//     auxiliary db "_webhookDeliveries" table (which acts both as queue and log).
//  3. The dispatcher (started on serve) claims the due deliveries with a lease,
//     sends them with a bounded worker pool and schedules the retries.
//
// Durability trade-off: the record is committed in the main db and the related
// deliveries are inserted in the auxiliary db only after the commit (the dbs
// are separate SQLite files and can't share a transaction). If the process
// crashes in the short window between the commit and the deliveries insert
// (usually a few ms) the event is lost. On graceful shutdown the queued events
// are always flushed. Once inserted, the deliveries survive restarts
// (at-least-once semantic; receivers should dedupe by the X-PB-Event-Id header).

const (
	// webhooksCacheTTL is the max age of the in-memory subscriptions cache
	// (the cache is also invalidated on each _webhooks record change; the
	// TTL is mainly for the changes made by other processes).
	webhooksCacheTTL = time.Minute

	// maxWebhooksQueuedEvents is the max number of queued (not processed yet) record events.
	maxWebhooksQueuedEvents = 100000

	// webhooksStopTimeout is the max time to wait for the in-flight deliveries on app stop.
	webhooksStopTimeout = 10 * time.Second
)

var (
	// ErrWebhookInvalidTopic is returned when the webhook topic is invalid.
	ErrWebhookInvalidTopic = errors.New("invalid webhook topic")

	// errWebhookFilterNotAllowed is returned when a valid webhook filter can't be evaluated
	// on behalf of the subscription actor (see [newActorFilterResolver]).
	errWebhookFilterNotAllowed = errors.New("the webhook filter is not allowed for the subscription actor")

	// ErrWebhookNotRedeliverable is returned when trying to redeliver
	// a pending, retrying or test delivery.
	ErrWebhookNotRedeliverable = errors.New("only completed non-test deliveries can be redelivered")
)

// Webhooks is the app outgoing webhooks service.
//
// It is accessible via [App.Webhooks].
type Webhooks struct {
	app        *BaseApp
	client     *webhooks.Client
	store      *webhookDeliveriesStore
	dispatcher *webhooks.Dispatcher

	cacheMu  sync.RWMutex
	cache    []*webhookSubscription
	cacheAt  time.Time
	cacheGen int64

	topicsMu     sync.RWMutex
	customTopics map[string]string

	queueMu   sync.Mutex
	queueCond *sync.Cond
	queue     []*webhookEvent
	queueBusy bool
}

func newWebhooks(app *BaseApp) *Webhooks {
	w := &Webhooks{
		app:          app,
		client:       webhooks.NewClient(newDefaultWebhooksConfig().ClientOptions()),
		store:        &webhookDeliveriesStore{app: app},
		customTopics: map[string]string{},
	}

	w.queueCond = sync.NewCond(&w.queueMu)

	w.dispatcher = webhooks.NewDispatcher(webhooks.DispatcherConfig{
		Store:       w.store,
		Send:        w.send,
		RetryPolicy: newDefaultWebhooksConfig().RetryPolicy(),
		Paused: func() bool {
			if !w.app.IsBootstrapped() {
				return true
			}
			return !w.syncSettings()
		},
		OnResult: func(d *webhooks.Delivery, a *webhooks.Attempt) {
			w.onResult(d, a, false)
		},
		OnError: func(err error) {
			w.app.Logger().Warn("Webhooks dispatcher error", slog.String("error", err.Error()))
		},
	})

	return w
}

// Start starts the background deliveries dispatcher (it is called automatically on serve).
func (w *Webhooks) Start() {
	w.syncSettings()
	w.dispatcher.Start()
}

// Stop stops the background deliveries dispatcher and waits for the
// in-flight attempts to complete (see [webhooks.Dispatcher.Close]).
func (w *Webhooks) Stop(ctx context.Context) error {
	return w.dispatcher.Close(ctx)
}

// ProcessDue synchronously sends up to limit due deliveries
// (it doesn't require the dispatcher to be started).
//
// It is mainly intended for tests and manual triggers.
func (w *Webhooks) ProcessDue(ctx context.Context, limit int) (int, error) {
	w.syncSettings()
	return w.dispatcher.ProcessDue(ctx, limit)
}

// syncSettings applies the current app settings to the client and the dispatcher.
//
// It returns whether the webhooks are enabled.
func (w *Webhooks) syncSettings() bool {
	settings := w.app.Settings().webhooksConfig()

	w.client.SetOptions(settings.ClientOptions())
	w.dispatcher.SetRetryPolicy(settings.RetryPolicy())

	return settings.Enabled
}

func (w *Webhooks) isEnabled() bool {
	return w.app.Settings().webhooksConfig().Enabled
}

// -------------------------------------------------------------------
// Events
// -------------------------------------------------------------------

// Trigger triggers a custom topic webhook event and enqueues
// a delivery for each matching active subscription.
//
// The topic must be in the "{namespace}.{name}" format and the namespace must not
// clash with an existing collection name or id (e.g. "orders.paid").
//
// The payload is serialized as JSON (raw []byte payloads must be valid JSON).
//
// It is no-op if the webhooks are globally disabled.
func (w *Webhooks) Trigger(ctx context.Context, topic string, payload any) error {
	if err := w.checkCustomTopic(topic); err != nil {
		return err
	}

	if !w.isEnabled() {
		return nil
	}

	raw, err := marshalWebhookPayload(payload)
	if err != nil {
		return err
	}

	ns, op, _ := splitWebhookTopic(topic)

	ev := &webhookEvent{
		id:          GenerateDefaultRandomId(),
		triggeredAt: time.Now(),
		namespace:   ns,
		op:          op,
		payload:     raw,
	}

	return w.processEvent(ctx, ev, newWebhookActorsCache())
}

// -------------------------------------------------------------------
// Sending
// -------------------------------------------------------------------

// send implements [webhooks.SendFunc].
func (w *Webhooks) send(ctx context.Context, d *webhooks.Delivery) (*webhooks.Attempt, error) {
	return w.sendDelivery(ctx, d, false)
}

func (w *Webhooks) sendDelivery(ctx context.Context, d *webhooks.Delivery, isTest bool) (*webhooks.Attempt, error) {
	webhook, err := w.app.FindWebhookById(d.SubscriptionId)
	if err != nil {
		return nil, fmt.Errorf("%w: missing webhook subscription", webhooks.ErrDisabled)
	}

	if !isTest && !webhook.Active() {
		return nil, fmt.Errorf("%w: inactive webhook subscription", webhooks.ErrDisabled)
	}

	topic := RenderWebhookTopic(w.app, d.Event.Topic)

	// recheck the linked client scopes
	if clientId := webhook.Client(); clientId != "" {
		ns, _, _ := strings.Cut(topic, ".")
		if !w.clientAllows(clientId, ns) {
			return nil, fmt.Errorf("%w: the linked OAuth2 client is missing, disabled or no longer has the required scope", webhooks.ErrDisabled)
		}
	}

	req := webhooks.NewRequest(d, webhook.URI(), webhook.Secret(), topic)
	if isTest {
		req.Header.Set(webhooks.HeaderTest, "true")
	}

	event := new(WebhookSendEvent)
	event.App = w.app
	event.Webhook = webhook
	event.Delivery = d
	event.Request = req
	event.Topic = topic
	event.Test = isTest

	var attempt *webhooks.Attempt

	hookErr := w.app.OnWebhookSend().Trigger(event, func(e *WebhookSendEvent) error {
		attempt = w.client.Send(ctx, e.Request)
		return nil
	})
	if hookErr != nil {
		return attempt, hookErr
	}

	if attempt == nil {
		return nil, fmt.Errorf("%w: skipped by an OnWebhookSend hook handler", webhooks.ErrDisabled)
	}

	return attempt, nil
}

// onResult is called after each processed delivery.
func (w *Webhooks) onResult(d *webhooks.Delivery, a *webhooks.Attempt, isTest bool) {
	webhook, _ := w.app.FindWebhookById(d.SubscriptionId)

	event := new(WebhookDeliveryEvent)
	event.App = w.app
	event.Webhook = webhook
	event.Delivery = d
	event.Attempt = a
	event.Topic = RenderWebhookTopic(w.app, d.Event.Topic)
	event.Test = isTest

	if err := w.app.OnWebhookDelivery().Trigger(event); err != nil {
		w.app.Logger().Warn("OnWebhookDelivery hook error", slog.String("error", err.Error()))
	}

	if isTest || webhook == nil {
		return
	}

	if err := w.updateWebhookStats(webhook, d); err != nil {
		w.app.Logger().Warn(
			"Failed to update the webhook delivery stats",
			slog.String("webhook", webhook.Id),
			slog.String("error", err.Error()),
		)
	}
}

// updateWebhookStats updates the subscription failure counters and
// auto disables it if the consecutive failed events threshold is reached.
//
// The counters are updated with plain SQL to avoid unnecessary
// record hooks and subscriptions cache invalidation.
func (w *Webhooks) updateWebhookStats(webhook *Webhook, d *webhooks.Delivery) error {
	now := types.NowDateTime().String()
	params := dbx.Params{"id": webhook.Id, "now": now}

	var sql string
	switch d.Status {
	case WebhookDeliveryStatusSuccess:
		sql = "UPDATE {{" + CollectionNameWebhooks + "}} SET [[failureCount]] = 0, [[lastSuccessAt]] = {:now} WHERE [[id]] = {:id}"
	case WebhookDeliveryStatusRetrying:
		sql = "UPDATE {{" + CollectionNameWebhooks + "}} SET [[lastFailureAt]] = {:now} WHERE [[id]] = {:id}"
	case WebhookDeliveryStatusFailed:
		sql = "UPDATE {{" + CollectionNameWebhooks + "}} SET [[failureCount]] = [[failureCount]] + 1, [[lastFailureAt]] = {:now} WHERE [[id]] = {:id}"
	default:
		return nil
	}

	if _, err := w.app.NonconcurrentDB().NewQuery(sql).Bind(params).Execute(); err != nil {
		return err
	}

	if d.Status != WebhookDeliveryStatusFailed {
		return nil
	}

	threshold := w.app.Settings().Webhooks.AutoDisableAfter
	if threshold <= 0 {
		return nil
	}

	fresh, err := w.app.FindWebhookById(webhook.Id)
	if err != nil {
		return err
	}

	if !fresh.Active() || fresh.FailureCount() < threshold {
		return nil
	}

	reason := fmt.Sprintf(
		"Automatically disabled after %d consecutive failed deliveries (last error: %s).",
		fresh.FailureCount(),
		w.lastDeliveryError(d.Id),
	)

	fresh.SetActive(false)
	fresh.SetDisabledReason(reason)

	// note: without validations to ensure that the subscription
	// will be disabled even if it is no longer valid
	// (and with the managed change context so that the application managed webhooks are disabled too)
	if err := w.app.SaveNoValidateWithContext(withManagedWebhookChange(context.Background()), fresh); err != nil {
		return err
	}

	w.app.Logger().Warn(
		"Webhook subscription automatically disabled",
		slog.String("webhook", fresh.Id),
		slog.String("name", fresh.Name()),
		slog.Int("failureCount", fresh.FailureCount()),
	)

	routine.FireAndForget(func() {
		details := fmt.Sprintf("Webhook subscription %q (%s) to %s was disabled.\n\n%s", fresh.Name(), fresh.Id, fresh.URI(), reason)
		if err := sendSystemAlertToAllSuperusers(w.app, "Webhook subscription disabled", details); err != nil {
			w.app.Logger().Warn("Failed to send the webhook disabled system alert", slog.String("error", err.Error()))
		}
	})

	return nil
}

func (w *Webhooks) lastDeliveryError(id string) string {
	d, err := w.app.FindWebhookDeliveryById(id)
	if err != nil {
		return "unknown"
	}

	if d.Error != "" {
		return d.Error
	}

	if d.ResponseStatus > 0 {
		return "response status " + strconv.Itoa(d.ResponseStatus)
	}

	return "unknown"
}

// newLeasedDelivery returns a new delivery row that is already leased
// by the caller (so that it couldn't be claimed by the dispatcher).
func (w *Webhooks) newLeasedDelivery() *WebhookDelivery {
	now := time.Now()

	row := &WebhookDelivery{
		Status:     WebhookDeliveryStatusPending,
		LeaseToken: webhooks.NewLeaseToken(),
		LeaseUntil: toDateTime(now.Add(w.dispatcher.LeaseDuration())),
		Created:    toDateTime(now),
		Updated:    toDateTime(now),
	}
	row.Id = GenerateDefaultRandomId()

	return row
}

// Redeliver creates a new delivery for the same event (same event id and payload)
// as the specified completed delivery and sends it synchronously.
//
// If the attempt fails, the new delivery is retried with the regular retry policy.
//
// Returns the new delivery.
func (w *Webhooks) Redeliver(ctx context.Context, deliveryId string) (*WebhookDelivery, error) {
	original, err := w.app.FindWebhookDeliveryById(deliveryId)
	if err != nil {
		return nil, err
	}

	if original.Test || !original.IsDone() {
		return nil, ErrWebhookNotRedeliverable
	}

	row := w.newLeasedDelivery()
	row.Webhook = original.Webhook
	row.EventId = original.EventId
	row.Topic = original.Topic
	row.ApiVersion = original.ApiVersion
	row.TriggeredAt = original.TriggeredAt
	row.Payload = original.Payload
	row.RedeliveryOf = original.Id

	if err := w.store.insert(ctx, row); err != nil {
		return nil, err
	}

	w.syncSettings()

	if _, err := w.dispatcher.Deliver(ctx, row.toDelivery()); err != nil && !errors.Is(err, context.Canceled) {
		return nil, err
	}

	return w.app.FindWebhookDeliveryById(row.Id)
}

// SendTest sends synchronously a synthetic test event for the specified
// subscription topic (it must match the subscription topics and if empty,
// the first non-wildcard subscription topic is used).
//
// For the record topics the payload contains a blank record of the topic collection.
//
// The test deliveries are logged (with Test=true) but they are never
// retried and don't affect the subscription failure counters.
// The subscription is not required to be active.
func (w *Webhooks) SendTest(ctx context.Context, webhook *Webhook, topic string) (*WebhookDelivery, error) {
	if topic == "" {
		for _, t := range webhook.Topics() {
			if !strings.Contains(t, WebhookTopicWildcard) {
				topic = t
				break
			}
		}
		if topic == "" {
			return nil, fmt.Errorf("%w: a non-wildcard topic is required", ErrWebhookInvalidTopic)
		}
	}

	target, err := parseWebhookTopic(w.app, topic)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWebhookInvalidTopic, err)
	}

	if target.namespace == WebhookTopicWildcard || target.op == WebhookTopicWildcard {
		return nil, fmt.Errorf("%w: a non-wildcard topic is required", ErrWebhookInvalidTopic)
	}

	ev := &webhookEvent{
		id:          GenerateDefaultRandomId(),
		triggeredAt: time.Now(),
		namespace:   target.namespace,
		op:          target.op,
	}

	var export map[string]any

	if target.collection != nil {
		ev.collection = target.collection

		record := NewRecord(target.collection)
		record.Id = GenerateDefaultRandomId()
		ev.record = record
		export = webhookRecordExport(target.collection, record)

		switch target.op {
		case WebhookOpUpdate:
			ev.changedFields = []string{}
		case WebhookOpAuth:
			ev.authMethod = AuthSessionMethodPassword
		}
	} else {
		ev.payload = []byte("{}")
	}

	if !slices.ContainsFunc(webhook.Topics(), func(pattern string) bool { return webhookTopicMatches(pattern, ev) }) {
		return nil, fmt.Errorf("%w: the topic doesn't match the subscription topics", ErrWebhookInvalidTopic)
	}

	payload, err := buildWebhookPayload(ev, export, strings.Join(webhook.Fields(), ","))
	if err != nil {
		return nil, err
	}

	row := w.newLeasedDelivery()
	row.Webhook = webhook.Id
	row.EventId = ev.id
	row.Topic = ev.topic()
	row.ApiVersion = webhook.ApiVersion()
	row.TriggeredAt = toDateTime(ev.triggeredAt)
	row.Payload = payload
	row.Test = true

	if err := w.store.insert(ctx, row); err != nil {
		return nil, err
	}

	w.syncSettings()

	d := row.toDelivery()

	attempt, sendErr := w.sendDelivery(ctx, d, true)

	// the store updates shouldn't be affected by the caller cancellation
	storeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	if errors.Is(sendErr, webhooks.ErrDisabled) {
		d.Status = WebhookDeliveryStatusDisabled
		attempt = nil
		err = w.store.MarkDisabled(storeCtx, d, sendErr.Error())
	} else {
		if attempt == nil {
			attempt = &webhooks.Attempt{StartedAt: time.Now()}
		}
		if sendErr != nil && attempt.Error == "" {
			attempt.Error = sendErr.Error()
		}

		d.Attempts = 1
		if attempt.Succeeded() {
			d.Status = WebhookDeliveryStatusSuccess
			err = w.store.MarkSuccess(storeCtx, d, attempt)
		} else {
			d.Status = WebhookDeliveryStatusFailed
			err = w.store.MarkFailure(storeCtx, d, attempt)
		}
	}
	if err != nil {
		return nil, err
	}

	w.onResult(d, attempt, true)

	return w.app.FindWebhookDeliveryById(row.Id)
}

// Webhooks returns the app outgoing webhooks service.
func (app *BaseApp) Webhooks() *Webhooks {
	return app.webhooks
}
