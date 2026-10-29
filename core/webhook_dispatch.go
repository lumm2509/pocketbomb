package core

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/tools/inflector"
	"github.com/lumm2509/pocketbomb/tools/picker"
	"github.com/lumm2509/pocketbomb/tools/routine"
	"github.com/lumm2509/pocketbomb/tools/search"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

// webhookSubscription is the cached (active) webhook subscription data.
type webhookSubscription struct {
	id         string
	topics     []string
	filter     string
	fields     string
	apiVersion string
	client     string

	// actorRef is the subscription topics actor (empty for the Owners and the trusted saves)
	actorRef string
}

// webhookActorsCache caches the dispatch time subscription actors checks
// of a single events batch (see [Webhooks.actorAllows]).
type webhookActorsCache struct {
	actors map[string]*Record // nil = missing actor
	access map[string]bool    // "{actorRef}|{collectionId}" => allowed
}

func newWebhookActorsCache() *webhookActorsCache {
	return &webhookActorsCache{
		actors: map[string]*Record{},
		access: map[string]bool{},
	}
}

// webhookEvent is a single (record or custom) webhook event.
type webhookEvent struct {
	id          string
	triggeredAt time.Time

	// namespace is the collection id or the custom topic namespace
	namespace string
	op        string

	// record events only
	collection    *Collection
	record        *Record
	changedFields []string
	authMethod    string

	// custom events only
	payload []byte
}

func (ev *webhookEvent) topic() string {
	return ev.namespace + "." + ev.op
}

// namespaceName returns the event collection name or the custom topic namespace.
func (ev *webhookEvent) namespaceName() string {
	if ev.collection != nil {
		return ev.collection.Name
	}
	return ev.namespace
}

func (w *Webhooks) invalidateCache() {
	w.cacheMu.Lock()
	defer w.cacheMu.Unlock()

	w.cache = nil
	w.cacheGen++
}

// subscriptions returns the cached active subscriptions.
func (w *Webhooks) subscriptions() []*webhookSubscription {
	w.cacheMu.RLock()
	if w.cache != nil && time.Since(w.cacheAt) < webhooksCacheTTL {
		cache := w.cache
		w.cacheMu.RUnlock()
		return cache
	}
	gen := w.cacheGen
	w.cacheMu.RUnlock()

	subs := w.loadSubscriptions()

	w.cacheMu.Lock()
	defer w.cacheMu.Unlock()

	// store only if there wasn't an invalidation in the meantime
	if gen == w.cacheGen {
		w.cache = subs
		w.cacheAt = time.Now()
	}

	return subs
}

func (w *Webhooks) loadSubscriptions() []*webhookSubscription {
	result := []*webhookSubscription{}

	if !w.app.IsBootstrapped() {
		return result
	}

	// the collection may not exist yet (e.g. before the system migrations)
	if _, err := w.app.FindCachedCollectionByNameOrId(CollectionNameWebhooks); err != nil {
		return result
	}

	records, err := w.app.FindAllRecords(CollectionNameWebhooks, dbx.HashExp{"active": true})
	if err != nil {
		w.app.Logger().Warn("Failed to load the webhook subscriptions", slog.String("error", err.Error()))
		return result
	}

	for _, r := range records {
		webhook := &Webhook{r}
		result = append(result, &webhookSubscription{
			id:         webhook.Id,
			topics:     webhook.Topics(),
			filter:     webhook.Filter(),
			fields:     strings.Join(webhook.Fields(), ","),
			apiVersion: webhook.ApiVersion(),
			client:     webhook.Client(),
			actorRef:   webhook.ActorRef(),
		})
	}

	return result
}

// match returns the active subscriptions matching the event topic.
func (w *Webhooks) match(ev *webhookEvent) []*webhookSubscription {
	var result []*webhookSubscription

	for _, sub := range w.subscriptions() {
		for _, pattern := range sub.topics {
			if webhookTopicMatches(pattern, ev) {
				result = append(result, sub)
				break
			}
		}
	}

	return result
}

func marshalWebhookPayload(payload any) ([]byte, error) {
	var raw []byte

	switch v := payload.(type) {
	case nil:
		raw = []byte("{}")
	case []byte:
		raw = v
	case types.JSONRaw:
		raw = v
	case jsontext.Value:
		raw = v
	default:
		var err error
		raw, err = json.Marshal(payload, json.Deterministic(true))
		if err != nil {
			return nil, fmt.Errorf("failed to serialize the webhook payload: %w", err)
		}
	}

	if !jsontext.Value(raw).IsValid() {
		return nil, errors.New("the webhook payload must be a valid JSON")
	}

	if len(raw) > maxWebhookPayloadSize {
		return nil, fmt.Errorf("the webhook payload exceeds the max allowed size of %d bytes", maxWebhookPayloadSize)
	}

	return raw, nil
}

// onRecordEvent queues a record event if there is at least one matching subscription.
//
// It is called in the request path and it is expected to be fast.
func (w *Webhooks) onRecordEvent(record *Record, op string, authMethod string) {
	if record == nil || !w.isEnabled() {
		return
	}

	collection := record.Collection()
	if isWebhookDeniedCollection(collection) {
		return
	}

	ev := &webhookEvent{
		namespace:  collection.Id,
		op:         op,
		collection: collection,
		authMethod: authMethod,
	}

	if len(w.match(ev)) == 0 {
		return
	}

	ev.id = GenerateDefaultRandomId()
	ev.triggeredAt = time.Now()
	ev.record = record.Fresh()

	if op == WebhookOpUpdate {
		ev.changedFields = webhookChangedFields(record)
	}

	w.enqueueEvent(ev)
}

// webhookChangedFields returns the names of the changed non-hidden record fields.
func webhookChangedFields(record *Record) []string {
	original := record.Original()

	result := []string{}

	for _, f := range record.Collection().Fields {
		name := f.GetName()
		if f.GetHidden() || name == FieldNamePassword || name == FieldNameTokenKey || IsSecretField(record.Collection(), f) {
			continue
		}

		if !areValuesEqual(original.GetRaw(name), record.GetRaw(name)) {
			result = append(result, name)
		}
	}

	return result
}

func (w *Webhooks) enqueueEvent(ev *webhookEvent) {
	w.queueMu.Lock()
	defer w.queueMu.Unlock()

	if len(w.queue) >= maxWebhooksQueuedEvents {
		w.app.Logger().Error(
			"Webhook event dropped because the events queue is full",
			slog.String("topic", ev.topic()),
			slog.String("eventId", ev.id),
		)
		return
	}

	w.queue = append(w.queue, ev)

	if !w.queueBusy {
		w.queueBusy = true
		go w.drainQueue()
	}
}

func (w *Webhooks) drainQueue() {
	for {
		w.queueMu.Lock()
		batch := w.queue
		w.queue = nil
		if len(batch) == 0 {
			w.queueBusy = false
			w.queueCond.Broadcast()
			w.queueMu.Unlock()
			return
		}
		w.queueMu.Unlock()

		actors := newWebhookActorsCache()

		for _, ev := range batch {
			err := routine.SafeWrap(func() error {
				return w.processEvent(context.Background(), ev, actors)
			})()
			if err != nil {
				w.app.Logger().Warn(
					"Failed to process webhook event",
					slog.String("topic", ev.topic()),
					slog.String("eventId", ev.id),
					slog.String("error", err.Error()),
				)
			}
		}
	}
}

// FlushEvents blocks until all queued record events are processed
// (aka. their deliveries are inserted in the auxiliary db).
//
// It is called automatically before the app bootstrap state is cleared.
func (w *Webhooks) FlushEvents() {
	w.queueMu.Lock()
	defer w.queueMu.Unlock()

	for w.queueBusy || len(w.queue) > 0 {
		w.queueCond.Wait()
	}
}

// processEvent matches the event subscriptions and inserts the related deliveries.
func (w *Webhooks) processEvent(ctx context.Context, ev *webhookEvent, actors *webhookActorsCache) error {
	if !w.app.IsBootstrapped() {
		return errors.New("the app is not bootstrapped")
	}

	subs := w.match(ev)
	if len(subs) == 0 {
		return nil
	}

	var export map[string]any
	if ev.record != nil {
		export = webhookRecordExport(ev.collection, ev.record)
	}

	filterResults := map[string]bool{}
	now := types.NowDateTime()
	rows := make([]*WebhookDelivery, 0, len(subs))

	for _, sub := range subs {
		if sub.client != "" && !w.clientAllows(sub.client, ev.namespaceName()) {
			continue
		}

		// the applications never receive the application lifecycle events (defense in depth, see [webhookTopicsViewErrors])
		if ev.collection == nil && strings.EqualFold(ev.namespace, ApplicationLifecycleTopicNamespace) && w.isApplicationActorRef(sub.actorRef) {
			continue
		}

		// the subscription actor must still be allowed to view the event records
		if !w.actorAllows(actors, sub.actorRef, ev) {
			w.app.Logger().Debug(
				"Webhook event skipped because the subscription actor is no longer allowed to view it",
				slog.String("webhook", sub.id),
				slog.String("topic", ev.topic()),
				slog.String("actorRef", sub.actorRef),
			)
			continue
		}

		if ev.record != nil && sub.filter != "" {
			// the filter is evaluated on behalf of the subscription actor (if any)
			filterKey := sub.actorRef + "|" + sub.filter
			matched, ok := filterResults[filterKey]
			if !ok {
				var err error
				matched, err = w.evalFilter(ev, sub.filter, w.actorCanViewFunc(actors, sub.actorRef))
				if errors.Is(err, errWebhookFilterNotAllowed) {
					w.app.Logger().Debug(
						"Webhook event skipped because the subscription actor is no longer allowed to use the filter",
						slog.String("webhook", sub.id),
						slog.String("topic", ev.topic()),
						slog.String("actorRef", sub.actorRef),
						slog.String("error", err.Error()),
					)
				} else if err != nil {
					w.app.Logger().Warn(
						"Failed to evaluate the webhook filter",
						slog.String("webhook", sub.id),
						slog.String("topic", ev.topic()),
						slog.String("error", err.Error()),
					)
				}
				filterResults[filterKey] = matched
			}
			if !matched {
				continue
			}
		}

		payload, err := buildWebhookPayload(ev, export, sub.fields)
		if err != nil {
			w.app.Logger().Warn(
				"Failed to build the webhook payload",
				slog.String("webhook", sub.id),
				slog.String("topic", ev.topic()),
				slog.String("error", err.Error()),
			)
			continue
		}

		row := &WebhookDelivery{
			Webhook:     sub.id,
			EventId:     ev.id,
			Topic:       ev.topic(),
			ApiVersion:  sub.apiVersion,
			TriggeredAt: toDateTime(ev.triggeredAt),
			Status:      WebhookDeliveryStatusPending,
			Payload:     payload,
			Created:     now,
			Updated:     now,
		}
		row.Id = GenerateDefaultRandomId()

		rows = append(rows, row)
	}

	if err := w.store.insert(ctx, rows...); err != nil {
		return err
	}

	if len(rows) > 0 {
		w.dispatcher.Notify()
	}

	return nil
}

// webhookRecordExport returns the webhook payload export of the provided event record
// (the hidden fields are excluded by the public export and the secret fields,
// e.g. a not hidden tokenKey or password field, are never sent; see [IsSecretField]).
func webhookRecordExport(collection *Collection, record *Record) map[string]any {
	record.IgnoreEmailVisibility(true)

	export := record.PublicExport()

	for _, name := range SecretFieldNames(collection) {
		delete(export, name)
	}

	return export
}

// actorAllows reports whether the subscription actor (if any) is allowed to view the records of
// the event collection (the custom topic events and the subscriptions without actor are always allowed).
//
// A deleted actor (incl. an uninstalled application) is never allowed.
func (w *Webhooks) actorAllows(cache *webhookActorsCache, actorRef string, ev *webhookEvent) bool {
	if actorRef == "" || ev.collection == nil {
		return true
	}

	return w.actorCanView(cache, actorRef, ev.collection)
}

// actorCanView reports whether the subscription actor could still view
// the records of the provided collection (the checks are cached per events batch).
func (w *Webhooks) actorCanView(cache *webhookActorsCache, actorRef string, collection *Collection) bool {
	if cache == nil {
		cache = newWebhookActorsCache()
	}

	key := actorRef + "|" + collection.Id
	if allowed, ok := cache.access[key]; ok {
		return allowed
	}

	actor, ok := cache.actors[actorRef]
	if !ok {
		actor = w.findWebhookActor(actorRef)
		cache.actors[actorRef] = actor
	}

	allowed := webhookActorCanView(w.app, actor, collection)
	cache.access[key] = allowed

	return allowed
}

// actorCanViewFunc returns the [newActorFilterResolver] canView function
// of the subscription actor (nil for the subscriptions without actor).
func (w *Webhooks) actorCanViewFunc(cache *webhookActorsCache, actorRef string) func(c *Collection) bool {
	if actorRef == "" {
		return nil
	}

	if cache == nil {
		cache = newWebhookActorsCache()
	}

	return func(c *Collection) bool {
		return w.actorCanView(cache, actorRef, c)
	}
}

// isApplicationActorRef reports whether the provided webhook actor reference is an application installation.
func (w *Webhooks) isApplicationActorRef(actorRef string) bool {
	if actorRef == "" {
		return false
	}

	installations, err := w.app.FindCachedCollectionByNameOrId(CollectionNameApplicationInstallations)

	return err == nil && strings.HasPrefix(actorRef, installations.Id+":")
}

// findWebhookActor returns the auth record of the provided webhook actor reference (nil if missing).
func (w *Webhooks) findWebhookActor(actorRef string) *Record {
	collectionId, recordId, ok := strings.Cut(actorRef, ":")
	if !ok || collectionId == "" || recordId == "" {
		return nil
	}

	actor, err := w.app.FindRecordById(collectionId, recordId)
	if err != nil || !actor.Collection().IsAuth() {
		return nil
	}

	return actor
}

// clientAllows reports whether the specified OAuth2 client allows the events of the specified namespace.
func (w *Webhooks) clientAllows(clientId string, namespace string) bool {
	client, err := w.app.FindOAuth2ClientById(clientId)
	if err != nil || client.Disabled() {
		return false
	}

	return webhookClientAllowsNamespace(client, namespace)
}

// evalFilter evaluates the filter expression against the event record state
// (the record values are bound as a single row derived table so that the
// filter could be evaluated also for already deleted records).
//
// canView is the subscription actor restriction (see [newActorFilterResolver]; nil = no restrictions).
// If the filter is valid but not allowed for the actor, it returns [errWebhookFilterNotAllowed].
func (w *Webhooks) evalFilter(ev *webhookEvent, filter string, canView func(c *Collection) bool) (bool, error) {
	resolver := newActorFilterResolver(w.app, ev.collection, canView)

	expr, err := search.FilterData(filter).BuildExpr(resolver)
	if err != nil {
		if canView != nil {
			unrestricted := NewRecordFieldResolver(w.app, ev.collection, &RequestInfo{Context: RequestInfoContextDefault}, true)
			if _, uErr := search.FilterData(filter).BuildExpr(unrestricted); uErr == nil {
				return false, fmt.Errorf("%w: %w", errWebhookFilterNotAllowed, err)
			}
		}
		return false, err
	}

	data, err := ev.record.dbExport()
	if err != nil {
		return false, err
	}

	columns := make([]string, 0, len(data))
	params := dbx.Params{}
	i := 0
	for k, v := range data {
		param := "__whf" + strconv.Itoa(i)
		columns = append(columns, "{:"+param+"} AS [["+inflector.Columnify(k)+"]]")
		params[param] = v
		i++
	}

	query := w.app.ConcurrentDB().
		Select("(1)").
		From("(SELECT " + strings.Join(columns, ", ") + ") " + inflector.Columnify(ev.collection.Name)).
		Bind(params)

	if err := resolver.UpdateQuery(query); err != nil {
		return false, err
	}

	var exists int

	err = query.AndWhere(expr).Limit(1).Row(&exists)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}

	return exists > 0, nil
}

// buildWebhookPayload builds the event payload for a single subscription.
//
// Record topics payload format:
//
//	{
//	  "action":         "create|update|delete|auth|verified",
//	  "collectionId":   "...",
//	  "collectionName": "...",
//	  "record":         {...}, // the record as superuser would see it minus the hidden fields (projected by the "fields")
//	  "changedFields":  [...], // update only - the names of the changed non-hidden fields
//	  "authMethod":     "..."  // auth only - password, otp, oauth2, etc.
//	}
//
// Custom topics payload is the one passed to [Webhooks.Trigger].
func buildWebhookPayload(ev *webhookEvent, export map[string]any, fields string) ([]byte, error) {
	if ev.record == nil {
		return ev.payload, nil
	}

	var recordData any = export
	if fields != "" {
		var err error
		recordData, err = picker.Pick(export, fields)
		if err != nil {
			return nil, err
		}
	}

	envelope := map[string]any{
		"action":         ev.op,
		"collectionId":   ev.collection.Id,
		"collectionName": ev.collection.Name,
		"record":         recordData,
	}

	if ev.op == WebhookOpUpdate {
		changed := ev.changedFields
		if changed == nil {
			changed = []string{}
		}
		envelope["changedFields"] = changed
	}

	if ev.op == WebhookOpAuth {
		envelope["authMethod"] = ev.authMethod
	}

	raw, err := json.Marshal(envelope, json.Deterministic(true), jsontext.AllowInvalidUTF8(true))
	if err != nil {
		return nil, err
	}

	if len(raw) > maxWebhookPayloadSize {
		return nil, fmt.Errorf("the webhook payload exceeds the max allowed size of %d bytes", maxWebhookPayloadSize)
	}

	return raw, nil
}
