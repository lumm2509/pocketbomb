package core

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/picker"
	"github.com/lumm2509/pocketbomb/tools/routine"
	"github.com/lumm2509/pocketbomb/tools/search"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// CollectionNameWebhooks is the name of the webhook subscriptions system collection.
const CollectionNameWebhooks = "_webhooks"

// WebhooksApiVersion is the current (and default) webhooks payload api version.
const WebhooksApiVersion = "2026-10"

// WebhooksApiVersions is the list of the supported webhooks payload api versions.
var WebhooksApiVersions = []string{WebhooksApiVersion}

// Webhook topic operations.
//
// The topics have the format "{collection}.{operation}" (or "{namespace}.{name}" for the custom topics).
const (
	WebhookOpCreate   = "create"
	WebhookOpUpdate   = "update"
	WebhookOpDelete   = "delete"
	WebhookOpAuth     = "auth"     // auth collections only
	WebhookOpVerified = "verified" // auth collections only

	WebhookTopicWildcard = "*"
)

// WebhookScopeAll is the OAuth2 client scope that allows a client-linked
// webhook subscription to subscribe to any topic.
//
// Otherwise the client is required to have the "{collectionName}:read"
// (or "{namespace}:read" for the custom topics) scope.
const WebhookScopeAll = "webhooks:*"

// webhookSecretLength is the length of the auto generated webhook secrets.
const webhookSecretLength = 40

// webhookSecretMinLength is the min length of a manually set webhook secret.
const webhookSecretMinLength = 16

// webhookDeniedCollections is the list of system collections that cannot be used in a webhook topic.
var webhookDeniedCollections = []string{
	CollectionNameOTPs,
	CollectionNameAuthSessions,
	CollectionNameWebhooks,
}

var webhookTopicPartRegex = regexp.MustCompile(`^[\w\-]+$`)

var (
	_ Model        = (*Webhook)(nil)
	_ PreValidator = (*Webhook)(nil)
	_ RecordProxy  = (*Webhook)(nil)
)

// Webhook defines a Record proxy for working with the webhook subscriptions collection.
//
// The secret is stored in plain text because it is required for
// calculating the HMAC signatures. It is never returned by the records API
// (only the "hasSecret" flag is exposed to the superusers).
type Webhook struct {
	*Record
}

// NewWebhook instantiates and returns a new blank *Webhook model.
//
// Example usage:
//
//	webhook := core.NewWebhook(app)
//	webhook.SetName("Orders sync")
//	webhook.SetURI("https://example.com/webhooks")
//	webhook.SetTopics([]string{"posts.create", "posts.update"}) // names are normalized to collection ids on save
//	webhook.SetActive(true)
//	app.Save(webhook) // a random secret is generated if not set
func NewWebhook(app App) *Webhook {
	m := &Webhook{}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameWebhooks)
	if err != nil {
		// this is just to make tests easier since it is a system collection and it is expected to be always accessible
		// (note: the loaded record is further checked on Webhook.PreValidate())
		c = NewBaseCollection("@__invalid__")
	}

	m.Record = NewRecord(c)

	return m
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *Webhook) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameWebhooks {
		return errors.New("missing or invalid webhook ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *Webhook) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *Webhook) SetProxyRecord(record *Record) {
	m.Record = record
}

// Name returns the "name" record field value.
func (m *Webhook) Name() string {
	return m.GetString("name")
}

// SetName updates the "name" record field value.
func (m *Webhook) SetName(name string) {
	m.Set("name", name)
}

// Active returns the "active" record field value.
func (m *Webhook) Active() bool {
	return m.GetBool("active")
}

// SetActive updates the "active" record field value.
func (m *Webhook) SetActive(active bool) {
	m.Set("active", active)
}

// URI returns the "uri" record field value (aka. the endpoint url).
func (m *Webhook) URI() string {
	return m.GetString("uri")
}

// SetURI updates the "uri" record field value.
func (m *Webhook) SetURI(uri string) {
	m.Set("uri", uri)
}

// Secret returns the "secret" record field value (the plain HMAC signing secret).
func (m *Webhook) Secret() string {
	return m.GetString("secret")
}

// SetSecret updates the "secret" record field value.
//
// If empty, a new random secret is generated on save.
func (m *Webhook) SetSecret(secret string) {
	m.Set("secret", secret)
}

// Topics returns the "topics" record field value.
//
// The collection topics are stored in the "{collectionId}.{op}" format
// (use [RenderWebhookTopic] to convert them to "{collectionName}.{op}").
func (m *Webhook) Topics() []string {
	return m.GetStringSlice("topics")
}

// SetTopics updates the "topics" record field value.
//
// The collection names are normalized to collection ids on save.
func (m *Webhook) SetTopics(topics []string) {
	m.Set("topics", topics)
}

// Filter returns the "filter" record field value
// (a PocketBase filter expression evaluated against the event record).
//
// The filter of a subscription with an actor (see [Webhook.ActorRef]) is evaluated
// with the actor restrictions (no secret fields and only the joins into the collections
// that the actor could view; the events are skipped if it is no longer allowed).
func (m *Webhook) Filter() string {
	return m.GetString("filter")
}

// SetFilter updates the "filter" record field value.
func (m *Webhook) SetFilter(filter string) {
	m.Set("filter", filter)
}

// Fields returns the "fields" record field value
// (the optional record payload projection in the "fields" query parameter format).
func (m *Webhook) Fields() []string {
	return m.GetStringSlice("fields")
}

// SetFields updates the "fields" record field value.
func (m *Webhook) SetFields(fields []string) {
	m.Set("fields", fields)
}

// ApiVersion returns the "apiVersion" record field value.
func (m *Webhook) ApiVersion() string {
	return m.GetString("apiVersion")
}

// SetApiVersion updates the "apiVersion" record field value.
func (m *Webhook) SetApiVersion(version string) {
	m.Set("apiVersion", version)
}

// Client returns the "client" record field value (the linked OAuth2 client record id, if any).
func (m *Webhook) Client() string {
	return m.GetString("client")
}

// SetClient updates the "client" record field value.
func (m *Webhook) SetClient(clientId string) {
	m.Set("client", clientId)
}

// ApplicationInstallationRef returns the "applicationInstallationRef" record field value
// (the application installation of a managed webhook; empty for the regular subscriptions).
func (m *Webhook) ApplicationInstallationRef() string {
	return m.GetString("applicationInstallationRef")
}

// ActorRef returns the "actorRef" record field value, aka. the actor that last created
// or changed the subscription in the "{collectionId}:{recordId}" format
// (see [WebhookActorRef] and [WebhookChangeActorRef]).
//
// An empty value means an Owner or a trusted programmatic save (no dispatch time actor checks).
//
// The deliveries of a subscription with an actor are created only for the collection
// events that the actor could still view (aka. narrowing its roles or its application
// installation grant applies immediately).
func (m *Webhook) ActorRef() string {
	return m.GetString("actorRef")
}

// SetActorRef updates the "actorRef" record field value (see [Webhook.ActorRef]).
func (m *Webhook) SetActorRef(actorRef string) {
	m.Set("actorRef", actorRef)
}

// WebhookActorRef returns the webhook actor reference of the provided auth record
// in the "{collectionId}:{recordId}" format (empty for nil).
func WebhookActorRef(actor *Record) string {
	if actor == nil {
		return ""
	}

	return actor.Collection().Id + ":" + actor.Id
}

// WebhookChangeActorRef returns the actorRef of the provided webhook subscription
// created or changed by the request actor (never taken from the submitted data):
//   - a non-Owner create or change (of any field) sets the request actor
//     (e.g. a changed URI must not keep receiving the events with the previous actor access)
//   - an Owner create or topics change clears it (no dispatch time actor checks)
//   - an Owner non-topics change keeps the previous actor (a rename or a toggle
//     doesn't silently lift the dispatch time checks of a staff/application subscription)
//
// A nil info is treated as a trusted programmatic change (same as an Owner).
func WebhookChangeActorRef(app App, info *RequestInfo, webhook *Record) string {
	if info != nil && !info.IsOwner(app) {
		return WebhookActorRef(info.Auth)
	}

	if webhook.IsNew() || webhookTopicsChanged(app, webhook) {
		return ""
	}

	return webhook.Original().GetString("actorRef")
}

// FailureCount returns the "failureCount" record field value
// (aka. the number of consecutive failed events).
func (m *Webhook) FailureCount() int {
	return m.GetInt("failureCount")
}

// SetFailureCount updates the "failureCount" record field value.
func (m *Webhook) SetFailureCount(count int) {
	m.Set("failureCount", count)
}

// DisabledReason returns the "disabledReason" record field value.
func (m *Webhook) DisabledReason() string {
	return m.GetString("disabledReason")
}

// SetDisabledReason updates the "disabledReason" record field value.
func (m *Webhook) SetDisabledReason(reason string) {
	m.Set("disabledReason", reason)
}

// LastSuccessAt returns the "lastSuccessAt" record field value.
func (m *Webhook) LastSuccessAt() types.DateTime {
	return m.GetDateTime("lastSuccessAt")
}

// LastFailureAt returns the "lastFailureAt" record field value.
func (m *Webhook) LastFailureAt() types.DateTime {
	return m.GetDateTime("lastFailureAt")
}

// Created returns the "created" record field value.
func (m *Webhook) Created() types.DateTime {
	return m.GetDateTime("created")
}

// Updated returns the "updated" record field value.
func (m *Webhook) Updated() types.DateTime {
	return m.GetDateTime("updated")
}

// -------------------------------------------------------------------
// Hooks
// -------------------------------------------------------------------

func (app *BaseApp) registerWebhookModelHooks() {
	app.OnRecordValidate(CollectionNameWebhooks).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			webhook := &Webhook{e.Record}

			// defaults
			// ---
			if webhook.Secret() == "" {
				webhook.SetSecret(security.RandomString(webhookSecretLength))
			}

			if webhook.ApiVersion() == "" {
				webhook.SetApiVersion(WebhooksApiVersion)
			}

			// reset the failures state on (re)activation
			if webhook.Active() && (webhook.IsNew() || !e.Record.Original().GetBool("active")) {
				webhook.SetFailureCount(0)
				webhook.SetDisabledReason("")
			}

			errs := validation.Errors{}

			if err := validation.Validate(webhook.URI(), validation.Required, validation.By(checkWebhookURI)); err != nil {
				errs["uri"] = err
			}

			if err := validation.Validate(webhook.Secret(), validation.Length(webhookSecretMinLength, 255)); err != nil {
				errs["secret"] = err
			}

			if err := validation.Validate(webhook.ApiVersion(), validation.In(list.ToInterfaceSlice(WebhooksApiVersions)...)); err != nil {
				errs["apiVersion"] = err
			}

			if err := validation.Validate(webhook.Fields(), validation.By(checkWebhookFields)); err != nil {
				errs["fields"] = err
			}

			// normalize and validate the topics
			// ---
			rawTopics := webhook.Topics()
			targets := make([]*webhookTopicTarget, 0, len(rawTopics))
			normalized := make([]string, 0, len(rawTopics))
			topicsErrs := validation.Errors{}
			for i, topic := range rawTopics {
				target, err := parseWebhookTopic(e.App, topic)
				if err != nil {
					topicsErrs[strconv.Itoa(i)] = err
					continue
				}

				if slices.Contains(normalized, target.String()) {
					continue // skip duplicates
				}

				targets = append(targets, target)
				normalized = append(normalized, target.String())
			}
			if len(topicsErrs) > 0 {
				errs["topics"] = topicsErrs
			} else if len(normalized) == 0 {
				errs["topics"] = validation.ErrRequired
			} else {
				webhook.SetTopics(normalized)
			}

			// filter
			// ---
			if errs["topics"] == nil {
				if err := checkWebhookFilter(e.App, webhook.Filter(), targets); err != nil {
					errs["filter"] = err
				}
			}

			// client scopes
			// ---
			if clientId := webhook.Client(); clientId != "" && errs["topics"] == nil {
				client, err := e.App.FindOAuth2ClientById(clientId)
				if err != nil {
					errs["client"] = validation.NewError("validation_invalid_client", "Missing or invalid OAuth2 client.")
				} else {
					scopesErrs := validation.Errors{}
					for i, target := range targets {
						ns := target.namespace
						if target.collection != nil {
							ns = target.collection.Name
						}
						if !webhookClientAllowsNamespace(client, ns) {
							scope := ns + ":read"
							if ns == WebhookTopicWildcard {
								scope = WebhookScopeAll
							}
							scopesErrs[strconv.Itoa(i)] = validation.NewError(
								"validation_webhook_topic_scope",
								"The linked OAuth2 client doesn't have the required {{.scope}} scope.",
							).SetParams(map[string]any{"scope": scope})
						}
					}
					if len(scopesErrs) > 0 {
						errs["topics"] = scopesErrs
					}
				}
			}

			if len(errs) > 0 {
				return errs
			}

			return e.Next()
		},
		Priority: 99,
	})

	// remove the topics of the deleted collections
	app.OnCollectionDeleteExecute().Bind(&hook.Handler[*CollectionEvent]{
		Func: func(e *CollectionEvent) error {
			if e.Collection.Name == CollectionNameWebhooks {
				return e.Next()
			}

			webhooksCollection, err := e.App.FindCachedCollectionByNameOrId(CollectionNameWebhooks)
			if err != nil {
				return e.Next() // missing webhooks collection (e.g. not migrated yet)
			}

			originalApp := e.App
			txErr := e.App.RunInTransaction(func(txApp App) error {
				e.App = txApp

				if err := e.Next(); err != nil {
					return err
				}

				prefix := e.Collection.Id + "."

				records, err := txApp.FindRecordsByFilter(
					webhooksCollection,
					"topics ~ {:prefix}",
					"",
					0,
					0,
					dbx.Params{"prefix": `"` + prefix},
				)
				if err != nil {
					return err
				}

				for _, r := range records {
					webhook := &Webhook{r}

					topics := slices.DeleteFunc(webhook.Topics(), func(t string) bool {
						return strings.HasPrefix(t, prefix)
					})
					webhook.SetTopics(topics)

					if len(topics) == 0 {
						webhook.SetActive(false)
						webhook.SetDisabledReason("All subscription topics were removed because their collections were deleted.")
					}

					// note: without validations because the topics could be empty
					// (and with the managed change context so that the application managed webhooks are updated too)
					if err := txApp.SaveNoValidateWithContext(withManagedWebhookChange(context.Background()), webhook); err != nil {
						return err
					}
				}

				return nil
			})
			e.App = originalApp

			return txErr
		},
		Priority: 99,
	})
}

func checkWebhookURI(value any) error {
	v, _ := value.(string)

	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Fragment != "" || u.Opaque != "" {
		return validation.NewError("validation_invalid_webhook_uri", "Must be an absolute http(s) URL without fragment.")
	}

	return nil
}

func checkWebhookFields(value any) error {
	v, _ := value.([]string)
	if len(v) == 0 {
		return nil
	}

	for _, f := range v {
		if strings.TrimSpace(f) == "" || strings.Contains(f, ",") {
			return validation.NewError("validation_invalid_webhook_fields", "Each field must be a single non-empty field path.")
		}
	}

	// validate the syntax and the modifiers
	if _, err := picker.Pick(map[string]any{}, strings.Join(v, ",")); err != nil {
		return validation.NewError("validation_invalid_webhook_fields", "Invalid fields: "+err.Error())
	}

	return nil
}

// checkWebhookFilter validates the filter against the explicit topics collections.
//
// The wildcard topics collections are checked during dispatch (the
// events of the collections for which the filter is invalid are skipped).
func checkWebhookFilter(app App, filter string, targets []*webhookTopicTarget) error {
	if filter == "" {
		return nil
	}

	var hasCollectionTopic bool

	checked := map[string]struct{}{}

	for _, t := range targets {
		if t.custom {
			continue
		}

		hasCollectionTopic = true

		if t.collection == nil {
			continue // wildcard
		}

		if _, ok := checked[t.collection.Id]; ok {
			continue
		}
		checked[t.collection.Id] = struct{}{}

		resolver := NewRecordFieldResolver(app, t.collection, &RequestInfo{}, true)
		if _, err := search.FilterData(filter).BuildExpr(resolver); err != nil {
			return validation.NewError(
				"validation_invalid_webhook_filter",
				"Invalid filter for collection {{.collection}}. Raw error: {{.error}}",
			).SetParams(map[string]any{"collection": t.collection.Name, "error": err.Error()})
		}
	}

	if !hasCollectionTopic {
		return validation.NewError("validation_webhook_filter_custom_topics", "Filter is supported only for collection topics.")
	}

	return nil
}

func (app *BaseApp) registerWebhooksHooks() {
	app.registerWebhookModelHooks()

	w := app.webhooks

	app.OnRecordAfterCreateSuccess().Bind(&hook.Handler[*RecordEvent]{
		Id: "__pbWebhooksRecordCreate__",
		Func: func(e *RecordEvent) error {
			err := e.Next()
			w.onRecordEvent(e.Record, WebhookOpCreate, "")
			return err
		},
		Priority: -99,
	})

	app.OnRecordAfterUpdateSuccess().Bind(&hook.Handler[*RecordEvent]{
		Id: "__pbWebhooksRecordUpdate__",
		Func: func(e *RecordEvent) error {
			err := e.Next()

			w.onRecordEvent(e.Record, WebhookOpUpdate, "")

			// verified state change
			if e.Record.Collection().IsAuth() &&
				e.Record.GetBool(FieldNameVerified) &&
				!e.Record.Original().GetBool(FieldNameVerified) {
				w.onRecordEvent(e.Record, WebhookOpVerified, "")
			}

			return err
		},
		Priority: -99,
	})

	app.OnRecordAfterDeleteSuccess().Bind(&hook.Handler[*RecordEvent]{
		Id: "__pbWebhooksRecordDelete__",
		Func: func(e *RecordEvent) error {
			err := e.Next()
			w.onRecordEvent(e.Record, WebhookOpDelete, "")
			return err
		},
		Priority: -99,
	})

	// a record "auth" event is a completed auth session authentication
	// (the auth method is the last completed factor or "sso" for a reused root SSO session)
	app.OnAuthSessionCompleteRequest().Bind(&hook.Handler[*AuthSessionCompleteRequestEvent]{
		Id: "__pbWebhooksRecordAuth__",
		Func: func(e *AuthSessionCompleteRequestEvent) error {
			err := e.Next()
			if err != nil || e.Record == nil {
				return err
			}

			method := "sso"
			if !e.SSO && e.Session != nil {
				if methods := e.Session.AuthMethods(); len(methods) > 0 {
					method = methods[len(methods)-1].Method
				}
			}

			w.onRecordEvent(e.Record, WebhookOpAuth, method)

			return nil
		},
		Priority: -99,
	})

	// invalidate the subscriptions cache
	invalidateCache := func(e *RecordEvent) error {
		w.invalidateCache()
		return e.Next()
	}
	app.OnRecordAfterCreateSuccess(CollectionNameWebhooks).Bind(&hook.Handler[*RecordEvent]{
		Id:       "__pbWebhooksCacheInvalidateCreate__",
		Func:     invalidateCache,
		Priority: -999,
	})
	app.OnRecordAfterUpdateSuccess(CollectionNameWebhooks).Bind(&hook.Handler[*RecordEvent]{
		Id:       "__pbWebhooksCacheInvalidateUpdate__",
		Func:     invalidateCache,
		Priority: -999,
	})
	app.OnRecordAfterDeleteSuccess(CollectionNameWebhooks).Bind(&hook.Handler[*RecordEvent]{
		Id:       "__pbWebhooksCacheInvalidateDelete__",
		Func:     invalidateCache,
		Priority: -999,
	})

	app.OnServe().Bind(&hook.Handler[*ServeEvent]{
		Id: "__pbWebhooksStart__",
		Func: func(e *ServeEvent) error {
			w.Start()
			return e.Next()
		},
		Priority: 999,
	})

	// flush the queued events and stop the dispatcher before clearing the app bootstrap state
	app.OnBootstrapClear().Bind(&hook.Handler[*BootstrapEvent]{
		Id: "__pbWebhooksStop__",
		Func: func(e *BootstrapEvent) error {
			// extra precaution in case the hook was manually triggered while inside a db transaction:
			//   - the queued events are inserted in the aux db
			//   - the in-flight attempts results are persisted in the aux db and
			//     the subscriptions stats in the data db (without context)
			// and waiting for them while the caller holds the db writer would deadlock
			_, isAuxTx := e.App.AuxNonconcurrentDB().(*dbx.Tx)
			_, isDataTx := e.App.NonconcurrentDB().(*dbx.Tx)

			if !isAuxTx {
				w.FlushEvents()
			}

			stop := func() {
				ctx, cancel := context.WithTimeout(context.Background(), webhooksStopTimeout)
				defer cancel()

				if err := w.Stop(ctx); err != nil {
					e.App.Logger().Warn("Webhooks dispatcher stop timeout", slog.String("error", err.Error()))
				}
			}

			if isAuxTx || isDataTx {
				routine.FireAndForget(stop)
			} else {
				stop()
			}

			w.invalidateCache()

			return e.Next()
		},
		Priority: bootstrapClearPriorityWebhooks,
	})

	// cleanup the old completed deliveries
	app.Cron().Add("__pbWebhookDeliveriesCleanup__", "20 */6 * * *", func() {
		maxDays := app.Settings().Webhooks.MaxDays
		if maxDays <= 0 {
			return
		}

		err := app.DeleteOldWebhookDeliveries(time.Now().AddDate(0, 0, -1*maxDays))
		if err != nil {
			app.Logger().Warn("Failed to delete old webhook deliveries", "error", err)
		}
	})
}
