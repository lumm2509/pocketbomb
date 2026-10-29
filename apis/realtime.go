package apis

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/picker"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/routine"
	"github.com/lumm2509/pocketbomb/tools/search"
	"github.com/lumm2509/pocketbomb/tools/subscriptions"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
	"golang.org/x/sync/errgroup"
)

// note: the chunk size is arbitrary chosen and may change in the future
const clientsChunkSize = 150

// RealtimeClientAuthKey is the name of the realtime client store key that holds its auth state.
const RealtimeClientAuthKey = "auth"

// RealtimeClientOAuth2Key is the name of the realtime client store key that holds
// the OAuth2 access token data (client, scopes, trust) of its auth state.
const RealtimeClientOAuth2Key = "oauth2"

// RealtimeClientIPKey is the name of the realtime client store key that holds the IP of the connected client.
const RealtimeClientIPKey = "pbRealtimeClientIP"

// RealtimeClientAPIKeyKey is the name of the realtime client store key that holds
// the API key data ([*core.RequestInfoAPIKey]) of the connect or subscribe request
// (e.g. a public key sent with the "pk" query parameter of the EventSource connection).
const RealtimeClientAPIKeyKey = "pbRealtimeClientAPIKey"

// bindRealtimeApi registers the realtime api endpoints.
func bindRealtimeApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	sub := rg.Group("/realtime")
	sub.GET("", realtimeConnect).Bind(SkipSuccessActivityLog())
	sub.POST("", realtimeSetSubscriptions)

	bindRealtimeEvents(app)
}

func realtimeConnect(e *core.RequestEvent) error {
	// disable global write deadline for the SSE connection
	rc := http.NewResponseController(e.Response)
	writeDeadlineErr := rc.SetWriteDeadline(time.Time{})
	if writeDeadlineErr != nil {
		if !errors.Is(writeDeadlineErr, http.ErrNotSupported) {
			return e.InternalServerError("Failed to initialize SSE connection.", writeDeadlineErr)
		}

		// only log since there are valid cases where it may not be implement (e.g. httptest.ResponseRecorder)
		e.App.Logger().Warn("SetWriteDeadline is not supported, fallback to the default server WriteTimeout")
	}

	// create cancellable request
	cancelCtx, cancelRequest := context.WithCancel(e.Request.Context())
	defer cancelRequest()
	e.Request = e.Request.Clone(cancelCtx)

	e.Response.Header().Set("Content-Type", "text/event-stream")
	e.Response.Header().Set("Cache-Control", "no-store")
	// https://github.com/lumm2509/pocketbomb/discussions/480#discussioncomment-3657640
	// https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffering
	e.Response.Header().Set("X-Accel-Buffering", "no")

	connectEvent := new(core.RealtimeConnectRequestEvent)
	connectEvent.RequestEvent = e
	connectEvent.IdleTimeout = 5 * time.Minute
	connectEvent.MaxTimeout = 30 * time.Minute
	connectEvent.Client = subscriptions.NewDefaultClient()

	// could be used as an optional cross-reference check in other API endpoints
	connectEvent.Client.Set(RealtimeClientIPKey, e.RealIP())

	// the EventSource connections can't send headers (e.g. "?pk=" public key)
	if apiKey, _ := e.Get(core.RequestEventKeyAPIKey).(*core.RequestInfoAPIKey); apiKey != nil {
		connectEvent.Client.Set(RealtimeClientAPIKeyKey, apiKey.Clone())
	}

	return e.App.OnRealtimeConnectRequest().Trigger(connectEvent, func(ce *core.RealtimeConnectRequestEvent) error {
		// register new subscription client
		ce.App.SubscriptionsBroker().Register(ce.Client)
		defer func() {
			e.App.SubscriptionsBroker().Unregister(ce.Client.Id())
		}()

		ce.App.Logger().Debug("Realtime connection established", slog.String("clientId", ce.Client.Id()))

		// signalize established connection (aka. fire "connect" message)
		connectMsgEvent := new(core.RealtimeMessageEvent)
		connectMsgEvent.RequestEvent = ce.RequestEvent
		connectMsgEvent.Client = ce.Client
		connectMsgEvent.Message = &subscriptions.Message{
			Name: "PB_CONNECT",
			Data: []byte(`{"clientId":"` + ce.Client.Id() + `"}`),
		}
		connectMsgErr := ce.App.OnRealtimeMessageSend().Trigger(connectMsgEvent, func(me *core.RealtimeMessageEvent) error {
			err := me.Message.WriteSSE(me.Response, me.Client.Id())
			if err != nil {
				return err
			}
			return me.Flush()
		})
		if connectMsgErr != nil {
			ce.App.Logger().Debug(
				"Realtime connection closed (failed to deliver PB_CONNECT)",
				slog.String("clientId", ce.Client.Id()),
				slog.String("error", connectMsgErr.Error()),
			)
			return nil
		}

		// start a max lifetime timer to prevent accumulating too much
		// connection resources and to allow the GC to run more regularly
		maxTimer := time.NewTimer(ce.MaxTimeout)
		defer maxTimer.Stop()

		// start an idle timer to keep track of inactive/forgotten connections
		idleTimer := time.NewTimer(ce.IdleTimeout)
		defer idleTimer.Stop()

		for {
			select {
			case <-maxTimer.C:
				cancelRequest()
			case <-idleTimer.C:
				cancelRequest()
			case msg, ok := <-ce.Client.Channel():
				if !ok {
					// channel is closed
					ce.App.Logger().Debug(
						"Realtime connection closed (closed channel)",
						slog.String("clientId", ce.Client.Id()),
					)
					return nil
				}

				msgEvent := new(core.RealtimeMessageEvent)
				msgEvent.RequestEvent = ce.RequestEvent
				msgEvent.Client = ce.Client
				msgEvent.Message = &msg
				msgErr := ce.App.OnRealtimeMessageSend().Trigger(msgEvent, func(me *core.RealtimeMessageEvent) error {
					err := me.Message.WriteSSE(me.Response, me.Client.Id())
					if err != nil {
						return err
					}
					return me.Flush()
				})
				if msgErr != nil {
					ce.App.Logger().Debug(
						"Realtime connection closed (failed to deliver message)",
						slog.String("clientId", ce.Client.Id()),
						slog.String("error", msgErr.Error()),
					)
					return nil
				}

				idleTimer.Stop()
				idleTimer.Reset(ce.IdleTimeout)
			case <-ce.Request.Context().Done():
				// connection is closed
				ce.App.Logger().Debug(
					"Realtime connection closed (cancelled request)",
					slog.String("clientId", ce.Client.Id()),
				)
				return nil
			}
		}
	})
}

type realtimeSubscribeForm struct {
	ClientId      string   `form:"clientId" json:"clientId"`
	Subscriptions []string `form:"subscriptions" json:"subscriptions"`
}

func (form *realtimeSubscribeForm) validate() error {
	return validation.ValidateStruct(form,
		validation.Field(&form.ClientId, validation.Required, validation.Length(1, 255)),
		validation.Field(&form.Subscriptions,
			validation.Length(0, 1000),
			validation.Each(validation.Length(0, 2500)),
		),
	)
}

// note: in case of reconnect, clients will have to resubmit all subscriptions again
func realtimeSetSubscriptions(e *core.RequestEvent) error {
	if err := checkThirdPartyTokenSubscriptions(e); err != nil {
		return err
	}

	form := new(realtimeSubscribeForm)

	err := e.BindBody(form)
	if err != nil {
		return e.BadRequestError("", err)
	}

	err = form.validate()
	if err != nil {
		return e.BadRequestError("", err)
	}

	// find subscription client
	client, err := e.App.SubscriptionsBroker().ClientById(form.ClientId)
	if err != nil {
		return e.NotFoundError("Missing or invalid client id.", err)
	}

	// for just in case to prevent someone changing a guest subscription
	//
	// note1: this is an extra precaution against clientId bruteforce attempts
	// for installations allowing longer realtime connections duration
	//
	// note2: custom registered clients (aka. those without IP in the store)
	// are excluded from the check for backward compatibility
	clientIP, _ := client.Get(RealtimeClientIPKey).(string)
	if clientIP != "" && clientIP != e.RealIP() {
		return e.BadRequestError(
			"Invalid realtime client.",
			errors.New("the subscription request IP doesn't match with the realtime client IP"),
		)
	}

	// for now allow only guest->auth upgrades and any other auth change is forbidden
	clientAuth, _ := client.Get(RealtimeClientAuthKey).(*core.Record)
	if clientAuth != nil && !isSameAuth(clientAuth, e.Auth) {
		return e.ForbiddenError("The current and the previous request authorization don't match.", nil)
	}

	// the API key of the subscribe request or of the connect request (it can't be switched to another client)
	apiKey, _ := e.Get(core.RequestEventKeyAPIKey).(*core.RequestInfoAPIKey)
	clientAPIKey, _ := client.Get(RealtimeClientAPIKeyKey).(*core.RequestInfoAPIKey)
	if apiKey != nil && clientAPIKey != nil && apiKey.ClientId != clientAPIKey.ClientId {
		return e.ForbiddenError("The current and the previous request API keys clients don't match.", nil)
	}
	if apiKey == nil {
		apiKey = clientAPIKey

		// the connect request key must belong to the client of the subscribe request access token too
		// (when the key is sent with the subscribe request this is already checked by the API key middleware)
		if apiKey != nil && e.Auth != nil {
			oauth2, _ := e.Get(core.RequestEventKeyOAuth2).(*core.RequestInfoOAuth2)
			if oauth2 == nil || oauth2.ClientId != apiKey.ClientId {
				return e.UnauthorizedError("The access token and the API key must belong to the same OAuth2 client.", nil)
			}
		}
	}

	// deny by default - the collection topics require an API key or an auth token
	if e.Auth == nil && apiKey == nil && realtimeHasCollectionTopic(e.App, form.Subscriptions) {
		if err := checkClientCredentials(e); err != nil {
			return err
		}
	}

	event := new(core.RealtimeSubscribeRequestEvent)
	event.RequestEvent = e
	event.Client = client
	event.Subscriptions = form.Subscriptions

	return e.App.OnRealtimeSubscribeRequest().Trigger(event, func(e *core.RealtimeSubscribeRequestEvent) error {
		// update auth state
		e.Client.Set(RealtimeClientAuthKey, e.Auth)
		if info, err := e.RequestInfo(); err == nil && e.Auth != nil {
			e.Client.Set(RealtimeClientOAuth2Key, info.OAuth2)
		} else {
			e.Client.Unset(RealtimeClientOAuth2Key)
		}
		if apiKey != nil {
			e.Client.Set(RealtimeClientAPIKeyKey, apiKey.Clone())
		}

		// unsubscribe from any previous existing subscriptions
		e.Client.Unsubscribe()

		// subscribe to the new subscriptions
		e.Client.Subscribe(e.Subscriptions...)

		e.App.Logger().Debug(
			"Realtime subscriptions updated",
			slog.String("clientId", e.Client.Id()),
			slog.Any("subscriptions", e.Subscriptions),
		)

		return execAfterSuccessTx(true, e.App, func() error {
			return e.NoContent(http.StatusNoContent)
		})
	})
}

// realtimeCurrentAPIKey returns the current state of the realtime client API key
// (nil if the key or its client is no longer usable; the key permissions are reloaded).
func realtimeCurrentAPIKey(app core.App, stored *core.RequestInfoAPIKey) *core.RequestInfoAPIKey {
	key, err := app.FindAPIKeyById(stored.KeyId)
	if err != nil || !key.IsUsable() || !stored.IsSameToken(key) {
		return nil
	}

	client, err := app.FindOAuth2ClientById(key.ClientRef())
	if err != nil || client.Disabled() || client.ClientId() != stored.ClientId {
		return nil
	}

	current := stored.Clone()
	current.Permissions = key.Permissions()

	return current
}

// checkThirdPartyTokenSubscriptions rejects the subscriptions to the system collections
// for the third-party OAuth2 access tokens (the application installations and the extensions
// online tokens are excluded since their access is governed by their grant, see [core.Authorize]).
func checkThirdPartyTokenSubscriptions(e *core.RequestEvent) error {
	if !hasThirdPartyToken(e) || e.IsApplication() || e.ActorInfo().Permissions(e.App).IsOnBehalfOfApplication() {
		return nil
	}

	info, err := e.RequestInfo()
	if err != nil {
		return err
	}

	subs, _ := info.Body["subscriptions"].([]any)
	for _, sub := range subs {
		topic, _ := sub.(string)
		collectionNameOrId, _, _ := strings.Cut(topic, "/")
		collection, _ := e.App.FindCachedCollectionByNameOrId(collectionNameOrId)
		if collection != nil && collection.System {
			return e.ForbiddenError(thirdPartyTokenForbiddenMessage, errors.New("restricted_collection"))
		}
	}

	return nil
}

// realtimeHasCollectionTopic reports whether at least one of the subscriptions
// is a collection records topic (e.g. "posts/*", "posts/RECORD_ID?options=...").
func realtimeHasCollectionTopic(app core.App, subscriptions []string) bool {
	for _, sub := range subscriptions {
		name, _, _ := strings.Cut(sub, "?")
		name, _, _ = strings.Cut(name, "/")
		if name == "" {
			continue
		}

		if c, _ := app.FindCachedCollectionByNameOrId(name); c != nil {
			return true
		}
	}

	return false
}

// realtimeUpdateClientsAuth updates the auth state of all clients related to the provided authRecord.
//
// Realtime connections has short lifetime by design, but to minimize abuse
// if the new record has a different tokenKey (e.g. in case of password reset)
// the auth state of the related realtime connections is also cleared
// (aka. they remain active but unauthenticated, allowing to reauthenicate with the next subscription).
func realtimeUpdateClientsAuth(app core.App, authRecord *core.Record) error {
	chunks := app.SubscriptionsBroker().ChunkedClients(clientsChunkSize)

	group := new(errgroup.Group)

	for _, chunk := range chunks {
		group.Go(routine.SafeWrap(func() error {
			for _, client := range chunk {
				clientAuth, _ := client.Get(RealtimeClientAuthKey).(*core.Record)
				if clientAuth != nil &&
					clientAuth.Id == authRecord.Id &&
					clientAuth.Collection().Name == authRecord.Collection().Name {
					if clientAuth.TokenKey() != authRecord.TokenKey() {
						client.Unset(RealtimeClientAuthKey)
					} else {
						client.Set(RealtimeClientAuthKey, authRecord)
					}
				}
			}

			return nil
		}))
	}

	return group.Wait()
}

// realtimeUnsetClientsAuthByRecordModelOrProxy unsets the auth state of all clients that have the provided auth model.
func realtimeUnsetClientsAuthByRecordModelOrProxy(app core.App, authModel core.Model) error {
	chunks := app.SubscriptionsBroker().ChunkedClients(clientsChunkSize)

	group := new(errgroup.Group)

	for _, chunk := range chunks {
		group.Go(routine.SafeWrap(func() error {
			for _, client := range chunk {
				clientAuth, _ := client.Get(RealtimeClientAuthKey).(*core.Record)
				if clientAuth != nil &&
					clientAuth.Id == authModel.PK() &&
					clientAuth.Collection().Name == authModel.TableName() {
					client.Unset(RealtimeClientAuthKey)
				}
			}

			return nil
		}))
	}

	return group.Wait()
}

// realtimeUnsetClientsAuthByCollection unsets the auth state of all authenticated clients related to the collection.
func realtimeUnsetClientsAuthByCollection(app core.App, collection *core.Collection) error {
	chunks := app.SubscriptionsBroker().ChunkedClients(clientsChunkSize)

	group := new(errgroup.Group)

	for _, chunk := range chunks {
		group.Go(routine.SafeWrap(func() error {
			for _, client := range chunk {
				clientAuth, _ := client.Get(RealtimeClientAuthKey).(*core.Record)
				if clientAuth != nil && clientAuth.Collection().Name == collection.Name {
					client.Unset(RealtimeClientAuthKey)
				}
			}

			return nil
		}))
	}

	return group.Wait()
}

func bindRealtimeEvents(app core.App) {
	// reset the clients auth on collection secret change
	// (@todo with the future tracking of old collections data consider replacing with *AfterUpdateSuccess to account for transaction rollback)
	app.OnCollectionUpdate().Bind(&hook.Handler[*core.CollectionEvent]{
		Func: func(e *core.CollectionEvent) error {
			if !e.Collection.IsAuth() {
				return e.Next()
			}

			cached, _ := e.App.FindCachedCollectionByNameOrId(e.Collection.Id)

			if err := e.Next(); err != nil {
				return err
			}

			if cached != nil && cached.AuthToken.Secret != e.Collection.AuthToken.Secret {
				if err := realtimeUnsetClientsAuthByCollection(e.App, e.Collection); err != nil {
					app.Logger().Warn(
						"Failed to remove client(s) associated to the changed auth collection",
						slog.String("collectionName", e.Collection.Name),
						slog.String("error", err.Error()),
					)
				}
			}

			return nil
		},
		Priority: -99,
	})

	// unset the clients auth on auth collection delete
	app.OnCollectionAfterDeleteSuccess().Bind(&hook.Handler[*core.CollectionEvent]{
		Func: func(e *core.CollectionEvent) error {
			if e.Collection.IsAuth() {
				if err := realtimeUnsetClientsAuthByCollection(e.App, e.Collection); err != nil {
					app.Logger().Warn(
						"Failed to remove client(s) associated to the deleted auth collection",
						slog.String("collectionName", e.Collection.Name),
						slog.String("error", err.Error()),
					)
				}
			}

			return e.Next()
		},
		Priority: -99,
	})

	// update the clients that has auth record association
	app.OnModelAfterUpdateSuccess().Bind(&hook.Handler[*core.ModelEvent]{
		Func: func(e *core.ModelEvent) error {
			authRecord := realtimeResolveRecord(e.App, e.Model, core.CollectionTypeAuth)
			if authRecord != nil {
				if err := realtimeUpdateClientsAuth(e.App, authRecord); err != nil {
					app.Logger().Warn(
						"Failed to update client(s) associated to the updated auth record",
						slog.Any("id", authRecord.Id),
						slog.String("collectionName", authRecord.Collection().Name),
						slog.String("error", err.Error()),
					)
				}
			}

			return e.Next()
		},
		Priority: -99,
	})

	// remove the client(s) associated to the deleted auth model
	// (note: works also with custom model for backward compatibility)
	app.OnModelAfterDeleteSuccess().Bind(&hook.Handler[*core.ModelEvent]{
		Func: func(e *core.ModelEvent) error {
			collection := realtimeResolveRecordCollection(e.App, e.Model)
			if collection != nil && collection.IsAuth() {
				if err := realtimeUnsetClientsAuthByRecordModelOrProxy(e.App, e.Model); err != nil {
					app.Logger().Warn(
						"Failed to remove client(s) associated to the deleted auth model",
						slog.Any("id", e.Model.PK()),
						slog.String("collectionName", e.Model.TableName()),
						slog.String("error", err.Error()),
					)
				}
			}

			return e.Next()
		},
		Priority: -99,
	})

	app.OnModelAfterCreateSuccess().Bind(&hook.Handler[*core.ModelEvent]{
		Func: func(e *core.ModelEvent) error {
			record := realtimeResolveRecord(e.App, e.Model, "")
			if record != nil {
				err := realtimeBroadcastRecord(e.App, "create", record, false)
				if err != nil {
					app.Logger().Debug(
						"Failed to broadcast record create",
						slog.String("id", record.Id),
						slog.String("collectionName", record.Collection().Name),
						slog.String("error", err.Error()),
					)
				}
			}

			return e.Next()
		},
		Priority: -99,
	})

	app.OnModelAfterUpdateSuccess().Bind(&hook.Handler[*core.ModelEvent]{
		Func: func(e *core.ModelEvent) error {
			record := realtimeResolveRecord(e.App, e.Model, "")
			if record != nil {
				err := realtimeBroadcastRecord(e.App, "update", record, false)
				if err != nil {
					app.Logger().Debug(
						"Failed to broadcast record update",
						slog.String("id", record.Id),
						slog.String("collectionName", record.Collection().Name),
						slog.String("error", err.Error()),
					)
				}
			}

			return e.Next()
		},
		Priority: -99,
	})

	// delete: dry cache
	app.OnModelDelete().Bind(&hook.Handler[*core.ModelEvent]{
		Func: func(e *core.ModelEvent) error {
			record := realtimeResolveRecord(e.App, e.Model, "")
			if record != nil {
				// note: use the outside scoped app instance for the access checks so that the API rules
				// are performed out of the delete transaction ensuring that they would still work even if
				// a cascade-deleted record's API rule relies on an already deleted parent record
				err := realtimeBroadcastRecord(e.App, "delete", record, true, app)
				if err != nil {
					app.Logger().Debug(
						"Failed to dry cache record delete",
						slog.String("id", record.Id),
						slog.String("collectionName", record.Collection().Name),
						slog.String("error", err.Error()),
					)
				}
			}

			return e.Next()
		},
		Priority: 99, // execute as later as possible
	})

	// delete: broadcast
	app.OnModelAfterDeleteSuccess().Bind(&hook.Handler[*core.ModelEvent]{
		Func: func(e *core.ModelEvent) error {
			// note: only ensure that it is a collection record
			// and don't use realtimeResolveRecord because in case of a
			// custom model it'll fail to resolve since the record is already deleted
			collection := realtimeResolveRecordCollection(e.App, e.Model)
			if collection != nil {
				err := realtimeBroadcastDryCacheKey(e.App, getDryCacheKey("delete", e.Model))
				if err != nil {
					app.Logger().Debug(
						"Failed to broadcast record delete",
						slog.Any("id", e.Model.PK()),
						slog.String("collectionName", collection.Name),
						slog.String("error", err.Error()),
					)
				}
			}

			return e.Next()
		},
		Priority: -99,
	})

	// delete: failure
	app.OnModelAfterDeleteError().Bind(&hook.Handler[*core.ModelErrorEvent]{
		Func: func(e *core.ModelErrorEvent) error {
			record := realtimeResolveRecord(e.App, e.Model, "")
			if record != nil {
				err := realtimeUnsetDryCacheKey(e.App, getDryCacheKey("delete", record))
				if err != nil {
					app.Logger().Debug(
						"Failed to cleanup after broadcast record delete failure",
						slog.String("id", record.Id),
						slog.String("collectionName", record.Collection().Name),
						slog.String("error", err.Error()),
					)
				}
			}

			return e.Next()
		},
		Priority: -99,
	})
}

// resolveRecord converts *if possible* the provided model interface to a Record.
// This is usually helpful if the provided model is a custom Record model struct.
func realtimeResolveRecord(app core.App, model core.Model, optCollectionType string) *core.Record {
	var record *core.Record
	switch m := model.(type) {
	case *core.Record:
		record = m
	case core.RecordProxy:
		record = m.ProxyRecord()
	}

	if record != nil {
		if optCollectionType == "" || record.Collection().Type == optCollectionType {
			return record
		}
		return nil
	}

	tblName := model.TableName()

	// skip Log model checks
	if tblName == core.LogsTableName {
		return nil
	}

	// check if it is custom Record model struct
	collection, _ := app.FindCachedCollectionByNameOrId(tblName)
	if collection != nil && (optCollectionType == "" || collection.Type == optCollectionType) {
		if id, ok := model.PK().(string); ok {
			record, _ = app.FindRecordById(collection, id)
		}
	}

	return record
}

// realtimeResolveRecordCollection extracts *if possible* the Collection model from the provided model interface.
// This is usually helpful if the provided model is a custom Record model struct.
func realtimeResolveRecordCollection(app core.App, model core.Model) (collection *core.Collection) {
	switch m := model.(type) {
	case *core.Record:
		return m.Collection()
	case core.RecordProxy:
		return m.ProxyRecord().Collection()
	default:
		// check if it is custom Record model struct
		collection, err := app.FindCachedCollectionByNameOrId(model.TableName())
		if err == nil {
			return collection
		}
	}

	return nil
}

// recordData represents the broadcasted record subscrition message data.
type recordData struct {
	Record any    `json:"record"` /* map or core.Record */
	Action string `json:"action"`
}

// Note: the optAccessCheckApp is there in case you want the access check
// to be performed against different db app context (e.g. out of a transaction).
// If set, it is expected that optAccessCheckApp instance is used for read-only operations to avoid deadlocks.
// If not set, it fallbacks to app.
func realtimeBroadcastRecord(app core.App, action string, record *core.Record, dryCache bool, optAccessCheckApp ...core.App) error {
	collection := record.Collection()
	if collection == nil {
		return errors.New("[broadcastRecord] Record collection not set")
	}

	chunks := app.SubscriptionsBroker().ChunkedClients(clientsChunkSize)
	if len(chunks) == 0 {
		return nil // no subscribers
	}

	subscriptionRuleMap := map[string]*string{
		(collection.Name + "/" + record.Id + "?"): collection.ViewRule,
		(collection.Id + "/" + record.Id + "?"):   collection.ViewRule,
		(collection.Name + "/*?"):                 collection.ListRule,
		(collection.Id + "/*?"):                   collection.ListRule,

		// @deprecated: the same as the wildcard topic but kept for backward compatibility
		(collection.Name + "?"): collection.ListRule,
		(collection.Id + "?"):   collection.ListRule,
	}

	dryCacheKey := getDryCacheKey(action, record)

	group := new(errgroup.Group)

	accessCheckApp := app
	if len(optAccessCheckApp) > 0 {
		accessCheckApp = optAccessCheckApp[0]
	}

	for _, chunk := range chunks {
		group.Go(routine.SafeWrap(func() error {
			var clientAuth *core.Record

			// the API keys are re-checked once per broadcast chunk (disabled, expired, rotated or deleted => no messages)
			apiKeys := map[string]*core.RequestInfoAPIKey{}

			for _, client := range chunk {
				// note: not executed concurrently to avoid races and to ensure
				// that the access checks are applied for the current record db state
				for prefix, rule := range subscriptionRuleMap {
					subs := client.Subscriptions(prefix)
					if len(subs) == 0 {
						continue
					}

					clientAuth, _ = client.Get(RealtimeClientAuthKey).(*core.Record)

					for sub, options := range subs {
						// mock request data
						requestInfo := &core.RequestInfo{
							Context: core.RequestInfoContextRealtime,
							Method:  "GET",
							Query:   options.Query,
							Headers: options.Headers,
							Auth:    clientAuth,
						}
						if clientAuth != nil {
							if oauth2Data, _ := client.Get(RealtimeClientOAuth2Key).(core.RequestInfoOAuth2); oauth2Data.ClientId != "" {
								requestInfo.OAuth2 = oauth2Data
							}
						}
						if apiKey, _ := client.Get(RealtimeClientAPIKeyKey).(*core.RequestInfoAPIKey); apiKey != nil {
							current, ok := apiKeys[apiKey.KeyId]
							if !ok {
								current = realtimeCurrentAPIKey(accessCheckApp, apiKey)
								apiKeys[apiKey.KeyId] = current
							}
							if current == nil {
								continue
							}
							requestInfo.APIKey = current
						}

						if !realtimeCanAccessRecord(accessCheckApp, record, requestInfo, rule) {
							continue
						}

						// create a clean record copy without expand and unknown fields because we don't know yet
						// which exact fields the client subscription requested or has permissions to access
						cleanRecord := record.Fresh()

						// -------------------------------------------
						// @todo consider with the refactoring whether
						// the default enriching used by the regular APIs
						// can be reused here too to avoid eventual future
						// discrepencies in the record event data
						//
						// https://github.com/lumm2509/pocketbomb/issues/7721
						// -------------------------------------------

						// enable hidden fields for the subscribers with bypass permission (e.g. Owners)
						if requestInfo.CollectionAccess(accessCheckApp, collection, core.PermissionActionView).BypassRules {
							unhide := collection.Fields.FieldNames()
							// the secret fields (e.g. tokenKey) are exported only for the Owners
							if !requestInfo.IsOwner(accessCheckApp) {
								secrets := core.SecretFieldNames(collection)
								unhide = slices.DeleteFunc(unhide, func(name string) bool {
									return slices.Contains(secrets, name)
								})
							}
							cleanRecord.Unhide(unhide...)
						}

						// trigger the enrich hooks
						enrichErr := triggerRecordEnrichHooks(app, requestInfo, []*core.Record{cleanRecord}, func() error {
							// apply expand
							rawExpand := options.Query[expandQueryParam]
							if rawExpand != "" {
								expandErrs := app.ExpandRecord(cleanRecord, strings.Split(rawExpand, ","), expandFetch(app, requestInfo))
								if len(expandErrs) > 0 {
									app.Logger().Debug(
										"[broadcastRecord] expand errors",
										slog.String("id", cleanRecord.Id),
										slog.String("collectionName", cleanRecord.Collection().Name),
										slog.String("sub", sub),
										slog.String("expand", rawExpand),
										slog.Any("errors", expandErrs),
									)
								}
							}

							// ignore the auth record email visibility checks
							// for auth owner, superuser or manager
							if collection.IsAuth() {
								if isSameAuth(clientAuth, cleanRecord) ||
									realtimeCanAccessRecord(accessCheckApp, cleanRecord, requestInfo, collection.ManageRule) {
									cleanRecord.IgnoreEmailVisibility(true)
								}
							}

							return nil
						})
						if enrichErr != nil {
							app.Logger().Debug(
								"[broadcastRecord] record enrich error",
								slog.String("id", cleanRecord.Id),
								slog.String("collectionName", cleanRecord.Collection().Name),
								slog.String("sub", sub),
								slog.Any("error", enrichErr),
							)
							continue
						}

						data := &recordData{
							Action: action,
							Record: cleanRecord,
						}

						// check fields
						rawFields := options.Query[fieldsQueryParam]
						if rawFields != "" {
							decoded, err := picker.Pick(cleanRecord, rawFields)
							if err == nil {
								data.Record = decoded
							} else {
								app.Logger().Debug(
									"[broadcastRecord] pick fields error",
									slog.String("id", cleanRecord.Id),
									slog.String("collectionName", cleanRecord.Collection().Name),
									slog.String("sub", sub),
									slog.String("fields", rawFields),
									slog.String("error", err.Error()),
								)
							}
						}

						dataBytes, err := json.Marshal(data)
						if err != nil {
							app.Logger().Debug(
								"[broadcastRecord] data marshal error",
								slog.String("id", cleanRecord.Id),
								slog.String("collectionName", cleanRecord.Collection().Name),
								slog.String("error", err.Error()),
							)
							continue
						}

						msg := subscriptions.Message{
							Name: sub,
							Data: dataBytes,
						}

						if dryCache {
							messages, ok := client.Get(dryCacheKey).([]subscriptions.Message)
							if !ok {
								messages = []subscriptions.Message{msg}
							} else {
								messages = append(messages, msg)
							}
							client.Set(dryCacheKey, messages)
						} else {
							routine.FireAndForget(func() {
								client.Send(msg)
							})
						}
					}
				}
			}

			return nil
		}))
	}

	return group.Wait()
}

// realtimeBroadcastDryCacheKey broadcasts the dry cached key related messages.
func realtimeBroadcastDryCacheKey(app core.App, key string) error {
	chunks := app.SubscriptionsBroker().ChunkedClients(clientsChunkSize)
	if len(chunks) == 0 {
		return nil // no subscribers
	}

	group := new(errgroup.Group)

	for _, chunk := range chunks {
		group.Go(routine.SafeWrap(func() error {
			for _, client := range chunk {
				messages, ok := client.Get(key).([]subscriptions.Message)
				if !ok {
					continue
				}

				client.Unset(key)

				client := client

				routine.FireAndForget(func() {
					for _, msg := range messages {
						client.Send(msg)
					}
				})
			}

			return nil
		}))
	}

	return group.Wait()
}

// realtimeUnsetDryCacheKey removes the dry cached key related messages.
func realtimeUnsetDryCacheKey(app core.App, key string) error {
	chunks := app.SubscriptionsBroker().ChunkedClients(clientsChunkSize)
	if len(chunks) == 0 {
		return nil // no subscribers
	}

	group := new(errgroup.Group)

	for _, chunk := range chunks {
		group.Go(routine.SafeWrap(func() error {
			for _, client := range chunk {
				if client.Get(key) != nil {
					client.Unset(key)
				}
			}

			return nil
		}))
	}

	return group.Wait()
}

func getDryCacheKey(action string, model core.Model) string {
	pkStr, ok := model.PK().(string)
	if !ok {
		pkStr = fmt.Sprintf("%v", model.PK())
	}

	return action + "/" + model.TableName() + "/" + pkStr
}

func isSameAuth(authA, authB *core.Record) bool {
	if authA == nil {
		return authB == nil
	}

	if authB == nil {
		return false
	}

	return authA.Id == authB.Id && authA.Collection().Id == authB.Collection().Id
}

// realtimeCanAccessRecord checks if the subscription client has access to the specified record model.
func realtimeCanAccessRecord(
	app core.App,
	record *core.Record,
	requestInfo *core.RequestInfo,
	accessRule *string,
) bool {
	// check the RBAC permission and the access rule
	// ---
	if !requestInfo.CollectionAccess(app, record.Collection(), core.PermissionActionView).Allowed {
		return false
	}

	if ok, _ := app.CanAccessRecord(record, requestInfo, accessRule); !ok {
		return false
	}

	// check the subscription client-side filter (if any)
	// ---
	filter := requestInfo.Query[search.FilterQueryParam]
	if filter == "" {
		return true // no further checks needed
	}

	err := checkForSuperuserOnlyRuleFields(
		requestInfo.CollectionAccess(app, record.Collection(), core.PermissionActionView).BypassRules,
		requestInfo.Query[search.FilterQueryParam],
		requestInfo.Query[search.SortQueryParam],
	)
	if err != nil {
		return false
	}

	var exists int

	q := app.ConcurrentDB().Select("(1)").
		From(record.Collection().Name).
		AndWhere(dbx.HashExp{record.Collection().Name + ".id": record.Id})

	// the same client-side filter restrictions as the records API list
	// (the secret fields are denied even if they are not hidden)
	resolver := core.NewRecordFieldResolver(app, record.Collection(), requestInfo, false)
	if !requestInfo.IsOwner(app) {
		resolver.SetDenySecretFields(true)
		resolver.SetJoinCollectionCheck(core.ClientFilterJoinCheck(app, requestInfo))
	}
	expr, err := search.FilterData(filter).BuildExpr(resolver)
	if err != nil {
		return false
	}

	q.AndWhere(expr)

	err = resolver.UpdateQuery(q)
	if err != nil {
		return false
	}

	err = q.Limit(1).Row(&exists)

	return err == nil && exists > 0
}
