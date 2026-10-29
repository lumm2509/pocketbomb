package apis

import (
	"errors"
	"net/http"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/security"
)

// webhookSecretLength is the length of the generated webhook secrets.
const webhookSecretLength = 40

// bindWebhooksApi registers the superuser only webhooks management endpoints.
//
// Note that the subscriptions CRUD is handled by the regular records API
// (the "_webhooks" system collection has superusers only rules).
//
// The subscription specific actions are under "/subscriptions/{id}" to avoid
// ambiguous patterns with the "/deliveries/{id}" routes.
func bindWebhooksApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	read := RequirePermission(core.PermissionResourceWebhooks, core.PermissionLevelRead)
	write := RequirePermission(core.PermissionResourceWebhooks, core.PermissionLevelWrite)

	sub := rg.Group("/webhooks")

	sub.GET("/topics", webhooksTopics).Bind(read)

	// note: revealing the secret requires write since it allows impersonating the server
	subscriptions := sub.Group("/subscriptions/{id}")
	subscriptions.GET("/secret", webhookRevealSecret).Bind(write)
	subscriptions.POST("/rotate-secret", webhookRotateSecret).Bind(write)
	subscriptions.POST("/test", webhookTest).Bind(write)

	deliveries := sub.Group("/deliveries").Bind(SkipSuccessActivityLog())
	deliveries.GET("", webhookDeliveriesList).Bind(read)
	deliveries.DELETE("", webhookDeliveriesTruncate).Bind(write)
	deliveries.GET("/stats", webhookDeliveriesStats).Bind(read)
	deliveries.GET("/{id}", webhookDeliveriesView).Bind(read)
	deliveries.POST("/{id}/redeliver", webhookDeliveriesRedeliver).Bind(write)

	// the plain secret is hidden by bindRecordAccessHooks,
	// return only whether the subscription has a secret (+ the human friendly topic names)
	app.OnRecordEnrich(core.CollectionNameWebhooks).Bind(&hook.Handler[*core.RecordEnrichEvent]{
		Id: "__pbWebhookEnrich__",
		Func: func(e *core.RecordEnrichEvent) error {
			if e.RequestInfo != nil && e.RequestInfo.Can(e.App, core.PermissionResourceWebhooks, core.PermissionLevelRead) {
				webhook := &core.Webhook{Record: e.Record}

				topicNames := make([]string, len(webhook.Topics()))
				for i, t := range webhook.Topics() {
					topicNames[i] = core.RenderWebhookTopic(e.App, t)
				}

				e.Record.WithCustomData(true)
				e.Record.Set("hasSecret", webhook.Secret() != "")
				e.Record.Set("topicNames", topicNames)
			}

			return e.Next()
		},
	})
}

// GET /api/webhooks/topics
//
// Returns all available webhook topics (per collection, wildcards and registered custom topics).
func webhooksTopics(e *core.RequestEvent) error {
	topics, err := e.App.Webhooks().Topics()
	if err != nil {
		return e.InternalServerError("Failed to load the webhook topics.", err)
	}

	return e.JSON(http.StatusOK, topics)
}

type webhookSecretResponse struct {
	Id     string `json:"id"`
	Secret string `json:"secret"`
}

// GET /api/webhooks/subscriptions/{id}/secret
//
// Reveals the current plain webhook signing secret.
//
// Revealing (instead of rotate-only) is allowed because the secret must be
// stored in plain text anyway (it is required for the HMAC signatures) and
// it allows reconfiguring a receiver without breaking the other receivers
// sharing the same secret. The route is superusers only and it is not
// accessible with OAuth2 access tokens.
func webhookRevealSecret(e *core.RequestEvent) error {
	webhook, err := e.App.FindWebhookById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("Missing or invalid webhook subscription.", err)
	}

	// the secrets of the OAuth2 client linked subscriptions belong to the client apps (Owner only)
	if webhook.Client() != "" && !e.IsOwner() {
		return e.ForbiddenError("Only the Owners could access the OAuth2 client linked webhook secrets.", nil)
	}

	if !core.CanAccessWebhook(e.App, e.ActorInfo(), webhook.Record) {
		return e.ForbiddenError("You are not allowed to access a subscription with topics you can't view or a filter you can't use.", nil)
	}

	e.Response.Header().Set("Cache-Control", "no-store")

	return e.JSON(http.StatusOK, webhookSecretResponse{
		Id:     webhook.Id,
		Secret: webhook.Secret(),
	})
}

// POST /api/webhooks/subscriptions/{id}/rotate-secret
//
// Generates a new random signing secret, replaces the old one and returns it.
func webhookRotateSecret(e *core.RequestEvent) error {
	webhook, err := e.App.FindWebhookById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("Missing or invalid webhook subscription.", err)
	}

	// the secrets of the OAuth2 client linked subscriptions belong to the client apps (Owner only)
	if webhook.Client() != "" && !e.IsOwner() {
		return e.ForbiddenError("Only the Owners could access the OAuth2 client linked webhook secrets.", nil)
	}

	if !core.CanAccessWebhook(e.App, e.ActorInfo(), webhook.Record) {
		return e.ForbiddenError("You are not allowed to access a subscription with topics you can't view or a filter you can't use.", nil)
	}

	secret := security.RandomString(webhookSecretLength)

	webhook.SetSecret(secret)
	webhook.SetActorRef(core.WebhookChangeActorRef(e.App, e.ActorInfo(), webhook.Record))

	if err := e.App.Save(webhook); err != nil {
		return e.BadRequestError("Failed to save the webhook secret.", err)
	}

	e.Response.Header().Set("Cache-Control", "no-store")

	return e.JSON(http.StatusOK, webhookSecretResponse{
		Id:     webhook.Id,
		Secret: secret,
	})
}

type webhookTestForm struct {
	// Topic is the test event topic (collection name or id format; e.g. "posts.create").
	//
	// If empty, the first non-wildcard subscription topic is used.
	Topic string `form:"topic" json:"topic"`
}

// POST /api/webhooks/subscriptions/{id}/test
//
// Synchronously sends a synthetic test event to the subscription endpoint
// and returns the logged test delivery (incl. the response).
func webhookTest(e *core.RequestEvent) error {
	webhook, err := e.App.FindWebhookById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("Missing or invalid webhook subscription.", err)
	}

	if !core.CanAccessWebhook(e.App, e.ActorInfo(), webhook.Record) {
		return e.ForbiddenError("You are not allowed to access a subscription with topics you can't view or a filter you can't use.", nil)
	}

	form := &webhookTestForm{}
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	delivery, err := e.App.Webhooks().SendTest(e.Request.Context(), webhook, form.Topic)
	if err != nil {
		if errors.Is(err, core.ErrWebhookInvalidTopic) {
			return e.BadRequestError(err.Error(), nil)
		}
		return e.InternalServerError("Failed to send the test webhook.", err)
	}

	return e.JSON(http.StatusOK, newWebhookDeliveryResponse(e.App, delivery))
}
