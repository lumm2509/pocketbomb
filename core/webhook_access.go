package core

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/lumm2509/pocketbomb/tools/search"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// CheckWebhookChange checks whether the request actor is allowed to create or update
// the provided webhook subscription record (the system collections topics are Owner only).
//
// A nil info is treated as a trusted programmatic change.
func CheckWebhookChange(app App, info *RequestInfo, webhook *Record) error {
	if info == nil || info.IsOwner(app) {
		return nil
	}

	for _, topic := range webhook.GetStringSlice("topics") {
		ns, _, ok := splitWebhookTopic(topic)
		if !ok || ns == WebhookTopicWildcard {
			continue
		}

		collection, err := app.FindCachedCollectionByNameOrId(ns)
		if err != nil {
			continue // validated by the model
		}

		if collection.System || strings.HasPrefix(collection.Name, "_") {
			return errPermissionDenied
		}
	}

	return nil
}

// webhookTopicsViewErrors returns the (per topic index) errors of the provided webhook topics
// whose events the request actor is not allowed to receive (nil for the Owners):
//   - a collection topic requires the view permission of the collection (see [Authorize];
//     staff: role permission, application: grant ∩ token scopes)
//   - a "*.{op}" wildcard topic requires the "*" (all collections) view permission
//     and it is never allowed for the applications
//   - the custom topics are allowed (application defined events) except the "application.*"
//     lifecycle topics for the applications (they learn about their own lifecycle only
//     through their install/uninstall notifications)
//
// The system collections topics are Owner only (see [CheckWebhookChange]) and the
// invalid topics are reported by the model validator.
func webhookTopicsViewErrors(app App, info *RequestInfo, topics []string) validation.Errors {
	perms := info.Permissions(app)
	if perms.Owner {
		return nil
	}

	errs := validation.Errors{}

	for i, topic := range topics {
		ns, _, ok := splitWebhookTopic(topic)
		if !ok {
			continue
		}

		key := strconv.Itoa(i)

		if perms.IsApplication() && strings.EqualFold(ns, ApplicationLifecycleTopicNamespace) {
			errs[key] = validation.NewError(
				"validation_webhook_topic_application_lifecycle",
				"The applications can't subscribe to the application lifecycle topics.",
			)
			continue
		}

		if ns == WebhookTopicWildcard {
			if perms.IsApplication() || perms.ThirdParty || !perms.IsStaff() ||
				!slices.Contains(perms.Permissions.Collections[PermissionAllCollections], PermissionActionView) {
				errs[key] = validation.NewError(
					"validation_webhook_topic_wildcard_forbidden",
					"The wildcard topics require the view permission of all collections.",
				)
			}
			continue
		}

		collection, _ := app.FindCachedCollectionByNameOrId(ns)
		if collection == nil || collection.System {
			continue // custom topic or Owner only system topic
		}

		if !info.CollectionAccess(app, collection, PermissionActionView).BypassRules {
			errs[key] = validation.NewError(
				"validation_webhook_topic_forbidden",
				"You are not allowed to view the {{.collection}} records.",
			).SetParams(map[string]any{"collection": collection.Name})
		}
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}

// CheckWebhookTopicsAccess checks whether the request actor is allowed to receive the events of
// every provided webhook topic (nobody subscribes to the records they can't view; see [webhookTopicsViewErrors]).
//
// Returns a [validation.Errors] with a "topics" key on failure.
//
// A nil info is treated as a trusted programmatic change.
func CheckWebhookTopicsAccess(app App, info *RequestInfo, topics []string) error {
	if info == nil {
		return nil
	}

	if errs := webhookTopicsViewErrors(app, info, topics); len(errs) > 0 {
		return validation.Errors{"topics": errs}
	}

	return nil
}

// CheckWebhookFilterAccess checks whether the request actor is allowed to use the filter
// of the provided webhook subscription (the filter can't be used as an oracle for the
// fields and collections that the actor can't access; see [newActorFilterResolver]).
//
// Returns a [validation.Errors] with a "filter" key on failure.
//
// A nil info is treated as a trusted programmatic change.
func CheckWebhookFilterAccess(app App, info *RequestInfo, webhook *Record) error {
	if info == nil {
		return nil
	}

	if err := webhookFilterAccessError(app, requestInfoCanView(app, info), webhook); err != nil {
		return validation.Errors{"filter": err}
	}

	return nil
}

// CanAccessWebhook reports whether the request actor could access the provided webhook subscription
// related data (its secret, test sends, deliveries and redeliveries, changes),
// aka. whether it could receive the events of all its current topics
// and it is allowed to use its current filter.
//
// A nil info is treated as a trusted programmatic access.
func CanAccessWebhook(app App, info *RequestInfo, webhook *Record) bool {
	if info == nil {
		return true
	}

	if len(webhookTopicsViewErrors(app, info, webhook.GetStringSlice("topics"))) > 0 {
		return false
	}

	return webhookFilterAccessError(app, requestInfoCanView(app, info), webhook) == nil
}

// webhookFilterAccessError checks the webhook filter against the explicit topics collections
// with the actor restricted resolver (see [newActorFilterResolver]).
//
// The invalid filters (regardless of the actor) are reported by the model validator and
// the wildcard topics collections are checked during dispatch (the events are skipped).
func webhookFilterAccessError(app App, canView func(c *Collection) bool, webhook *Record) error {
	filter := webhook.GetString("filter")
	if filter == "" || canView == nil {
		return nil
	}

	checked := map[string]struct{}{}

	for _, topic := range webhook.GetStringSlice("topics") {
		target, err := parseWebhookTopic(app, topic)
		if err != nil || target.collection == nil {
			continue // invalid, wildcard or custom topic
		}

		if _, ok := checked[target.collection.Id]; ok {
			continue
		}
		checked[target.collection.Id] = struct{}{}

		unrestricted := NewRecordFieldResolver(app, target.collection, &RequestInfo{}, true)
		if _, err := search.FilterData(filter).BuildExpr(unrestricted); err != nil {
			continue // invalid filter
		}

		if _, err := search.FilterData(filter).BuildExpr(newActorFilterResolver(app, target.collection, canView)); err != nil {
			return validation.NewError(
				"validation_webhook_filter_forbidden",
				"The filter references fields or collections that you are not allowed to access ({{.collection}}). Raw error: {{.error}}",
			).SetParams(map[string]any{"collection": target.collection.Name, "error": err.Error()})
		}
	}

	return nil
}

// requestInfoCanView returns the [newActorFilterResolver] canView function of the request actor
// (nil for the Owners, aka. no restrictions).
//
// A collection is viewable if the actor could view its records with rules bypass
// (staff: role permission, application: grant ∩ token scopes; see [Authorize]).
func requestInfoCanView(app App, info *RequestInfo) func(c *Collection) bool {
	if info.IsOwner(app) {
		return nil
	}

	return func(c *Collection) bool {
		return info.CollectionAccess(app, c, PermissionActionView).BypassRules
	}
}

// newActorFilterResolver returns a resolver for a filter expression saved by an actor and
// evaluated later on its behalf without a request (e.g. a webhook subscription filter),
// restricted as the records API client-side filter of the actor:
//   - the secret fields (see [IsSecretField]) are never allowed
//   - the hidden fields are allowed only if the actor could view the base collection
//     with rules bypass (same as the records API)
//   - the relation, back-relation and "@collection.*" joins are allowed only into
//     the collections that the actor could view (incl. the system collections)
//
// canView reports whether the actor could view the records of a collection with rules bypass
// (nil for the Owners and the trusted programmatic filters, aka. no restrictions).
func newActorFilterResolver(app App, collection *Collection, canView func(c *Collection) bool) *RecordFieldResolver {
	resolver := NewRecordFieldResolver(app, collection, &RequestInfo{Context: RequestInfoContextDefault}, true)

	if canView == nil {
		return resolver
	}

	resolver.SetAllowHiddenFields(canView(collection))
	resolver.SetDenySecretFields(true)
	resolver.SetJoinCollectionCheck(func(c *Collection) error {
		if !canView(c) {
			return fmt.Errorf("the filter cannot reference the %q collection", c.Name)
		}
		return nil
	})

	return resolver
}

// webhookActorCanView reports whether the provided webhook subscription actor
// could still view the records of the provided collection (dispatch time check).
//
// The applications are checked against their installation grant only
// (the token scopes are a per-token narrowing that doesn't exist at dispatch time).
func webhookActorCanView(app App, actor *Record, collection *Collection) bool {
	if actor == nil || collection == nil {
		return false
	}

	info := &RequestInfo{Auth: actor}

	if actor.Collection().Name == CollectionNameApplicationInstallations {
		// note: nothing is delivered before the application acknowledged the install notification
		if collection.System || actor.GetString("status") != ApplicationInstallationStatusActive {
			return false
		}

		info = applicationInstallationActorInfo(app, &ApplicationInstallation{Record: actor})
	}

	return info.CollectionAccess(app, collection, PermissionActionView).BypassRules
}
