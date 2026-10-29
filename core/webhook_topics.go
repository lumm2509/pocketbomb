package core

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	validation "github.com/pocketbase/ozzo-validation/v4"
)

// webhookTopicMatches reports whether the stored subscription topic pattern matches the event.
func webhookTopicMatches(pattern string, ev *webhookEvent) bool {
	ns, op, ok := splitWebhookTopic(pattern)
	if !ok {
		return false
	}

	if op != WebhookTopicWildcard && op != ev.op {
		return false
	}

	if ev.collection != nil {
		if ns == ev.collection.Id {
			return true
		}

		return ns == WebhookTopicWildcard && !isWebhookWildcardExcludedCollection(ev.collection)
	}

	return ns == ev.namespace
}

// WebhookTopicInfo defines a single webhook topic picker item.
type WebhookTopicInfo struct {
	// Topic is the topic in its storage format (e.g. "pbc_123.create").
	Topic string `json:"topic"`

	// Label is the human friendly topic (e.g. "posts.create").
	Label string `json:"label"`

	Description string `json:"description,omitempty"`
}

// WebhookCollectionTopics defines the available webhook topics of a single collection.
type WebhookCollectionTopics struct {
	Id     string             `json:"id"`
	Name   string             `json:"name"`
	Type   string             `json:"type"`
	System bool               `json:"system"`
	Topics []WebhookTopicInfo `json:"topics"`
}

// WebhookTopicsList defines all available webhook topics.
type WebhookTopicsList struct {
	Collections []WebhookCollectionTopics `json:"collections"`
	Wildcards   []WebhookTopicInfo        `json:"wildcards"`
	Custom      []WebhookTopicInfo        `json:"custom"`
}

// RegisterTopic registers a custom webhook topic so that it could be
// listed in the dashboard topics picker.
//
// Registration is optional - [Webhooks.Trigger] accepts any valid custom topic.
func (w *Webhooks) RegisterTopic(topic string, description string) error {
	if err := w.checkCustomTopic(topic); err != nil {
		return err
	}

	w.topicsMu.Lock()
	defer w.topicsMu.Unlock()

	w.customTopics[strings.TrimSpace(topic)] = description

	return nil
}

func (w *Webhooks) checkCustomTopic(topic string) error {
	ns, op, ok := splitWebhookTopic(topic)
	if !ok || !webhookTopicPartRegex.MatchString(ns) || !webhookTopicPartRegex.MatchString(op) {
		return fmt.Errorf("%w %q: expected {namespace}.{name} format", ErrWebhookInvalidTopic, topic)
	}

	if c, _ := w.app.FindCachedCollectionByNameOrId(ns); c != nil {
		return fmt.Errorf("%w %q: the namespace clashes with an existing collection", ErrWebhookInvalidTopic, topic)
	}

	return nil
}

// Topics returns all available webhook topics (e.g. for the dashboard topics picker).
func (w *Webhooks) Topics() (*WebhookTopicsList, error) {
	collections, err := w.app.FindAllCollections()
	if err != nil {
		return nil, err
	}

	sort.SliceStable(collections, func(i, j int) bool {
		return collections[i].Name < collections[j].Name
	})

	result := &WebhookTopicsList{
		Collections: []WebhookCollectionTopics{},
		Wildcards:   []WebhookTopicInfo{},
		Custom:      []WebhookTopicInfo{},
	}

	for _, c := range collections {
		if isWebhookDeniedCollection(c) {
			continue
		}

		ops := []string{WebhookTopicWildcard, WebhookOpCreate, WebhookOpUpdate, WebhookOpDelete}
		if c.IsAuth() {
			ops = append(ops, WebhookOpAuth, WebhookOpVerified)
		}

		item := WebhookCollectionTopics{
			Id:     c.Id,
			Name:   c.Name,
			Type:   c.Type,
			System: c.System,
			Topics: make([]WebhookTopicInfo, len(ops)),
		}
		for i, op := range ops {
			item.Topics[i] = WebhookTopicInfo{Topic: c.Id + "." + op, Label: c.Name + "." + op}
		}

		result.Collections = append(result.Collections, item)
	}

	for _, op := range []string{WebhookTopicWildcard, WebhookOpCreate, WebhookOpUpdate, WebhookOpDelete, WebhookOpAuth, WebhookOpVerified} {
		topic := WebhookTopicWildcard + "." + op
		result.Wildcards = append(result.Wildcards, WebhookTopicInfo{
			Topic:       topic,
			Label:       topic,
			Description: "All non-system collections (excluding the \"_*\" ones).",
		})
	}

	w.topicsMu.RLock()
	for topic, description := range w.customTopics {
		result.Custom = append(result.Custom, WebhookTopicInfo{Topic: topic, Label: topic, Description: description})
	}
	w.topicsMu.RUnlock()

	sort.Slice(result.Custom, func(i, j int) bool {
		return result.Custom[i].Topic < result.Custom[j].Topic
	})

	return result, nil
}

// webhookTopicTarget describes the target of a single concrete
// or wildcard webhook topic.
type webhookTopicTarget struct {
	// collection is the topic collection (nil for wildcard collection and custom topics)
	collection *Collection

	// namespace is the first topic part
	// ("*" for the wildcard collection topics, collection id for the collection topics)
	namespace string

	// op is the second topic part (operation or "*")
	op string

	custom bool
}

// splitWebhookTopic splits the topic into its 2 parts.
func splitWebhookTopic(topic string) (string, string, bool) {
	ns, op, ok := strings.Cut(strings.TrimSpace(topic), ".")
	if !ok || ns == "" || op == "" || strings.Contains(op, ".") {
		return "", "", false
	}

	return ns, op, true
}

func isWebhookCollectionOp(op string, collection *Collection) bool {
	switch op {
	case WebhookTopicWildcard, WebhookOpCreate, WebhookOpUpdate, WebhookOpDelete:
		return true
	case WebhookOpAuth, WebhookOpVerified:
		return collection == nil || collection.IsAuth()
	}

	return false
}

// isWebhookWildcardExcludedCollection reports whether the collection should be
// excluded from the "*.{op}" wildcard topics (aka. the system "_*" collections).
func isWebhookWildcardExcludedCollection(collection *Collection) bool {
	return strings.HasPrefix(collection.Name, "_")
}

// isWebhookDeniedCollection reports whether the collection could not be used in a webhook topic.
func isWebhookDeniedCollection(collection *Collection) bool {
	return slices.Contains(webhookDeniedCollections, collection.Name)
}

// parseWebhookTopic parses and validates a single webhook topic.
//
// The collection could be specified by its name or id.
func parseWebhookTopic(app App, topic string) (*webhookTopicTarget, error) {
	ns, op, ok := splitWebhookTopic(topic)
	if !ok {
		return nil, validation.NewError("validation_invalid_webhook_topic", "Invalid topic format - expected {collection}.{operation}.")
	}

	// wildcard collection
	if ns == WebhookTopicWildcard {
		if !isWebhookCollectionOp(op, nil) {
			return nil, validation.NewError("validation_invalid_webhook_topic_op", "Invalid topic operation.")
		}
		return &webhookTopicTarget{namespace: ns, op: op}, nil
	}

	if !webhookTopicPartRegex.MatchString(ns) {
		return nil, validation.NewError("validation_invalid_webhook_topic", "Invalid topic format - expected {collection}.{operation}.")
	}

	collection, _ := app.FindCachedCollectionByNameOrId(ns)
	if collection != nil {
		if isWebhookDeniedCollection(collection) {
			return nil, validation.NewError("validation_webhook_topic_collection_denied", "The collection is not allowed to be used in webhooks.")
		}

		if !isWebhookCollectionOp(op, collection) {
			return nil, validation.NewError("validation_invalid_webhook_topic_op", "Invalid topic operation.")
		}

		return &webhookTopicTarget{collection: collection, namespace: collection.Id, op: op}, nil
	}

	// custom topic
	if op != WebhookTopicWildcard && !webhookTopicPartRegex.MatchString(op) {
		return nil, validation.NewError("validation_invalid_webhook_topic", "Invalid custom topic format.")
	}

	return &webhookTopicTarget{namespace: ns, op: op, custom: true}, nil
}

// String returns the topic in its storage format.
func (t *webhookTopicTarget) String() string {
	return t.namespace + "." + t.op
}

// normalizeWebhookTopic validates the provided webhook topic and
// returns it in its storage format, aka. with the collection name replaced
// by the collection id (e.g. "posts.create" -> "pbc_123.create").
//
// Wildcard and custom topics are returned as they are.
func normalizeWebhookTopic(app App, topic string) (string, error) {
	target, err := parseWebhookTopic(app, topic)
	if err != nil {
		return "", err
	}

	return target.String(), nil
}

// RenderWebhookTopic returns the human friendly version of a stored
// webhook topic, aka. with the collection id replaced by the collection name
// (e.g. "pbc_123.create" -> "posts.create").
//
// Wildcard, custom and invalid topics are returned as they are.
func RenderWebhookTopic(app App, topic string) string {
	ns, op, ok := splitWebhookTopic(topic)
	if !ok || ns == WebhookTopicWildcard {
		return topic
	}

	collection, _ := app.FindCachedCollectionByNameOrId(ns)
	if collection == nil {
		return topic
	}

	return collection.Name + "." + op
}

// webhookTopicsChanged reports whether the (normalized) topics of the provided webhook record differ from the original ones.
func webhookTopicsChanged(app App, record *Record) bool {
	normalize := func(topics []string) []string {
		result := make([]string, 0, len(topics))
		for _, t := range topics {
			if n, err := normalizeWebhookTopic(app, t); err == nil {
				t = n
			}
			if !slices.Contains(result, t) {
				result = append(result, t)
			}
		}
		slices.Sort(result)
		return result
	}

	return !slices.Equal(normalize(record.GetStringSlice("topics")), normalize(record.Original().GetStringSlice("topics")))
}

// webhookClientAllowsNamespace reports whether the OAuth2 client scopes
// allow webhook events of the specified namespace (collection or custom topic namespace name).
func webhookClientAllowsNamespace(client *OAuth2Client, namespace string) bool {
	if client == nil {
		return false
	}

	scopes := client.Scopes()

	if slices.Contains(scopes, WebhookScopeAll) {
		return true
	}

	return namespace != WebhookTopicWildcard && slices.Contains(scopes, namespace+":read")
}
