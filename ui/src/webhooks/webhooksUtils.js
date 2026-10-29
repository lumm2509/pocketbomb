// Shared webhooks dashboard helpers.

export const WEBHOOKS_COLLECTION = "_webhooks";

export const WEBHOOK_SCOPE_ALL = "webhooks:*";

export const WEBHOOK_STATUSES = [
    { value: "success", label: "Success", className: "success", color: "--successColor" },
    { value: "failed", label: "Failed", className: "danger", color: "--dangerColor" },
    { value: "retrying", label: "Retrying", className: "warning", color: "--warningColor" },
    { value: "pending", label: "Pending", className: "info", color: "--infoColor" },
    { value: "disabled", label: "Disabled", className: "", color: "--surfaceTxtHintColor" },
];

export const WEBHOOK_COMPLETED_STATUSES = ["success", "failed", "disabled"];

export const WEBHOOK_OPS = ["*", "create", "update", "delete", "auth", "verified"];
export const WEBHOOK_AUTH_OPS = ["auth", "verified"];

export const WEBHOOK_GROUP_BY_OPTIONS = [
    { value: "status", label: "Status" },
    { value: "topic", label: "Topic" },
    { value: "webhook", label: "Subscription" },
];

// the deliveries list fields excluding the heavy request/response bodies
export const WEBHOOK_DELIVERY_LIST_FIELDS = [
    "id",
    "created",
    "updated",
    "webhook",
    "eventId",
    "topic",
    "topicName",
    "apiVersion",
    "triggeredAt",
    "status",
    "attempts",
    "nextAttemptAt",
    "responseStatus",
    "error",
    "durationMs",
    "test",
    "redeliveryOf",
].join(",");

export const WEBHOOK_SEARCH_FALLBACK_FIELDS = ["id", "eventId", "topic", "error", "webhook"];

export const WEBHOOK_SEARCH_AUTOCOMPLETE = [
    "id",
    "created",
    "updated",
    "webhook",
    "eventId",
    "topic",
    "apiVersion",
    "triggeredAt",
    "status",
    "attempts",
    "nextAttemptAt",
    "responseStatus",
    "error",
    "durationMs",
    "test",
    "redeliveryOf",
];

// shared lazily loaded dashboard data (topics, subscriptions and OAuth2 clients)
export const webhooksState = store({
    topics: null, // {collections, wildcards, custom}
    subscriptions: [],
    subscriptionsLoaded: false,
    isLoadingSubscriptions: false,
    clients: [],
    clientsLoaded: false,
});

/**
 * Loads (and caches) the available webhook topics.
 *
 * @param  {boolean} [force]
 * @return {Promise<Object>}
 */
export async function webhooksLoadTopics(force = false) {
    if (webhooksState.topics && !force) {
        return webhooksState.topics;
    }

    try {
        webhooksState.topics = await app.pb.send("/api/webhooks/topics", { requestKey: "webhooks_topics" });
    } catch (err) {
        if (!err?.isAbort) {
            app.checkApiError(err);
        }
    }

    return webhooksState.topics;
}

/**
 * Loads the webhook subscriptions (expanded with their linked OAuth2 client).
 *
 * @return {Promise<Array>}
 */
export async function webhooksLoadSubscriptions() {
    webhooksState.isLoadingSubscriptions = true;

    try {
        webhooksState.subscriptions = await app.pb.collection(WEBHOOKS_COLLECTION).getFullList({
            sort: "name,created",
            expand: "client",
            requestKey: "webhooks_subscriptions",
        });
        webhooksState.subscriptionsLoaded = true;
    } catch (err) {
        if (!err?.isAbort) {
            app.checkApiError(err);
        }
    }

    webhooksState.isLoadingSubscriptions = false;

    return webhooksState.subscriptions;
}

/**
 * Updates (or inserts) a single subscription in the shared state.
 *
 * @param {Object} subscription
 */
export function webhooksUpsertCachedSubscription(subscription) {
    if (!subscription?.id) {
        return;
    }

    const list = webhooksState.subscriptions.slice();
    const index = list.findIndex((s) => s.id == subscription.id);
    if (index >= 0) {
        list[index] = subscription;
    } else {
        list.push(subscription);
        list.sort((a, b) => (a.name || "").localeCompare(b.name || ""));
    }
    webhooksState.subscriptions = list;
}

/**
 * Removes a single subscription from the shared state.
 *
 * @param {string} id
 */
export function webhooksRemoveCachedSubscription(id) {
    webhooksState.subscriptions = webhooksState.subscriptions.filter((s) => s.id != id);
}

/**
 * Loads (and caches) the OAuth2 clients list.
 *
 * @param  {boolean} [force]
 * @return {Promise<Array>}
 */
export async function webhooksLoadClients(force = false) {
    if (webhooksState.clientsLoaded && !force) {
        return webhooksState.clients;
    }

    // the OAuth2 clients are listed only with the oauth2_clients permission
    if (!app.perms.can("oauth2_clients")) {
        webhooksState.clients = [];
        return webhooksState.clients;
    }

    try {
        webhooksState.clients = await app.pb.collection("_oauth2Clients").getFullList({
            sort: "name",
            fields: "id,name,clientId,collectionRef,scopes,disabled,logo",
            requestKey: "webhooks_clients",
        });
        webhooksState.clientsLoaded = true;
    } catch (err) {
        if (!err?.isAbort) {
            app.checkApiError(err);
        }
    }

    return webhooksState.clients;
}

/**
 * Returns the cached subscription with the specified id (if loaded).
 *
 * @param  {string} id
 * @return {Object|undefined}
 */
export function webhooksFindSubscription(id) {
    return webhooksState.subscriptions.find((s) => s.id == id);
}

/**
 * Returns the delivery status option.
 *
 * @param  {string} status
 * @return {Object}
 */
export function webhookStatus(status) {
    return WEBHOOK_STATUSES.find((s) => s.value == status)
        || { value: status, label: status || "N/A", className: "", color: "--surfaceAlt5Color" };
}

/**
 * Returns a delivery status label element.
 *
 * @param  {string} status
 * @param  {string} [errorMsg]
 * @return {Element}
 */
export function webhookStatusLabel(status, errorMsg = "") {
    const opt = webhookStatus(status);

    return t.span(
        {
            className: `label llm-status-label webhook-status-label status-${opt.value} ${opt.className}`,
            ariaDescription: errorMsg ? app.attrs.tooltip(app.utils.truncate(errorMsg, 300)) : undefined,
        },
        opt.label,
    );
}

/**
 * Returns a HTTP response status code label element.
 *
 * @param  {number} code
 * @return {Element}
 */
export function webhookResponseCodeLabel(code) {
    if (!code) {
        return t.span({ className: "txt-hint" }, "-");
    }

    let className = "danger";
    if (code >= 200 && code < 300) {
        className = "success";
    } else if (code >= 300 && code < 500) {
        className = "warning";
    }

    return t.span({ className: `label sm webhook-code-label ${className}` }, code);
}

/**
 * Splits a topic into its namespace and operation parts.
 *
 * @param  {string} topic
 * @return {[string, string]}
 */
export function webhookSplitTopic(topic) {
    const idx = (topic || "").indexOf(".");
    if (idx <= 0) {
        return [topic || "", ""];
    }
    return [topic.substring(0, idx), topic.substring(idx + 1)];
}

/**
 * Returns the collection model (if loaded) by its name or id.
 *
 * @param  {string} nameOrId
 * @return {Object|undefined}
 */
export function webhookCollection(nameOrId) {
    if (!nameOrId || nameOrId == "*") {
        return;
    }
    return app.store.collections.find((c) => c.id == nameOrId || c.name == nameOrId);
}

/**
 * Returns the human friendly name of a stored topic
 * (e.g. "pbc_123.create" -> "posts.create").
 *
 * @param  {string} topic
 * @return {string}
 */
export function webhookTopicLabel(topic) {
    const [ns, op] = webhookSplitTopic(topic);
    const collection = webhookCollection(ns);
    if (collection) {
        return collection.name + "." + op;
    }
    return topic;
}

/**
 * Normalizes a topic to its storage format (collection name -> id).
 *
 * @param  {string} topic
 * @return {string}
 */
export function webhookNormalizeTopic(topic) {
    topic = (topic || "").trim();
    const [ns, op] = webhookSplitTopic(topic);
    const collection = webhookCollection(ns);
    if (collection && op) {
        return collection.id + "." + op;
    }
    return topic;
}

/**
 * Returns the topic kind - "collection", "wildcard" or "custom".
 *
 * @param  {string} topic
 * @return {string}
 */
export function webhookTopicKind(topic) {
    const [ns] = webhookSplitTopic(topic);
    if (ns == "*") {
        return "wildcard";
    }
    if (webhookCollection(ns)) {
        return "collection";
    }
    return "custom";
}

/**
 * Returns the OAuth2 client scope required for the specified topic.
 *
 * @param  {string} topic
 * @return {string}
 */
export function webhookRequiredScope(topic) {
    const [ns] = webhookSplitTopic(topic);
    if (ns == "*") {
        return WEBHOOK_SCOPE_ALL;
    }

    const collection = webhookCollection(ns);

    return (collection?.name || ns) + ":read";
}

/**
 * Reports whether the provided client scopes allow the specified topic.
 *
 * @param  {Array<string>} scopes
 * @param  {string} topic
 * @return {boolean}
 */
export function webhookScopesAllowTopic(scopes, topic) {
    scopes = scopes || [];
    if (scopes.includes(WEBHOOK_SCOPE_ALL)) {
        return true;
    }
    const required = webhookRequiredScope(topic);
    return required != WEBHOOK_SCOPE_ALL && scopes.includes(required);
}

/**
 * Returns a list of topic chip elements.
 *
 * @param  {Array<string>} topics     The stored topics.
 * @param  {Array<string>} [names]    Optional server rendered names (same order as topics).
 * @param  {number}        [max]      Max visible chips (the rest are summarized as "+N").
 * @return {Element}
 */
export function webhookTopicChips(topics, names = null, max = 0) {
    topics = topics || [];

    const all = topics.map((topic, i) => ({ topic, label: names?.[i] || webhookTopicLabel(topic) }));
    const visible = max > 0 && all.length > max ? all.slice(0, max) : all;
    const rest = all.length - visible.length;

    return t.span(
        { className: "webhook-topic-chips" },
        visible.map((item) =>
            t.span(
                {
                    className: `label sm webhook-topic-chip kind-${webhookTopicKind(item.topic)}`,
                    title: item.label != item.topic ? item.topic : undefined,
                },
                item.label,
            )
        ),
        rest > 0
            ? t.span(
                {
                    className: "label sm webhook-topic-chip more",
                    ariaDescription: app.attrs.tooltip(all.slice(visible.length).map((i) => i.label).join("\n")),
                },
                "+" + rest,
            )
            : null,
    );
}

/**
 * Returns the concrete (non-wildcard) topics that could be used for a test send
 * of a subscription with the specified (stored) topics.
 *
 * @param  {Array<string>} topics
 * @param  {Object}        [topicsList] The /api/webhooks/topics response.
 * @param  {number}        [max]
 * @return {Array<{value:string,label:string}>}
 */
export function webhookTestTopics(topics, topicsList = null, max = 200) {
    const result = [];
    const seen = new Set();

    function add(topic) {
        if (seen.has(topic) || result.length >= max) {
            return;
        }
        seen.add(topic);
        result.push({ value: topic, label: webhookTopicLabel(topic) });
    }

    function collectionOps(c) {
        const ops = ["create", "update", "delete"];
        if (c.type == "auth") {
            ops.push(...WEBHOOK_AUTH_OPS);
        }
        return ops;
    }

    const collections = topicsList?.collections?.length ? topicsList.collections : app.store.collections;

    for (const topic of topics || []) {
        const [ns, op] = webhookSplitTopic(topic);

        if (ns == "*") {
            for (const c of collections) {
                if (c.name.startsWith("_")) {
                    continue; // wildcard topics exclude the system "_*" collections
                }
                for (const cop of collectionOps(c)) {
                    if (op == "*" || op == cop) {
                        add(c.id + "." + cop);
                    }
                }
            }
            continue;
        }

        if (op == "*") {
            const c = webhookCollection(ns);
            if (c) {
                for (const cop of collectionOps(c)) {
                    add(c.id + "." + cop);
                }
            }
            // custom namespace wildcards can't be tested without a concrete topic
            continue;
        }

        add(topic);
    }

    return result;
}

/**
 * Builds the deliveries API filter expression from the dashboard filter settings.
 *
 * @param  {Object} filters
 * @param  {Object} [range] Optional resolved range (see `llmResolveRange`).
 * @return {string}
 */
export function webhooksBuildFilter(filters, range = null) {
    const parts = [];

    if (range?.from) {
        parts.push(app.pb.filter("created >= {:from}", { from: app.utils.toRFC3339Datetime(range.from) }));
    }
    if (range?.to) {
        parts.push(app.pb.filter("created <= {:to}", { to: app.utils.toRFC3339Datetime(range.to) }));
    }
    if (filters.webhook) {
        parts.push(app.pb.filter("webhook = {:v}", { v: filters.webhook }));
    }
    if (filters.topic) {
        parts.push(app.pb.filter("topic = {:v}", { v: filters.topic }));
    }
    if (filters.status) {
        parts.push(app.pb.filter("status = {:v}", { v: filters.status }));
    }
    if (filters.test == "only") {
        parts.push("test = true");
    } else if (filters.test == "exclude") {
        parts.push("test = false");
    }
    if (filters.search) {
        parts.push(app.utils.normalizeSearchFilter(filters.search, WEBHOOK_SEARCH_FALLBACK_FIELDS));
    }

    return parts.filter(Boolean).map((f) => "(" + f + ")").join("&&");
}

/**
 * Returns the reason why the delivery can't be redelivered (empty string if it can).
 *
 * @param  {Object} delivery
 * @return {string}
 */
export function webhookRedeliverBlockReason(delivery) {
    if (!delivery) {
        return "Missing delivery.";
    }
    if (app.store.settings?.webhooks && !app.store.settings.webhooks.enabled) {
        return "Webhooks are globally disabled in the settings.";
    }
    if (delivery.test) {
        return "Test deliveries can't be redelivered (send a new test instead).";
    }
    if (!WEBHOOK_COMPLETED_STATUSES.includes(delivery.status)) {
        return "The delivery is still in the queue (pending or retrying).";
    }
    return "";
}

/**
 * Pretty formats a JSON string (returns the original value if not a valid JSON).
 *
 * @param  {string|Object} value
 * @return {{value: string, isJSON: boolean}}
 */
export function webhookPrettyBody(value) {
    if (value == null || value === "") {
        return { value: "", isJSON: false };
    }

    if (typeof value != "string") {
        return { value: JSON.stringify(value, null, 2), isJSON: true };
    }

    try {
        return { value: JSON.stringify(JSON.parse(value), null, 2), isJSON: true };
    } catch (_) {
        return { value, isJSON: false };
    }
}

/**
 * Parses the fields input value (`?fields=` like syntax) into a list.
 *
 * @param  {string} str
 * @return {Array<string>}
 */
export function webhookParseFields(str) {
    const result = [];
    let depth = 0;
    let current = "";

    for (const ch of str || "") {
        if (ch == "(") {
            depth++;
        } else if (ch == ")") {
            depth = Math.max(0, depth - 1);
        }
        if (ch == "," && depth == 0) {
            if (current.trim()) {
                result.push(current.trim());
            }
            current = "";
            continue;
        }
        current += ch;
    }
    if (current.trim()) {
        result.push(current.trim());
    }

    return result;
}

/**
 * Returns the deliveries page url with the specified filters.
 *
 * @param  {Object} params
 * @return {string}
 */
export function webhooksDeliveriesURL(params = {}) {
    const query = new URLSearchParams({ tab: "deliveries" });
    for (const key in params) {
        if (params[key]) {
            query.set(key, params[key]);
        }
    }
    return "#/webhooks?" + query.toString();
}
