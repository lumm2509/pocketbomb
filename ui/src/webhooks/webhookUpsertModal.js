import { llmFormatDuration } from "@/llm/llmUtils";
import { openWebhookDeliveryModal } from "./webhookDeliveryModal";
import { webhookReceiverTab } from "./webhookReceiverTab";
import { openWebhookSecretModal } from "./webhookSecretModal";
import {
    webhookCollection,
    webhookParseFields,
    webhookPrettyBody,
    webhookRequiredScope,
    webhookResponseCodeLabel,
    WEBHOOKS_COLLECTION,
    webhookScopesAllowTopic,
    webhooksDeliveriesURL,
    webhooksLoadClients,
    webhooksLoadTopics,
    webhookSplitTopic,
    webhooksRemoveCachedSubscription,
    webhooksState,
    webhookStatusLabel,
    webhooksUpsertCachedSubscription,
    webhookTestTopics,
    webhookTopicKind,
    webhookTopicLabel,
} from "./webhooksUtils";
import { webhookTopicPicker } from "./webhookTopicPicker";

const TAB_SETTINGS = "settings";
const TAB_TEST = "test";
const TAB_RECEIVER = "receiver";

const DEFAULT_API_VERSION = "2026-10";

/**
 * Opens the webhook subscription create/edit panel.
 *
 * @param {Object} [webhook]              The subscription record to edit (leave empty to create).
 * @param {Object} [settings]
 * @param {string} [settings.clientId]    Pre-linked OAuth2 client record id on create.
 * @param {string} [settings.clientName]  Optional pre-linked client name (used for the default subscription name).
 * @param {string} [settings.tab]         The initial tab.
 * @param {function} [settings.onsave]    function(webhook, isNew) {}
 * @param {function} [settings.ondelete]  function(webhook) {}
 */
export function openWebhookUpsertModal(webhook = null, settings = {}) {
    app.store.errors = null;

    const modal = webhookUpsertModal(webhook, settings);

    document.body.appendChild(modal);

    app.modals.open(modal);
}

function newWebhookData(clientId = "") {
    return {
        name: "",
        active: true,
        uri: "",
        topics: [],
        filter: "",
        fields: [],
        apiVersion: DEFAULT_API_VERSION,
        client: clientId || "",
    };
}

function normalizeWebhook(raw) {
    const w = JSON.parse(JSON.stringify(raw || {}));
    w.topics = Array.isArray(w.topics) ? w.topics : [];
    w.fields = Array.isArray(w.fields) ? w.fields : [];
    w.filter = w.filter || "";
    w.client = w.client || "";
    w.apiVersion = w.apiVersion || DEFAULT_API_VERSION;
    w._fieldsStr = w.fields.join(", ");
    return w;
}

function serialize(w) {
    return {
        name: w.name,
        active: !!w.active,
        uri: (w.uri || "").trim(),
        topics: w.topics.slice(),
        filter: (w.filter || "").trim(),
        fields: webhookParseFields(w._fieldsStr),
        apiVersion: w.apiVersion,
        client: w.client || "",
    };
}

function webhookUpsertModal(rawWebhook, settings) {
    const uniqueId = "webhook_" + app.utils.randomString();

    const isEdit = !!rawWebhook?.id;

    const initial = normalizeWebhook(isEdit ? rawWebhook : newWebhookData(settings.clientId));
    if (!isEdit && settings.clientId) {
        const clientName = settings.clientName
            || webhooksState.clients.find((c) => c.id == settings.clientId)?.name;
        if (clientName) {
            initial.name = clientName + " webhook";
        }
    }

    const data = store({
        isSaving: false,
        isRevealing: false,
        isRotating: false,
        isTesting: false,
        activeTab: isEdit && [TAB_TEST, TAB_RECEIVER].includes(settings.tab) ? settings.tab : TAB_SETTINGS,
        original: normalizeWebhook(isEdit ? rawWebhook : initial),
        form: initial,
        testTopic: "",
        testResult: null,
        testError: "",
        get isNew() {
            return !data.original.id;
        },
        get hasChanges() {
            return JSON.stringify(serialize(data.original)) != JSON.stringify(serialize(data.form));
        },
        get topicsList() {
            return webhooksState.topics;
        },
        // the explicit (non-wildcard) collections of the selected topics
        get filterCollections() {
            const result = [];
            for (const topic of data.form.topics) {
                if (webhookTopicKind(topic) != "collection") {
                    continue;
                }
                const c = webhookCollection(webhookSplitTopic(topic)[0]);
                if (c && !result.includes(c)) {
                    result.push(c);
                }
            }
            return result;
        },
        get hasWildcardTopics() {
            return data.form.topics.some((t) => webhookTopicKind(t) == "wildcard");
        },
        get hasOnlyCustomTopics() {
            return data.form.topics.length > 0 && data.form.topics.every((t) => webhookTopicKind(t) == "custom");
        },
        get client() {
            return webhooksState.clients.find((c) => c.id == data.form.client);
        },
        get requiredScopes() {
            const result = [];
            for (const topic of data.form.topics) {
                const scope = webhookRequiredScope(topic);
                let item = result.find((r) => r.scope == scope);
                if (!item) {
                    item = { scope, topics: [], ok: true };
                    result.push(item);
                }
                item.topics.push(topic);
                if (!webhookScopesAllowTopic(data.client?.scopes, topic)) {
                    item.ok = false;
                }
            }
            return result;
        },
        get testTopics() {
            return webhookTestTopics(data.original.topics, data.topicsList);
        },
    });

    webhooksLoadTopics();
    webhooksLoadClients();

    async function save() {
        if (data.isSaving) {
            return;
        }

        data.isSaving = true;

        const wasNew = data.isNew;
        const collection = app.pb.collection(WEBHOOKS_COLLECTION);

        try {
            const payload = serialize(data.form);

            let saved;
            if (wasNew) {
                saved = await collection.create(payload, { expand: "client" });
            } else {
                saved = await collection.update(data.original.id, payload, { expand: "client" });
            }

            data.original = normalizeWebhook(saved);
            data.form = normalizeWebhook(saved);

            app.store.errors = null;

            webhooksUpsertCachedSubscription(saved);
            settings.onsave?.(saved, wasNew);

            app.toasts.success(
                wasNew
                    ? `Successfully created subscription "${saved.name}".`
                    : `Successfully updated subscription "${saved.name}".`,
            );

            data.isSaving = false;

            // show the auto generated signing secret
            if (wasNew) {
                await revealSecret("create");
            }

            return;
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        data.isSaving = false;
    }

    async function revealSecret(mode = "reveal") {
        if (data.isRevealing || data.isNew) {
            return;
        }

        data.isRevealing = true;

        try {
            const result = await app.pb.send(
                `/api/webhooks/subscriptions/${encodeURIComponent(data.original.id)}/secret`,
                { requestKey: null },
            );
            openWebhookSecretModal(result, { name: data.original.name, mode });
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        data.isRevealing = false;
    }

    function rotateSecret() {
        if (data.isRotating || data.isNew) {
            return;
        }

        app.modals.confirm(
            t.div(
                null,
                t.p(null, "Do you really want to rotate the signing secret?"),
                t.p(
                    { className: "txt-hint txt-sm" },
                    "The current secret stops working immediately - the receiver signature checks will fail until it is reconfigured with the new secret (the queued retries are signed with the new one).",
                ),
            ),
            async () => {
                data.isRotating = true;
                try {
                    const result = await app.pb.send(
                        `/api/webhooks/subscriptions/${encodeURIComponent(data.original.id)}/rotate-secret`,
                        { method: "POST", requestKey: null },
                    );
                    openWebhookSecretModal(result, { name: data.original.name, mode: "rotate" });
                } catch (err) {
                    if (!err?.isAbort) {
                        app.checkApiError(err);
                    }
                }
                data.isRotating = false;
            },
            null,
            { yesButton: "Rotate secret" },
        );
    }

    async function sendTest() {
        if (data.isTesting || data.isNew) {
            return;
        }

        data.isTesting = true;
        data.testError = "";
        data.testResult = null;

        try {
            data.testResult = await app.pb.send(
                `/api/webhooks/subscriptions/${encodeURIComponent(data.original.id)}/test`,
                {
                    method: "POST",
                    body: { topic: data.testTopic || data.testTopics[0]?.value || "" },
                    requestKey: null,
                },
            );
        } catch (err) {
            if (!err?.isAbort) {
                data.testError = err?.response?.message || err?.message || "Failed to send the test webhook.";
            }
        }

        data.isTesting = false;
    }

    function deleteWebhook() {
        app.modals.confirm(
            t.div(
                null,
                t.p(null, "Do you really want to delete subscription ", t.strong(null, data.original.name), "?"),
                t.p(
                    { className: "txt-hint txt-sm" },
                    "The queued deliveries of the subscription will not be sent anymore.",
                ),
            ),
            async () => {
                try {
                    await app.pb.collection(WEBHOOKS_COLLECTION).delete(data.original.id);
                    app.toasts.success(`Successfully deleted subscription "${data.original.name}".`);
                    webhooksRemoveCachedSubscription(data.original.id);
                    settings.ondelete?.(data.original);
                    app.modals.close(modal, true);
                } catch (err) {
                    app.checkApiError(err);
                }
            },
            null,
            { yesButton: "Delete" },
        );
    }

    // --- settings tab

    function filterField() {
        const help = t.div({ className: "field-help" }, () => {
            if (data.hasOnlyCustomTopics) {
                return "The filter is supported only for collection topics.";
            }

            const parts = [
                "Optional PocketBase filter expression evaluated against the event record (e.g. ",
                t.code(null, "status = 'paid' && total > 100"),
                "). Only the matching events are delivered.",
            ];

            if (data.filterCollections.length > 1) {
                parts.push(
                    ` It must be valid for each of the selected collections (${
                        data.filterCollections.map((c) => c.name).join(", ")
                    }).`,
                );
            }
            if (data.hasWildcardTopics) {
                parts.push(
                    " For the wildcard topics the events of the collections for which the filter is invalid are skipped.",
                );
            }
            if (data.filterCollections.length != 1 || data.hasWildcardTopics) {
                parts.push(
                    " Field autocomplete is available when exactly one collection (and no wildcard) is selected.",
                );
            }

            return parts;
        });

        return t.div(
            { className: "col-sm-12" },
            () => {
                const single = data.filterCollections.length == 1 && !data.hasWildcardTopics
                    ? data.filterCollections[0]
                    : null;

                if (single) {
                    return app.components.ruleField({
                        id: uniqueId + ".filter",
                        name: "filter",
                        label: t.span(null, "Filter ", t.span({ className: "txt-hint" }, `(${single.name})`)),
                        nullable: false,
                        placeholder: "Leave empty to deliver all events...",
                        autocomplete: (word) => {
                            return app.utils.collectionAutocompleteKeys(single, word, { requestKeys: false });
                        },
                        value: () => data.form.filter,
                        oninput: (val) => data.form.filter = val || "",
                    });
                }

                return t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".filter" }, "Filter"),
                    t.input({
                        type: "text",
                        id: uniqueId + ".filter",
                        name: "filter",
                        spellcheck: false,
                        disabled: () => data.hasOnlyCustomTopics && !data.form.filter,
                        placeholder: "Leave empty to deliver all events...",
                        value: () => data.form.filter,
                        oninput: (e) => data.form.filter = e.target.value,
                    }),
                );
            },
            help,
        );
    }

    function clientField() {
        return t.div(
            { className: "col-sm-12" },
            t.div(
                { className: "field" },
                t.label({ htmlFor: uniqueId + ".client" }, "Linked OAuth2 client"),
                app.components.select({
                    id: uniqueId + ".client",
                    name: "client",
                    searchThreshold: 8,
                    options: () =>
                        [{ value: "", label: "None (standalone subscription)" }].concat(
                            webhooksState.clients.map((c) => ({
                                value: c.id,
                                label: `${c.name} (${c.clientId})` + (c.disabled ? " - disabled" : ""),
                            })),
                        ),
                    value: () => data.form.client || "",
                    onchange: (opts) => {
                        data.form.client = opts?.[0]?.value || "";
                        app.utils.deleteByPath(app.store.errors, "topics");
                    },
                }),
            ),
            () => {
                if (!data.form.client) {
                    return t.div(
                        { className: "field-help" },
                        "Optionally link the subscription to an OAuth2 app - the topics are then limited by the app scopes and the subscription is deleted together with the app.",
                    );
                }

                const required = data.requiredScopes;
                if (!required.length) {
                    return t.div(
                        { className: "field-help" },
                        "Select topics to see the required OAuth2 client scopes.",
                    );
                }

                const missing = required.filter((r) => !r.ok);

                return t.div(
                    { className: "field-help webhook-scopes-help" },
                    t.span(null, "Required OAuth2 client scope for each topic: "),
                    required.map((r) =>
                        t.span(
                            {
                                className: `label sm ${r.ok ? "success" : "warning"}`,
                                ariaDescription: app.attrs.tooltip(r.topics.map(webhookTopicLabel).join("\n")),
                            },
                            t.i({ className: r.ok ? "ri-check-line" : "ri-error-warning-line", ariaHidden: true }),
                            r.scope,
                        )
                    ),
                    t.span({ className: "txt-hint" }, " (or ", t.code(null, "webhooks:*"), " for all topics)."),
                    missing.length
                        ? t.div(
                            { className: "txt-warning m-t-5" },
                            "The OAuth2 client is missing ",
                            missing.map((m) => m.scope).join(", "),
                            ". Add the scope(s) to the issuer collection custom scopes and allow them in the OAuth2 client settings.",
                        )
                        : null,
                );
            },
        );
    }

    function secretBox() {
        return t.div(
            { className: "col-sm-12" },
            t.div(
                { className: "oauth2-secret-box webhook-secret-box" },
                t.i({ className: "ri-lock-password-line", ariaHidden: true }),
                t.div(
                    { className: "content" },
                    t.strong(null, "Signing secret"),
                    t.div({ className: "txt-hint txt-sm" }, () => {
                        if (data.isNew) {
                            return "A random signing secret is generated and shown after the subscription is created.";
                        }
                        return t.span(
                            null,
                            "Each request is signed with HMAC-SHA256 of the raw body in the ",
                            t.code(null, "X-PB-Hmac-Sha256"),
                            " header (base64).",
                        );
                    }),
                ),
                () => {
                    if (data.isNew) {
                        return;
                    }

                    return [
                        t.button(
                            {
                                type: "button",
                                className: () => `btn sm secondary ${data.isRevealing ? "loading" : ""}`,
                                disabled: () => data.isRevealing,
                                onclick: () => revealSecret("reveal"),
                            },
                            t.i({ className: "ri-eye-line", ariaHidden: true }),
                            t.span({ className: "txt" }, "Reveal"),
                        ),
                        t.button(
                            {
                                type: "button",
                                className: () => `btn sm secondary ${data.isRotating ? "loading" : ""}`,
                                disabled: () => data.isRotating,
                                onclick: rotateSecret,
                            },
                            t.i({ className: "ri-key-line", ariaHidden: true }),
                            t.span({ className: "txt" }, "Rotate"),
                        ),
                    ];
                },
            ),
        );
    }

    function settingsTab() {
        return t.form(
            {
                id: uniqueId + "_form",
                className: "grid webhook-upsert-form",
                inert: () => data.isSaving,
                onsubmit: (e) => {
                    e.preventDefault();
                    save();
                },
            },
            () => {
                if (data.original.disabledReason && !data.original.active) {
                    return t.div(
                        { className: "col-sm-12" },
                        t.div(
                            { className: "alert danger m-0" },
                            t.i({ className: "ri-forbid-line", ariaHidden: true }),
                            t.div(
                                { className: "content" },
                                t.strong(null, "Disabled: "),
                                data.original.disabledReason,
                                t.div(
                                    { className: "txt-sm" },
                                    "Fix the endpoint and re-activate the subscription (the failure counter will be reset).",
                                ),
                            ),
                        ),
                    );
                }
            },
            t.div(
                { className: "col-sm-8" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".name" }, "Name"),
                    t.input({
                        type: "text",
                        id: uniqueId + ".name",
                        name: "name",
                        required: true,
                        maxLength: 255,
                        placeholder: "e.g. Orders sync",
                        value: () => data.form.name || "",
                        oninput: (e) => data.form.name = e.target.value,
                    }),
                ),
            ),
            t.div(
                { className: "col-sm-4 webhook-active-col" },
                t.div(
                    { className: "field" },
                    t.input({
                        type: "checkbox",
                        id: uniqueId + ".active",
                        name: "active",
                        className: "switch",
                        checked: () => !!data.form.active,
                        onchange: (e) => data.form.active = e.target.checked,
                    }),
                    t.label({ htmlFor: uniqueId + ".active" }, "Active"),
                ),
            ),
            t.div(
                { className: "col-sm-12" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".uri" }, "Endpoint URL"),
                    t.input({
                        type: "url",
                        id: uniqueId + ".uri",
                        name: "uri",
                        required: true,
                        maxLength: 2048,
                        spellcheck: false,
                        placeholder: "https://example.com/webhooks/pocketbase",
                        value: () => data.form.uri || "",
                        oninput: (e) => data.form.uri = e.target.value,
                    }),
                ),
                () => {
                    if (app.store.settings?.webhooks?.allowPrivateTargets) {
                        return;
                    }
                    if (/^https?:\/\/(localhost|127\.|10\.|192\.168\.|\[::1\])/i.test(data.form.uri || "")) {
                        return t.div(
                            { className: "field-help txt-warning" },
                            "Private and loopback targets are blocked unless allowed in ",
                            t.a({ href: "#/settings/webhooks" }, "Settings > Webhooks"),
                            ".",
                        );
                    }
                },
            ),
            t.div(
                { className: "col-sm-12" },
                t.div({ className: "webhook-field-label required" }, "Topics"),
                webhookTopicPicker({
                    id: uniqueId + "_topics",
                    name: "topics",
                    topics: () => data.topicsList,
                    value: () => data.form.topics,
                    onchange: (list) => data.form.topics = list,
                }),
            ),
            filterField(),
            t.div(
                { className: "col-sm-8" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".fields" }, "Payload fields"),
                    t.input({
                        type: "text",
                        id: uniqueId + ".fields",
                        name: "fields",
                        spellcheck: false,
                        placeholder: "All fields",
                        value: () => data.form._fieldsStr || "",
                        oninput: (e) => data.form._fieldsStr = e.target.value,
                    }),
                ),
                t.div(
                    { className: "field-help" },
                    "Comma separated record fields to include (",
                    t.code(null, "?fields="),
                    " syntax, e.g. ",
                    t.code(null, "id,total,note:excerpt(100)"),
                    ").",
                ),
            ),
            t.div(
                { className: "col-sm-4" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".apiVersion" }, "API version"),
                    app.components.select({
                        id: uniqueId + ".apiVersion",
                        name: "apiVersion",
                        required: true,
                        options: () => {
                            const versions = [DEFAULT_API_VERSION];
                            if (data.form.apiVersion && !versions.includes(data.form.apiVersion)) {
                                versions.push(data.form.apiVersion);
                            }
                            return versions.map((v) => ({
                                value: v,
                                label: v + (v == DEFAULT_API_VERSION ? " (latest)" : ""),
                            }));
                        },
                        value: () => data.form.apiVersion,
                        onchange: (opts) => data.form.apiVersion = opts?.[0]?.value || DEFAULT_API_VERSION,
                    }),
                ),
            ),
            clientField(),
            secretBox(),
        );
    }

    // --- test tab

    function testResultView() {
        const d = data.testResult;
        const body = webhookPrettyBody(d.responseBody);

        return t.div(
            { className: "webhook-test-result" },
            t.div(
                { className: "webhook-test-summary" },
                webhookStatusLabel(d.status, d.error),
                t.span(
                    { className: "inline-flex gap-5" },
                    t.span({ className: "txt-hint" }, "Response"),
                    webhookResponseCodeLabel(d.responseStatus),
                ),
                t.span(
                    { className: "inline-flex gap-5" },
                    t.span({ className: "txt-hint" }, "Duration"),
                    t.strong(null, d.durationMs ? llmFormatDuration(d.durationMs) : "-"),
                ),
                t.span({ className: "txt-hint txt-sm" }, d.topicName || webhookTopicLabel(d.topic)),
                t.button(
                    {
                        type: "button",
                        className: "btn sm transparent secondary m-l-auto",
                        onclick: () => openWebhookDeliveryModal(d.id),
                    },
                    t.span({ className: "txt" }, "Delivery details"),
                    t.i({ className: "ri-arrow-right-line", ariaHidden: true }),
                ),
            ),
            d.error
                ? t.div(
                    { className: "alert danger m-0" },
                    t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                    t.div({ className: "content" }, d.error),
                )
                : null,
            t.div({ className: "webhook-test-body-label txt-hint txt-sm" }, "Response body"),
            body.value
                ? app.components.codeBlock({ language: body.isJSON ? "js" : "html", value: body.value })
                : t.div({ className: "txt-hint txt-sm" }, "(empty)"),
        );
    }

    function testTab() {
        return t.div(
            { className: "webhook-test-tab" },
            () => {
                if (data.hasChanges) {
                    return t.div(
                        { className: "alert warning" },
                        t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                        t.div(
                            { className: "content" },
                            "You have unsaved changes - the test uses the saved subscription.",
                        ),
                    );
                }
            },
            () => {
                if (!data.original.active) {
                    return t.div(
                        { className: "alert info" },
                        t.i({ className: "ri-information-line", ariaHidden: true }),
                        t.div(
                            { className: "content" },
                            "The subscription is inactive, but test events are still sent.",
                        ),
                    );
                }
            },
            t.p(
                { className: "txt-hint" },
                "Sends synchronously a synthetic event (with a blank record for the collection topics and the ",
                t.code(null, "X-PB-Test: true"),
                " header) to ",
                t.code(null, () => data.original.uri),
                ". Test deliveries are logged but never retried and don't affect the failure counter.",
            ),
            t.form(
                {
                    className: "fields webhook-test-form",
                    onsubmit: (e) => {
                        e.preventDefault();
                        sendTest();
                    },
                },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".testTopic" }, "Topic"),
                    app.components.select({
                        id: uniqueId + ".testTopic",
                        required: true,
                        searchThreshold: 8,
                        placeholder: "No testable topic",
                        options: () => data.testTopics,
                        value: () => data.testTopic || data.testTopics[0]?.value,
                        onchange: (opts) => data.testTopic = opts?.[0]?.value || "",
                    }),
                ),
                t.div(
                    { className: "field addon" },
                    t.button(
                        {
                            type: "submit",
                            className: () => `btn ${data.isTesting ? "loading" : ""}`,
                            disabled: () => data.isTesting || !data.testTopics.length,
                        },
                        t.i({ className: "ri-send-plane-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "Send test"),
                    ),
                ),
            ),
            () => {
                if (!data.testTopics.length) {
                    return t.div(
                        { className: "field-help" },
                        "The subscription has only custom wildcard topics - add a concrete topic to send a test event.",
                    );
                }
            },
            () => {
                if (data.testError) {
                    return t.div(
                        { className: "alert danger m-t-sm" },
                        t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                        t.div({ className: "content" }, data.testError),
                    );
                }
                if (data.testResult) {
                    return testResultView();
                }
            },
        );
    }

    function tabButton(tab, label, icon) {
        return t.button(
            {
                type: "button",
                disabled: () => data.isSaving || (tab != TAB_SETTINGS && data.isNew),
                className: () => `tab-item ${data.activeTab == tab ? "active" : ""}`,
                onclick: () => data.activeTab = tab,
            },
            t.i({ className: icon, ariaHidden: true }),
            t.span({ className: "txt" }, label),
        );
    }

    const modal = t.div(
        {
            pbEvent: "webhookUpsertModal",
            className: "modal lg webhook-upsert-modal",
            onbeforeclose: (el, forceClosed) => {
                if (forceClosed) {
                    return;
                }

                if (data.isSaving) {
                    return false;
                }

                if (!data.hasChanges) {
                    return;
                }

                return new Promise((r) => {
                    app.modals.confirm(
                        "You have unsaved changes. Do you really want to discard them?",
                        () => r(true),
                        () => r(false),
                        { yesButton: "Yes, discard" },
                    );
                });
            },
            onafterclose: (el) => {
                app.store.errors = null;
                el?.remove();
            },
        },
        t.header(
            { className: "modal-header isolated" },
            t.div(
                { className: "grid" },
                t.div(
                    { className: "col-12 flex" },
                    t.i({ className: "ri-webhook-line txt-hint", ariaHidden: true }),
                    t.h6(
                        { className: "modal-title" },
                        () =>
                            data.isNew
                                ? "New webhook subscription"
                                : t.span(null, "Edit subscription ", t.strong(null, data.original.name)),
                    ),
                    () => {
                        if (data.isNew) {
                            return;
                        }
                        return data.original.active
                            ? t.span({ className: "label success" }, "active")
                            : t.span(
                                { className: "label danger" },
                                data.original.disabledReason ? "disabled" : "inactive",
                            );
                    },
                    t.div({ className: "flex-fill" }),
                    () => {
                        if (data.isNew) {
                            return;
                        }

                        return [
                            t.a(
                                {
                                    href: () => webhooksDeliveriesURL({ webhook: data.original.id }),
                                    className: "btn sm transparent secondary",
                                    onclick: () => app.modals.close(modal),
                                },
                                t.i({ className: "ri-history-line", ariaHidden: true }),
                                t.span({ className: "txt" }, "Deliveries"),
                            ),
                            t.button(
                                {
                                    type: "button",
                                    className: "btn sm circle transparent danger",
                                    ariaLabel: app.attrs.tooltip("Delete subscription", "left"),
                                    onclick: deleteWebhook,
                                },
                                t.i({ className: "ri-delete-bin-7-line", ariaHidden: true }),
                            ),
                        ];
                    },
                ),
                t.div(
                    { className: "col-12" },
                    t.nav(
                        { className: "tabs-header equal-width" },
                        tabButton(TAB_SETTINGS, "Settings", "ri-settings-3-line"),
                        tabButton(TAB_TEST, "Send test", "ri-send-plane-line"),
                        tabButton(TAB_RECEIVER, "Receiver", "ri-code-s-slash-line"),
                    ),
                ),
            ),
        ),
        t.div(
            { className: "modal-content" },
            () => {
                if (data.activeTab == TAB_TEST && !data.isNew) {
                    return testTab();
                }
                if (data.activeTab == TAB_RECEIVER && !data.isNew) {
                    return webhookReceiverTab();
                }
                return settingsTab();
            },
        ),
        t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn transparent m-r-auto",
                    disabled: () => data.isSaving,
                    onclick: () => app.modals.close(modal),
                },
                t.span({ className: "txt" }, "Close"),
            ),
            t.button(
                {
                    "type": "submit",
                    "html-form": uniqueId + "_form",
                    "hidden": () => data.activeTab != TAB_SETTINGS,
                    "className": () => `btn expanded-lg ${data.isSaving ? "loading" : ""}`,
                    "disabled": () => data.isSaving || (!data.isNew && !data.hasChanges),
                },
                t.span({ className: "txt" }, () => (data.isNew ? "Create subscription" : "Save changes")),
            ),
        ),
    );

    return modal;
}
