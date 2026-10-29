import {
    WEBHOOK_AUTH_OPS,
    WEBHOOK_OPS,
    webhookNormalizeTopic,
    webhookSplitTopic,
    webhookTopicKind,
    webhookTopicLabel,
} from "./webhooksUtils";

const OP_LABELS = {
    "*": "All",
    create: "create",
    update: "update",
    delete: "delete",
    auth: "auth",
    verified: "verified",
};

const OP_DESCRIPTIONS = {
    "*": "All operations (incl. future ones)",
    create: "Record created",
    update: "Record updated (incl. the changed fields)",
    delete: "Record deleted",
    auth: "Record authenticated (auth collections only)",
    verified: "Record email verified (auth collections only)",
};

const customTopicRegex = /^[\w\-]+\.(?:[\w\-]+|\*)$/;

/**
 * Webhook topics picker grouped by collection with per-operation checkboxes,
 * wildcards and custom topics (incl. free-text unregistered ones).
 *
 * @example
 * ```js
 * webhookTopicPicker({
 *     id: "my_picker",
 *     topics: () => data.topicsList, // the /api/webhooks/topics response
 *     value: () => data.topics,       // stored topics format
 *     onchange: (list) => data.topics = list,
 * })
 * ```
 *
 * @param  {Object} propsArg
 * @return {Element}
 */
export function webhookTopicPicker(propsArg = {}) {
    const props = store({
        id: "",
        name: "topics",
        topics: null,
        value: [],
        onchange: (list) => {},
    });

    const watchers = app.utils.extendStore(props, propsArg);

    const local = store({
        search: "",
        showSystem: false,
        customInput: "",
        customError: "",
        get selected() {
            return props.value || [];
        },
        // note: only the topics of the collections that the actor could view are offered
        // (the server rejects the others; the system collections topics are Owner only)
        get collections() {
            const all = (props.topics?.collections || []).filter((c) =>
                canViewCollectionTopics(c) || local.selected.some((tp) => webhookSplitTopic(tp)[0] == c.id)
            );
            const search = local.search.trim().toLowerCase();

            return all.filter((c) => {
                if (search) {
                    return c.name.toLowerCase().includes(search) || c.id.toLowerCase().includes(search);
                }

                // always show the collections with selected topics
                if (local.selected.some((tp) => webhookSplitTopic(tp)[0] == c.id)) {
                    return true;
                }

                return local.showSystem || !c.system;
            });
        },
        get hiddenSystemCount() {
            if (local.showSystem || local.search) {
                return 0;
            }
            return (props.topics?.collections || []).filter((c) => c.system && canViewCollectionTopics(c)).length
                - local.collections.filter((c) => c.system).length;
        },
        // the selected custom topics that are not registered
        get unregisteredCustom() {
            const registered = (props.topics?.custom || []).map((c) => c.topic);
            return local.selected.filter((tp) => webhookTopicKind(tp) == "custom" && !registered.includes(tp));
        },
    });

    function canViewCollectionTopics(collection) {
        if (app.perms.isOwner()) {
            return true;
        }

        return !collection.system && app.perms.canCollection(collection, "view");
    }

    // the wildcard topics require the view permission of all collections
    function canUseWildcards() {
        return app.perms.isOwner()
            || !!app.store.permissions?.permissions?.collections?.["*"]?.includes("view");
    }

    function isSelected(topic) {
        return local.selected.includes(topic);
    }

    function toggle(topic, checked) {
        let list = local.selected.filter((tp) => tp != topic);
        if (checked) {
            list.push(topic);

            // "{collection}.*" supersedes the individual collection ops
            const [ns, op] = webhookSplitTopic(topic);
            if (op == "*") {
                list = list.filter((tp) => tp == topic || webhookSplitTopic(tp)[0] != ns);
            }
        }

        props.onchange?.(list);

        // the errors indexes are no longer valid
        app.utils.deleteByPath(app.store.errors, props.name);
    }

    // returns the wildcard topic (if any) that covers the specified collection op
    function coveredBy(collection, op) {
        if (op != "*" && isSelected(collection.id + ".*")) {
            return collection.name + ".*";
        }

        if (collection.name.startsWith("_")) {
            return ""; // wildcards exclude the system "_*" collections
        }

        if (isSelected("*.*")) {
            return "*.*";
        }

        if (op != "*" && isSelected("*." + op)) {
            return "*." + op;
        }

        return "";
    }

    function addCustom() {
        const raw = local.customInput.trim();
        if (!raw) {
            return;
        }

        if (!customTopicRegex.test(raw)) {
            local.customError = "Invalid topic format - expected {namespace}.{name} (letters, digits, _ and -).";
            return;
        }

        const topic = webhookNormalizeTopic(raw);
        if (!isSelected(topic)) {
            toggle(topic, true);
        }

        local.customInput = "";
        local.customError = "";
    }

    function opCell(collection, op) {
        if (WEBHOOK_AUTH_OPS.includes(op) && collection.type != "auth") {
            return t.td({ className: "col-op txt-center txt-hint" }, "-");
        }

        const topic = collection.id + "." + op;
        const id = props.id + "_" + topic.replaceAll(/[^\w]/g, "_");

        return t.td(
            { className: "col-op" },
            t.div(
                {
                    className: () => `field webhook-op-check ${coveredBy(collection, op) ? "implied" : ""}`,
                    ariaDescription: app.attrs.tooltip(() => {
                        const by = coveredBy(collection, op);
                        return by ? `Covered by ${by}` : `${collection.name}.${op}`;
                    }),
                },
                t.input({
                    type: "checkbox",
                    id: id,
                    className: "sm",
                    checked: () => isSelected(topic) || !!coveredBy(collection, op),
                    disabled: () => !isSelected(topic) && !!coveredBy(collection, op),
                    onchange: (e) => toggle(topic, e.target.checked),
                }),
                t.label({ htmlFor: id, ariaLabel: `${collection.name}.${op}` }),
            ),
        );
    }

    function topicCheckbox(item, extraClass = "") {
        const id = props.id + "_t_" + item.topic.replaceAll(/[^\w]/g, "_");

        return t.div(
            { className: "field webhook-topic-check " + extraClass },
            t.input({
                type: "checkbox",
                id,
                className: "sm",
                checked: () => isSelected(item.topic),
                onchange: (e) => toggle(item.topic, e.target.checked),
            }),
            t.label(
                { htmlFor: id },
                t.code(null, item.label || item.topic),
                item.description ? t.small({ className: "txt-hint" }, item.description) : null,
            ),
        );
    }

    function selectedSummary() {
        return t.div(
            { className: "webhook-selected-topics" },
            () => {
                if (!local.selected.length) {
                    return t.span({ className: "txt-hint txt-sm" }, "No topics selected yet.");
                }

                return local.selected.map((topic) =>
                    t.span(
                        { className: `label webhook-topic-chip kind-${webhookTopicKind(topic)}` },
                        t.span({ className: "txt" }, webhookTopicLabel(topic)),
                        t.button(
                            {
                                type: "button",
                                className: "webhook-chip-remove",
                                ariaLabel: "Remove " + webhookTopicLabel(topic),
                                onclick: () => toggle(topic, false),
                            },
                            t.i({ className: "ri-close-line", ariaHidden: true }),
                        ),
                    )
                );
            },
        );
    }

    function topicsErrors() {
        const errs = app.utils.getByPath(app.store.errors, props.name);
        if (app.utils.isEmpty(errs)) {
            return;
        }

        if (errs.message) {
            return t.div({ className: "field-help error" }, errs.message);
        }

        const lines = [];
        for (const key in errs) {
            const topic = local.selected[key << 0];
            lines.push(
                t.div(null, t.code(null, topic ? webhookTopicLabel(topic) : "#" + key), ": ", errs[key]?.message),
            );
        }

        return t.div({ className: "field-help error webhook-topics-errors" }, lines);
    }

    return t.div(
        {
            pbEvent: "webhookTopicPicker",
            className: "webhook-topic-picker",
            onunmount: () => {
                watchers.forEach((w) => w?.unwatch());
            },
        },
        selectedSummary(),
        () => topicsErrors(),
        () => {
            if (!props.topics) {
                return t.div({ className: "block txt-center p-sm" }, t.span({ className: "loader" }));
            }

            return [
                // collections
                t.div(
                    { className: "webhook-picker-section" },
                    t.div(
                        { className: "webhook-picker-toolbar" },
                        t.strong({ className: "txt-sm" }, "Collections"),
                        t.div(
                            { className: "field webhook-picker-search" },
                            t.input({
                                type: "search",
                                placeholder: "Search collections...",
                                ariaLabel: "Search collections",
                                value: () => local.search,
                                oninput: (e) => local.search = e.target.value,
                            }),
                        ),
                        t.div(
                            { className: "field" },
                            t.input({
                                type: "checkbox",
                                id: props.id + "_show_system",
                                className: "switch sm",
                                checked: () => local.showSystem,
                                onchange: (e) => local.showSystem = e.target.checked,
                            }),
                            t.label(
                                { htmlFor: props.id + "_show_system" },
                                "Show system",
                                () => (local.hiddenSystemCount > 0 ? ` (${local.hiddenSystemCount})` : ""),
                            ),
                        ),
                    ),
                    t.div(
                        { className: "table-wrapper webhook-topics-table-wrapper" },
                        t.table(
                            { className: "webhook-topics-table" },
                            t.thead(
                                null,
                                t.tr(
                                    null,
                                    t.th(null, "Collection"),
                                    WEBHOOK_OPS.map((op) =>
                                        t.th(
                                            {
                                                className: "col-op",
                                                ariaDescription: app.attrs.tooltip(OP_DESCRIPTIONS[op]),
                                            },
                                            OP_LABELS[op],
                                        )
                                    ),
                                ),
                            ),
                            t.tbody(null, () => {
                                if (!local.collections.length) {
                                    return t.tr(
                                        null,
                                        t.td(
                                            { colSpan: 99, className: "txt-hint txt-center" },
                                            "No collections found.",
                                        ),
                                    );
                                }

                                return local.collections.map((c) =>
                                    t.tr(
                                        {
                                            className: () => (local.selected.some((tp) => tp.startsWith(c.id + "."))
                                                ? "has-selected"
                                                : ""),
                                        },
                                        t.td(
                                            { className: "col-collection" },
                                            t.span({ className: "txt" }, c.name),
                                            c.type == "auth" ? t.span({ className: "label sm" }, "auth") : null,
                                            c.system ? t.span({ className: "label sm" }, "system") : null,
                                        ),
                                        WEBHOOK_OPS.map((op) => opCell(c, op)),
                                    )
                                );
                            }),
                        ),
                    ),
                ),
                // wildcards
                t.div(
                    {
                        className: "webhook-picker-section webhook-picker-wildcards",
                        hidden: () => !canUseWildcards() && !local.selected.some((tp) => tp.startsWith("*.")),
                    },
                    t.div(
                        { className: "webhook-picker-toolbar" },
                        t.strong({ className: "txt-sm" }, "Wildcards"),
                        t.small({ className: "txt-hint" }, "All non-system collections (excluding the \"_*\" ones)"),
                    ),
                    t.div(
                        { className: "webhook-topic-checks" },
                        (props.topics.wildcards || []).filter((w) => canUseWildcards() || isSelected(w.topic)).map((
                            w,
                        ) => topicCheckbox({
                            topic: w.topic,
                            label: w.label,
                            description: OP_DESCRIPTIONS[webhookSplitTopic(w.topic)[1]],
                        })),
                    ),
                ),
                // custom
                t.div(
                    { className: "webhook-picker-section" },
                    t.div(
                        { className: "webhook-picker-toolbar" },
                        t.strong({ className: "txt-sm" }, "Custom topics"),
                        t.small(
                            { className: "txt-hint" },
                            "Triggered from code via ",
                            t.code(null, "app.Webhooks().Trigger(ctx, topic, payload)"),
                        ),
                    ),
                    () => {
                        const custom = props.topics.custom || [];
                        if (!custom.length) {
                            return t.div({ className: "txt-hint txt-sm" }, "No registered custom topics.");
                        }
                        return t.div({ className: "webhook-topic-checks" }, custom.map((c) => topicCheckbox(c)));
                    },
                    () => {
                        if (!local.unregisteredCustom.length) {
                            return;
                        }
                        return t.div(
                            { className: "webhook-topic-checks" },
                            local.unregisteredCustom.map((topic) =>
                                topicCheckbox({ topic, label: topic, description: "unregistered" }, "unregistered")
                            ),
                        );
                    },
                    t.div(
                        { className: "fields webhook-custom-topic-input" },
                        t.div(
                            { className: () => `field ${local.customError ? "error" : ""}` },
                            t.input({
                                type: "text",
                                className: "no-error",
                                placeholder: "Other topic, e.g. orders.paid or billing.*",
                                ariaLabel: "Custom topic",
                                spellcheck: false,
                                value: () => local.customInput,
                                oninput: (e) => {
                                    local.customInput = e.target.value;
                                    local.customError = "";
                                },
                                onkeydown: (e) => {
                                    if (e.key == "Enter") {
                                        e.preventDefault();
                                        addCustom();
                                    }
                                },
                            }),
                        ),
                        t.div(
                            { className: "field addon" },
                            t.button(
                                {
                                    type: "button",
                                    className: "btn sm secondary",
                                    disabled: () => !local.customInput.trim(),
                                    onclick: addCustom,
                                },
                                t.i({ className: "ri-add-line", ariaHidden: true }),
                                t.span({ className: "txt" }, "Add"),
                            ),
                        ),
                    ),
                    () => {
                        if (local.customError) {
                            return t.div({ className: "field-help error" }, local.customError);
                        }
                    },
                ),
            ];
        },
    );
}
