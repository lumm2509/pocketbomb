import { LLM_RANGE_PRESETS } from "@/llm/llmUtils";
import { WEBHOOK_SEARCH_AUTOCOMPLETE, WEBHOOK_STATUSES, webhooksState, webhookTopicLabel } from "./webhooksUtils";

/**
 * The webhook deliveries filters bar (date range, subscription, topic, status, test and search).
 *
 * @param  {Object} pageData
 * @return {Element}
 */
export function webhookDeliveriesFilters(pageData) {
    const filters = pageData.filters;

    function topicOptions() {
        const result = [{ value: "", label: "All topics" }];
        const seen = new Set([""]);

        function add(value, label) {
            if (!seen.has(value)) {
                seen.add(value);
                result.push({ value, label });
            }
        }

        // the concrete topics of the existing collections and the registered custom topics
        for (const c of webhooksState.topics?.collections || []) {
            for (const item of c.topics || []) {
                if (!item.topic.endsWith(".*")) {
                    add(item.topic, item.label);
                }
            }
        }
        for (const item of webhooksState.topics?.custom || []) {
            if (!item.topic.endsWith(".*")) {
                add(item.topic, item.label);
            }
        }
        if (filters.topic) {
            add(filters.topic, webhookTopicLabel(filters.topic));
        }

        return result;
    }

    function subscriptionOptions() {
        const result = [{ value: "", label: "All subscriptions" }];
        for (const s of webhooksState.subscriptions) {
            result.push({ value: s.id, label: s.name + (s.active ? "" : " (inactive)") });
        }
        if (filters.webhook && !webhooksState.subscriptions.find((s) => s.id == filters.webhook)) {
            result.push({ value: filters.webhook, label: filters.webhook });
        }
        return result;
    }

    function selectField(key, optionsFunc, className = "") {
        return t.div(
            { className: "field llm-filter-field " + className },
            app.components.select({
                id: "webhooks_filter_" + key,
                className: "sm",
                required: true,
                searchThreshold: 8,
                options: optionsFunc,
                value: () => filters[key] || "",
                onchange: (opts) => {
                    filters[key] = opts?.[0]?.value || "";
                },
            }),
        );
    }

    function testToggleBtn(value, label) {
        return t.button(
            {
                type: "button",
                className: () => `btn sm ${filters.test == value ? "" : "transparent secondary"}`,
                onclick: () => filters.test = value,
            },
            t.span({ className: "txt" }, label),
        );
    }

    return t.div(
        { pbEvent: "webhookDeliveriesFilters", className: "llm-filters webhook-filters" },
        t.div(
            { className: "llm-filters-row" },
            t.div(
                { className: "field llm-filter-field llm-range-field" },
                app.components.select({
                    id: "webhooks_filter_range",
                    required: true,
                    options: LLM_RANGE_PRESETS.map((p) => ({
                        value: p.value,
                        label: p.label,
                        selected: () =>
                            t.span(
                                { className: "inline-flex gap-5" },
                                t.i({ className: "ri-calendar-line txt-hint", ariaHidden: true }),
                                t.span({ className: "txt" }, p.label),
                            ),
                    })),
                    value: () => filters.range,
                    onchange: (opts) => {
                        const val = opts?.[0]?.value || "24h";
                        if (val == "custom" && !filters.from) {
                            const now = new Date();
                            filters.to = app.utils.toDatetimeLocalInputValue(now);
                            filters.from = app.utils.toDatetimeLocalInputValue(new Date(now.getTime() - 86400000));
                        }
                        filters.range = val;
                    },
                }),
            ),
            () => {
                if (filters.range != "custom") {
                    return;
                }

                return t.div(
                    { className: "llm-custom-range" },
                    t.div(
                        { className: "field llm-filter-field" },
                        t.input({
                            type: "datetime-local",
                            ariaLabel: "From",
                            title: "From",
                            value: () => filters.from || "",
                            onchange: (e) => filters.from = e.target.value,
                        }),
                    ),
                    t.span({ className: "txt-hint" }, "-"),
                    t.div(
                        { className: "field llm-filter-field" },
                        t.input({
                            type: "datetime-local",
                            ariaLabel: "To",
                            title: "To",
                            value: () => filters.to || "",
                            onchange: (e) => filters.to = e.target.value,
                        }),
                    ),
                );
            },
            selectField("webhook", subscriptionOptions, "webhook-filter-subscription"),
            selectField("topic", topicOptions),
            selectField("status", () => {
                return [{ value: "", label: "Any status" }].concat(
                    WEBHOOK_STATUSES.map((s) => ({ value: s.value, label: s.label })),
                );
            }),
            t.div(
                { className: "llm-toggle", role: "group", ariaLabel: "Test deliveries" },
                testToggleBtn("", "All"),
                testToggleBtn("exclude", "Live"),
                testToggleBtn("only", "Test"),
            ),
            t.button(
                {
                    type: "button",
                    hidden: () => !pageData.hasActiveFilters,
                    className: "btn sm transparent secondary",
                    onclick: () => pageData.resetFilters(),
                },
                t.span({ className: "txt" }, "Reset filters"),
            ),
        ),
        app.components.searchbar({
            className: "llm-searchbar",
            historyKey: "pbWebhookDeliveriesSearchHistory",
            placeholder: "Search term or filter like `status = \"failed\" && responseStatus >= 500`",
            value: () => filters.search || "",
            onsubmit: (val) => filters.search = val,
            autocomplete: WEBHOOK_SEARCH_AUTOCOMPLETE,
        }),
    );
}
