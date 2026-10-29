import { LLM_RANGE_PRESETS } from "@/llm/llmUtils";
import { webhookDeliveriesFilters } from "./webhookDeliveriesFilters";
import { webhookDeliveriesList } from "./webhookDeliveriesList";
import { webhookDeliveriesStats } from "./webhookDeliveriesStats";
import { openWebhookDeliveryModal } from "./webhookDeliveryModal";
import { webhookSubscriptionsList } from "./webhookSubscriptionsList";
import { webhooksLoadSubscriptions, webhooksLoadTopics, webhooksState } from "./webhooksUtils";
import { openWebhookUpsertModal } from "./webhookUpsertModal";

const TAB_SUBSCRIPTIONS = "subscriptions";
const TAB_DELIVERIES = "deliveries";

const FILTER_KEYS = ["range", "from", "to", "webhook", "topic", "status", "test", "search", "groupBy"];

const DEFAULT_FILTERS = {
    range: "24h",
    from: "",
    to: "",
    webhook: "",
    topic: "",
    status: "",
    test: "",
    search: "",
    groupBy: "status",
};

export function pageWebhooks(route) {
    app.store.title = "Webhooks";

    const query = (key) => route.query[key]?.[0] || "";

    const initialFilters = Object.assign({}, DEFAULT_FILTERS);
    for (const key of FILTER_KEYS) {
        if (route.query[key]) {
            initialFilters[key] = query(key);
        }
    }
    if (!LLM_RANGE_PRESETS.find((p) => p.value == initialFilters.range)) {
        initialFilters.range = DEFAULT_FILTERS.range;
    }

    const pageData = store({
        tab: query("tab") == TAB_DELIVERIES ? TAB_DELIVERIES : TAB_SUBSCRIPTIONS,
        reset: 0,
        filters: initialFilters,
        subscriptionsSearch: "",
        activeDeliveryId: query("deliveryId"),
        isTruncating: false,
        get hasActiveFilters() {
            const f = pageData.filters;
            return !!(f.webhook || f.topic || f.status || f.test || f.search || f.range != DEFAULT_FILTERS.range);
        },
        resetFilters() {
            const groupBy = pageData.filters.groupBy;
            // update in place to preserve the filters store references
            Object.assign(pageData.filters, DEFAULT_FILTERS, { groupBy });
        },
    });

    webhooksLoadTopics(true);
    webhooksLoadSubscriptions();

    function refresh() {
        pageData.reset = Date.now();
        webhooksLoadSubscriptions();
        webhooksLoadTopics(true);
    }

    async function truncateDeliveries() {
        pageData.isTruncating = true;

        try {
            await app.pb.send("/api/webhooks/deliveries", { method: "DELETE" });
            app.toasts.success("Successfully cleared the completed webhook deliveries.");
            pageData.reset = Date.now();
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        pageData.isTruncating = false;
    }

    function tabBtn(tab, icon, label, countFunc = null) {
        return t.button(
            {
                type: "button",
                className: () => `tab-item ${pageData.tab == tab ? "active" : ""}`,
                onclick: () => pageData.tab = tab,
            },
            t.i({ className: icon, ariaHidden: true }),
            t.span({ className: "txt" }, label),
            countFunc
                ? t.span({ className: "label sm webhook-tab-count", hidden: () => !countFunc() }, countFunc)
                : null,
        );
    }

    const watchers = [];

    return t.div(
        {
            pbEvent: "pageWebhooks",
            className: "page page-llm page-webhooks",
            onmount: () => {
                watchers.push(
                    // sync the url query params
                    watch(() => {
                        const params = { tab: pageData.tab == TAB_SUBSCRIPTIONS ? "" : pageData.tab };
                        for (const key of FILTER_KEYS) {
                            const val = pageData.filters[key];
                            params[key] = pageData.tab != TAB_DELIVERIES || val == DEFAULT_FILTERS[key] ? "" : val;
                        }
                        if (pageData.filters.range != "custom") {
                            params.from = "";
                            params.to = "";
                        }
                        app.utils.replaceHashQueryParams(params);
                    }),
                    watch(
                        () => pageData.activeDeliveryId,
                        (id) => {
                            app.utils.replaceHashQueryParams({ deliveryId: id || "" });

                            if (id) {
                                // force close any previous modal
                                app.modals.close(null, true);

                                openWebhookDeliveryModal(id, {
                                    onredeliver: () => {
                                        pageData.reset = Date.now();
                                    },
                                    onafterclose: () => {
                                        pageData.activeDeliveryId = "";
                                    },
                                });
                            }
                        },
                    ),
                );
            },
            onunmount: () => {
                watchers.forEach((w) => w?.unwatch());
            },
        },
        t.div(
            { className: "page-content full-height" },
            t.header(
                { className: "page-header" },
                t.nav({ className: "breadcrumbs" }, t.div(null, "Webhooks")),
                t.div(
                    { className: "inline-flex gap-sm" },
                    t.a(
                        {
                            href: "#/settings/webhooks",
                            className: "btn circle transparent secondary tooltip-right",
                            ariaLabel: app.attrs.tooltip("Webhooks settings"),
                        },
                        t.i({ className: "ri-settings-3-line", ariaHidden: true }),
                    ),
                    app.components.refreshButton({ onclick: refresh }),
                    t.button(
                        {
                            type: "button",
                            hidden: () => pageData.tab != TAB_DELIVERIES,
                            className: () =>
                                `btn circle transparent secondary ${pageData.isTruncating ? "loading" : ""}`,
                            disabled: () => pageData.isTruncating,
                            ariaLabel: app.attrs.tooltip("Clear completed deliveries"),
                            onclick: () => {
                                app.modals.confirm(
                                    t.div(
                                        null,
                                        t.p(null, "Do you really want to delete all completed webhook deliveries?"),
                                        t.p(
                                            { className: "txt-hint txt-sm" },
                                            "The successful, failed and disabled deliveries logs are deleted. The pending and retrying deliveries are kept since they are part of the delivery queue.",
                                        ),
                                    ),
                                    () => truncateDeliveries(),
                                    null,
                                    { yesButton: "Yes, clear" },
                                );
                            },
                        },
                        t.i({ className: "ri-delete-bin-7-line", ariaHidden: true }),
                    ),
                ),
                t.nav(
                    { className: "tabs-header llm-tabs m-l-auto" },
                    tabBtn(
                        TAB_SUBSCRIPTIONS,
                        "ri-webhook-line",
                        "Subscriptions",
                        () => webhooksState.subscriptions.length,
                    ),
                    tabBtn(TAB_DELIVERIES, "ri-history-line", "Deliveries"),
                ),
            ),
            () => {
                if (app.store.settings?.webhooks && !app.store.settings.webhooks.enabled) {
                    return t.div(
                        { className: "alert warning m-b-sm" },
                        t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                        t.div(
                            { className: "content" },
                            "Webhooks are globally disabled - no new events are queued and the queued deliveries are paused. ",
                            t.a({ href: "#/settings/webhooks", className: "txt-bold" }, "Enable them in the settings"),
                            ".",
                        ),
                    );
                }
            },
            () => {
                if (pageData.tab == TAB_DELIVERIES) {
                    return [
                        webhookDeliveriesFilters(pageData),
                        webhookDeliveriesStats(pageData),
                        webhookDeliveriesList(pageData),
                    ];
                }

                return [
                    t.div(
                        { className: "flex gap-10 m-b-sm webhook-subscriptions-toolbar" },
                        t.div(
                            { className: "field webhook-subscriptions-search" },
                            t.input({
                                type: "search",
                                placeholder: "Search by name, endpoint, topic or app...",
                                ariaLabel: "Search subscriptions",
                                value: () => pageData.subscriptionsSearch,
                                oninput: (e) => pageData.subscriptionsSearch = e.target.value,
                            }),
                        ),
                        t.div({ className: "flex-fill" }),
                        t.button(
                            { type: "button", className: "btn sm", onclick: () => openWebhookUpsertModal() },
                            t.i({ className: "ri-add-line", ariaHidden: true }),
                            t.span({ className: "txt" }, "New subscription"),
                        ),
                    ),
                    webhookSubscriptionsList(pageData),
                ];
            },
            t.footer({ className: "page-footer" }, app.components.credits()),
        ),
    );
}
