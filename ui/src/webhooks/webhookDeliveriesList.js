import { llmFormatDuration, llmResolveRange } from "@/llm/llmUtils";
import {
    WEBHOOK_DELIVERY_LIST_FIELDS,
    webhookResponseCodeLabel,
    webhooksBuildFilter,
    webhooksFindSubscription,
    webhookStatusLabel,
    webhookTopicLabel,
} from "./webhooksUtils";

const perPage = 40;

/**
 * The webhook deliveries (aka. logs) table.
 *
 * @param  {Object} pageData
 * @return {Element}
 */
export function webhookDeliveriesList(pageData) {
    const filters = pageData.filters;

    const data = store({
        isLoading: false,
        deliveries: [],
        lastLoadCount: 0,
        lastPage: 1,
        totalItems: null,
        get canLoadMore() {
            return data.lastLoadCount >= perPage;
        },
    });

    // used as a loose guard to prevent the new deliveries from shifting the older pages
    let loadRange;

    async function load(reset = false) {
        data.isLoading = true;

        try {
            let page;
            if (reset) {
                page = 1;
                loadRange = llmResolveRange(filters);
            } else {
                page = data.lastPage + 1;
            }

            const result = await app.pb.send("/api/webhooks/deliveries", {
                query: {
                    page,
                    perPage,
                    skipTotal: page > 1 ? 1 : 0,
                    sort: "-created,-id",
                    fields: WEBHOOK_DELIVERY_LIST_FIELDS,
                    filter: webhooksBuildFilter(filters, loadRange),
                },
                requestKey: "webhooks_deliveries_list",
            });

            if (result.page == 1) {
                data.deliveries = [];
                data.totalItems = result.totalItems;
            }

            data.lastPage = result.page;
            data.lastLoadCount = result.items.length;

            for (const item of result.items) {
                app.utils.pushOrReplaceObject(data.deliveries, item);
            }

            data.isLoading = false;
        } catch (err) {
            if (!err?.isAbort) {
                data.isLoading = false;
                app.checkApiError(err);
            }
        }
    }

    function openDelivery(delivery) {
        pageData.activeDeliveryId = delivery.id;
    }

    function th(icon, label, className = "") {
        return t.th(
            { className },
            t.div(
                { className: "inline-flex gap-5" },
                t.i({ className: icon, ariaHidden: true }),
                t.span({ className: "txt" }, label),
            ),
        );
    }

    const watchers = [];

    return t.div(
        {
            pbEvent: "webhookDeliveriesList",
            className: "page-table-wrapper llm-logs-wrapper webhook-deliveries-wrapper",
            onmount: (el) => {
                watchers.push(
                    watch(
                        () => [pageData.reset, JSON.stringify(filters)],
                        () => {
                            load(true);
                            el.scrollTop = 0;
                        },
                    ),
                );
            },
            onunmount: () => {
                watchers.forEach((w) => w?.unwatch());
            },
        },
        t.table(
            { className: "llm-logs-table webhook-deliveries-table" },
            t.thead(
                null,
                t.tr(
                    null,
                    th("ri-calendar-line", "Created", "col-field-type-date"),
                    th("ri-price-tag-3-line", "Topic"),
                    th("ri-webhook-line", "Subscription"),
                    th("ri-pulse-line", "Status"),
                    th("ri-reply-line", "Response"),
                    th("ri-loop-left-line", "Attempts", "txt-right"),
                    th("ri-timer-line", "Duration", "txt-right"),
                    t.th(
                        { className: "col-meta" },
                        t.span({ className: "loader sm", hidden: () => !data.isLoading }),
                    ),
                ),
            ),
            t.tbody(
                null,
                () => {
                    if (!data.deliveries.length) {
                        return t.tr(
                            null,
                            t.td({ colSpan: 99 }, () => {
                                if (data.isLoading) {
                                    return t.span({ className: "skeleton-loader" });
                                }

                                return t.div(
                                    { className: "sticky-content txt-center txt-hint" },
                                    t.div({ className: "txt-bold" }, "No deliveries found."),
                                    t.button(
                                        {
                                            hidden: () => !pageData.hasActiveFilters,
                                            type: "button",
                                            className: "btn secondary expanded-lg m-t-10",
                                            onclick: () => pageData.resetFilters(),
                                        },
                                        t.span({ className: "txt" }, "Reset filters"),
                                    ),
                                );
                            }),
                        );
                    }

                    return data.deliveries.map((d) => {
                        return t.tr(
                            {
                                rid: d.id + d.updated,
                                tabIndex: 0,
                                role: "button",
                                className: "handle",
                                onclick: () => openDelivery(d),
                                onkeypress: (e) => {
                                    if (e.key == "Enter" || e.key == " ") {
                                        e.preventDefault();
                                        openDelivery(d);
                                    }
                                },
                            },
                            t.td(
                                { className: "col-field-type-date" },
                                app.components.formattedDate({ value: d.created, short: true }),
                            ),
                            t.td(
                                null,
                                t.code({ className: "webhook-topic-code" }, d.topicName || webhookTopicLabel(d.topic)),
                                d.test ? t.span({ className: "label sm m-l-5" }, "test") : null,
                                d.redeliveryOf ? t.span({ className: "label sm info m-l-5" }, "redelivery") : null,
                            ),
                            t.td(
                                null,
                                t.div(
                                    { className: "txt-ellipsis" },
                                    () =>
                                        webhooksFindSubscription(d.webhook)?.name
                                        || t.span({ className: "txt-hint" }, d.webhook),
                                ),
                            ),
                            t.td(null, webhookStatusLabel(d.status, d.error)),
                            t.td(
                                null,
                                webhookResponseCodeLabel(d.responseStatus),
                                d.error && !d.responseStatus
                                    ? t.span(
                                        {
                                            className: "txt-hint txt-sm txt-ellipsis webhook-error-txt m-l-5",
                                            title: d.error,
                                        },
                                        d.error,
                                    )
                                    : null,
                            ),
                            t.td({ className: "txt-right txt-nowrap" }, d.attempts),
                            t.td(
                                { className: "txt-right txt-nowrap" },
                                d.durationMs ? llmFormatDuration(d.durationMs) : t.span({ className: "txt-hint" }, "-"),
                            ),
                            t.td(
                                { className: "col-meta" },
                                t.i({ className: "ri-arrow-right-line", ariaHidden: true }),
                            ),
                        );
                    });
                },
                t.tr(
                    { hidden: () => !data.canLoadMore },
                    t.td(
                        { colSpan: 99 },
                        t.button(
                            {
                                type: "button",
                                className: () =>
                                    `btn lg secondary load-more-btn ${data.isLoading ? "transparent loading" : ""}`,
                                disabled: () => data.isLoading,
                                onclick: () => load(),
                            },
                            t.span({ className: "txt" }, "Load older"),
                        ),
                    ),
                ),
            ),
        ),
        t.div(
            { className: "llm-logs-total txt-hint txt-sm" },
            "Total found: ",
            () => (data.totalItems == null ? "..." : data.totalItems),
        ),
    );
}
