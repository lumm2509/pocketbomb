import { webhooksDeliveriesURL, webhooksState, webhookTopicChips } from "./webhooksUtils";
import { openWebhookUpsertModal } from "./webhookUpsertModal";

/**
 * Webhook subscriptions status label element.
 *
 * @param  {Object} webhook
 * @return {Element}
 */
export function webhookActiveLabel(webhook) {
    if (webhook.active) {
        return t.span({ className: "label success webhook-active-label" }, "active");
    }

    if (webhook.disabledReason) {
        return t.span(
            {
                className: "label danger webhook-active-label",
                ariaDescription: app.attrs.tooltip(webhook.disabledReason),
            },
            t.i({ className: "ri-forbid-line", ariaHidden: true }),
            "disabled",
        );
    }

    return t.span({ className: "label webhook-active-label" }, "inactive");
}

/**
 * The webhook subscriptions table.
 *
 * @param  {Object} pageData
 * @return {Element}
 */
export function webhookSubscriptionsList(pageData) {
    const local = store({
        get filtered() {
            const search = (pageData.subscriptionsSearch || "").trim().toLowerCase();
            if (!search) {
                return webhooksState.subscriptions;
            }

            return webhooksState.subscriptions.filter((s) => {
                return (s.name || "").toLowerCase().includes(search)
                    || (s.uri || "").toLowerCase().includes(search)
                    || (s.expand?.client?.name || "").toLowerCase().includes(search)
                    || (s.topicNames || []).some((t) => t.toLowerCase().includes(search));
            });
        },
    });

    function open(webhook) {
        openWebhookUpsertModal(webhook);
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

    function dateCell(value) {
        if (!value) {
            return t.span({ className: "txt-hint" }, "-");
        }
        return app.components.formattedDate({ value, short: true });
    }

    return t.div(
        { pbEvent: "webhookSubscriptionsList", className: "page-table-wrapper webhook-subscriptions-wrapper" },
        t.table(
            { className: "webhook-subscriptions-table" },
            t.thead(
                null,
                t.tr(
                    null,
                    th("ri-webhook-line", "Subscription"),
                    th("ri-price-tag-3-line", "Topics"),
                    th("ri-pulse-line", "Status"),
                    th("ri-apps-2-line", "OAuth2 client"),
                    th("ri-checkbox-circle-line", "Last success", "col-field-type-date"),
                    th("ri-close-circle-line", "Last failure", "col-field-type-date"),
                    th("ri-error-warning-line", "Failures", "txt-right"),
                    t.th(
                        { className: "col-meta" },
                        t.span({ className: "loader sm", hidden: () => !webhooksState.isLoadingSubscriptions }),
                    ),
                ),
            ),
            t.tbody(null, () => {
                if (!local.filtered.length) {
                    return t.tr(
                        null,
                        t.td({ colSpan: 99 }, () => {
                            if (webhooksState.isLoadingSubscriptions && !webhooksState.subscriptionsLoaded) {
                                return t.span({ className: "skeleton-loader" });
                            }

                            return t.div(
                                { className: "sticky-content txt-center txt-hint p-sm" },
                                t.div(
                                    { className: "txt-bold" },
                                    webhooksState.subscriptions.length
                                        ? "No subscriptions match the search."
                                        : "No webhook subscriptions yet.",
                                ),
                                webhooksState.subscriptions.length
                                    ? null
                                    : t.div(
                                        null,
                                        t.p(
                                            null,
                                            "Subscriptions send signed HTTP POST requests to your endpoints when records change or custom events are triggered.",
                                        ),
                                        t.button(
                                            {
                                                type: "button",
                                                className: "btn secondary expanded-lg m-t-10",
                                                onclick: () => openWebhookUpsertModal(),
                                            },
                                            t.i({ className: "ri-add-line", ariaHidden: true }),
                                            t.span({ className: "txt" }, "New subscription"),
                                        ),
                                    ),
                            );
                        }),
                    );
                }

                return local.filtered.map((webhook) =>
                    t.tr(
                        {
                            rid: webhook.id + webhook.updated,
                            tabIndex: 0,
                            role: "button",
                            className: () => `handle ${webhook.active ? "" : "faded-row"}`,
                            onclick: () => open(webhook),
                            onkeypress: (e) => {
                                if (e.key == "Enter" || e.key == " ") {
                                    e.preventDefault();
                                    open(webhook);
                                }
                            },
                        },
                        t.td(
                            { className: "col-webhook-name" },
                            t.div({ className: "txt-bold txt-ellipsis" }, webhook.name),
                            t.div(
                                { className: "txt-hint txt-sm txt-ellipsis txt-code", title: webhook.uri },
                                webhook.uri,
                            ),
                        ),
                        t.td(
                            { className: "col-webhook-topics" },
                            webhookTopicChips(webhook.topics, webhook.topicNames, 4),
                            webhook.filter
                                ? t.span(
                                    {
                                        className: "label sm webhook-filter-badge",
                                        ariaDescription: app.attrs.tooltip(webhook.filter),
                                    },
                                    t.i({ className: "ri-filter-3-line", ariaHidden: true }),
                                    "filter",
                                )
                                : null,
                        ),
                        t.td(null, webhookActiveLabel(webhook)),
                        t.td(
                            null,
                            webhook.expand?.client
                                ? t.span(
                                    { className: "inline-flex gap-5" },
                                    t.i({ className: "ri-apps-2-line txt-hint", ariaHidden: true }),
                                    t.span({ className: "txt" }, webhook.expand.client.name),
                                )
                                : t.span({ className: "txt-hint" }, "-"),
                        ),
                        t.td({ className: "col-field-type-date" }, dateCell(webhook.lastSuccessAt)),
                        t.td({ className: "col-field-type-date" }, dateCell(webhook.lastFailureAt)),
                        t.td(
                            { className: "txt-right" },
                            webhook.failureCount
                                ? t.span({ className: "label sm danger" }, webhook.failureCount)
                                : t.span({ className: "txt-hint" }, "0"),
                        ),
                        t.td(
                            { className: "col-meta" },
                            t.a(
                                {
                                    href: webhooksDeliveriesURL({ webhook: webhook.id }),
                                    className: "btn sm circle transparent secondary",
                                    ariaLabel: app.attrs.tooltip("View deliveries", "left"),
                                    onclick: (e) => e.stopPropagation(),
                                },
                                t.i({ className: "ri-history-line", ariaHidden: true }),
                            ),
                        ),
                    )
                );
            }),
        ),
    );
}
