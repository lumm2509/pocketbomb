import { llmFormatDuration } from "@/llm/llmUtils";
import {
    WEBHOOK_DELIVERY_LIST_FIELDS,
    webhookPrettyBody,
    webhookRedeliverBlockReason,
    webhookResponseCodeLabel,
    webhooksFindSubscription,
    webhooksLoadSubscriptions,
    webhooksState,
    webhookStatus,
    webhookStatusLabel,
    webhookTopicLabel,
} from "./webhooksUtils";

const TAB_OVERVIEW = "overview";
const TAB_REQUEST = "request";
const TAB_RESPONSE = "response";

window.app = window.app || {};
window.app.modals = window.app.modals || {};

/**
 * Opens the webhook delivery details modal.
 *
 * @param {string} deliveryId
 * @param {Object} [settings]
 * @param {function} [settings.onredeliver]  function(newDelivery) {}
 * @param {function} [settings.onafterclose] function() {}
 */
export function openWebhookDeliveryModal(deliveryId, settings = {}) {
    const modal = webhookDeliveryModal(deliveryId, settings);

    document.body.appendChild(modal);

    app.modals.open(modal);
}

window.app.modals.openWebhookDelivery = openWebhookDeliveryModal;

function parseDate(str) {
    if (!str) {
        return null;
    }
    const d = new Date(str.replace(" ", "T"));
    return isNaN(d.getTime()) ? null : d;
}

function relativeTime(str) {
    const d = parseDate(str);
    if (!d) {
        return "";
    }

    const diff = Math.round((d.getTime() - Date.now()) / 1000);
    const abs = Math.abs(diff);
    if (abs < 3) {
        return "just now";
    }

    let value;
    if (abs < 60) {
        value = abs + "s";
    } else if (abs < 3600) {
        value = Math.round(abs / 60) + "m";
    } else if (abs < 86400) {
        value = +(abs / 3600).toFixed(1) + "h";
    } else {
        value = +(abs / 86400).toFixed(1) + "d";
    }

    return diff >= 0 ? "in " + value : value + " ago";
}

function deliveryFilename(d) {
    return "webhook_delivery_" + (d?.id || "") + ".json";
}

function webhookDeliveryModal(initialId, settings) {
    let modal;

    const data = store({
        deliveryId: initialId,
        isLoading: false,
        isRedelivering: false,
        delivery: null,
        related: [],
        activeTab: TAB_OVERVIEW,
        get subscription() {
            return webhooksFindSubscription(data.delivery?.webhook);
        },
        get maxAttempts() {
            return app.store.settings?.webhooks?.maxAttempts || 0;
        },
        get redeliverBlockReason() {
            return webhookRedeliverBlockReason(data.delivery);
        },
    });

    if (!webhooksState.subscriptionsLoaded) {
        webhooksLoadSubscriptions();
    }

    let pollTimeoutId;
    let isClosed = false;

    // auto refresh the queued (pending or retrying) deliveries
    function schedulePoll() {
        clearTimeout(pollTimeoutId);
        if (isClosed || !["pending", "retrying"].includes(data.delivery?.status)) {
            return;
        }
        pollTimeoutId = setTimeout(() => load(), 3000);
    }

    async function load(id = data.deliveryId) {
        clearTimeout(pollTimeoutId);

        data.isLoading = true;
        data.deliveryId = id;

        try {
            data.delivery = await app.pb.send("/api/webhooks/deliveries/" + encodeURIComponent(id), {
                requestKey: "webhook_delivery_preview",
            });

            data.isLoading = false;

            loadRelated();
            schedulePoll();
        } catch (err) {
            if (!err?.isAbort) {
                data.isLoading = false;
                app.checkApiError(err);
            }
        }
    }

    async function loadRelated() {
        if (!data.delivery?.eventId) {
            data.related = [];
            return;
        }

        try {
            const result = await app.pb.send("/api/webhooks/deliveries", {
                query: {
                    page: 1,
                    perPage: 50,
                    skipTotal: 1,
                    sort: "created,id",
                    fields: WEBHOOK_DELIVERY_LIST_FIELDS,
                    filter: app.pb.filter("eventId = {:eventId} && webhook = {:webhook}", {
                        eventId: data.delivery.eventId,
                        webhook: data.delivery.webhook,
                    }),
                },
                requestKey: "webhook_delivery_related",
            });
            data.related = result.items || [];
        } catch (err) {
            if (!err?.isAbort) {
                console.warn("[webhooks] failed to load the related deliveries:", err);
            }
        }
    }

    async function redeliver() {
        if (data.isRedelivering || data.redeliverBlockReason) {
            return;
        }

        data.isRedelivering = true;

        try {
            const result = await app.pb.send(
                `/api/webhooks/deliveries/${encodeURIComponent(data.delivery.id)}/redeliver`,
                { method: "POST", requestKey: null },
            );

            const status = webhookStatus(result.status);
            if (result.status == "success") {
                app.toasts.success("Redelivered successfully.");
            } else {
                app.toasts.info(
                    `Redelivery ${status.label.toLowerCase()} (response ${result.responseStatus || "-"}).`,
                );
            }

            settings.onredeliver?.(result);

            data.activeTab = TAB_OVERVIEW;
            await load(result.id);
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        data.isRedelivering = false;
    }

    function copyJSON() {
        app.utils.copyToClipboard(JSON.stringify(data.delivery, null, 2));
        app.toasts.success("Delivery copied to clipboard!");
    }

    function metaRow(label, value, copyValue = undefined) {
        return t.tr(
            null,
            t.th({ className: "min-width p-r-0" }, label),
            t.td(null, value),
            t.td(
                { className: "col-copy min-width" },
                typeof copyValue != "undefined" && copyValue !== "" ? app.components.copyButton(copyValue) : null,
            ),
        );
    }

    function timelineItem(state, icon, title, dateStr, ...content) {
        return t.li(
            { className: `webhook-timeline-item ${state}` },
            t.span({ className: "webhook-timeline-icon" }, t.i({ className: icon, ariaHidden: true })),
            t.div(
                { className: "webhook-timeline-content" },
                t.div(
                    { className: "webhook-timeline-title" },
                    t.strong(null, title),
                    dateStr
                        ? t.span(
                            { className: "txt-hint txt-sm", title: dateStr },
                            parseDate(dateStr)?.toLocaleString() + " (" + relativeTime(dateStr) + ")",
                        )
                        : null,
                ),
                content.length ? t.div({ className: "txt-sm" }, content) : null,
            ),
        );
    }

    function timeline() {
        const d = data.delivery;
        const items = [];

        items.push(
            timelineItem(
                "done",
                "ri-flashlight-line",
                d.test ? "Test event triggered" : "Event triggered",
                d.triggeredAt,
                t.code(null, d.topicName || webhookTopicLabel(d.topic)),
            ),
        );

        items.push(
            timelineItem(
                "done",
                "ri-inbox-archive-line",
                d.redeliveryOf ? "Queued (manual redelivery)" : "Queued",
                d.created,
                d.redeliveryOf
                    ? t.span(
                        null,
                        "Redelivery of ",
                        t.a(
                            {
                                href: "#",
                                className: "txt-code",
                                onclick: (e) => (e.preventDefault(), load(d.redeliveryOf)),
                            },
                            d.redeliveryOf,
                        ),
                    )
                    : null,
            ),
        );

        if (d.attempts > 0) {
            const ok = d.responseStatus >= 200 && d.responseStatus < 300;
            items.push(
                timelineItem(
                    ok ? "success" : "danger",
                    ok ? "ri-check-line" : "ri-close-line",
                    `Attempt #${d.attempts}${data.maxAttempts && !d.test ? " of " + data.maxAttempts : ""} (last)`,
                    d.updated,
                    t.span(
                        { className: "inline-flex gap-10 flex-wrap" },
                        t.span(null, "Response ", webhookResponseCodeLabel(d.responseStatus)),
                        d.durationMs ? t.span(null, "in " + llmFormatDuration(d.durationMs)) : null,
                    ),
                    d.error ? t.div({ className: "txt-danger m-t-5" }, d.error) : null,
                    d.attempts > 1
                        ? t.div(
                            { className: "txt-hint m-t-5" },
                            `${
                                d.attempts - 1
                            } previous failed attempt(s) - only the last attempt request/response is stored.`,
                        )
                        : null,
                ),
            );
        }

        if (d.status == "pending" || d.status == "retrying") {
            const remaining = data.maxAttempts ? Math.max(data.maxAttempts - d.attempts, 0) : null;
            items.push(
                timelineItem(
                    "pending",
                    "ri-time-line",
                    d.attempts > 0 ? `Next attempt #${d.attempts + 1} scheduled` : "First attempt scheduled",
                    d.nextAttemptAt,
                    remaining != null ? t.span({ className: "txt-hint" }, `${remaining} attempt(s) remaining`) : null,
                ),
            );
        } else if (d.status == "success") {
            items.push(timelineItem("success", "ri-checkbox-circle-line", "Delivered", d.updated));
        } else if (d.status == "failed") {
            items.push(
                timelineItem(
                    "danger",
                    "ri-close-circle-line",
                    "Failed",
                    d.updated,
                    d.test
                        ? t.span({ className: "txt-hint" }, "Test deliveries are not retried.")
                        : t.span({ className: "txt-hint" }, "All delivery attempts were exhausted."),
                ),
            );
        } else if (d.status == "disabled") {
            items.push(
                timelineItem(
                    "muted",
                    "ri-forbid-line",
                    "Not delivered (disabled)",
                    d.updated,
                    d.error ? t.span({ className: "txt-hint" }, d.error) : null,
                ),
            );
        }

        return t.ol({ className: "webhook-timeline" }, items);
    }

    function relatedList() {
        if (data.related.length <= 1) {
            return;
        }

        return t.div(
            { className: "webhook-related" },
            t.div({ className: "webhook-section-title" }, "Deliveries of the same event"),
            t.div(
                { className: "list webhook-related-list" },
                data.related.map((r) =>
                    t.div(
                        {
                            className: `list-item handle ${r.id == data.delivery.id ? "active" : ""}`,
                            tabIndex: 0,
                            onclick: () => r.id != data.delivery.id && load(r.id),
                            onkeydown: (e) => e.key == "Enter" && r.id != data.delivery.id && load(r.id),
                        },
                        webhookStatusLabel(r.status, r.error),
                        t.span({ className: "txt-code txt-sm" }, r.id),
                        r.redeliveryOf ? t.span({ className: "label sm" }, "redelivery") : null,
                        r.id == data.delivery.id ? t.span({ className: "label sm info" }, "current") : null,
                        t.span(
                            { className: "txt-hint txt-sm m-l-auto" },
                            app.components.formattedDate({ value: r.created, short: true }),
                        ),
                    )
                ),
            ),
        );
    }

    function overviewTab() {
        const d = data.delivery;

        return t.div(
            { className: "webhook-delivery-overview" },
            t.table(
                { className: "log-view-table responsive-table webhook-delivery-meta-table" },
                t.tbody(
                    null,
                    metaRow("id", d.id, d.id),
                    metaRow("event id", t.span({ className: "txt-code" }, d.eventId), d.eventId),
                    metaRow(
                        "subscription",
                        t.span(
                            { className: "inline-flex gap-5" },
                            () => data.subscription?.name || t.span({ className: "txt-hint" }, "(deleted)"),
                            t.span({ className: "txt-hint txt-code txt-sm" }, d.webhook),
                        ),
                        d.webhook,
                    ),
                    metaRow(
                        "topic",
                        t.span(
                            { className: "inline-flex gap-5" },
                            t.code(null, d.topicName || d.topic),
                            d.topicName && d.topicName != d.topic
                                ? t.span({ className: "txt-hint txt-sm" }, d.topic)
                                : null,
                        ),
                        d.topicName || d.topic,
                    ),
                    metaRow(
                        "status",
                        t.span(
                            { className: "inline-flex gap-5" },
                            webhookStatusLabel(d.status),
                            d.test ? t.span({ className: "label sm" }, "test") : null,
                        ),
                    ),
                    metaRow(
                        "attempts",
                        `${d.attempts}${data.maxAttempts && !d.test ? " / " + data.maxAttempts : ""}`,
                    ),
                    metaRow("api version", d.apiVersion || "-"),
                ),
            ),
            t.div({ className: "webhook-section-title" }, "Status timeline"),
            timeline(),
            () => relatedList(),
        );
    }

    function headersTable(headers) {
        const keys = Object.keys(headers || {}).sort();
        if (!keys.length) {
            return t.div({ className: "txt-hint txt-sm p-sm" }, "No headers.");
        }

        return t.table(
            { className: "table webhook-headers-table" },
            t.tbody(
                null,
                keys.map((key) =>
                    t.tr(
                        null,
                        t.td({ className: "min-width txt-nowrap" }, t.code(null, key)),
                        t.td({ className: "txt-break" }, String(headers[key])),
                    )
                ),
            ),
        );
    }

    function bodyBlock(raw, emptyText) {
        const body = webhookPrettyBody(raw);
        if (!body.value) {
            return t.div({ className: "txt-hint txt-sm p-sm" }, emptyText);
        }

        return app.components.codeBlock({ language: body.isJSON ? "js" : "html", value: body.value });
    }

    function requestTab() {
        const d = data.delivery;

        return t.div(
            { className: "webhook-delivery-request" },
            t.div(
                { className: "webhook-request-line" },
                t.span({ className: "label sm" }, "POST"),
                t.code({ className: "txt-break" }, () => data.subscription?.uri || "(subscription endpoint)"),
            ),
            t.div({ className: "webhook-section-title" }, "Headers"),
            d.attempts > 0
                ? headersTable(d.requestHeaders)
                : t.div({ className: "txt-hint txt-sm p-sm" }, "No attempt was made yet."),
            t.div(
                { className: "webhook-section-title" },
                d.requestBody ? "Body" : "Payload",
                d.requestBody ? null : t.span({ className: "txt-hint txt-sm" }, " (not sent yet)"),
            ),
            bodyBlock(d.requestBody || d.payload, "Empty body."),
        );
    }

    function responseTab() {
        const d = data.delivery;

        if (!d.attempts) {
            return t.div({ className: "txt-hint txt-center p-sm" }, "No attempt was made yet.");
        }

        return t.div(
            { className: "webhook-delivery-response" },
            t.div(
                { className: "webhook-request-line" },
                t.span({ className: "txt-hint" }, "Status"),
                webhookResponseCodeLabel(d.responseStatus),
                d.durationMs ? t.span({ className: "txt-hint" }, "in " + llmFormatDuration(d.durationMs)) : null,
            ),
            d.error
                ? t.div(
                    { className: "alert danger m-b-sm" },
                    t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                    t.div({ className: "content" }, d.error),
                )
                : null,
            t.div({ className: "webhook-section-title" }, "Headers"),
            headersTable(d.responseHeaders),
            t.div({ className: "webhook-section-title" }, "Body"),
            bodyBlock(d.responseBody, "Empty response body."),
        );
    }

    function tabBtn(tab, label) {
        return t.button(
            {
                type: "button",
                className: () => `tab-item ${data.activeTab == tab ? "active" : ""}`,
                onclick: () => data.activeTab = tab,
            },
            t.span({ className: "txt" }, label),
        );
    }

    modal = t.div(
        {
            pbEvent: "webhookDeliveryModal",
            className: "modal lg webhook-delivery-modal",
            onbeforeopen: () => {
                load();
            },
            onafterclose: (el) => {
                isClosed = true;
                clearTimeout(pollTimeoutId);
                settings.onafterclose?.();
                el?.remove();
            },
        },
        t.header(
            { className: "modal-header" },
            t.h5(null, "Webhook delivery"),
            () => (data.delivery ? webhookStatusLabel(data.delivery.status) : null),
            () => (data.delivery?.test ? t.span({ className: "label sm" }, "test") : null),
            t.div({ className: "m-l-auto" }),
            t.button(
                {
                    type: "button",
                    className: () => `btn sm circle transparent ${data.isLoading ? "loading" : ""}`,
                    ariaLabel: app.attrs.tooltip("Refresh", "left"),
                    disabled: () => !data.delivery || data.isLoading,
                    onclick: () => load(),
                },
                t.i({ className: "ri-refresh-line", ariaHidden: true }),
            ),
            t.button(
                {
                    type: "button",
                    className: "btn sm circle transparent",
                    ariaLabel: app.attrs.tooltip("Copy JSON", "left"),
                    disabled: () => !data.delivery,
                    onclick: copyJSON,
                },
                t.i({ className: "ri-braces-line", ariaHidden: true }),
            ),
        ),
        t.div({ className: "modal-content" }, () => {
            if (!data.delivery) {
                return t.div({ className: "block txt-center" }, t.span({ className: "loader" }));
            }

            return t.div(
                { className: () => `webhook-delivery-content ${data.isLoading ? "faded" : ""}` },
                t.nav(
                    { className: "tabs-header m-b-sm" },
                    tabBtn(TAB_OVERVIEW, "Overview"),
                    tabBtn(TAB_REQUEST, "Request"),
                    tabBtn(TAB_RESPONSE, "Response"),
                ),
                () => {
                    // rerender on delivery change
                    data.delivery;
                    if (data.activeTab == TAB_REQUEST) {
                        return requestTab();
                    }
                    if (data.activeTab == TAB_RESPONSE) {
                        return responseTab();
                    }
                    return overviewTab();
                },
            );
        }),
        t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn transparent m-r-auto",
                    onclick: () => app.modals.close(modal),
                },
                t.span({ className: "txt" }, "Close"),
            ),
            t.button(
                {
                    type: "button",
                    className: "btn transparent secondary",
                    disabled: () => !data.delivery,
                    onclick: () => app.utils.downloadJSON(data.delivery, deliveryFilename(data.delivery)),
                },
                t.i({ className: "ri-download-line", ariaHidden: true }),
                t.span({ className: "txt" }, "Download JSON"),
            ),
            t.span(
                {
                    className: "inline-flex",
                    ariaDescription: app.attrs.tooltip(() => data.redeliverBlockReason, "top"),
                },
                t.button(
                    {
                        type: "button",
                        className: () => `btn ${data.isRedelivering ? "loading" : ""}`,
                        disabled: () => !data.delivery || data.isRedelivering || !!data.redeliverBlockReason,
                        onclick: redeliver,
                    },
                    t.i({ className: "ri-repeat-line", ariaHidden: true }),
                    t.span({ className: "txt" }, "Redeliver"),
                ),
            ),
        ),
    );

    return modal;
}
