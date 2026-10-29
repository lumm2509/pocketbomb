import { llmCallerElem, llmFormatDuration, llmFormatNumber, llmLoadRecords, llmStatusLabel } from "./llmUtils";

window.app = window.app || {};
window.app.modals = window.app.modals || {};

window.app.modals.openLLMLogPreview = function(logIdOrModel, settings = {
    onbeforeopen: null,
    onafteropen: null,
    onbeforeclose: null,
    onafterclose: null,
}) {
    const modal = llmLogPreviewModal(logIdOrModel, settings);
    if (!modal) {
        return;
    }

    document.body.appendChild(modal);

    app.modals.open(modal);
};

const TRUNCATED_KEY = "__pb_truncated__";

const TAB_CONVERSATION = "conversation";
const TAB_REQUEST = "request";
const TAB_RESPONSE = "response";

function logFilename(log) {
    return "llm_log_" + (log?.created || "").replaceAll(/[-:\. ]/gi, "") + ".json";
}

/**
 * Renders a single normalized llm message part.
 *
 * @param  {Object} part
 * @return {Element}
 */
function llmPart(part) {
    switch (part?.type) {
        case "text":
            return t.div({ className: "llm-part llm-part-text" }, part.text || "");
        case "image": {
            const src = part.image?.url
                || (part.image?.data ? `data:${part.image.mimeType || "image/png"};base64,${part.image.data}` : "");
            return t.div(
                { className: "llm-part llm-part-image" },
                src
                    ? t.a(
                        { href: src, target: "_blank", rel: "noopener noreferrer" },
                        t.img({ src, alt: "Image part", loading: "lazy" }),
                    )
                    : t.span({ className: "txt-hint" }, "[image]"),
            );
        }
        case "tool_call":
            return t.div(
                { className: "llm-part llm-part-tool" },
                t.div(
                    { className: "llm-part-tool-header" },
                    t.i({ className: "ri-tools-line", ariaHidden: true }),
                    t.span({ className: "txt" }, "Tool call "),
                    t.code(null, part.toolCall?.name || "N/A"),
                    part.toolCall?.id ? t.small({ className: "txt-hint" }, part.toolCall.id) : null,
                ),
                app.components.codeBlock({
                    language: "js",
                    value: JSON.stringify(part.toolCall?.arguments ?? {}, null, 2),
                }),
            );
        case "tool_result":
            return t.div(
                { className: `llm-part llm-part-tool ${part.toolResult?.isError ? "error" : ""}` },
                t.div(
                    { className: "llm-part-tool-header" },
                    t.i({ className: "ri-reply-line", ariaHidden: true }),
                    t.span({ className: "txt" }, "Tool result "),
                    part.toolResult?.name ? t.code(null, part.toolResult.name) : null,
                    part.toolResult?.toolCallId ? t.small({ className: "txt-hint" }, part.toolResult.toolCallId) : null,
                    part.toolResult?.isError ? t.span({ className: "label sm danger" }, "error") : null,
                ),
                t.div({ className: "llm-part-text" }, part.toolResult?.content || ""),
            );
        default:
            return app.components.codeBlock({ language: "js", value: JSON.stringify(part, null, 2) });
    }
}

/**
 * Renders a chat-like message bubble.
 *
 * @param  {string} role
 * @param  {Array|Element} content
 * @param  {Element} [meta]
 * @return {Element}
 */
export function llmMessageBubble(role, content, meta = null) {
    const icons = {
        system: "ri-settings-4-line",
        user: "ri-user-line",
        assistant: "ri-sparkling-line",
        tools: "ri-tools-line",
    };

    return t.div(
        { className: `llm-message role-${role}` },
        t.div(
            { className: "llm-message-role" },
            t.i({ className: icons[role] || "ri-chat-3-line", ariaHidden: true }),
            t.span({ className: "txt" }, role),
            meta,
        ),
        t.div({ className: "llm-message-content" }, content),
    );
}

function llmMessageParts(message) {
    const parts = message?.parts || [];
    if (!parts.length) {
        return t.span({ className: "txt-hint" }, "(empty)");
    }
    return parts.map(llmPart);
}

function llmLogPreviewModal(logIdOrModel, settings) {
    let modal;

    const data = store({
        isLoading: false,
        log: null,
        activeTab: TAB_CONVERSATION,
        get hasContent() {
            return !!(data.log?.request || data.log?.response);
        },
        get isTruncated() {
            return !!(data.log?.request?.[TRUNCATED_KEY] || data.log?.response?.[TRUNCATED_KEY]);
        },
    });

    async function load() {
        data.isLoading = true;

        try {
            const id = typeof logIdOrModel == "string" ? logIdOrModel : logIdOrModel?.id;

            data.log = await app.pb.send("/api/llm/logs/" + encodeURIComponent(id), {
                requestKey: "llm_log_preview",
            });

            llmLoadRecords([data.log]);

            data.isLoading = false;
        } catch (err) {
            if (!err?.isAbort) {
                data.isLoading = false;
                app.checkApiError(err);
            }
        }
    }

    function copyJSON() {
        app.utils.copyToClipboard(JSON.stringify(data.log, null, 2));
        app.toasts.success("LLM log copied to clipboard!");
    }

    function metaRow(label, valueFunc, copyValue = undefined) {
        return t.tr(
            null,
            t.th({ className: "min-width p-r-0" }, label),
            t.td(null, valueFunc),
            t.td(
                { className: "col-copy min-width" },
                typeof copyValue != "undefined" && copyValue !== "" ? app.components.copyButton(copyValue) : null,
            ),
        );
    }

    function metaTable() {
        const log = data.log;

        return t.table(
            { pbEvent: "llmLogPreviewTable", className: "log-view-table responsive-table llm-log-meta-table" },
            t.tbody(
                null,
                metaRow("id", log.id, log.id),
                metaRow(
                    "created",
                    app.components.formattedDate({ value: log.created, short: false }),
                    log.created,
                ),
                metaRow(
                    "status",
                    t.div(
                        { className: "inline-flex gap-10" },
                        llmStatusLabel(log.status),
                        log.error ? t.span({ className: "label danger log-error-label" }, log.error) : null,
                    ),
                    log.error || log.status,
                ),
                metaRow("profile", log.profile || t.span({ className: "txt-hint" }, "N/A"), log.profile),
                metaRow(
                    "provider / model",
                    t.span(
                        null,
                        `${log.provider || "N/A"} / ${log.model || "N/A"}`,
                        log.stream ? t.span({ className: "label sm m-l-5" }, "stream") : null,
                    ),
                    log.model,
                ),
                metaRow(
                    "tokens",
                    t.span(
                        null,
                        `${llmFormatNumber(log.inputTokens)} in / ${llmFormatNumber(log.outputTokens)} out`,
                        t.span(
                            { className: "txt-hint" },
                            ` (${llmFormatNumber(log.inputTokens + log.outputTokens)} total)`,
                        ),
                    ),
                ),
                metaRow("duration", log.durationMs ? llmFormatDuration(log.durationMs) : "-", log.durationMs),
                metaRow(
                    "caller",
                    t.div(
                        { className: "inline-flex gap-10" },
                        llmCallerElem(log),
                        log.authRecord && log.ip ? t.span({ className: "txt-hint" }, "IP: " + log.ip) : null,
                    ),
                    log.authRecord || log.ip,
                ),
                () => {
                    if (app.utils.isEmpty(log.meta)) {
                        return;
                    }
                    return metaRow(
                        "meta",
                        app.components.codeBlock({ language: "js", value: JSON.stringify(log.meta, null, 2) }),
                        JSON.stringify(log.meta),
                    );
                },
            ),
        );
    }

    function conversationView() {
        const log = data.log;

        if (!data.hasContent) {
            return t.div(
                { className: "alert info m-0" },
                t.i({ className: "ri-eye-off-line", ariaHidden: true }),
                t.div(
                    { className: "content" },
                    log.status == "denied" || log.status == "limited"
                        ? t.p(null, "The request was rejected before reaching the provider (no content is stored).")
                        : t.p(
                            null,
                            "The request and response content were not stored for this call. ",
                            "Enable ",
                            t.a({ href: "#/settings/llm", className: "txt-bold" }, "Settings > LLM > Store content"),
                            " (or the profile override) to inspect the messages of the future calls.",
                        ),
                ),
            );
        }

        const req = log.request || {};
        const resp = log.response || null;

        const items = [];

        if (data.isTruncated) {
            items.push(
                t.div(
                    { className: "alert warning m-0" },
                    t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                    t.div({ className: "content" }, "The stored content was too large and was truncated."),
                ),
            );
        }

        if (req.system) {
            items.push(llmMessageBubble("system", t.div({ className: "llm-part llm-part-text" }, req.system)));
        }

        for (const message of req.messages || []) {
            items.push(llmMessageBubble(message.role, llmMessageParts(message)));
        }

        if (req.tools?.length) {
            items.push(
                llmMessageBubble(
                    "tools",
                    t.div(
                        { className: "inline-flex flex-wrap gap-5" },
                        req.tools.map((tool) =>
                            t.span(
                                {
                                    className: "label",
                                    ariaDescription: app.attrs.tooltip(tool.description || null),
                                },
                                tool.name,
                            )
                        ),
                    ),
                    t.small({ className: "txt-hint" }, "available tools"),
                ),
            );
        }

        if (resp?.message) {
            items.push(
                llmMessageBubble(
                    "assistant",
                    llmMessageParts(resp.message),
                    t.small(
                        { className: "txt-hint llm-message-meta" },
                        [
                            "response",
                            resp.stopReason ? "stop: " + resp.stopReason : "",
                            resp.usage ? `${resp.usage.inputTokens || 0} in / ${resp.usage.outputTokens || 0} out` : "",
                        ].filter(Boolean).join(" · "),
                    ),
                ),
            );
        } else if (log.status == "error") {
            items.push(
                t.div(
                    { className: "alert danger m-0" },
                    t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                    t.div({ className: "content" }, log.error || "The call failed without a response."),
                ),
            );
        }

        const params = [];
        for (
            const key of ["model", "maxTokens", "temperature", "topP", "toolChoice", "responseFormat", "stopSequences"]
        ) {
            if (!app.utils.isEmpty(req[key])) {
                const val = typeof req[key] == "object" ? JSON.stringify(req[key]) : req[key];
                params.push(t.span({ className: "label sm" }, `${key}: ${val}`));
            }
        }
        if (params.length) {
            items.unshift(t.div({ className: "inline-flex flex-wrap gap-5 llm-request-params" }, params));
        }

        return t.div({ className: "llm-conversation" }, items);
    }

    function rawView(value) {
        if (value == null) {
            return t.div({ className: "txt-hint txt-center p-sm" }, "N/A (content not stored)");
        }
        return app.components.codeBlock({ language: "js", value: JSON.stringify(value, null, 2) });
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
            pbEvent: "llmLogPreviewModal",
            className: "modal lg llm-log-preview-modal",
            onbeforeopen: (el) => {
                load();
                return settings.onbeforeopen?.(el);
            },
            onafteropen: (el) => {
                settings.onafteropen?.(el);
            },
            onbeforeclose: (el) => {
                return settings.onbeforeclose?.(el);
            },
            onafterclose: (el) => {
                settings.onafterclose?.(el);
                el?.remove();
            },
        },
        t.header(
            { className: "modal-header" },
            t.h5(null, "LLM call details"),
            t.button(
                {
                    type: "button",
                    className: "btn sm circle transparent m-l-auto",
                    ariaLabel: app.attrs.tooltip("Copy JSON", "left"),
                    disabled: () => !data.log,
                    onclick: copyJSON,
                },
                t.i({ className: "ri-braces-line", ariaHidden: true }),
            ),
        ),
        t.div({ className: "modal-content" }, () => {
            if (!data.log || data.isLoading) {
                return t.div({ className: "block txt-center" }, t.span({ className: "loader" }));
            }

            return t.div(
                { className: "llm-log-preview-content" },
                metaTable(),
                t.nav(
                    { className: "tabs-header m-t-sm m-b-sm" },
                    tabBtn(TAB_CONVERSATION, "Conversation"),
                    tabBtn(TAB_REQUEST, "Request JSON"),
                    tabBtn(TAB_RESPONSE, "Response JSON"),
                ),
                () => {
                    if (data.activeTab == TAB_REQUEST) {
                        return rawView(data.log.request);
                    }
                    if (data.activeTab == TAB_RESPONSE) {
                        return rawView(data.log.response);
                    }
                    return conversationView();
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
                    className: "btn",
                    disabled: () => !data.log,
                    onclick: () => app.utils.downloadJSON(data.log, logFilename(data.log)),
                },
                t.i({ className: "ri-download-line", ariaHidden: true }),
                t.span({ className: "txt" }, "Download JSON"),
            ),
        ),
    );

    return modal;
}
