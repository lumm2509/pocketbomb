import { llmMessageBubble } from "./llmLogPreviewModal";
import { llmFormatDuration, llmFormatNumber } from "./llmUtils";

/**
 * Parses a single SSE event block.
 *
 * @param  {string} block
 * @return {{event: string, data: string}}
 */
function parseSSEBlock(block) {
    let event = "message";
    const dataLines = [];

    for (const line of block.split("\n")) {
        if (line.startsWith("event:")) {
            event = line.substring(6).trim();
        } else if (line.startsWith("data:")) {
            dataLines.push(line.substring(5).replace(/^ /, ""));
        }
    }

    return { event, data: dataLines.join("\n") };
}

/**
 * The LLM dashboard playground tab (chat with a profile as superuser).
 *
 * @param  {Object} pageData
 * @return {Element}
 */
export function llmPlayground(pageData) {
    const data = store({
        profile: "",
        model: "",
        temperature: "",
        maxTokens: "",
        stream: true,
        input: "",
        messages: [], // [{role, content, parts?, error?, pending?, stats?}]
        isSending: false,
        get profiles() {
            return app.store.settings?.llm?.profiles || [];
        },
        get activeProfile() {
            return data.profiles.find((p) => p.name == data.profile);
        },
        get modelOptions() {
            const p = data.activeProfile;
            if (!p) {
                return [];
            }
            return [p.model, ...(p.allowedModels || [])].filter(Boolean);
        },
    });

    // init the default profile outside of the current render cycle
    // (to avoid registering the store reads as dependencies of the parent)
    setTimeout(() => {
        const preferred = pageData.filters.profile;
        if (preferred && data.profiles.find((p) => p.name == preferred)) {
            data.profile = preferred;
        } else if (!data.profile && data.profiles.length) {
            data.profile = data.profiles[0].name;
        }
    }, 0);

    let abortController;
    let messagesEl;

    function scrollToBottom() {
        setTimeout(() => {
            if (messagesEl) {
                messagesEl.scrollTop = messagesEl.scrollHeight;
            }
        }, 0);
    }

    function buildBody() {
        const body = {
            stream: data.stream,
            messages: data.messages
                .filter((m) => !m.error && !m.pending)
                .map((m) => {
                    if (m.parts?.length) {
                        return { role: m.role, parts: m.parts };
                    }
                    return { role: m.role, content: m.content };
                }),
        };

        if (data.model) {
            body.model = data.model;
        }
        if (data.temperature !== "" && data.temperature != null) {
            body.temperature = Number(data.temperature);
        }
        if (data.maxTokens) {
            body.maxTokens = Number(data.maxTokens) << 0;
        }

        return body;
    }

    async function send() {
        const text = data.input.trim();
        if (!text || data.isSending || !data.profile) {
            return;
        }

        data.messages.push({ role: "user", content: text });
        data.input = "";

        const body = buildBody();

        data.messages.push({ role: "assistant", content: "", pending: true });
        const assistantIndex = data.messages.length - 1;
        const assistant = data.messages[assistantIndex];

        scrollToBottom();

        data.isSending = true;
        abortController = new AbortController();

        const start = performance.now();
        let ttft = null;

        try {
            const response = await fetch(app.pb.buildURL(`/api/llm/${encodeURIComponent(data.profile)}/chat`), {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": app.pb.authStore.token,
                    "x-request-source": "pbui",
                },
                body: JSON.stringify(body),
                signal: abortController.signal,
            });

            if (!response.ok) {
                let msg = "Request failed with status " + response.status;
                try {
                    const errData = await response.json();
                    msg = errData?.message || msg;
                    const details = Object.entries(errData?.data || {})
                        .map(([k, v]) => `${k}: ${v?.message || JSON.stringify(v)}`)
                        .join("; ");
                    if (details) {
                        msg += " (" + details + ")";
                    }
                } catch (_) {}
                throw new Error(msg);
            }

            const contentType = response.headers.get("content-type") || "";

            if (!contentType.includes("text/event-stream")) {
                const result = await response.json();
                assistant.content = result.text || "";
                assistant.parts = result.message?.parts;
                assistant.stats = {
                    model: result.model,
                    usage: result.usage,
                    stopReason: result.stopReason,
                    durationMs: performance.now() - start,
                };
            } else {
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let buffer = "";

                while (true) {
                    const { value, done } = await reader.read();
                    if (done) {
                        break;
                    }

                    buffer += decoder.decode(value, { stream: true }).replaceAll("\r\n", "\n");

                    let sepIndex;
                    while ((sepIndex = buffer.indexOf("\n\n")) >= 0) {
                        const block = buffer.substring(0, sepIndex);
                        buffer = buffer.substring(sepIndex + 2);

                        const evt = parseSSEBlock(block);
                        if (!evt.data) {
                            continue;
                        }

                        const payload = JSON.parse(evt.data);

                        if (evt.event == "delta") {
                            if (payload.type == "text_delta" && payload.text) {
                                if (ttft == null) {
                                    ttft = performance.now() - start;
                                }
                                assistant.content += payload.text;
                                scrollToBottom();
                            }
                        } else if (evt.event == "done") {
                            assistant.content = payload.text || assistant.content;
                            assistant.parts = payload.message?.parts;
                            assistant.stats = {
                                model: payload.model,
                                usage: payload.usage,
                                stopReason: payload.stopReason,
                                durationMs: performance.now() - start,
                                ttftMs: ttft,
                            };
                        } else if (evt.event == "error") {
                            throw new Error(payload.message || "Stream error.");
                        }
                    }
                }
            }

            assistant.pending = false;
        } catch (err) {
            assistant.pending = false;
            if (err?.name == "AbortError") {
                assistant.error = "Aborted.";
            } else {
                assistant.error = err?.message || "Failed to send the request.";
            }
        }

        data.isSending = false;
        abortController = null;

        // refresh the dashboard stats
        pageData.reset = Date.now();

        scrollToBottom();
    }

    function stop() {
        abortController?.abort();
    }

    function clear() {
        stop();
        data.messages = [];
    }

    function statsElem(stats) {
        if (!stats) {
            return null;
        }

        const items = [];
        if (stats.model) {
            items.push(stats.model);
        }
        if (stats.usage) {
            items.push(
                `${llmFormatNumber(stats.usage.inputTokens || 0)} in / ${
                    llmFormatNumber(stats.usage.outputTokens || 0)
                } out`,
            );
        }
        if (stats.ttftMs != null) {
            items.push("TTFT " + llmFormatDuration(stats.ttftMs));
        }
        if (stats.durationMs != null) {
            items.push(llmFormatDuration(stats.durationMs));
        }
        if (stats.stopReason) {
            items.push("stop: " + stats.stopReason);
        }

        return t.small({ className: "txt-hint llm-message-meta" }, items.join(" · "));
    }

    return t.div(
        { pbEvent: "llmPlayground", className: "llm-playground" },
        t.aside(
            { className: "llm-playground-options" },
            t.div(
                { className: "field" },
                t.label({ htmlFor: "llm_pg_profile" }, "Profile"),
                app.components.select({
                    id: "llm_pg_profile",
                    required: true,
                    placeholder: "- Select profile -",
                    options: () => data.profiles.map((p) => ({ value: p.name, label: p.name })),
                    value: () => data.profile,
                    onchange: (opts) => {
                        data.profile = opts?.[0]?.value || "";
                        data.model = "";
                    },
                }),
            ),
            () => {
                const p = data.activeProfile;
                if (!p) {
                    if (!data.profiles.length) {
                        return t.div(
                            { className: "alert warning m-0" },
                            t.div(
                                { className: "content" },
                                "No LLM profiles found. ",
                                t.a({ href: "#/settings/llm", className: "txt-bold" }, "Create a profile"),
                                " first.",
                            ),
                        );
                    }
                    return;
                }

                return t.div(
                    { className: "llm-profile-summary txt-sm txt-hint" },
                    t.div(null, "Provider: ", t.strong(null, p.provider || "(default)")),
                    t.div(null, "Model: ", t.strong(null, p.model || "(provider default)")),
                    p.rule === null
                        ? t.div(null, "Access: ", t.strong(null, "superusers only"))
                        : t.div(null, "Access: ", t.strong(null, p.rule === "" ? "public" : "rule")),
                    p.systemPrompt
                        ? t.div(
                            { className: "txt-ellipsis", ariaDescription: app.attrs.tooltip(p.systemPrompt) },
                            "System: ",
                            t.strong(null, p.systemPrompt),
                        )
                        : null,
                );
            },
            t.div(
                { className: "field" },
                t.label({ htmlFor: "llm_pg_model" }, "Model override"),
                t.input({
                    id: "llm_pg_model",
                    type: "text",
                    list: "llm_pg_models",
                    placeholder: "Profile default",
                    value: () => data.model,
                    oninput: (e) => data.model = e.target.value.trim(),
                }),
                t.datalist(
                    { id: "llm_pg_models" },
                    () => data.modelOptions.map((m) => t.option({ value: m })),
                ),
            ),
            t.div(
                { className: "llm-inline-fields" },
                t.div(
                    null,
                    t.div(
                        { className: "field" },
                        t.label({ htmlFor: "llm_pg_temperature" }, "Temperature"),
                        t.input({
                            id: "llm_pg_temperature",
                            type: "number",
                            min: 0,
                            max: 2,
                            step: 0.1,
                            placeholder: () => data.activeProfile?.temperature ?? "Default",
                            value: () => data.temperature,
                            oninput: (e) => data.temperature = e.target.value,
                        }),
                    ),
                ),
                t.div(
                    null,
                    t.div(
                        { className: "field" },
                        t.label({ htmlFor: "llm_pg_max_tokens" }, "Max tokens"),
                        t.input({
                            id: "llm_pg_max_tokens",
                            type: "number",
                            min: 0,
                            step: 1,
                            placeholder: () => data.activeProfile?.maxTokens || "Default",
                            value: () => data.maxTokens,
                            oninput: (e) => data.maxTokens = e.target.value,
                        }),
                    ),
                ),
            ),
            t.div(
                { className: "field" },
                t.input({
                    id: "llm_pg_stream",
                    type: "checkbox",
                    className: "switch",
                    checked: () => data.stream,
                    onchange: (e) => data.stream = e.target.checked,
                }),
                t.label({ htmlFor: "llm_pg_stream" }, "Stream response"),
            ),
            t.p(
                { className: "txt-hint txt-sm m-0" },
                "The playground calls the public ",
                t.code(null, () => `POST /api/llm/${data.profile || "{profile}"}/chat`),
                " endpoint as superuser (the profile rule and quotas are bypassed but the call is logged).",
            ),
        ),
        t.div(
            { className: "llm-playground-chat" },
            t.div(
                {
                    className: "llm-playground-messages",
                    onmount: (el) => (messagesEl = el),
                },
                () => {
                    if (!data.messages.length) {
                        return t.div(
                            { className: "llm-playground-empty txt-hint txt-center" },
                            t.i({ className: "ri-chat-ai-line", ariaHidden: true }),
                            t.div(null, "Send a message to test the selected profile."),
                        );
                    }

                    return data.messages.map((m) => {
                        return llmMessageBubble(
                            m.role,
                            () => {
                                if (m.error) {
                                    return t.div({ className: "llm-part llm-part-text txt-danger" }, m.error);
                                }
                                if (m.pending && !m.content) {
                                    return t.span({ className: "loader sm" });
                                }
                                return t.div({ className: "llm-part llm-part-text" }, () => m.content);
                            },
                            () => statsElem(m.stats),
                        );
                    });
                },
            ),
            t.form(
                {
                    className: "llm-playground-input",
                    onsubmit: (e) => {
                        e.preventDefault();
                        send();
                    },
                },
                t.div(
                    { className: "field" },
                    t.textarea({
                        id: "llm_pg_input",
                        rows: 3,
                        placeholder: "Type a message... (Enter to send, Shift+Enter for a new line)",
                        value: () => data.input,
                        disabled: () => !data.profile,
                        oninput: (e) => data.input = e.target.value,
                        onkeydown: (e) => {
                            if (e.key == "Enter" && !e.shiftKey && !e.isComposing) {
                                e.preventDefault();
                                send();
                            }
                        },
                    }),
                ),
                t.div(
                    { className: "flex gap-10" },
                    t.button(
                        {
                            type: "button",
                            className: "btn transparent secondary",
                            disabled: () => !data.messages.length,
                            onclick: clear,
                        },
                        t.i({ className: "ri-delete-bin-7-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "Clear"),
                    ),
                    t.div({ className: "m-l-auto" }),
                    () => {
                        if (data.isSending) {
                            return t.button(
                                { type: "button", className: "btn secondary", onclick: stop },
                                t.i({ className: "ri-stop-circle-line", ariaHidden: true }),
                                t.span({ className: "txt" }, "Stop"),
                            );
                        }

                        return t.button(
                            {
                                type: "submit",
                                className: "btn",
                                disabled: () => !data.profile || !data.input.trim(),
                            },
                            t.i({ className: "ri-send-plane-fill", ariaHidden: true }),
                            t.span({ className: "txt" }, "Send"),
                        );
                    },
                ),
            ),
        ),
    );
}
