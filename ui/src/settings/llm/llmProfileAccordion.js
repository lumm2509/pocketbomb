const WINDOW_OPTIONS = [
    { value: "minute", label: "per minute" },
    { value: "hour", label: "per hour" },
    { value: "day", label: "per day" },
];

const STORE_CONTENT_OPTIONS = [
    { value: "inherit", label: "Inherit (logs setting)" },
    { value: "yes", label: "Always store" },
    { value: "no", label: "Never store" },
];

// pseudo collection used for the profile rule @request.body.* autocomplete
const chatRequestCollection = {
    id: "__llm_chat_request__",
    name: "__llm_chat_request__",
    type: "base",
    fields: [
        { name: "messages", type: "json" },
        { name: "model", type: "text" },
        { name: "stream", type: "bool" },
        { name: "temperature", type: "number" },
        { name: "maxTokens", type: "number" },
        { name: "tools", type: "json" },
    ],
};

function ruleAutocomplete(word) {
    return app.utils
        .collectionAutocompleteKeys(chatRequestCollection, word, { maxKeys: 60 })
        .filter((key) => key.startsWith("@"))
        .slice(0, 30);
}

/**
 * Settings LLM profile accordion.
 *
 * @param  {Object} pageData
 * @param  {Object} profile The reactive profile form object.
 * @param  {number} index
 * @return {Element}
 */
export function llmProfileAccordion(pageData, profile, index) {
    const prefix = `llm.profiles.${index}.`;

    function hasErrors() {
        return !app.utils.isEmpty(app.store.errors?.llm?.profiles?.[index]);
    }

    function remove() {
        pageData.formSettings.llm.profiles.splice(index, 1);
        app.store.errors = null;
    }

    function providerOptions() {
        const result = [{ value: "", label: "Default provider" }];
        for (const p of pageData.allProviders) {
            result.push({ value: p.name, label: p.name + (p.source == "env" ? " (env)" : "") });
        }
        if (profile.provider && !result.find((o) => o.value == profile.provider)) {
            result.push({ value: profile.provider, label: profile.provider + " (missing)" });
        }
        return result;
    }

    function providerModels() {
        const name = profile.provider || pageData.formSettings.llm.defaultProvider;
        const p = pageData.allProviders.find((p) => p.name == name);
        return [p?.defaultModel, ...(p?.models || [])].filter(Boolean);
    }

    function quotaRow(key, label, tooltip) {
        const quotaPrefix = `${prefix}quotas.${key}.`;

        function quota() {
            profile.quotas = profile.quotas || {};
            profile.quotas[key] = profile.quotas[key] || { requests: 0, tokens: 0, window: "" };
            return profile.quotas[key];
        }

        function ensureWindow() {
            const q = quota();
            if ((q.requests > 0 || q.tokens > 0) && !q.window) {
                q.window = "hour";
            }
        }

        return t.div(
            { className: "llm-quota-row" },
            t.label(
                { className: "txt-sm txt-bold inline-flex gap-5" },
                t.span({ className: "txt" }, label),
                t.i({ className: "ri-information-line link-hint", ariaDescription: app.attrs.tooltip(tooltip) }),
            ),
            t.div(
                { className: "field" },
                t.input({
                    id: quotaPrefix + "requests",
                    name: quotaPrefix + "requests",
                    type: "number",
                    min: 0,
                    step: 1,
                    ariaLabel: "Max requests",
                    placeholder: "Max requests (unlimited)",
                    value: () => quota().requests || "",
                    oninput: (e) => {
                        quota().requests = e.target.value << 0;
                        ensureWindow();
                    },
                }),
            ),
            t.div(
                { className: "field" },
                t.input({
                    id: quotaPrefix + "tokens",
                    name: quotaPrefix + "tokens",
                    type: "number",
                    min: 0,
                    step: 1,
                    ariaLabel: "Max tokens",
                    placeholder: "Max tokens (unlimited)",
                    value: () => quota().tokens || "",
                    oninput: (e) => {
                        quota().tokens = e.target.value << 0;
                        ensureWindow();
                    },
                }),
            ),
            t.div(
                { className: "field" },
                app.components.select({
                    id: quotaPrefix + "window",
                    name: quotaPrefix + "window",
                    placeholder: "- Window -",
                    options: WINDOW_OPTIONS,
                    value: () => quota().window || "",
                    onchange: (opts) => quota().window = opts?.[0]?.value || "",
                }),
            ),
        );
    }

    return t.details(
        {
            pbEvent: "llmProfileAccordion",
            className: "accordion llm-profile-accordion",
            onmount: (el) => {
                // auto expand on server validation errors
                el._errorsWatcher = watch(
                    () => hasErrors(),
                    (has) => {
                        if (has) {
                            el.open = true;
                        }
                    },
                );
            },
            onunmount: (el) => {
                el._errorsWatcher?.unwatch();
            },
            open: !profile._originalName,
        },
        t.summary(
            null,
            t.i({ className: "ri-route-line", ariaHidden: true }),
            t.span({ className: "txt txt-bold" }, () => profile.name || "(unnamed)"),
            t.code({ className: "txt-hint txt-sm" }, () => `/api/llm/${profile.name || "{profile}"}/chat`),
            t.div({ className: "flex-fill" }),
            () => {
                if (profile.rule === null || typeof profile.rule == "undefined") {
                    return t.span({ className: "label" }, "Superusers only");
                }
                if (profile.rule === "") {
                    return t.span({ className: "label warning" }, "Public");
                }
                return t.span({ className: "label info" }, "Rule");
            },
            () => {
                const q = profile.quotas || {};
                if (q.perUser?.requests || q.perUser?.tokens || q.perGuestIP?.requests || q.perGuestIP?.tokens) {
                    return t.span({ className: "label success" }, "Quotas");
                }
            },
            () => {
                if (hasErrors()) {
                    return t.i({
                        className: "ri-error-warning-fill txt-danger",
                        ariaDescription: app.attrs.tooltip("Has errors", "left"),
                    });
                }
            },
        ),
        t.div(
            { className: "grid" },
            t.div(
                { className: "col-lg-4" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: prefix + "name" }, "Name"),
                    t.input({
                        id: prefix + "name",
                        name: prefix + "name",
                        type: "text",
                        required: true,
                        pattern: "^[\\w\\-]+$",
                        placeholder: "e.g. support-bot",
                        value: () => profile.name || "",
                        oninput: (e) => profile.name = e.target.value.trim(),
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-4" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: prefix + "provider" }, "Provider"),
                    app.components.select({
                        id: prefix + "provider",
                        name: prefix + "provider",
                        required: true,
                        options: providerOptions,
                        value: () => profile.provider || "",
                        onchange: (opts) => profile.provider = opts?.[0]?.value || "",
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-4" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: prefix + "model" }, "Model"),
                    t.input({
                        id: prefix + "model",
                        name: prefix + "model",
                        type: "text",
                        list: "llm_profile_models_" + index,
                        placeholder: "Provider default",
                        value: () => profile.model || "",
                        oninput: (e) => profile.model = e.target.value.trim(),
                    }),
                    t.datalist(
                        { id: "llm_profile_models_" + index },
                        () => providerModels().map((m) => t.option({ value: m })),
                    ),
                ),
            ),
            t.div(
                { className: "col-lg-12" },
                t.div(
                    { className: "field" },
                    t.label(
                        { htmlFor: prefix + "systemPrompt" },
                        t.span({ className: "txt" }, "System prompt"),
                        t.small({ className: "txt-hint" }, "(optional, always prepended)"),
                    ),
                    t.textarea({
                        id: prefix + "systemPrompt",
                        name: prefix + "systemPrompt",
                        rows: 3,
                        placeholder: "e.g. You are a helpful assistant for ...",
                        value: () => profile.systemPrompt || "",
                        oninput: (e) => profile.systemPrompt = e.target.value,
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-4" },
                t.div(
                    { className: "field" },
                    t.label(
                        { htmlFor: prefix + "maxTokens" },
                        t.span({ className: "txt" }, "Max output tokens"),
                        t.i({
                            className: "ri-information-line link-hint",
                            ariaDescription: app.attrs.tooltip("Caps the max output tokens of every request."),
                        }),
                    ),
                    t.input({
                        id: prefix + "maxTokens",
                        name: prefix + "maxTokens",
                        type: "number",
                        min: 0,
                        step: 1,
                        placeholder: "No cap",
                        value: () => profile.maxTokens || "",
                        oninput: (e) => profile.maxTokens = e.target.value << 0,
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-4" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: prefix + "temperature" }, "Default temperature"),
                    t.input({
                        id: prefix + "temperature",
                        name: prefix + "temperature",
                        type: "number",
                        min: 0,
                        max: 2,
                        step: 0.01,
                        placeholder: "Provider default",
                        value: () => profile.temperature ?? "",
                        oninput: (e) => {
                            profile.temperature = e.target.value === "" ? null : Number(e.target.value);
                        },
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-4" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: prefix + "storeContent" }, "Store content"),
                    app.components.select({
                        id: prefix + "storeContent",
                        name: prefix + "storeContent",
                        required: true,
                        options: STORE_CONTENT_OPTIONS,
                        value: () =>
                            profile.storeContent === true ? "yes" : profile.storeContent === false ? "no" : "inherit",
                        onchange: (opts) => {
                            const val = opts?.[0]?.value;
                            profile.storeContent = val == "yes" ? true : val == "no" ? false : null;
                        },
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-12" },
                t.div(
                    { className: "field" },
                    t.input({
                        id: prefix + "allowClientOverrides",
                        name: prefix + "allowClientOverrides",
                        type: "checkbox",
                        className: "switch",
                        checked: () => !!profile.allowClientOverrides,
                        onchange: (e) => profile.allowClientOverrides = e.target.checked,
                    }),
                    t.label(
                        { htmlFor: prefix + "allowClientOverrides" },
                        t.span({ className: "txt" }, "Allow client overrides"),
                        t.i({
                            className: "ri-information-line link-hint",
                            ariaDescription: app.attrs.tooltip(
                                "Allow the API clients to change the model (restricted to the allowed models), temperature, max tokens (still capped) and tools.",
                            ),
                        }),
                    ),
                ),
            ),
            t.div(
                { className: "col-lg-12" },
                t.div(
                    { className: "field" },
                    t.label(
                        { htmlFor: prefix + "allowedModels" },
                        t.span({ className: "txt" }, "Allowed models"),
                        t.small({ className: "txt-hint" }, "(comma separated, in addition to the profile model)"),
                    ),
                    t.input({
                        id: prefix + "allowedModels",
                        name: prefix + "allowedModels",
                        type: "text",
                        placeholder: () =>
                            profile.allowClientOverrides ? "Leave empty to allow any model" : "Only the profile model",
                        value: () => app.utils.joinNonEmpty(profile.allowedModels),
                        oninput: (e) => {
                            const newValue = app.utils.splitNonEmpty(e.target.value, ",");
                            if (app.utils.joinNonEmpty(newValue) != app.utils.joinNonEmpty(profile.allowedModels)) {
                                profile.allowedModels = newValue;
                            }
                        },
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-12" },
                app.components.ruleField({
                    name: prefix + "rule",
                    label: "Access rule",
                    placeholder: "Leave empty to grant everyone access...",
                    value: () => (typeof profile.rule == "undefined" ? null : profile.rule),
                    oninput: (val) => profile.rule = val,
                    autocomplete: ruleAutocomplete,
                }),
                t.div(
                    { className: "field-help" },
                    "Same semantics as the collection API rules: ",
                    t.strong(null, "locked"),
                    " = superusers only, ",
                    t.strong(null, "empty"),
                    " = everyone (incl. guests), otherwise a filter expression evaluated against ",
                    t.code(null, "@request.*"),
                    " (e.g. ",
                    t.code(null, "@request.auth.id != \"\""),
                    ").",
                ),
            ),
            t.div(
                { className: "col-lg-12" },
                t.div(
                    { className: "flex gap-5 m-b-10" },
                    t.strong({ className: "txt-sm" }, "Quotas"),
                    t.small(
                        { className: "txt-hint" },
                        "(sliding window, computed from the LLM logs; leave empty for no limit; superusers are not limited)",
                    ),
                ),
                t.div(
                    { className: "llm-quotas" },
                    quotaRow("perUser", "Per user", "Applied to the authenticated (non-superuser) requests."),
                    quotaRow("perGuestIP", "Per guest IP", "Applied to the guest requests grouped by the client IP."),
                ),
                // errors anchor for the general quotas validation error
                t.div({ className: "field llm-error-anchor" }, t.input({ type: "hidden", name: prefix + "quotas" })),
            ),
            t.div(
                { className: "col-lg-12" },
                t.div(
                    { className: "flex" },
                    t.div({ className: "m-l-auto" }),
                    t.button(
                        {
                            type: "button",
                            className: "btn sm transparent secondary",
                            onclick: () => {
                                app.modals.confirm(
                                    `Do you really want to remove the "${profile.name || "unnamed"}" profile?`,
                                    remove,
                                );
                            },
                        },
                        t.i({ className: "ri-delete-bin-7-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "Remove"),
                    ),
                ),
            ),
        ),
    );
}
