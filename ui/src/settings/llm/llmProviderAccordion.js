/**
 * Settings LLM provider accordion (editable settings provider).
 *
 * @param  {Object} pageData
 * @param  {Object} provider The reactive provider form object.
 * @param  {number} index
 * @return {Element}
 */
export function llmProviderAccordion(pageData, provider, index) {
    const prefix = `llm.providers.${index}.`;

    const local = store({
        isTesting: false,
        testResult: null, // {ok, text}
    });

    function hasErrors() {
        return !app.utils.isEmpty(app.store.errors?.llm?.providers?.[index]);
    }

    async function test() {
        local.isTesting = true;
        local.testResult = null;

        try {
            const body = {
                provider: provider.provider,
                baseURL: provider.baseURL,
                defaultModel: provider.defaultModel,
                timeout: provider.timeout || 0,
            };

            if (typeof provider.apiKey != "undefined") {
                body.apiKey = provider.apiKey;
            } else if (provider._originalName) {
                // use the stored api key
                body.name = provider._originalName;
            }

            const result = await app.pb.send("/api/llm/test", {
                method: "POST",
                body,
                requestKey: "llm_test_" + index,
            });

            local.testResult = {
                ok: true,
                text: `${result.model || "OK"} · ${result.durationMs}ms · ${result.usage?.inputTokens || 0} in / ${
                    result.usage?.outputTokens || 0
                } out\n> ${app.utils.truncate(result.text, 200)}`,
            };
        } catch (err) {
            if (err?.isAbort) {
                return;
            }

            const details = Object.entries(err?.response?.data || {})
                .map(([k, v]) => `${k}: ${v?.message}`)
                .join("\n");

            local.testResult = {
                ok: false,
                text: (err?.response?.message || err?.message || "Test failed.") + (details ? "\n" + details : ""),
            };
        }

        local.isTesting = false;
    }

    function remove() {
        pageData.formSettings.llm.providers.splice(index, 1);
        app.store.errors = null;
    }

    return t.details(
        {
            pbEvent: "llmProviderAccordion",
            className: "accordion llm-provider-accordion",
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
            open: !provider._originalName,
        },
        t.summary(
            null,
            t.i({ className: "ri-plug-line", ariaHidden: true }),
            t.span({ className: "txt txt-bold" }, () => provider.name || "(unnamed)"),
            t.span({ className: "txt-hint txt-sm" }, () => provider.provider || ""),
            t.div({ className: "flex-fill" }),
            () => {
                if (
                    pageData.formSettings.llm.defaultProvider
                    && pageData.formSettings.llm.defaultProvider == provider.name
                ) {
                    return t.span({ className: "label info" }, "Default");
                }
            },
            () => {
                if (provider.enabled) {
                    return t.span({ className: "label success" }, "Enabled");
                }
                return t.span({ className: "label" }, "Disabled");
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
                { className: "col-lg-6" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: prefix + "name" }, "Name"),
                    t.input({
                        id: prefix + "name",
                        name: prefix + "name",
                        type: "text",
                        required: true,
                        pattern: "^[\\w\\-]+$",
                        placeholder: "e.g. openai, local-ollama",
                        value: () => provider.name || "",
                        oninput: (e) => {
                            const oldName = provider.name;
                            provider.name = e.target.value.trim();

                            // keep the default provider and the profiles references in sync
                            if (oldName && pageData.formSettings.llm.defaultProvider == oldName) {
                                pageData.formSettings.llm.defaultProvider = provider.name;
                            }
                            for (const profile of pageData.formSettings.llm.profiles || []) {
                                if (oldName && profile.provider == oldName) {
                                    profile.provider = provider.name;
                                }
                            }
                        },
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-6" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: prefix + "provider" }, "Driver"),
                    app.components.select({
                        id: prefix + "provider",
                        name: prefix + "provider",
                        required: true,
                        options: () => pageData.drivers.map((d) => ({ value: d, label: d })),
                        value: () => provider.provider,
                        onchange: (opts) => provider.provider = opts?.[0]?.value || "",
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-6" },
                t.div(
                    { className: "field" },
                    t.label(
                        { htmlFor: prefix + "baseURL" },
                        t.span({ className: "txt" }, "Base URL"),
                        t.small(
                            { className: "txt-hint" },
                            () => provider.provider == "openai-compatible" ? "(required)" : "(optional)",
                        ),
                    ),
                    t.input({
                        id: prefix + "baseURL",
                        name: prefix + "baseURL",
                        type: "url",
                        required: () => provider.provider == "openai-compatible",
                        placeholder: () =>
                            provider.provider == "openai-compatible"
                                ? "e.g. http://localhost:8080/v1"
                                : "Leave empty to use the driver default",
                        value: () => provider.baseURL || "",
                        oninput: (e) => provider.baseURL = e.target.value.trim(),
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-6" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: prefix + "apiKey" }, "API key"),
                    t.input({
                        id: prefix + "apiKey",
                        name: prefix + "apiKey",
                        type: "password",
                        autocomplete: "new-password",
                        value: () => provider.apiKey || "",
                        oninput: (e) => provider.apiKey = e.target.value,
                        onkeyup: (e) => {
                            if (e.key == "Backspace" && typeof provider.apiKey === "undefined") {
                                provider.apiKey = "";
                            }
                        },
                        placeholder: () =>
                            typeof provider.apiKey === "undefined" && provider.hasApiKey ? "* * * * * *" : "",
                    }),
                ),
                t.div({ className: "field-help" }, () => {
                    if (
                        typeof provider.apiKey == "undefined"
                        && provider.hasApiKey
                        && provider._originalName
                        && provider._originalName != provider.name
                    ) {
                        return t.span(
                            { className: "txt-warning" },
                            "Re-enter the API key after renaming the provider.",
                        );
                    }
                    if (typeof provider.apiKey == "undefined" && provider.hasApiKey) {
                        return "Leave untouched to keep the stored key.";
                    }
                    if (provider.hasApiKey && provider.apiKey === "") {
                        return t.span({ className: "txt-warning" }, "The stored key will be removed on save.");
                    }
                }),
            ),
            t.div(
                { className: "col-lg-4" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: prefix + "defaultModel" }, "Default model"),
                    t.input({
                        id: prefix + "defaultModel",
                        name: prefix + "defaultModel",
                        type: "text",
                        list: "llm_models_list_" + index,
                        placeholder: "e.g. gpt-4o-mini",
                        value: () => provider.defaultModel || "",
                        oninput: (e) => provider.defaultModel = e.target.value.trim(),
                    }),
                    t.datalist(
                        { id: "llm_models_list_" + index },
                        () => (provider.models || []).map((m) => t.option({ value: m })),
                    ),
                ),
            ),
            t.div(
                { className: "col-lg-5" },
                t.div(
                    { className: "field" },
                    t.label(
                        { htmlFor: prefix + "models" },
                        t.span({ className: "txt" }, "Models"),
                        t.i({
                            className: "ri-information-line link-hint",
                            ariaDescription: app.attrs.tooltip(
                                "Comma separated list with the provider models (used only as dashboard hints/autocomplete).",
                            ),
                        }),
                    ),
                    t.input({
                        id: prefix + "models",
                        name: prefix + "models",
                        type: "text",
                        placeholder: "e.g. model-a, model-b",
                        value: () => app.utils.joinNonEmpty(provider.models),
                        oninput: (e) => {
                            const newValue = app.utils.splitNonEmpty(e.target.value, ",");
                            if (app.utils.joinNonEmpty(newValue) != app.utils.joinNonEmpty(provider.models)) {
                                provider.models = newValue;
                            }
                        },
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-3" },
                t.div(
                    { className: "field" },
                    t.label(
                        { htmlFor: prefix + "timeout" },
                        t.span({ className: "txt" }, "Timeout"),
                        t.small({ className: "txt-hint" }, "(sec)"),
                    ),
                    t.input({
                        id: prefix + "timeout",
                        name: prefix + "timeout",
                        type: "number",
                        min: 0,
                        step: 1,
                        placeholder: "No timeout",
                        value: () => provider.timeout || "",
                        oninput: (e) => provider.timeout = e.target.value << 0,
                    }),
                ),
            ),
            t.div(
                { className: "col-lg-12" },
                t.div(
                    { className: "flex flex-wrap gap-10" },
                    t.div(
                        { className: "field" },
                        t.input({
                            id: prefix + "enabled",
                            name: prefix + "enabled",
                            type: "checkbox",
                            className: "switch",
                            checked: () => !!provider.enabled,
                            onchange: (e) => provider.enabled = e.target.checked,
                        }),
                        t.label({ htmlFor: prefix + "enabled" }, "Enabled"),
                    ),
                    t.div({ className: "m-l-auto" }),
                    t.button(
                        {
                            type: "button",
                            className: "btn sm transparent secondary",
                            onclick: () => {
                                app.modals.confirm(
                                    `Do you really want to remove the "${provider.name || "unnamed"}" provider?`,
                                    remove,
                                );
                            },
                        },
                        t.i({ className: "ri-delete-bin-7-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "Remove"),
                    ),
                    t.button(
                        {
                            type: "button",
                            className: () => `btn sm outline ${local.isTesting ? "loading" : ""}`,
                            disabled: () => local.isTesting || !provider.provider,
                            onclick: test,
                        },
                        t.i({ className: "ri-flask-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "Test"),
                    ),
                ),
                () => {
                    if (!local.testResult) {
                        return;
                    }

                    return t.div(
                        { className: `alert m-t-sm m-b-0 ${local.testResult.ok ? "success" : "danger"}` },
                        t.i({
                            className: local.testResult.ok ? "ri-checkbox-circle-line" : "ri-error-warning-line",
                            ariaHidden: true,
                        }),
                        t.div({ className: "content llm-test-result" }, local.testResult.text),
                    );
                },
            ),
        ),
    );
}

/**
 * Read-only env provider row.
 *
 * @param  {Object} provider
 * @return {Element}
 */
export function llmEnvProviderRow(provider) {
    const local = store({
        isTesting: false,
        testResult: null,
    });

    async function test() {
        local.isTesting = true;
        local.testResult = null;

        try {
            const result = await app.pb.send("/api/llm/test", {
                method: "POST",
                body: { name: provider.name },
                requestKey: "llm_test_env_" + provider.name,
            });
            local.testResult = { ok: true, text: `${result.model || "OK"} · ${result.durationMs}ms` };
        } catch (err) {
            if (err?.isAbort) {
                return;
            }
            local.testResult = { ok: false, text: err?.response?.message || err?.message || "Test failed." };
        }

        local.isTesting = false;
    }

    return t.div(
        { className: "llm-env-provider" },
        t.i({ className: "ri-terminal-box-line txt-hint", ariaHidden: true }),
        t.strong(null, provider.name),
        t.span({ className: "label sm info" }, "env"),
        t.span({ className: "txt-hint txt-sm" }, provider.provider),
        provider.defaultModel ? t.span({ className: "txt-hint txt-sm" }, "· " + provider.defaultModel) : null,
        provider.baseURL ? t.span({ className: "txt-hint txt-sm" }, "· " + provider.baseURL) : null,
        t.div({ className: "flex-fill" }),
        () => {
            if (local.testResult) {
                return t.span(
                    {
                        className: `label sm ${local.testResult.ok ? "success" : "danger"}`,
                        ariaDescription: app.attrs.tooltip(local.testResult.text, "left"),
                    },
                    local.testResult.ok ? "OK" : "Failed",
                );
            }
        },
        t.button(
            {
                type: "button",
                className: () => `btn sm outline ${local.isTesting ? "loading" : ""}`,
                disabled: () => local.isTesting,
                onclick: test,
            },
            t.i({ className: "ri-flask-line", ariaHidden: true }),
            t.span({ className: "txt" }, "Test"),
        ),
    );
}
