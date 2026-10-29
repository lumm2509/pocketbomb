import { settingsSidebar } from "../settingsSidebar";
import { llmProfileAccordion } from "./llmProfileAccordion";
import { llmEnvProviderRow, llmProviderAccordion } from "./llmProviderAccordion";

export function pageLLMSettings(route) {
    app.store.title = "LLM settings";

    const data = store({
        isLoading: false,
        isSaving: false,
        formSettings: null,
        envProviders: [],
        drivers: [],
        initSerialized: "null",
        get hasChanges() {
            return data.initSerialized != JSON.stringify(data.formSettings);
        },
        // settings and env providers (settings take precedence)
        get allProviders() {
            const result = [];
            for (const p of data.formSettings?.llm?.providers || []) {
                if (p.name) {
                    result.push(p);
                }
            }
            for (const p of data.envProviders) {
                if (!result.find((r) => r.name == p.name)) {
                    result.push(p);
                }
            }
            return result;
        },
    });

    loadSettings();

    async function loadSettings() {
        data.isLoading = true;

        try {
            const [settings, providers] = await Promise.all([
                app.pb.settings.getAll(),
                app.pb.send("/api/llm/providers", { requestKey: "llm_settings_providers" }),
            ]);

            data.drivers = providers?.drivers || [];

            init(settings);

            data.isLoading = false;
        } catch (err) {
            if (!err.isAbort) {
                app.checkApiError(err);
                // data.isLoading = false; don't reset in case of a server error
            }
        }
    }

    // returns the llm settings ready for submission
    function serialize() {
        const llm = JSON.parse(JSON.stringify(data.formSettings.llm));

        for (const p of llm.providers || []) {
            delete p.hasApiKey;
            delete p._originalName;
            // note: undefined apiKey is excluded from the JSON to preserve the stored key
        }
        for (const p of llm.profiles || []) {
            delete p._originalName;
        }

        return { llm };
    }

    async function save() {
        if (data.isSaving || !data.hasChanges) {
            return;
        }

        data.isSaving = true;

        try {
            const settings = await app.pb.settings.update(serialize());
            init(settings);

            app.toasts.success("Successfully saved LLM settings.");
        } catch (err) {
            app.checkApiError(err);
        }

        data.isSaving = false;
    }

    function init(settings = {}) {
        // refresh local app settings
        app.store.settings = JSON.parse(JSON.stringify(settings));

        const llm = JSON.parse(JSON.stringify(settings?.llm || {}));

        data.envProviders = llm.envProviders || [];
        delete llm.envProviders;

        llm.defaultProvider = llm.defaultProvider || "";
        llm.providers = llm.providers || [];
        llm.profiles = llm.profiles || [];
        llm.logs = llm.logs || { enabled: false, storeContent: false, maxDays: 0 };

        for (const p of llm.providers) {
            p._originalName = p.name;
            p.models = p.models || [];
        }
        for (const p of llm.profiles) {
            p._originalName = p.name;
            p.allowedModels = p.allowedModels || [];
            p.quotas = p.quotas || {};
            p.quotas.perUser = p.quotas.perUser || { requests: 0, tokens: 0, window: "" };
            p.quotas.perGuestIP = p.quotas.perGuestIP || { requests: 0, tokens: 0, window: "" };
        }

        data.formSettings = { llm };

        data.initSerialized = JSON.stringify(data.formSettings);
    }

    function reset() {
        data.formSettings = JSON.parse(data.initSerialized);
        app.store.errors = null;
    }

    function addProvider() {
        data.formSettings.llm.providers.push({
            name: "",
            provider: data.drivers.includes("openai") ? "openai" : data.drivers[0] || "",
            baseURL: "",
            apiKey: "",
            defaultModel: "",
            models: [],
            timeout: 0,
            enabled: true,
        });
    }

    function addProfile() {
        data.formSettings.llm.profiles.push({
            name: "",
            provider: "",
            model: "",
            allowedModels: [],
            systemPrompt: "",
            maxTokens: 0,
            temperature: null,
            allowClientOverrides: false,
            rule: null,
            quotas: {
                perUser: { requests: 0, tokens: 0, window: "" },
                perGuestIP: { requests: 0, tokens: 0, window: "" },
            },
            storeContent: null,
        });
    }

    function sectionHeader(icon, title, description, ...actions) {
        return t.div(
            { className: "llm-section-header" },
            t.i({ className: icon + " txt-hint", ariaHidden: true }),
            t.div(
                { className: "flex-fill" },
                t.h6(null, title),
                description ? t.div({ className: "txt-hint txt-sm" }, description) : null,
            ),
            ...actions,
        );
    }

    function providersSection() {
        const llm = data.formSettings.llm;

        return t.div(
            { className: "col-lg-12 llm-settings-section" },
            sectionHeader(
                "ri-plug-line",
                "Providers",
                "The LLM API connections. Providers could be also loaded from env variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, XAI_API_KEY, OLLAMA_HOST).",
            ),
            t.div(
                { className: "accordions" },
                () => llm.providers.map((p, i) => llmProviderAccordion(data, p, i)),
            ),
            () => {
                if (!data.envProviders.length) {
                    return;
                }
                return t.div(
                    { className: "flex flex-wrap gap-10" },
                    data.envProviders.map((p) => llmEnvProviderRow(p)),
                );
            },
            () => {
                if (!llm.providers.length && !data.envProviders.length) {
                    return t.div({ className: "txt-hint txt-center p-sm" }, "No LLM providers configured yet.");
                }
            },
            t.div(
                { className: "flex flex-wrap gap-10" },
                t.button(
                    { type: "button", className: "btn sm secondary", onclick: addProvider },
                    t.i({ className: "ri-add-line", ariaHidden: true }),
                    t.span({ className: "txt" }, "Add provider"),
                ),
                t.div({ className: "flex-fill" }),
                t.div(
                    { className: "field llm-default-provider" },
                    t.label({ htmlFor: "llm.defaultProvider" }, "Default provider"),
                    app.components.select({
                        id: "llm.defaultProvider",
                        name: "llm.defaultProvider",
                        placeholder: "Auto (first enabled)",
                        options: () =>
                            [{ value: "", label: "Auto (first enabled)" }].concat(
                                data.allProviders.map((p) => ({
                                    value: p.name,
                                    label: p.name + (p.source == "env" ? " (env)" : ""),
                                })),
                            ),
                        value: () => llm.defaultProvider || "",
                        onchange: (opts) => llm.defaultProvider = opts?.[0]?.value || "",
                    }),
                ),
            ),
        );
    }

    function profilesSection() {
        const llm = data.formSettings.llm;

        return t.div(
            { className: "col-lg-12 llm-settings-section" },
            sectionHeader(
                "ri-route-line",
                "Profiles",
                t.span(
                    null,
                    "Named gateway routes exposed via ",
                    t.code(null, "POST /api/llm/{profile}/chat"),
                    " with their own access rule, defaults, limits and quotas.",
                ),
            ),
            t.div(
                { className: "accordions" },
                () => llm.profiles.map((p, i) => llmProfileAccordion(data, p, i)),
            ),
            () => {
                if (!llm.profiles.length) {
                    return t.div({ className: "txt-hint txt-center p-sm" }, "No LLM profiles configured yet.");
                }
            },
            t.div(
                null,
                t.button(
                    { type: "button", className: "btn sm secondary", onclick: addProfile },
                    t.i({ className: "ri-add-line", ariaHidden: true }),
                    t.span({ className: "txt" }, "Add profile"),
                ),
            ),
        );
    }

    function logsSection() {
        const logs = data.formSettings.llm.logs;

        return t.div(
            { className: "col-lg-12 llm-settings-section" },
            sectionHeader(
                "ri-file-list-3-line",
                "Usage logs",
                t.span(
                    null,
                    "The LLM calls are stored in the auxiliary database and are visible in the ",
                    t.a({ href: "#/llm" }, "LLM dashboard"),
                    ". The profile quotas require the logs to be enabled.",
                ),
            ),
            t.div(
                { className: "grid" },
                t.div(
                    { className: "col-lg-6" },
                    t.div(
                        { className: "field" },
                        t.input({
                            id: "llm.logs.enabled",
                            name: "llm.logs.enabled",
                            type: "checkbox",
                            className: "switch",
                            checked: () => !!logs.enabled,
                            onchange: (e) => {
                                logs.enabled = e.target.checked;
                                if (logs.enabled && !logs.maxDays) {
                                    logs.maxDays = 7;
                                }
                            },
                        }),
                        t.label({ htmlFor: "llm.logs.enabled" }, "Enable LLM usage logs"),
                    ),
                ),
                t.div(
                    { className: "col-lg-6" },
                    t.div(
                        { className: "field" },
                        t.label({ htmlFor: "llm.logs.maxDays" }, "Max days retention"),
                        t.input({
                            id: "llm.logs.maxDays",
                            name: "llm.logs.maxDays",
                            type: "number",
                            min: 0,
                            step: 1,
                            required: () => !!logs.enabled,
                            disabled: () => !logs.enabled,
                            value: () => logs.maxDays || "",
                            oninput: (e) => logs.maxDays = e.target.value << 0,
                        }),
                    ),
                ),
                t.div(
                    { className: "col-lg-12" },
                    t.div(
                        { className: "field" },
                        t.input({
                            id: "llm.logs.storeContent",
                            name: "llm.logs.storeContent",
                            type: "checkbox",
                            className: "switch",
                            disabled: () => !logs.enabled,
                            checked: () => !!logs.storeContent,
                            onchange: (e) => logs.storeContent = e.target.checked,
                        }),
                        t.label(
                            { htmlFor: "llm.logs.storeContent" },
                            "Store the requests and responses content (messages, tools, etc.)",
                        ),
                    ),
                    () => {
                        if (!logs.storeContent || !logs.enabled) {
                            return;
                        }
                        return t.div(
                            { className: "alert warning m-t-sm m-b-0" },
                            t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                            t.div(
                                { className: "content" },
                                "The prompts and completions may contain personal or sensitive user data. ",
                                "Make sure that storing them complies with your privacy policy. ",
                                "Individual profiles could override this option.",
                            ),
                        );
                    },
                ),
            ),
        );
    }

    return t.div(
        { pbEvent: "pageLLMSettings", className: "page page-llm-settings" },
        settingsSidebar(),
        t.div(
            { className: "page-content full-height" },
            t.header(
                { className: "page-header" },
                t.nav(
                    { className: "breadcrumbs" },
                    t.div({ className: "breadcrumb-item" }, "Settings"),
                    t.div({ className: "breadcrumb-item" }, () => app.store.title),
                ),
                t.div(
                    { className: "page-header-primary-btns" },
                    t.a(
                        { href: "#/llm", className: "btn sm transparent secondary" },
                        t.i({ className: "ri-bar-chart-box-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "LLM dashboard"),
                    ),
                ),
            ),
            t.div(
                { className: "wrapper m-b-base" },
                () => {
                    if (data.isLoading) {
                        return t.div({ className: "block txt-center" }, t.span({ className: "loader lg" }));
                    }

                    return t.form(
                        {
                            pbEvent: "llmSettingsForm",
                            className: "grid llm-settings-form",
                            inert: () => data.isSaving,
                            onsubmit: (e) => {
                                e.preventDefault();
                                save();
                            },
                        },
                        providersSection(),
                        t.div({ className: "col-lg-12" }, t.hr()),
                        profilesSection(),
                        t.div({ className: "col-lg-12" }, t.hr()),
                        logsSection(),
                        t.div({ className: "col-lg-12" }, t.hr()),
                        t.div(
                            { className: "col-lg-12" },
                            t.div(
                                { className: "flex" },
                                t.div({ className: "m-r-auto" }),
                                t.button(
                                    {
                                        type: "button",
                                        hidden: () => !data.hasChanges,
                                        className: "btn transparent secondary",
                                        onclick: reset,
                                    },
                                    t.span({ className: "txt" }, "Cancel"),
                                ),
                                t.button(
                                    {
                                        className: () => `btn expanded-lg ${data.isSaving ? "loading" : ""}`,
                                        disabled: () => !data.hasChanges || data.isSaving,
                                    },
                                    t.span({ className: "txt" }, "Save changes"),
                                ),
                            ),
                        ),
                    );
                },
            ),
            t.footer({ className: "page-footer" }, app.components.credits()),
        ),
    );
}
