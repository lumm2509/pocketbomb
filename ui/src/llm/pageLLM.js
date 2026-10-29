import "./llmLogPreviewModal";
import { llmFilters } from "./llmFilters";
import { llmLogsList } from "./llmLogsList";
import { llmOverview } from "./llmOverview";
import { llmPlayground } from "./llmPlayground";
import { LLM_RANGE_PRESETS } from "./llmUtils";

const TAB_OVERVIEW = "overview";
const TAB_CALLS = "calls";
const TAB_PLAYGROUND = "playground";

const FILTER_KEYS = ["range", "from", "to", "profile", "model", "provider", "status", "search", "groupBy"];

const DEFAULT_FILTERS = {
    range: "24h",
    from: "",
    to: "",
    profile: "",
    model: "",
    provider: "",
    status: "",
    search: "",
    groupBy: "model",
    user: null,
};

export function pageLLM(route) {
    app.store.title = "LLM";

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
    if (query("authRecord")) {
        initialFilters.user = { authCollection: query("authCollection"), authRecord: query("authRecord") };
    } else if (query("ip")) {
        initialFilters.user = { ip: query("ip") };
    }

    const pageData = store({
        tab: [TAB_OVERVIEW, TAB_CALLS, TAB_PLAYGROUND].includes(query("tab")) ? query("tab") : TAB_OVERVIEW,
        reset: 0,
        filters: initialFilters,
        activeLogIdOrModel: query("logId"),
        isDeleting: false,
        options: {
            profiles: [],
            models: [],
            providers: [],
        },
        get isPlayground() {
            return pageData.tab == TAB_PLAYGROUND;
        },
        get hasActiveFilters() {
            const f = pageData.filters;
            return !!(f.profile || f.model || f.provider || f.status || f.search || f.user
                || f.range != DEFAULT_FILTERS.range);
        },
        resetFilters() {
            const groupBy = pageData.filters.groupBy;
            // update in place to preserve the filters store references
            Object.assign(pageData.filters, DEFAULT_FILTERS, { groupBy });
        },
    });

    loadOptions();

    async function loadOptions() {
        const llm = app.store.settings?.llm || {};

        const profiles = new Set();
        const models = new Set();
        const providers = new Set();

        for (const p of llm.profiles || []) {
            profiles.add(p.name);
            if (p.model) {
                models.add(p.model);
            }
            for (const m of p.allowedModels || []) {
                models.add(m);
            }
        }

        try {
            const result = await app.pb.send("/api/llm/providers", { requestKey: "llm_page_providers" });
            for (const p of (llm.providers || []).concat(result.providers || [])) {
                providers.add(p.name);
                if (p.defaultModel) {
                    models.add(p.defaultModel);
                }
                for (const m of p.models || []) {
                    models.add(m);
                }
            }
        } catch (err) {
            if (!err?.isAbort) {
                console.warn("[llm] failed to load providers:", err);
            }
        }

        pageData.options = {
            profiles: [...profiles].sort(),
            models: [...models].sort(),
            providers: [...providers].sort(),
        };
    }

    function refresh() {
        pageData.reset = Date.now();
    }

    async function deleteAllLogs() {
        pageData.isDeleting = true;

        try {
            await app.pb.send("/api/llm/logs", { method: "DELETE" });
            app.toasts.success("Successfully deleted all LLM logs.");
            refresh();
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        pageData.isDeleting = false;
    }

    function tabBtn(tab, icon, label) {
        return t.button(
            {
                type: "button",
                className: () => `tab-item ${pageData.tab == tab ? "active" : ""}`,
                onclick: () => pageData.tab = tab,
            },
            t.i({ className: icon, ariaHidden: true }),
            t.span({ className: "txt" }, label),
        );
    }

    const watchers = [];

    return t.div(
        {
            pbEvent: "pageLLM",
            className: "page page-llm",
            onmount: () => {
                watchers.push(
                    // sync the url query params
                    watch(() => {
                        const params = { tab: pageData.tab == TAB_OVERVIEW ? "" : pageData.tab };
                        for (const key of FILTER_KEYS) {
                            const val = pageData.filters[key];
                            params[key] = val == DEFAULT_FILTERS[key] ? "" : val;
                        }
                        if (pageData.filters.range != "custom") {
                            params.from = "";
                            params.to = "";
                        }
                        params.authCollection = pageData.filters.user?.authCollection || "";
                        params.authRecord = pageData.filters.user?.authRecord || "";
                        params.ip = pageData.filters.user?.ip || "";
                        app.utils.replaceHashQueryParams(params);
                    }),
                    watch(
                        () => pageData.activeLogIdOrModel,
                        (idOrModel) => {
                            const id = typeof idOrModel == "string" ? idOrModel : idOrModel?.id;

                            app.utils.replaceHashQueryParams({ logId: id || "" });

                            if (id) {
                                // force close any previous modal
                                app.modals.close(null, true);

                                app.modals.openLLMLogPreview(id, {
                                    onafterclose: () => {
                                        pageData.activeLogIdOrModel = null;
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
                t.nav({ className: "breadcrumbs" }, t.div(null, "LLM")),
                t.div(
                    { className: "inline-flex gap-sm" },
                    t.a(
                        {
                            href: "#/settings/llm",
                            className: "btn circle transparent secondary tooltip-right",
                            ariaLabel: app.attrs.tooltip("LLM settings"),
                        },
                        t.i({ className: "ri-settings-3-line", ariaHidden: true }),
                    ),
                    app.components.refreshButton({ onclick: refresh }),
                    t.button(
                        {
                            type: "button",
                            className: () => `btn circle transparent secondary ${pageData.isDeleting ? "loading" : ""}`,
                            disabled: () => pageData.isDeleting,
                            ariaLabel: app.attrs.tooltip("Delete all LLM logs"),
                            onclick: () => {
                                app.modals.confirm(
                                    "Do you really want to delete all LLM logs?\nThe profile quotas usage will be also reset.",
                                    () => deleteAllLogs(),
                                    null,
                                    { yesButton: "Yes, delete" },
                                );
                            },
                        },
                        t.i({ className: "ri-delete-bin-7-line", ariaHidden: true }),
                    ),
                ),
                t.nav(
                    { className: "tabs-header llm-tabs m-l-auto" },
                    tabBtn(TAB_OVERVIEW, "ri-dashboard-line", "Overview"),
                    tabBtn(TAB_CALLS, "ri-list-check", "Calls"),
                    tabBtn(TAB_PLAYGROUND, "ri-chat-ai-line", "Playground"),
                ),
            ),
            () => {
                if (app.store.settings?.llm && !app.store.settings.llm.logs?.enabled) {
                    return t.div(
                        { className: "alert warning m-b-sm" },
                        t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                        t.div(
                            { className: "content" },
                            "The LLM usage logs are disabled so no new calls will be recorded. ",
                            t.a({ href: "#/settings/llm", className: "txt-bold" }, "Enable them in the LLM settings"),
                            ".",
                        ),
                    );
                }
            },
            () => {
                if (pageData.isPlayground) {
                    return llmPlayground(pageData);
                }
                return llmFilters(pageData);
            },
            () => {
                if (pageData.tab == TAB_CALLS) {
                    return llmLogsList(pageData);
                }
                if (pageData.tab == TAB_OVERVIEW) {
                    return llmOverview(pageData);
                }
            },
            t.footer({ className: "page-footer" }, app.components.credits()),
        ),
    );
}
