import {
    LLM_RANGE_PRESETS,
    LLM_SEARCH_AUTOCOMPLETE,
    LLM_STATUSES,
    llmAuthCollection,
    llmCachedRecord,
    llmRecordLabel,
} from "./llmUtils";

/**
 * The LLM dashboard filters bar (date range, dimensions and search).
 *
 * @param  {Object} pageData
 * @return {Element}
 */
export function llmFilters(pageData) {
    const filters = pageData.filters;

    function withCurrent(options, current, allLabel) {
        const result = [{ value: "", label: allLabel }];
        for (const opt of options) {
            result.push({ value: opt, label: opt });
        }
        if (current && !options.includes(current)) {
            result.push({ value: current, label: current });
        }
        return result;
    }

    function dimensionSelect(key, allLabel, optionsFunc) {
        return t.div(
            { className: "field llm-filter-field" },
            app.components.select({
                id: "llm_filter_" + key,
                className: "sm",
                required: true,
                searchThreshold: 8,
                options: () => optionsFunc(),
                value: () => filters[key] || "",
                onchange: (opts) => {
                    filters[key] = opts?.[0]?.value || "";
                },
            }),
        );
    }

    return t.div(
        { pbEvent: "llmFilters", className: "llm-filters" },
        t.div(
            { className: "llm-filters-row" },
            t.div(
                { className: "field llm-filter-field llm-range-field" },
                app.components.select({
                    id: "llm_filter_range",
                    required: true,
                    options: LLM_RANGE_PRESETS.map((p) => ({
                        value: p.value,
                        label: p.label,
                        selected: () =>
                            t.span(
                                { className: "inline-flex gap-5" },
                                t.i({ className: "ri-calendar-line txt-hint", ariaHidden: true }),
                                t.span({ className: "txt" }, p.label),
                            ),
                    })),
                    value: () => filters.range,
                    onchange: (opts) => {
                        const val = opts?.[0]?.value || "24h";
                        if (val == "custom" && !filters.from) {
                            const now = new Date();
                            filters.to = app.utils.toDatetimeLocalInputValue(now);
                            filters.from = app.utils.toDatetimeLocalInputValue(new Date(now.getTime() - 86400000));
                        }
                        filters.range = val;
                    },
                }),
            ),
            () => {
                if (filters.range != "custom") {
                    return;
                }

                return t.div(
                    { className: "llm-custom-range" },
                    t.div(
                        { className: "field llm-filter-field" },
                        t.input({
                            type: "datetime-local",
                            ariaLabel: "From",
                            title: "From",
                            value: () => filters.from || "",
                            onchange: (e) => filters.from = e.target.value,
                        }),
                    ),
                    t.span({ className: "txt-hint" }, "-"),
                    t.div(
                        { className: "field llm-filter-field" },
                        t.input({
                            type: "datetime-local",
                            ariaLabel: "To",
                            title: "To",
                            value: () => filters.to || "",
                            onchange: (e) => filters.to = e.target.value,
                        }),
                    ),
                );
            },
            dimensionSelect(
                "profile",
                "All profiles",
                () => withCurrent(pageData.options.profiles, filters.profile, "All profiles"),
            ),
            dimensionSelect(
                "model",
                "All models",
                () => withCurrent(pageData.options.models, filters.model, "All models"),
            ),
            dimensionSelect(
                "provider",
                "All providers",
                () => withCurrent(pageData.options.providers, filters.provider, "All providers"),
            ),
            dimensionSelect("status", "Any status", () => {
                return [{ value: "", label: "Any status" }].concat(
                    LLM_STATUSES.map((s) => ({ value: s.value, label: s.label })),
                );
            }),
            () => {
                if (!filters.user) {
                    return;
                }

                return t.span(
                    { className: "label llm-user-filter" },
                    t.i({
                        className: filters.user.authRecord ? "ri-user-line" : "ri-global-line",
                        ariaHidden: true,
                    }),
                    t.span({ className: "txt" }, () => {
                        if (filters.user.authRecord) {
                            const record = llmCachedRecord(filters.user.authCollection, filters.user.authRecord);
                            const collection = llmAuthCollection(filters.user.authCollection);
                            return `${collection?.name || filters.user.authCollection}: ${
                                llmRecordLabel(record) || filters.user.authRecord
                            }`;
                        }
                        return "Guest IP: " + filters.user.ip;
                    }),
                    t.button(
                        {
                            type: "button",
                            className: "btn xs circle transparent secondary",
                            ariaLabel: app.attrs.tooltip("Clear user filter"),
                            onclick: () => filters.user = null,
                        },
                        t.i({ className: "ri-close-line", ariaHidden: true }),
                    ),
                );
            },
            t.button(
                {
                    type: "button",
                    hidden: () => !pageData.hasActiveFilters,
                    className: "btn sm transparent secondary",
                    onclick: () => pageData.resetFilters(),
                },
                t.span({ className: "txt" }, "Reset filters"),
            ),
        ),
        app.components.searchbar({
            className: "llm-searchbar",
            historyKey: "pbLLMLogsSearchHistory",
            placeholder: "Search term or filter like `status = \"error\" && durationMs > 1000`",
            value: () => filters.search || "",
            onsubmit: (val) => filters.search = val,
            autocomplete: LLM_SEARCH_AUTOCOMPLETE,
        }),
    );
}
