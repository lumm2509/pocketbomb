import {
    LLM_LOG_LIST_FIELDS,
    llmBuildFilter,
    llmCallerElem,
    llmFormatDuration,
    llmFormatNumber,
    llmLoadRecords,
    llmResolveRange,
    llmStatusLabel,
} from "./llmUtils";

const perPage = 40;

/**
 * The LLM calls (logs) table.
 *
 * @param  {Object} pageData
 * @return {Element}
 */
export function llmLogsList(pageData) {
    const filters = pageData.filters;

    const data = store({
        isLoading: false,
        logs: [],
        lastLoadCount: 0,
        lastPage: 1,
        totalItems: null,
        get canLoadMore() {
            return data.lastLoadCount >= perPage;
        },
    });

    // used as a loose guard to prevent the new logs from shifting the older pages
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

            const result = await app.pb.send("/api/llm/logs", {
                query: {
                    page,
                    perPage,
                    skipTotal: page > 1 ? 1 : 0,
                    sort: "-created,-id",
                    fields: LLM_LOG_LIST_FIELDS,
                    filter: llmBuildFilter(filters, loadRange),
                },
                requestKey: "llm_logs_list",
            });

            if (result.page == 1) {
                data.logs = [];
                data.totalItems = result.totalItems;
            }

            data.lastPage = result.page;
            data.lastLoadCount = result.items.length;

            for (const item of result.items) {
                app.utils.pushOrReplaceObject(data.logs, item);
            }

            data.isLoading = false;

            llmLoadRecords(result.items);
        } catch (err) {
            if (!err?.isAbort) {
                data.isLoading = false;
                app.checkApiError(err);
            }
        }
    }

    function openLog(log) {
        pageData.activeLogIdOrModel = log.id;
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
            pbEvent: "llmLogsList",
            className: "page-table-wrapper llm-logs-wrapper",
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
            { className: "llm-logs-table" },
            t.thead(
                null,
                t.tr(
                    null,
                    th("ri-calendar-line", "Created", "col-field-type-date"),
                    th("ri-route-line", "Profile"),
                    th("ri-cpu-line", "Model"),
                    th("ri-user-line", "Caller"),
                    th("ri-pulse-line", "Status"),
                    th("ri-coin-line", "Tokens (in / out)", "txt-right"),
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
                    if (!data.logs.length) {
                        return t.tr(
                            null,
                            t.td({ colSpan: 99 }, () => {
                                if (data.isLoading) {
                                    return t.span({ className: "skeleton-loader" });
                                }

                                return t.div(
                                    { className: "sticky-content txt-center txt-hint" },
                                    t.div({ className: "txt-bold" }, "No LLM calls found."),
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

                    return data.logs.map((log) => {
                        return t.tr(
                            {
                                rid: log.id,
                                tabIndex: 0,
                                role: "button",
                                className: "handle",
                                onclick: () => openLog(log),
                                onkeypress: (e) => {
                                    if (e.key == "Enter" || e.key == " ") {
                                        e.preventDefault();
                                        openLog(log);
                                    }
                                },
                            },
                            t.td(
                                { className: "col-field-type-date" },
                                app.components.formattedDate({ value: log.created, short: true }),
                            ),
                            t.td(
                                null,
                                log.profile
                                    ? t.span({ className: "label" }, log.profile)
                                    : t.span({ className: "txt-hint" }, "N/A"),
                            ),
                            t.td(
                                null,
                                t.div({ className: "txt-ellipsis" }, log.model || "N/A"),
                                t.div(
                                    { className: "txt-hint txt-sm" },
                                    log.provider,
                                    log.stream ? t.span({ className: "label sm m-l-5" }, "stream") : null,
                                ),
                            ),
                            t.td(null, llmCallerElem(log)),
                            t.td(null, llmStatusLabel(log.status, log.error)),
                            t.td(
                                { className: "txt-right txt-nowrap" },
                                llmFormatNumber(log.inputTokens),
                                t.span({ className: "txt-hint" }, " / "),
                                llmFormatNumber(log.outputTokens),
                            ),
                            t.td(
                                { className: "txt-right txt-nowrap" },
                                log.durationMs
                                    ? llmFormatDuration(log.durationMs)
                                    : t.span({ className: "txt-hint" }, "-"),
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
