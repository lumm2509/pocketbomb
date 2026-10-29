import { llmBuildFilter, llmCacheRecords, llmCallerElem, llmFormatNumber, llmResolveRange } from "./llmUtils";

const LIMIT = 10;

/**
 * The LLM dashboard top users table.
 *
 * @param  {Object} pageData
 * @return {Element}
 */
export function llmTopUsers(pageData) {
    const filters = pageData.filters;

    const data = store({
        isLoading: false,
        by: "user",
        sort: "tokens",
        items: [],
    });

    async function load() {
        data.isLoading = true;

        try {
            const range = llmResolveRange(filters);

            let filter = llmBuildFilter(filters, range);
            if (data.by == "ip") {
                // the IP grouping is for guests only
                filter = filter ? `(${filter})&&authRecord=''` : "authRecord=''";
            }

            const items = await app.pb.send("/api/llm/logs/top-users", {
                query: { by: data.by, sort: data.sort, limit: LIMIT, filter },
                requestKey: "llm_top_users",
            });

            llmCacheRecords(items.map((item) => item.record).filter(Boolean));

            data.items = items;
            data.isLoading = false;
        } catch (err) {
            if (!err?.isAbort) {
                data.isLoading = false;
                app.checkApiError(err);
            }
        }
    }

    function filterBy(item) {
        if (data.by == "user" && item.authRecord) {
            filters.user = { authCollection: item.authCollection, authRecord: item.authRecord };
        } else if (item.ip) {
            filters.user = { ip: item.ip };
        }
    }

    function toggleBtn(key, value, label) {
        return t.button(
            {
                type: "button",
                className: () => `btn sm ${data[key] == value ? "secondary" : "transparent secondary"}`,
                onclick: () => data[key] = value,
            },
            t.span({ className: "txt" }, label),
        );
    }

    const watchers = [];

    return t.section(
        {
            pbEvent: "llmTopUsers",
            className: "llm-panel llm-top-users",
            onmount: () => {
                watchers.push(
                    watch(
                        () => [pageData.reset, JSON.stringify(filters), data.by, data.sort],
                        () => load(),
                    ),
                );
            },
            onunmount: () => {
                watchers.forEach((w) => w?.unwatch());
            },
        },
        t.header(
            { className: "llm-panel-header" },
            t.div(
                { className: "llm-chart-title" },
                t.i({ className: "ri-group-line", ariaHidden: true }),
                t.span({ className: "txt" }, () => (data.by == "user" ? "Top users" : "Top guest IPs")),
                t.span({ className: "loader sm", hidden: () => !data.isLoading }),
            ),
            t.div(
                { className: "inline-flex gap-5 m-l-auto" },
                t.div(
                    { className: "llm-toggle" },
                    toggleBtn("by", "user", "Users"),
                    toggleBtn("by", "ip", "Guest IPs"),
                ),
                t.div(
                    { className: "llm-toggle" },
                    toggleBtn("sort", "tokens", "By tokens"),
                    toggleBtn("sort", "requests", "By requests"),
                ),
            ),
        ),
        t.div(
            { className: "table-wrapper" },
            t.table(
                { className: "llm-top-users-table" },
                t.thead(
                    null,
                    t.tr(
                        null,
                        t.th(null, () => (data.by == "user" ? "User" : "IP")),
                        t.th({ className: "txt-right" }, "Requests"),
                        t.th({ className: "txt-right" }, "Errors"),
                        t.th({ className: "txt-right" }, "Denied"),
                        t.th({ className: "txt-right" }, "Input tokens"),
                        t.th({ className: "txt-right" }, "Output tokens"),
                        t.th({ className: "txt-right" }, "Total tokens"),
                        t.th(null, "Last call"),
                        t.th({ className: "col-meta" }),
                    ),
                ),
                t.tbody(null, () => {
                    if (!data.items.length) {
                        return t.tr(
                            null,
                            t.td(
                                { colSpan: 99, className: "txt-center txt-hint" },
                                () => (data.isLoading ? t.span({ className: "skeleton-loader" }) : "No data found."),
                            ),
                        );
                    }

                    return data.items.map((item) => {
                        return t.tr(
                            { rid: (item.authCollection || "") + "/" + (item.authRecord || item.ip) },
                            t.td(
                                { className: "min-width" },
                                data.by == "user"
                                    ? llmCallerElem(item, item.record)
                                    : llmCallerElem({ ip: item.ip }),
                            ),
                            t.td({ className: "txt-right" }, llmFormatNumber(item.requests)),
                            t.td(
                                { className: `txt-right ${item.errors ? "txt-danger" : "txt-hint"}` },
                                llmFormatNumber(item.errors),
                            ),
                            t.td(
                                { className: `txt-right ${item.denied ? "txt-warning" : "txt-hint"}` },
                                llmFormatNumber(item.denied),
                            ),
                            t.td({ className: "txt-right" }, llmFormatNumber(item.inputTokens)),
                            t.td({ className: "txt-right" }, llmFormatNumber(item.outputTokens)),
                            t.td({ className: "txt-right txt-bold" }, llmFormatNumber(item.totalTokens)),
                            t.td(
                                { className: "col-field-type-date" },
                                app.components.formattedDate({ value: item.lastCall, short: true }),
                            ),
                            t.td(
                                { className: "col-meta" },
                                t.button(
                                    {
                                        type: "button",
                                        className: "btn sm circle transparent secondary",
                                        ariaLabel: app.attrs.tooltip("Filter the dashboard by this caller", "left"),
                                        onclick: () => filterBy(item),
                                    },
                                    t.i({ className: "ri-filter-3-line", ariaHidden: true }),
                                ),
                            ),
                        );
                    });
                }),
            ),
        ),
    );
}
