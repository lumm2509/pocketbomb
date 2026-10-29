import { llmChart } from "./llmChart";
import { llmTopUsers } from "./llmTopUsers";
import {
    LLM_GROUP_BY_OPTIONS,
    llmBuildFilter,
    llmFormatDuration,
    llmFormatNumber,
    llmParseDate,
    llmResolveRange,
} from "./llmUtils";

const MAX_GROUPS = 7; // + "Other"

const STATUS_COLORS = {
    success: "--successColor",
    error: "--dangerColor",
    denied: "--warningColor",
    limited: "--infoColor",
};

/**
 * The LLM dashboard overview tab (KPIs, charts and top users).
 *
 * @param  {Object} pageData
 * @return {Element}
 */
export function llmOverview(pageData) {
    const filters = pageData.filters;

    const data = store({
        isLoading: false,
        timestamps: [],
        bucketSeconds: 3600,
        grouped: [],
        totals: [],
        p95: null,
        get kpis() {
            const result = {
                requests: 0,
                calls: 0,
                errors: 0,
                denied: 0,
                inputTokens: 0,
                outputTokens: 0,
                avgDurationMs: 0,
            };

            let durationSum = 0;
            for (const item of data.totals) {
                const calls = item.requests - item.denied;
                result.requests += item.requests;
                result.calls += calls;
                result.errors += item.errors;
                result.denied += item.denied;
                result.inputTokens += item.inputTokens;
                result.outputTokens += item.outputTokens;
                durationSum += (item.avgDurationMs || 0) * calls;
            }

            result.avgDurationMs = result.calls > 0 ? durationSum / result.calls : 0;
            result.errorRate = result.calls > 0 ? (result.errors / result.calls) * 100 : 0;

            return result;
        },
    });

    // returns the stable color of a group value
    function groupColor(groupBy, value, fallbackIndex) {
        if (groupBy == "status") {
            return STATUS_COLORS[value] || "--surfaceAlt5Color";
        }

        if (value == "__other__") {
            return "--llmSeriesOther";
        }

        // use the position in the (stable) options list so that
        // the color follows the entity and not its rank
        const list = groupBy == "model"
            ? pageData.options.models
            : groupBy == "profile"
            ? pageData.options.profiles
            : groupBy == "provider"
            ? pageData.options.providers
            : [];
        let idx = list.indexOf(value);
        if (idx < 0) {
            idx = list.length + fallbackIndex;
        }

        return "--llmSeries" + ((idx % 8) + 1);
    }

    function groupLabel(groupBy, value) {
        if (value == "__other__") {
            return "Other";
        }
        if (!value) {
            return groupBy == "profile" ? "(no profile)" : "(empty)";
        }
        return value;
    }

    function bucketIndexer(stats) {
        const result = new Map();
        for (const item of stats) {
            const ts = llmParseDate(item.date);
            if (!result.has(ts)) {
                result.set(ts, []);
            }
            result.get(ts).push(item);
        }
        return result;
    }

    function fillTimestamps(range) {
        const bucket = range.bucketSeconds;
        const from = Math.floor(range.from.getTime() / 1000 / bucket) * bucket;
        const to = Math.floor(range.to.getTime() / 1000 / bucket) * bucket;

        const result = [];
        for (let ts = from; ts <= to && result.length < 2000; ts += bucket) {
            result.push(ts);
        }
        return result;
    }

    async function loadP95(filter, calls) {
        if (calls <= 0) {
            return null;
        }

        // nearest-rank percentile (descending position)
        const rank = calls - Math.ceil(0.95 * calls) + 1;

        const callsFilter = "(status='success'||status='error')";

        const result = await app.pb.send("/api/llm/logs", {
            query: {
                page: rank,
                perPage: 1,
                skipTotal: 1,
                sort: "-durationMs",
                fields: "durationMs",
                filter: filter ? `${filter}&&${callsFilter}` : callsFilter,
            },
            requestKey: "llm_overview_p95",
        });

        return result.items?.[0]?.durationMs ?? null;
    }

    async function load() {
        data.isLoading = true;

        try {
            const range = llmResolveRange(filters);
            const filter = llmBuildFilter(filters, range);

            const [grouped, totals] = await Promise.all([
                filters.groupBy
                    ? app.pb.send("/api/llm/logs/stats", {
                        query: { interval: range.interval, groupBy: filters.groupBy, filter },
                        requestKey: "llm_overview_stats_grouped",
                    })
                    : null,
                app.pb.send("/api/llm/logs/stats", {
                    query: { interval: range.interval, filter },
                    requestKey: "llm_overview_stats",
                }),
            ]);

            const calls = totals.reduce((sum, item) => sum + item.requests - item.denied, 0);
            const p95 = await loadP95(filter, calls);

            data.bucketSeconds = range.bucketSeconds;
            data.timestamps = fillTimestamps(range);
            data.grouped = grouped || [];
            data.totals = totals;
            data.p95 = p95;
            data.isLoading = false;
        } catch (err) {
            if (!err?.isAbort) {
                data.isLoading = false;
                app.checkApiError(err);
            }
        }
    }

    function requestsChartData() {
        const timestamps = data.timestamps;
        const series = [];

        const totalsByTs = bucketIndexer(data.totals);

        if (filters.groupBy && data.grouped.length) {
            // sort the groups by their total requests
            const groupTotals = new Map();
            for (const item of data.grouped) {
                groupTotals.set(item.group, (groupTotals.get(item.group) || 0) + item.requests);
            }
            const sortedGroups = [...groupTotals.keys()].sort((a, b) => groupTotals.get(b) - groupTotals.get(a));
            const visible = sortedGroups.length > MAX_GROUPS + 1 ? sortedGroups.slice(0, MAX_GROUPS) : sortedGroups;
            const hasOther = visible.length < sortedGroups.length;

            const groupedByTs = bucketIndexer(data.grouped);

            const keys = visible.slice();
            if (hasOther) {
                keys.push("__other__");
            }

            keys.forEach((group, i) => {
                series.push({
                    label: groupLabel(filters.groupBy, group),
                    color: groupColor(filters.groupBy, group, i),
                    kind: "bars",
                    stacked: true,
                    values: timestamps.map((ts) => {
                        const items = groupedByTs.get(ts) || [];
                        if (group == "__other__") {
                            return items
                                .filter((item) => !visible.includes(item.group))
                                .reduce((sum, item) => sum + item.requests, 0);
                        }
                        return items.find((item) => item.group == group)?.requests || 0;
                    }),
                });
            });
        } else {
            series.push({
                label: "Requests",
                color: "--llmSeries1",
                kind: "bars",
                stacked: true,
                values: timestamps.map((ts) => totalsByTs.get(ts)?.[0]?.requests || 0),
            });
        }

        if (filters.groupBy != "status") {
            series.push({
                label: "Errors",
                color: "--dangerColor",
                kind: "line",
                values: timestamps.map((ts) => totalsByTs.get(ts)?.[0]?.errors || 0),
            });
            series.push({
                label: "Denied/limited",
                color: "--surfaceTxtHintColor",
                kind: "line",
                dash: [4, 3],
                values: timestamps.map((ts) => totalsByTs.get(ts)?.[0]?.denied || 0),
            });
        }

        return { timestamps, bucketSeconds: data.bucketSeconds, series, totalLabel: "Total" };
    }

    function tokensChartData() {
        const timestamps = data.timestamps;
        const totalsByTs = bucketIndexer(data.totals);

        return {
            timestamps,
            bucketSeconds: data.bucketSeconds,
            totalLabel: "Total",
            series: [
                {
                    label: "Input tokens",
                    color: "--llmSeries1",
                    kind: "bars",
                    stacked: true,
                    values: timestamps.map((ts) => totalsByTs.get(ts)?.[0]?.inputTokens || 0),
                },
                {
                    label: "Output tokens",
                    color: "--llmSeries2",
                    kind: "bars",
                    stacked: true,
                    values: timestamps.map((ts) => totalsByTs.get(ts)?.[0]?.outputTokens || 0),
                },
            ],
        };
    }

    function latencyChartData() {
        const timestamps = data.timestamps;
        const totalsByTs = bucketIndexer(data.totals);

        function values(key) {
            return timestamps.map((ts) => {
                const item = totalsByTs.get(ts)?.[0];
                if (!item || item.requests - item.denied <= 0) {
                    return null;
                }
                return Math.round(item[key] || 0);
            });
        }

        return {
            timestamps,
            bucketSeconds: data.bucketSeconds,
            series: [
                { label: "Avg", color: "--llmSeries1", kind: "line", values: values("avgDurationMs") },
                { label: "p50", color: "--llmSeries3", kind: "line", values: values("p50DurationMs") },
                { label: "p95", color: "--llmSeries2", kind: "line", values: values("p95DurationMs") },
            ],
        };
    }

    function onChartSelect(min, max) {
        filters.from = app.utils.toDatetimeLocalInputValue(new Date(min * 1000));
        filters.to = app.utils.toDatetimeLocalInputValue(new Date(max * 1000));
        filters.range = "custom";
    }

    function kpiTile(icon, label, valueFunc, metaFunc, className = "") {
        return t.div(
            { className: () => `llm-kpi ${typeof className == "function" ? className() : className}` },
            t.div(
                { className: "llm-kpi-label" },
                t.i({ className: icon, ariaHidden: true }),
                t.span({ className: "txt" }, label),
            ),
            t.div({ className: "llm-kpi-value" }, valueFunc),
            t.div({ className: "llm-kpi-meta" }, metaFunc),
        );
    }

    const watchers = [];

    return t.div(
        {
            pbEvent: "llmOverview",
            className: "llm-overview",
            onmount: () => {
                watchers.push(
                    watch(
                        () => [pageData.reset, JSON.stringify(filters)],
                        () => load(),
                    ),
                );
            },
            onunmount: () => {
                watchers.forEach((w) => w?.unwatch());
            },
        },
        t.div(
            { className: () => `llm-kpis ${data.isLoading ? "loading" : ""}` },
            kpiTile(
                "ri-arrow-left-right-line",
                "Requests",
                () => llmFormatNumber(data.kpis.requests),
                () => `${llmFormatNumber(data.kpis.calls)} provider calls`,
            ),
            kpiTile(
                "ri-login-circle-line",
                "Input tokens",
                () => llmFormatNumber(data.kpis.inputTokens),
                () =>
                    data.kpis.calls
                        ? `~${llmFormatNumber(Math.round(data.kpis.inputTokens / data.kpis.calls))} per call`
                        : "-",
            ),
            kpiTile(
                "ri-logout-circle-r-line",
                "Output tokens",
                () => llmFormatNumber(data.kpis.outputTokens),
                () =>
                    data.kpis.calls
                        ? `~${llmFormatNumber(Math.round(data.kpis.outputTokens / data.kpis.calls))} per call`
                        : "-",
            ),
            kpiTile(
                "ri-error-warning-line",
                "Error rate",
                () => (+data.kpis.errorRate.toFixed(2)) + "%",
                () =>
                    `${llmFormatNumber(data.kpis.errors)} errors, ${llmFormatNumber(data.kpis.denied)} denied/limited`,
                () => (data.kpis.errorRate >= 5 ? "danger" : ""),
            ),
            kpiTile(
                "ri-timer-line",
                "p95 latency",
                () => (data.p95 == null ? "-" : llmFormatDuration(data.p95)),
                () => (data.kpis.calls ? `avg ${llmFormatDuration(data.kpis.avgDurationMs)}` : "-"),
            ),
        ),
        t.div(
            { className: "llm-charts-toolbar" },
            t.span({ className: "txt-hint txt-sm" }, () => {
                const interval = data.bucketSeconds >= 86400 ? "day" : data.bucketSeconds >= 3600 ? "hour" : "minute";
                return `Per ${interval} buckets. Drag over a chart to zoom into a time range.`;
            }),
            t.div(
                { className: "inline-flex gap-10 m-l-auto llm-group-by" },
                t.label({ htmlFor: "llm_group_by", className: "txt-hint txt-sm" }, "Group requests by"),
                t.div(
                    { className: "field llm-filter-field" },
                    app.components.select({
                        id: "llm_group_by",
                        required: true,
                        options: LLM_GROUP_BY_OPTIONS,
                        value: () => filters.groupBy || "",
                        onchange: (opts) => filters.groupBy = opts?.[0]?.value || "",
                    }),
                ),
            ),
        ),
        t.div(
            { className: "llm-charts" },
            llmChart({
                className: "llm-chart-requests",
                title: "Requests",
                icon: "ri-bar-chart-2-line",
                isLoading: () => data.isLoading,
                format: (v) => llmFormatNumber(v),
                data: requestsChartData,
                onselect: onChartSelect,
            }),
            llmChart({
                title: "Tokens",
                icon: "ri-coin-line",
                isLoading: () => data.isLoading,
                format: (v) => llmFormatNumber(v),
                data: tokensChartData,
                onselect: onChartSelect,
            }),
            llmChart({
                title: "Latency",
                icon: "ri-timer-line",
                isLoading: () => data.isLoading,
                format: (v) => llmFormatDuration(v),
                data: latencyChartData,
                onselect: onChartSelect,
            }),
        ),
        llmTopUsers(pageData),
    );
}
