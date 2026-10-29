import { llmChart } from "@/llm/llmChart";
import { llmFormatDuration, llmFormatNumber, llmParseDate, llmResolveRange } from "@/llm/llmUtils";
import {
    WEBHOOK_GROUP_BY_OPTIONS,
    WEBHOOK_STATUSES,
    webhooksBuildFilter,
    webhooksFindSubscription,
    webhookTopicLabel,
} from "./webhooksUtils";

const MAX_GROUPS = 7; // + "Other"

/**
 * The webhook deliveries KPI tiles and chart.
 *
 * @param  {Object} pageData
 * @return {Element}
 */
export function webhookDeliveriesStats(pageData) {
    const filters = pageData.filters;

    const data = store({
        isLoading: false,
        timestamps: [],
        bucketSeconds: 3600,
        totals: [],
        grouped: [],
        get kpis() {
            const result = {
                total: 0,
                success: 0,
                failed: 0,
                retrying: 0,
                pending: 0,
                disabled: 0,
                attempts: 0,
                avgDurationMs: 0,
            };

            let durationSum = 0;
            let durationCount = 0;
            for (const item of data.totals) {
                result.total += item.total;
                result.success += item.success;
                result.failed += item.failed;
                result.retrying += item.retrying;
                result.pending += item.pending;
                result.disabled += item.disabled;
                result.attempts += item.attempts;

                // approximate weight - the deliveries with at least one attempt
                const attempted = item.total - item.pending;
                if (item.avgDurationMs && attempted > 0) {
                    durationSum += item.avgDurationMs * attempted;
                    durationCount += attempted;
                }
            }

            const completed = result.success + result.failed;
            result.successRate = completed > 0 ? (result.success / completed) * 100 : null;
            result.avgDurationMs = durationCount > 0 ? durationSum / durationCount : 0;

            return result;
        },
    });

    function groupLabel(value) {
        if (value == "__other__") {
            return "Other";
        }
        if (filters.groupBy == "topic") {
            return webhookTopicLabel(value);
        }
        if (filters.groupBy == "webhook") {
            return webhooksFindSubscription(value)?.name || value || "(empty)";
        }
        return value || "(empty)";
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

    async function load() {
        data.isLoading = true;

        try {
            const range = llmResolveRange(filters);
            const filter = webhooksBuildFilter(filters, range);

            const needsGroups = filters.groupBy && filters.groupBy != "status";

            const [totals, grouped] = await Promise.all([
                app.pb.send("/api/webhooks/deliveries/stats", {
                    query: { interval: range.interval, filter },
                    requestKey: "webhooks_stats_totals",
                }),
                needsGroups
                    ? app.pb.send("/api/webhooks/deliveries/stats", {
                        query: { interval: range.interval, groupBy: filters.groupBy, filter },
                        requestKey: "webhooks_stats_grouped",
                    })
                    : null,
            ]);

            data.bucketSeconds = range.bucketSeconds;
            data.timestamps = fillTimestamps(range);
            data.totals = totals || [];
            data.grouped = grouped || [];
            data.isLoading = false;
        } catch (err) {
            if (!err?.isAbort) {
                data.isLoading = false;
                app.checkApiError(err);
            }
        }
    }

    function chartData() {
        const timestamps = data.timestamps;
        const totalsByTs = bucketIndexer(data.totals);
        const series = [];

        if (filters.groupBy && filters.groupBy != "status" && data.grouped.length) {
            const groupTotals = new Map();
            for (const item of data.grouped) {
                groupTotals.set(item.group, (groupTotals.get(item.group) || 0) + item.total);
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
                    label: groupLabel(group),
                    color: group == "__other__" ? "--llmSeriesOther" : "--llmSeries" + ((i % 8) + 1),
                    kind: "bars",
                    stacked: true,
                    values: timestamps.map((ts) => {
                        const items = groupedByTs.get(ts) || [];
                        if (group == "__other__") {
                            return items
                                .filter((item) => !visible.includes(item.group))
                                .reduce((sum, item) => sum + item.total, 0);
                        }
                        return items.find((item) => item.group == group)?.total || 0;
                    }),
                });
            });

            series.push({
                label: "Failed",
                color: "--dangerColor",
                kind: "line",
                values: timestamps.map((ts) => totalsByTs.get(ts)?.[0]?.failed || 0),
            });
        } else {
            // stacked by status
            for (const status of WEBHOOK_STATUSES) {
                series.push({
                    label: status.label,
                    color: status.color,
                    kind: "bars",
                    stacked: true,
                    values: timestamps.map((ts) => totalsByTs.get(ts)?.[0]?.[status.value] || 0),
                });
            }
        }

        return { timestamps, bucketSeconds: data.bucketSeconds, series, totalLabel: "Total" };
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
            pbEvent: "webhookDeliveriesStats",
            className: "webhook-deliveries-stats",
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
                "ri-send-plane-line",
                "Deliveries",
                () => llmFormatNumber(data.kpis.total),
                () => `${llmFormatNumber(data.kpis.attempts)} attempts`,
            ),
            kpiTile(
                "ri-checkbox-circle-line",
                "Success rate",
                () => (data.kpis.successRate == null ? "-" : (+data.kpis.successRate.toFixed(2)) + "%"),
                () => `${llmFormatNumber(data.kpis.success)} delivered`,
                () => (data.kpis.successRate != null && data.kpis.successRate < 95 ? "danger" : ""),
            ),
            kpiTile(
                "ri-close-circle-line",
                "Failed",
                () => llmFormatNumber(data.kpis.failed),
                () => `${llmFormatNumber(data.kpis.disabled)} not sent (disabled)`,
                () => (data.kpis.failed > 0 ? "danger" : ""),
            ),
            kpiTile(
                "ri-loop-left-line",
                "Retrying / pending",
                () => `${llmFormatNumber(data.kpis.retrying)} / ${llmFormatNumber(data.kpis.pending)}`,
                () => "in the delivery queue",
            ),
            kpiTile(
                "ri-timer-line",
                "Avg duration",
                () => (data.kpis.avgDurationMs ? llmFormatDuration(data.kpis.avgDurationMs) : "-"),
                () => "last attempt response time",
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
                t.label({ htmlFor: "webhooks_group_by", className: "txt-hint txt-sm" }, "Group deliveries by"),
                t.div(
                    { className: "field llm-filter-field" },
                    app.components.select({
                        id: "webhooks_group_by",
                        required: true,
                        options: WEBHOOK_GROUP_BY_OPTIONS,
                        value: () => filters.groupBy || "status",
                        onchange: (opts) => filters.groupBy = opts?.[0]?.value || "status",
                    }),
                ),
            ),
        ),
        t.div(
            { className: "llm-charts webhook-charts" },
            llmChart({
                className: "llm-chart-requests",
                title: "Deliveries",
                icon: "ri-bar-chart-2-line",
                height: 150,
                isLoading: () => data.isLoading,
                format: (v) => llmFormatNumber(v),
                data: chartData,
                onselect: onChartSelect,
            }),
        ),
    );
}
