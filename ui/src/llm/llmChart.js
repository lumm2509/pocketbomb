/**
 * Small uPlot based time series chart used by the LLM dashboard.
 *
 * Supports stacked bars and line series with a shared legend, crosshair
 * tooltip and optional drag-to-select time range.
 *
 * @example
 * ```js
 * llmChart({
 *     title: "Requests",
 *     isLoading: () => data.isLoading,
 *     format: (v) => v,
 *     data: () => ({
 *         timestamps: [...], // unix seconds
 *         bucketSeconds: 3600,
 *         series: [
 *             { label: "gpt-a", color: "--llmSeries1", kind: "bars", stacked: true, values: [...] },
 *             { label: "Errors", color: "--dangerColor", kind: "line", values: [...] },
 *         ],
 *     }),
 *     onselect: (minUnix, maxUnix) => {},
 * })
 * ```
 *
 * @param  {Object} propsArg
 * @return {Element}
 */
export function llmChart(propsArg = {}) {
    const props = Object.assign({
        title: "",
        icon: "",
        className: "",
        height: 170,
        isLoading: () => false,
        data: () => ({ timestamps: [], series: [] }),
        format: (v) => v,
        onselect: null,
    }, propsArg);

    const local = store({
        legend: [],
        hasData: false,
        tooltip: {
            show: false,
            date: "",
            rows: [],
            left: 0,
            top: 0,
        },
    });

    let chartEl;
    let lastData;
    const watchers = [];

    function cssVar(name, fallback = "") {
        if (!name?.startsWith("--")) {
            return name || fallback;
        }
        return getComputedStyle(chartEl).getPropertyValue(name).trim() || fallback;
    }

    function render(data) {
        lastData = data;

        if (!chartEl?.isConnected) {
            return;
        }

        const timestamps = data?.timestamps || [];
        const series = data?.series || [];

        local.legend = series.map((s) => ({ label: s.label, color: s.color, kind: s.kind }));
        local.hasData = series.some((s) => s.values?.some((v) => v > 0));

        // compute the stacked cumulative values
        const cumulative = [];
        let running = new Array(timestamps.length).fill(0);
        for (const s of series) {
            if (s.kind == "bars" && s.stacked) {
                running = running.map((v, i) => v + (s.values[i] || 0));
                cumulative.push({ s, values: running.slice() });
            }
        }

        // draw the largest stacked bars first so that the smaller ones are painted on top
        const drawOrder = cumulative.slice().reverse();
        const lines = series.filter((s) => !(s.kind == "bars" && s.stacked));

        const surface = cssVar("--surfaceColor", "#fff");
        const gridTxtColor = cssVar("--surfaceTxtHintColor");
        const gridColor = cssVar("--surfaceAlt2Color");

        const uSeries = [{}];
        const uData = [timestamps];

        // skip the surface gaps for dense charts so that the thin bars remain visible
        const slotPx = (chartEl.clientWidth - 60) / Math.max(timestamps.length, 1);
        const isDense = slotPx < 10;
        const barsPaths = uPlot.paths.bars({ size: [isDense ? 0.9 : 0.75, 48], gap: isDense ? 0 : 2, align: 0 });

        for (const item of drawOrder) {
            const color = cssVar(item.s.color);
            uSeries.push({
                label: item.s.label,
                paths: barsPaths,
                points: { show: false },
                width: isDense ? 0 : 1,
                stroke: isDense ? color : surface, // surface gap between the stacked segments
                fill: color,
            });
            uData.push(item.values);
        }

        for (const s of lines) {
            const color = cssVar(s.color);
            uSeries.push({
                label: s.label,
                paths: s.kind == "bars" ? barsPaths : undefined,
                points: { show: false },
                width: 2,
                dash: s.dash,
                stroke: color,
                fill: s.kind == "bars" ? color : undefined,
                spanGaps: true,
            });
            uData.push(s.values.map((v) => (v == null ? null : v)));
        }

        const opts = {
            width: Math.max(chartEl.clientWidth, 100),
            height: props.height,
            legend: { show: false },
            padding: [10, 10, 0, 0],
            cursor: {
                x: true,
                y: false,
                points: { show: false },
                drag: { x: !!props.onselect, y: false, setScale: false },
            },
            select: { show: !!props.onselect },
            scales: {
                x: {
                    time: true,
                    // pad with half bucket so that the edge bars are fully visible
                    range: (u, min, max) => {
                        const half = (data.bucketSeconds || 0) / 2;
                        return [min - half, max + half];
                    },
                },
                y: {
                    range: (u, min, max) => [0, max > 0 ? max * 1.15 : 1],
                },
            },
            series: uSeries,
            axes: [
                {
                    stroke: gridTxtColor,
                    space: 70,
                    size: 45,
                    grid: { show: false },
                    ticks: { show: true, stroke: gridColor, width: 1, size: 4 },
                    // dprint-ignore
                    values: [
                        // incr  default         year            month  day             hour  min   sec   mode
                        [86400,  "{MMM} {D}",    "\n{YYYY}",     null,  null,           null, null, null, 1],
                        [3600,   "{h}{aa}",      "\n{MMM} {D}",  null,  "\n{MMM} {D}",  null, null, null, 1],
                        [60,     "{h}:{mm}{aa}", "\n{MMM} {D}",  null,  "\n{MMM} {D}",  null, null, null, 1],
                    ],
                },
                {
                    stroke: gridTxtColor,
                    size: 50,
                    values: (u, vals) => vals.map((v) => props.format(v)),
                    grid: { show: true, stroke: gridColor, width: 1 },
                    ticks: { show: false },
                },
            ],
            hooks: {
                setCursor: [(u) => updateTooltip(u, data, cumulative.length)],
                setSelect: [
                    (u) => {
                        if (props.onselect && u.select.width > 2) {
                            const min = u.posToVal(u.select.left, "x");
                            const max = u.posToVal(u.select.left + u.select.width, "x");
                            u.setSelect({ left: 0, width: 0, top: 0, height: 0 }, false);
                            props.onselect(min, max + (data.bucketSeconds || 0));
                        }
                    },
                ],
            },
        };

        chartEl._uplot?.destroy();
        chartEl._uplot = new uPlot(opts, uData, chartEl.querySelector(".llm-chart-canvas"));

        const over = chartEl._uplot.over;
        over.addEventListener("mouseleave", () => {
            local.tooltip.show = false;
        });
    }

    function updateTooltip(u, data, totalStacked) {
        const idx = u.cursor.idx;
        if (idx == null || !data?.timestamps?.length) {
            local.tooltip.show = false;
            return;
        }

        const ts = data.timestamps[idx];
        const rows = [];
        for (const s of data.series) {
            const v = s.values[idx];
            if (v == null || (s.stacked && !v)) {
                continue;
            }
            rows.push({ label: s.label, color: s.color, value: props.format(v), raw: v });
        }

        if (data.totalLabel && totalStacked > 1) {
            const total = data.series
                .filter((s) => s.stacked)
                .reduce((sum, s) => sum + (s.values[idx] || 0), 0);
            rows.push({ label: data.totalLabel, value: props.format(total), isTotal: true });
        }

        const start = new Date(ts * 1000);
        const end = new Date((ts + (data.bucketSeconds || 0)) * 1000);
        local.tooltip.date = formatBucket(start, end, data.bucketSeconds);
        local.tooltip.rows = rows;
        local.tooltip.left = Math.round(u.valToPos(ts, "x")) + u.bbox.left / uPlot.pxRatio;
        local.tooltip.top = 5;
        local.tooltip.show = true;
    }

    function resize() {
        clearTimeout(chartEl?._resizeTimeoutId);
        chartEl._resizeTimeoutId = setTimeout(() => {
            if (chartEl?._uplot) {
                chartEl._uplot.setSize({ width: Math.max(chartEl.clientWidth, 100), height: props.height });
            }
        }, 100);
    }

    return t.div(
        {
            className: () =>
                `llm-chart ${props.className} ${props.isLoading() ? "loading" : ""} ${local.hasData ? "" : "nodata"}`,
            onmount: (el) => {
                chartEl = el;
                watchers.push(
                    watch(
                        () => props.data(),
                        (data) => {
                            // defer to ensure the layout is ready
                            setTimeout(() => render(data), 0);
                        },
                    ),
                    watch(
                        () => app.store.activeColorScheme,
                        (newScheme, oldScheme) => {
                            if (oldScheme && newScheme != oldScheme) {
                                setTimeout(() => render(lastData), 0);
                            }
                        },
                    ),
                );
                window.addEventListener("resize", resize);
            },
            onunmount: (el) => {
                watchers.forEach((w) => w?.unwatch());
                window.removeEventListener("resize", resize);
                clearTimeout(el._resizeTimeoutId);
                el._uplot?.destroy();
                el._uplot = null;
            },
        },
        t.header(
            { className: "llm-chart-header" },
            t.div(
                { className: "llm-chart-title" },
                props.icon ? t.i({ className: props.icon, ariaHidden: true }) : null,
                t.span({ className: "txt" }, props.title),
            ),
            t.div({ className: "llm-chart-legend" }, () => {
                return local.legend.map((item) =>
                    t.span(
                        { className: "llm-legend-item" },
                        t.span({
                            className: `llm-swatch ${item.kind == "line" ? "line" : ""}`,
                            style: `--swatchColor: var(${item.color})`,
                        }),
                        t.span({ className: "txt" }, item.label || "N/A"),
                    )
                );
            }),
        ),
        t.div(
            { className: "llm-chart-body" },
            t.div({ className: "llm-chart-canvas" }),
            t.div(
                {
                    className: () => `llm-chart-tooltip ${local.tooltip.show ? "" : "hidden"}`,
                    onmount: (el) => {
                        el._posWatcher = watch(
                            () => [local.tooltip.left, local.tooltip.show],
                            () => {
                                if (!el || !chartEl) {
                                    return;
                                }
                                const width = el.offsetWidth;
                                const maxLeft = chartEl.clientWidth - width;
                                let left = local.tooltip.left + 12;
                                if (left > maxLeft) {
                                    left = local.tooltip.left - width - 12;
                                }
                                el.style.left = Math.max(0, left) + "px";
                                el.style.top = local.tooltip.top + "px";
                            },
                        );
                    },
                    onunmount: (el) => {
                        el._posWatcher?.unwatch();
                    },
                },
                t.div({ className: "llm-tooltip-date" }, () => local.tooltip.date),
                () => {
                    return local.tooltip.rows.map((row) =>
                        t.div(
                            { className: `llm-tooltip-row ${row.isTotal ? "total" : ""}` },
                            row.color
                                ? t.span({ className: "llm-swatch", style: `--swatchColor: var(${row.color})` })
                                : t.span({ className: "llm-swatch empty" }),
                            t.span({ className: "txt label-txt" }, row.label || "N/A"),
                            t.span({ className: "txt value-txt" }, row.value),
                        )
                    );
                },
            ),
            t.div(
                { className: "llm-chart-empty", hidden: () => local.hasData || props.isLoading() },
                "No data for the selected range",
            ),
            t.div(
                { className: "llm-chart-loader", hidden: () => !props.isLoading() },
                t.span({ className: "loader" }),
            ),
        ),
    );
}

function pad(n) {
    return n.toString().padStart(2, "0");
}

function formatBucket(start, end, bucketSeconds) {
    const month = start.toLocaleString("default", { month: "short" });
    const day = start.getDate();

    if (bucketSeconds >= 86400) {
        return `${month} ${day}, ${start.getFullYear()}`;
    }

    return `${month} ${day}, ${pad(start.getHours())}:${pad(start.getMinutes())} - ${pad(end.getHours())}:${
        pad(end.getMinutes())
    }`;
}
