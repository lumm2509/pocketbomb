// Shared LLM dashboard helpers.

export const LLM_STATUSES = [
    { value: "success", label: "Success", className: "success" },
    { value: "error", label: "Error", className: "danger" },
    { value: "denied", label: "Denied", className: "warning" },
    { value: "limited", label: "Limited", className: "warning" },
];

export const LLM_RANGE_PRESETS = [
    { value: "1h", label: "Last hour", seconds: 3600 },
    { value: "24h", label: "Last 24 hours", seconds: 86400 },
    { value: "7d", label: "Last 7 days", seconds: 7 * 86400 },
    { value: "30d", label: "Last 30 days", seconds: 30 * 86400 },
    { value: "custom", label: "Custom range" },
];

export const LLM_GROUP_BY_OPTIONS = [
    { value: "", label: "No grouping" },
    { value: "model", label: "Model" },
    { value: "profile", label: "Profile" },
    { value: "provider", label: "Provider" },
    { value: "status", label: "Status" },
];

// the logs list fields excluding the heavy request/response content
export const LLM_LOG_LIST_FIELDS = [
    "id",
    "created",
    "provider",
    "model",
    "profile",
    "stream",
    "status",
    "error",
    "inputTokens",
    "outputTokens",
    "durationMs",
    "authCollection",
    "authRecord",
    "ip",
].join(",");

export const LLM_SEARCH_FALLBACK_FIELDS = ["model", "profile", "provider", "error", "ip", "authRecord"];

export const LLM_SEARCH_AUTOCOMPLETE = [
    "id",
    "created",
    "provider",
    "model",
    "profile",
    "stream",
    "status",
    "error",
    "inputTokens",
    "outputTokens",
    "durationMs",
    "authCollection",
    "authRecord",
    "ip",
    { value: "meta.", label: "meta.*" },
];

/**
 * Returns the status option for the specified status value.
 *
 * @param  {string} status
 * @return {Object}
 */
export function llmStatus(status) {
    return LLM_STATUSES.find((s) => s.value == status) || { value: status, label: status || "N/A", className: "" };
}

/**
 * Returns a status label element.
 *
 * @param  {string} status
 * @param  {string} [errorMsg]
 * @return {Element}
 */
export function llmStatusLabel(status, errorMsg = "") {
    const opt = llmStatus(status);

    return t.span(
        {
            className: `label llm-status-label status-${opt.value} ${opt.className}`,
            ariaDescription: errorMsg ? app.attrs.tooltip(app.utils.truncate(errorMsg, 300)) : undefined,
        },
        opt.label,
    );
}

/**
 * Resolves the date range of the specified filter settings.
 *
 * @param  {Object} filters
 * @return {{from: Date, to: Date, interval: string, bucketSeconds: number}}
 */
export function llmResolveRange(filters) {
    let to = new Date();
    let from;

    if (filters.range == "custom") {
        from = filters.from ? new Date(filters.from) : null;
        to = filters.to ? new Date(filters.to) : to;
        if (!from || isNaN(from.getTime())) {
            from = new Date(to.getTime() - 86400 * 1000);
        }
        if (isNaN(to.getTime())) {
            to = new Date();
        }
    } else {
        const preset = LLM_RANGE_PRESETS.find((p) => p.value == filters.range) || LLM_RANGE_PRESETS[1];
        from = new Date(to.getTime() - preset.seconds * 1000);
    }

    const span = (to.getTime() - from.getTime()) / 1000;

    let interval = "day";
    if (span <= 3 * 3600) {
        interval = "minute";
    } else if (span <= 8 * 86400) {
        interval = "hour";
    }

    const bucketSeconds = interval == "minute" ? 60 : interval == "hour" ? 3600 : 86400;

    return { from, to, interval, bucketSeconds };
}

/**
 * Builds the API filter expression from the dashboard filter settings.
 *
 * @param  {Object}  filters
 * @param  {Object}  [range] Optional resolved range (see `llmResolveRange`).
 * @return {string}
 */
export function llmBuildFilter(filters, range = null) {
    const parts = [];

    if (range?.from) {
        parts.push(app.pb.filter("created >= {:from}", { from: app.utils.toRFC3339Datetime(range.from) }));
    }
    if (range?.to) {
        parts.push(app.pb.filter("created <= {:to}", { to: app.utils.toRFC3339Datetime(range.to) }));
    }

    if (filters.profile) {
        parts.push(app.pb.filter("profile = {:v}", { v: filters.profile }));
    }
    if (filters.model) {
        parts.push(app.pb.filter("model = {:v}", { v: filters.model }));
    }
    if (filters.provider) {
        parts.push(app.pb.filter("provider = {:v}", { v: filters.provider }));
    }
    if (filters.status) {
        parts.push(app.pb.filter("status = {:v}", { v: filters.status }));
    }
    if (filters.user?.authRecord) {
        parts.push(
            app.pb.filter("authCollection = {:c} && authRecord = {:r}", {
                c: filters.user.authCollection,
                r: filters.user.authRecord,
            }),
        );
    } else if (filters.user?.ip) {
        parts.push(app.pb.filter("ip = {:ip} && authRecord = ''", { ip: filters.user.ip }));
    }

    if (filters.search) {
        parts.push(app.utils.normalizeSearchFilter(filters.search, LLM_SEARCH_FALLBACK_FIELDS));
    }

    return parts.filter(Boolean).map((f) => "(" + f + ")").join("&&");
}

/**
 * Parses an API datetime string (YYYY-MM-DD HH:mm:ss.nnnZ) into unix seconds.
 *
 * @param  {string} str
 * @return {number}
 */
export function llmParseDate(str) {
    return new Date((str || "").replace(" ", "T")).getTime() / 1000;
}

/**
 * Formats a number in a short human readable form (e.g. 1.2k, 3.4M).
 *
 * @param  {number} num
 * @return {string}
 */
export function llmFormatNumber(num) {
    num = Number(num) || 0;

    const abs = Math.abs(num);
    if (abs >= 1e9) {
        return +(num / 1e9).toFixed(1) + "B";
    }
    if (abs >= 1e6) {
        return +(num / 1e6).toFixed(1) + "M";
    }
    if (abs >= 1e4) {
        return +(num / 1e3).toFixed(1) + "k";
    }

    return Number.isInteger(num) ? num.toLocaleString() : (+num.toFixed(2)).toLocaleString();
}

/**
 * Formats a milliseconds duration (e.g. 350ms, 1.24s).
 *
 * @param  {number} ms
 * @return {string}
 */
export function llmFormatDuration(ms) {
    ms = Number(ms) || 0;

    if (ms >= 60000) {
        return +(ms / 60000).toFixed(1) + "m";
    }
    if (ms >= 1000) {
        return +(ms / 1000).toFixed(2) + "s";
    }

    return Math.round(ms) + "ms";
}

/**
 * Returns the auth collection model (if loaded) with the specified id.
 *
 * @param  {string} collectionId
 * @return {Object|undefined}
 */
export function llmAuthCollection(collectionId) {
    return app.store.collections.find((c) => c.id == collectionId || c.name == collectionId);
}

/**
 * Returns the dashboard record preview url.
 *
 * @param  {string} collectionId
 * @param  {string} recordId
 * @return {string}
 */
export function llmRecordURL(collectionId, recordId) {
    const collection = llmAuthCollection(collectionId);

    return `#/collections?collection=${encodeURIComponent(collection?.name || collectionId)}&record=${
        encodeURIComponent(recordId)
    }`;
}

// lazily loaded auth records cache shared between the dashboard components
const recordsCache = store({});
const pendingRecords = new Set();

/**
 * Returns the cached auth record (if loaded).
 *
 * @param  {string} collectionId
 * @param  {string} recordId
 * @return {Object|null|undefined} undefined if not loaded yet, null if missing.
 */
export function llmCachedRecord(collectionId, recordId) {
    return recordsCache[collectionId + ":" + recordId];
}

/**
 * Caches the provided auth records.
 *
 * @param {Array<Object>} records
 */
export function llmCacheRecords(records) {
    for (const r of records || []) {
        if (r?.id && r?.collectionId) {
            recordsCache[r.collectionId + ":" + r.id] = r;
        }
    }
}

/**
 * Loads (in batches) the missing auth records of the specified logs.
 *
 * @param {Array<Object>} logs
 */
export async function llmLoadRecords(logs) {
    const missing = {};

    for (const log of logs || []) {
        if (!log.authRecord || !log.authCollection) {
            continue;
        }

        const key = log.authCollection + ":" + log.authRecord;
        if (typeof recordsCache[key] != "undefined" || pendingRecords.has(key)) {
            continue;
        }

        pendingRecords.add(key);
        missing[log.authCollection] = missing[log.authCollection] || [];
        missing[log.authCollection].push(log.authRecord);
    }

    for (const collectionId in missing) {
        const ids = missing[collectionId];

        for (let i = 0; i < ids.length; i += 50) {
            const chunk = ids.slice(i, i + 50);

            try {
                const records = await app.pb.collection(collectionId).getFullList({
                    filter: chunk.map((id) => app.pb.filter("id={:id}", { id })).join("||"),
                    requestKey: null,
                });
                llmCacheRecords(records);
            } catch (err) {
                if (!err?.isAbort) {
                    console.warn("[llm] failed to load auth records:", err);
                }
            }

            // mark the not found as missing
            for (const id of chunk) {
                const key = collectionId + ":" + id;
                pendingRecords.delete(key);
                if (typeof recordsCache[key] == "undefined") {
                    recordsCache[key] = null;
                }
            }
        }
    }
}

/**
 * Returns a short display label for the specified auth record.
 *
 * @param  {Object} record
 * @return {string}
 */
export function llmRecordLabel(record) {
    return record?.email || record?.username || record?.name || record?.id || "";
}

/**
 * Returns a caller (auth record or guest IP) element.
 *
 * @param  {Object} log Object with authCollection, authRecord and ip props.
 * @param  {Object} [record] Optional already loaded record.
 * @return {Element}
 */
export function llmCallerElem(log, record = undefined) {
    if (!log.authRecord) {
        return t.span(
            { className: "llm-caller guest" },
            t.i({ className: "ri-global-line txt-hint", ariaHidden: true }),
            t.span({ className: "txt" }, log.ip || "N/A"),
            t.small({ className: "txt-hint" }, "guest"),
        );
    }

    const collection = llmAuthCollection(log.authCollection);
    const isSuperuser = collection?.name == "_superusers";

    return t.a(
        {
            className: "llm-caller link-primary",
            href: llmRecordURL(log.authCollection, log.authRecord),
            target: "_blank",
            rel: "noopener noreferrer",
            onclick: (e) => e.stopPropagation(),
            ariaDescription: app.attrs.tooltip(
                () => `${collection?.name || log.authCollection}/${log.authRecord}${log.ip ? "\nIP: " + log.ip : ""}`,
            ),
        },
        t.i({ className: isSuperuser ? "ri-shield-user-line" : "ri-user-line", ariaHidden: true }),
        t.span({ className: "txt" }, () => {
            const r = typeof record != "undefined" ? record : llmCachedRecord(log.authCollection, log.authRecord);
            return llmRecordLabel(r) || log.authRecord;
        }),
    );
}
