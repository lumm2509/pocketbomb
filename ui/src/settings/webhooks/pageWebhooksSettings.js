import { settingsSidebar } from "../settingsSidebar";

const DEFAULTS = {
    enabled: true,
    maxAttempts: 8,
    retryBaseInterval: 120,
    retryMaxInterval: 7200,
    timeout: 5,
    allowPrivateTargets: false,
    maxDays: 7,
    autoDisableAfter: 20,
};

export function pageWebhooksSettings(route) {
    app.store.title = "Webhooks settings";

    const data = store({
        isLoading: false,
        isSaving: false,
        formSettings: null,
        initSerialized: "null",
        get hasChanges() {
            return data.initSerialized != JSON.stringify(data.formSettings);
        },
        // approximate retry schedule (without jitter)
        get schedule() {
            const w = data.formSettings?.webhooks;
            if (!w) {
                return [];
            }

            const result = [];
            let delay = w.retryBaseInterval || 0;
            let total = 0;
            for (let i = 1; i < Math.min(w.maxAttempts || 0, 26); i++) {
                const d = Math.min(delay, w.retryMaxInterval || delay);
                total += d;
                result.push({ attempt: i + 1, delay: d, total });
                delay = delay * 2;
            }
            return result;
        },
    });

    loadSettings();

    async function loadSettings() {
        data.isLoading = true;

        try {
            const settings = await app.pb.settings.getAll();
            init(settings);
            data.isLoading = false;
        } catch (err) {
            if (!err.isAbort) {
                app.checkApiError(err);
            }
        }
    }

    function init(settings = {}) {
        // refresh local app settings
        app.store.settings = JSON.parse(JSON.stringify(settings));

        data.formSettings = {
            webhooks: Object.assign({}, DEFAULTS, JSON.parse(JSON.stringify(settings?.webhooks || {}))),
        };

        data.initSerialized = JSON.stringify(data.formSettings);
    }

    async function save() {
        if (data.isSaving || !data.hasChanges) {
            return;
        }

        data.isSaving = true;

        try {
            const settings = await app.pb.settings.update(JSON.parse(JSON.stringify(data.formSettings)));
            init(settings);
            app.toasts.success("Successfully saved webhooks settings.");
        } catch (err) {
            app.checkApiError(err);
        }

        data.isSaving = false;
    }

    function reset() {
        data.formSettings = JSON.parse(data.initSerialized);
        app.store.errors = null;
    }

    function formatSeconds(sec) {
        if (sec >= 86400) {
            return +(sec / 86400).toFixed(1) + "d";
        }
        if (sec >= 3600) {
            return +(sec / 3600).toFixed(1) + "h";
        }
        if (sec >= 60) {
            return +(sec / 60).toFixed(1) + "m";
        }
        return sec + "s";
    }

    function numberField(key, label, opts = {}) {
        const w = data.formSettings.webhooks;
        const id = "webhooks." + key;

        return t.div(
            { className: opts.col || "col-lg-6" },
            t.div(
                { className: "field" },
                t.label({ htmlFor: id }, label),
                t.input({
                    id,
                    name: id,
                    type: "number",
                    min: opts.min ?? 0,
                    max: opts.max,
                    step: 1,
                    required: opts.required ?? true,
                    value: () => w[key] ?? "",
                    oninput: (e) => w[key] = e.target.value << 0,
                }),
                opts.suffix ? t.span({ className: "field-addon-txt txt-hint" }, opts.suffix) : null,
            ),
            opts.help ? t.div({ className: "field-help" }, opts.help) : null,
        );
    }

    function sectionHeader(icon, title, description) {
        return t.div(
            { className: "llm-section-header" },
            t.i({ className: icon + " txt-hint", ariaHidden: true }),
            t.div(
                { className: "flex-fill" },
                t.h6(null, title),
                description ? t.div({ className: "txt-hint txt-sm" }, description) : null,
            ),
        );
    }

    function form() {
        const w = data.formSettings.webhooks;

        return t.form(
            {
                pbEvent: "webhooksSettingsForm",
                className: "grid webhooks-settings-form",
                inert: () => data.isSaving,
                onsubmit: (e) => {
                    e.preventDefault();
                    save();
                },
            },
            t.div(
                { className: "col-lg-12" },
                t.div(
                    { className: "field" },
                    t.input({
                        id: "webhooks.enabled",
                        name: "webhooks.enabled",
                        type: "checkbox",
                        className: "switch",
                        checked: () => !!w.enabled,
                        onchange: (e) => w.enabled = e.target.checked,
                    }),
                    t.label({ htmlFor: "webhooks.enabled" }, "Enable webhooks"),
                ),
                t.div(
                    { className: "field-help" },
                    "Global kill switch. When disabled no new events are queued and the dispatcher stops sending the already queued deliveries (they are resumed once re-enabled).",
                ),
            ),
            t.div({ className: "col-lg-12" }, t.hr()),
            t.div(
                { className: "col-lg-12" },
                sectionHeader(
                    "ri-send-plane-line",
                    "Delivery",
                    "Each delivery is retried with exponential backoff (with jitter) until a 2xx response or until the max attempts are exhausted.",
                ),
            ),
            numberField("timeout", "Request timeout (seconds)", { min: 1, max: 60 }),
            numberField("maxAttempts", "Max attempts (incl. the first one)", { min: 1, max: 25 }),
            numberField("retryBaseInterval", "Retry base interval (seconds)", {
                min: 1,
                max: 86400,
                help: "The delay after the first failed attempt (doubled for each next attempt).",
            }),
            numberField("retryMaxInterval", "Retry max interval (seconds)", {
                min: 1,
                max: 7 * 86400,
                help: "The max delay between two attempts.",
            }),
            t.div(
                { className: "col-lg-12" },
                t.div(
                    { className: "webhook-retry-schedule txt-sm" },
                    t.span({ className: "txt-hint" }, "Approximate retry schedule: "),
                    () => {
                        const schedule = data.schedule;
                        if (!schedule.length) {
                            return t.span({ className: "txt-hint" }, "no retries (single attempt).");
                        }
                        return [
                            ...schedule.map((s) =>
                                t.span(
                                    {
                                        className: "label sm",
                                        ariaDescription: app.attrs.tooltip(
                                            `Attempt #${s.attempt} ~${formatSeconds(s.total)} after the first one`,
                                        ),
                                    },
                                    "+" + formatSeconds(s.delay),
                                )
                            ),
                            t.span(
                                { className: "txt-hint" },
                                ` (~${formatSeconds(schedule[schedule.length - 1].total)} total)`,
                            ),
                        ];
                    },
                ),
            ),
            numberField("autoDisableAfter", "Auto-disable after consecutive failed events", {
                min: 0,
                max: 10000,
                required: false,
                help:
                    "A subscription is automatically deactivated after this number of consecutive events that exhausted all of their attempts. Set to 0 to never auto-disable.",
            }),
            numberField("maxDays", "Deliveries log retention (days)", {
                min: 1,
                max: 365,
                help:
                    "The completed (success, failed or disabled) deliveries older than this are deleted. The queued ones are always kept.",
            }),
            t.div({ className: "col-lg-12" }, t.hr()),
            t.div(
                { className: "col-lg-12" },
                sectionHeader("ri-shield-keyhole-line", "Security"),
                t.div(
                    { className: "field" },
                    t.input({
                        id: "webhooks.allowPrivateTargets",
                        name: "webhooks.allowPrivateTargets",
                        type: "checkbox",
                        className: "switch",
                        checked: () => !!w.allowPrivateTargets,
                        onchange: (e) => w.allowPrivateTargets = e.target.checked,
                    }),
                    t.label({ htmlFor: "webhooks.allowPrivateTargets" }, "Allow private network targets"),
                ),
                t.div(
                    { className: "field-help" },
                    "By default the webhooks can't be sent to loopback, private and other reserved IP addresses (SSRF protection).",
                ),
                () => {
                    if (!w.allowPrivateTargets) {
                        return;
                    }
                    return t.div(
                        { className: "alert danger m-t-sm m-b-0" },
                        t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                        t.div(
                            { className: "content" },
                            t.strong(null, "SSRF risk: "),
                            "the subscription endpoints could target internal services (e.g. localhost, the cloud metadata endpoint 169.254.169.254, intranet hosts). ",
                            "Enable this only for local development or when all superusers and the linked apps are fully trusted.",
                        ),
                    );
                },
            ),
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
    }

    return t.div(
        { pbEvent: "pageWebhooksSettings", className: "page page-webhooks-settings" },
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
                        { href: "#/webhooks", className: "btn sm transparent secondary" },
                        t.i({ className: "ri-webhook-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "Webhooks dashboard"),
                    ),
                ),
            ),
            t.div(
                { className: "wrapper m-b-base" },
                () => {
                    if (data.isLoading || !data.formSettings) {
                        return t.div({ className: "block txt-center" }, t.span({ className: "loader lg" }));
                    }
                    return form();
                },
            ),
            t.footer({ className: "page-footer" }, app.components.credits()),
        ),
    );
}
