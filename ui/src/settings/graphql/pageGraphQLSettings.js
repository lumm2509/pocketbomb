import { settingsSidebar } from "../settingsSidebar";
import { graphqlSchemaEditor } from "./graphqlSchemaEditor";

export function pageGraphQLSettings(route) {
    app.store.title = "GraphQL";

    const data = store({
        isLoading: false,
        isSaving: false,
        formSettings: null,
        initSerialized: "null",
        get hasChanges() {
            return data.initSerialized != JSON.stringify(data.formSettings);
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
            graphql: JSON.parse(JSON.stringify(settings?.graphql || {})),
        };
        // the stored schema is changed only by the schema editor apply
        delete data.formSettings.graphql.schema;

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
            app.store.errors = null;
            app.toasts.success("Successfully saved GraphQL settings.");
        } catch (err) {
            app.checkApiError(err);
        }

        data.isSaving = false;
    }

    function reset() {
        data.formSettings = JSON.parse(data.initSerialized);
        app.store.errors = null;
    }

    function numberField(key, label, opts = {}) {
        const g = data.formSettings.graphql;
        const id = "graphql." + key;

        return t.div(
            { className: "col-lg-4" },
            t.div(
                { className: "field" },
                t.label({ htmlFor: id }, label),
                t.input({
                    id,
                    name: id,
                    type: "number",
                    min: opts.min ?? 1,
                    max: opts.max,
                    step: 1,
                    required: true,
                    value: () => g[key] ?? "",
                    oninput: (e) => g[key] = e.target.value << 0,
                }),
            ),
            opts.help ? t.div({ className: "field-help" }, opts.help) : null,
        );
    }

    function form() {
        const g = data.formSettings.graphql;

        return t.form(
            {
                pbEvent: "graphqlSettingsForm",
                className: "grid graphql-settings-form",
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
                        id: "graphql.enabled",
                        name: "graphql.enabled",
                        type: "checkbox",
                        className: "switch",
                        checked: () => !!g.enabled,
                        onchange: (e) => g.enabled = e.target.checked,
                    }),
                    t.label({ htmlFor: "graphql.enabled" }, "Enable the GraphQL API"),
                ),
                t.div(
                    { className: "field-help" },
                    "Read-only GraphQL API at ",
                    t.code(null, "/api/graphql"),
                    " for the collections with a List or View API rule. Every record is read with the same access checks as the records API (API rules, API keys and OAuth2 scopes); the requests without an API key or an access token are rejected.",
                ),
            ),
            t.div({ className: "col-lg-12" }, t.hr()),
            t.div(
                { className: "col-lg-12" },
                t.h6(null, "Limits"),
                t.div(
                    { className: "txt-hint txt-sm" },
                    "The queries are checked before execution. The query size (32KB) and the execution time (10s) limits are fixed. Use the rate limit rule ",
                    t.code(null, "/api/graphql"),
                    " to limit the number of requests.",
                ),
            ),
            numberField("maxDepth", "Max depth", {
                max: 50,
                help: "Max selection depth (the introspection fields are not counted).",
            }),
            numberField("maxCost", "Max cost", {
                max: 1000000,
                help:
                    "Each returned record costs 1; the lists multiply their children cost by first/last (default 50) or the relation max select.",
            }),
            numberField("maxPageSize", "Max page size", {
                max: 500,
                help: "Max first/last argument value of the connections.",
            }),
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
                            className: () =>
                                `btn expanded-lg graphql-settings-save-btn ${data.isSaving ? "loading" : ""}`,
                            disabled: () => !data.hasChanges || data.isSaving,
                        },
                        t.span({ className: "txt" }, "Save changes"),
                    ),
                ),
            ),
        );
    }

    return t.div(
        { pbEvent: "pageGraphQLSettings", className: "page page-graphql-settings" },
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
            ),
            t.div(
                { className: "wrapper m-b-base" },
                () => {
                    if (data.isLoading || !data.formSettings) {
                        return t.div({ className: "block txt-center" }, t.span({ className: "loader lg" }));
                    }
                    return form();
                },
                () => {
                    if (data.isLoading || !data.formSettings || !app.perms.can("collections", "write")) {
                        return;
                    }
                    return [t.hr(), graphqlSchemaEditor()];
                },
            ),
            t.footer({ className: "page-footer" }, app.components.credits()),
        ),
    );
}
