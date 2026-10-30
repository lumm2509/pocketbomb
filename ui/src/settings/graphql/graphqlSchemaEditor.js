// The GraphQL schema editor: the SDL of the collections (Owner only). The plan previews
// the changes and the apply saves the collections and generates a single migration.

export function graphqlSchemaEditor() {
    const data = store({
        isLoading: true,
        isBusy: false,
        schema: "",
        source: "",
        canApply: false,
        drifted: false,
        plan: null,
        // the schema of the last plan
        plannedSchema: null,
        allowDestructive: false,
        get hasValidPlan() {
            return !!data.plan?.planHash && data.plannedSchema === data.schema;
        },
        get isDestructive() {
            return !!data.plan?.changes?.some((c) => c.destructive);
        },
        get canSubmitApply() {
            return data.canApply && data.hasValidPlan && !!data.plan?.changes?.length
                && (!data.isDestructive || data.allowDestructive);
        },
    });

    load();

    async function load(source = "") {
        data.isLoading = true;
        try {
            const result = await app.pb.send("/api/graphql/schema" + (source ? "?source=" + source : ""), {
                requestKey: "graphql_schema",
            });
            data.schema = result.schema;
            data.source = result.source;
            data.canApply = result.canApply;
            data.drifted = result.drifted;
            data.plan = null;
            data.plannedSchema = null;
            data.allowDestructive = false;
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }
        data.isLoading = false;
    }

    async function preview() {
        if (data.isBusy) {
            return;
        }

        data.isBusy = true;
        try {
            const schema = data.schema;
            data.plan = await app.pb.send("/api/graphql/schema/plan", {
                method: "POST",
                body: { schema },
                requestKey: null,
            });
            data.plannedSchema = schema;
            data.canApply = data.plan.canApply;
            data.allowDestructive = false;
        } catch (err) {
            app.checkApiError(err);
        }
        data.isBusy = false;
    }

    async function apply() {
        if (data.isBusy || !data.canSubmitApply) {
            return;
        }

        data.isBusy = true;
        try {
            const result = await app.pb.send("/api/graphql/schema/apply", {
                method: "POST",
                body: {
                    schema: data.schema,
                    planHash: data.plan.planHash,
                    allowDestructive: data.allowDestructive,
                },
                requestKey: null,
            });

            app.toasts.success(`Successfully applied the schema (${result.migrationFile || "no changes"}).`);

            await Promise.all([load(), app.store.silentlyReloadCollections()]);
        } catch (err) {
            app.checkApiError(err);
            // e.g. a stale plan
            data.plan = null;
            data.plannedSchema = null;
        }
        data.isBusy = false;
    }

    function upload(e) {
        const file = e.target.files?.[0];
        if (!file) {
            return;
        }

        const reader = new FileReader();
        reader.onload = () => {
            data.schema = String(reader.result || "");
            e.target.value = "";
        };
        reader.readAsText(file);
    }

    function planView() {
        const plan = data.plan;

        if (plan.errors?.length) {
            return t.div(
                { className: "alert danger graphql-schema-errors m-t-sm" },
                t.div(
                    { className: "content" },
                    plan.errors.map((err) =>
                        t.div(
                            null,
                            err.line ? t.code(null, `${err.line}:${err.column}`) : null,
                            " ",
                            err.message,
                        )
                    ),
                ),
            );
        }

        return t.div(
            { className: "graphql-schema-plan m-t-sm" },
            plan.warnings?.length
                ? t.div(
                    { className: "alert warning graphql-schema-warnings m-b-sm" },
                    t.div({ className: "content" }, plan.warnings.map((w) => t.div(null, w))),
                )
                : null,
            !plan.changes?.length
                ? t.div({ className: "txt-hint graphql-schema-no-changes" }, "No changes.")
                : t.div(
                    { className: "list" },
                    plan.changes.map((change) =>
                        t.div(
                            {
                                className: "list-item graphql-schema-change",
                                "html-data-collection": change.collection,
                                "html-data-action": change.action,
                            },
                            t.div(
                                { className: "content" },
                                t.strong(null, change.collection),
                                " ",
                                t.span(
                                    { className: `label sm ${change.destructive ? "danger" : ""}` },
                                    change.action,
                                ),
                                t.small(
                                    { className: "txt-hint" },
                                    " ",
                                    [
                                        ...(change.details || []),
                                        ...(change.fields || []).map((f) => `${f.action} ${f.name}`),
                                    ].join(", "),
                                ),
                            ),
                        )
                    ),
                ),
            data.isDestructive
                ? t.div(
                    { className: "field m-t-sm" },
                    t.input({
                        id: "graphql.allowDestructive",
                        name: "allowDestructive",
                        type: "checkbox",
                        checked: () => data.allowDestructive,
                        onchange: (e) => data.allowDestructive = e.target.checked,
                    }),
                    t.label(
                        { htmlFor: "graphql.allowDestructive", className: "txt-danger" },
                        "I understand that the destructive changes permanently delete data.",
                    ),
                )
                : null,
        );
    }

    return t.div(
        { pbEvent: "graphqlSchemaEditor", className: "graphql-schema-editor" },
        t.h6({ className: "m-b-xs" }, "Schema"),
        t.div(
            { className: "txt-hint txt-sm m-b-sm" },
            "Describe the collections with a GraphQL schema: applying it creates, changes or deletes the collections and generates a migration. The system and view collections are not part of it.",
        ),
        () => {
            if (data.isLoading) {
                return t.div({ className: "block txt-center" }, t.span({ className: "loader" }));
            }

            return [
                !data.canApply
                    ? t.div(
                        { className: "alert warning graphql-schema-readonly m-b-sm" },
                        t.div(
                            { className: "content" },
                            "The schema is read-only because the migrations can't be generated here: the migratecmd plugin with automigrate enabled is required.",
                        ),
                    )
                    : null,
                data.drifted
                    ? t.div(
                        { className: "alert warning graphql-schema-drifted m-b-sm" },
                        t.div(
                            { className: "content" },
                            "The stored schema no longer matches the current collections (they were changed outside of this editor). Applying it would change them back.",
                        ),
                        t.button(
                            {
                                type: "button",
                                className: "btn sm graphql-schema-regenerate-btn",
                                onclick: () => load("derived"),
                            },
                            t.span({ className: "txt" }, "Regenerate from current collections"),
                        ),
                    )
                    : null,
                t.div(
                    { className: "field graphql-schema-field" },
                    app.components.codeEditor({
                        id: "graphql.schema",
                        name: "schema",
                        language: "graphql",
                        disabled: () => !data.canApply || data.isBusy,
                        value: () => data.schema,
                        oninput: (val) => data.schema = val,
                    }),
                ),
                t.div(
                    { className: "flex m-t-sm" },
                    t.label(
                        {
                            className: "btn sm secondary graphql-schema-upload-btn",
                            hidden: () => !data.canApply,
                        },
                        t.span({ className: "txt" }, "Upload .graphqls"),
                        t.input({
                            type: "file",
                            name: "schemaFile",
                            className: "hidden",
                            accept: ".graphqls,.graphql,text/plain",
                            onchange: upload,
                        }),
                    ),
                    t.div({ className: "m-r-auto" }),
                    t.button(
                        {
                            type: "button",
                            className: () =>
                                `btn sm secondary graphql-schema-preview-btn ${data.isBusy ? "loading" : ""}`,
                            disabled: () => data.isBusy,
                            onclick: preview,
                        },
                        t.span({ className: "txt" }, "Preview changes"),
                    ),
                    t.button(
                        {
                            type: "button",
                            className: () => `btn sm graphql-schema-apply-btn ${data.isBusy ? "loading" : ""}`,
                            hidden: () => !data.canApply,
                            disabled: () => data.isBusy || !data.canSubmitApply,
                            onclick: apply,
                        },
                        t.span({ className: "txt" }, "Apply"),
                    ),
                ),
                t.div(
                    { className: "graphql-schema-plan-wrapper" },
                    () => {
                        if (data.plan && data.plannedSchema === data.schema) {
                            return planView();
                        }
                    },
                ),
            ];
        },
    );
}
