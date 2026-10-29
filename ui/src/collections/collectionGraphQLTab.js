import { loadGraphQLInfo } from "./graphqlInfo";

export function collectionGraphQLTab(upsertData) {
    const local = store({
        isLoading: false,
        enabled: true,
        info: null,
    });

    const collectionId = upsertData.originalCollection?.id;

    load();

    async function load() {
        if (!collectionId || upsertData.originalCollection?.system) {
            return;
        }

        local.isLoading = true;

        try {
            const result = await loadGraphQLInfo("graphql_collection_tab");
            local.enabled = !!result?.enabled;
            local.info = (result?.collections || []).find((c) => c.collectionId == collectionId) || null;
            local.isLoading = false;
        } catch (err) {
            if (!err?.isAbort) {
                local.isLoading = false;
                app.checkApiError(err);
            }
        }
    }

    function fieldsTable(info) {
        return t.table(
            { className: "table collection-graphql-fields" },
            t.thead(
                null,
                t.tr(
                    null,
                    t.th(null, "Collection field"),
                    t.th(null, "GraphQL field"),
                    t.th(null, "Type"),
                ),
            ),
            t.tbody(
                null,
                () => {
                    return (info.fields || []).map((f) => {
                        return t.tr(
                            { className: f.reason ? "txt-hint" : "" },
                            t.td(null, f.field),
                            t.td(null, f.reason ? t.em(null, "skipped: " + f.reason) : t.code(null, f.name)),
                            t.td(null, f.type ? t.span({ className: "label" }, f.type) : null),
                        );
                    });
                },
            ),
        );
    }

    function includedInfo(info) {
        const singularArgs = ["id: ID"].concat((info.uniqueArgs || []).map((a) => `${a}: String`)).join(", ");

        return [
            t.div(
                { className: "grid sm" },
                t.div(
                    { className: "col-lg-12" },
                    t.div(
                        { className: "collection-graphql-names" },
                        t.div(null, t.span({ className: "txt-hint" }, "Type: "), t.code(null, info.typeName)),
                        t.div(
                            null,
                            t.span({ className: "txt-hint" }, "Single record: "),
                            t.code(null, `${info.singularField}(${singularArgs}): ${info.typeName}`),
                        ),
                        t.div(
                            null,
                            t.span({ className: "txt-hint" }, "List: "),
                            t.code(
                                null,
                                `${info.pluralField}(first, after, last, before, filter, sort, reverse): ${info.typeName}Connection`,
                            ),
                        ),
                        t.div(
                            null,
                            t.span({ className: "txt-hint" }, "Sortable fields: "),
                            (info.sortFields || []).join(", "),
                        ),
                    ),
                ),
                t.div({ className: "col-lg-12" }, fieldsTable(info)),
            ),
        ];
    }

    return t.div(
        { className: "collection-tab-content collection-graphql-tab-content" },
        t.div(
            { className: "txt-hint txt-sm m-b-sm" },
            "The collections with a List or View API rule are exposed in the read-only GraphQL API (",
            t.code(null, "/api/graphql"),
            ") with the same access checks as the records API.",
        ),
        () => {
            if (!collectionId) {
                return t.div({ className: "alert info" }, "Save the collection to see its GraphQL mapping.");
            }

            if (upsertData.originalCollection?.system) {
                return t.div({ className: "alert info" }, "The system collections are not exposed in GraphQL.");
            }

            if (local.isLoading) {
                return t.div({ className: "block txt-center" }, t.span({ className: "loader" }));
            }

            const result = [];

            if (!local.enabled) {
                result.push(
                    t.div(
                        { className: "alert warning" },
                        "The GraphQL API is disabled (Settings > GraphQL).",
                    ),
                );
            }

            if (!local.info) {
                return result;
            }

            if (!local.info.included) {
                result.push(
                    t.div(
                        { className: "alert warning collection-graphql-skipped" },
                        t.strong(null, "Not exposed: "),
                        local.info.reason,
                    ),
                );
                return result;
            }

            result.push(...includedInfo(local.info));

            return result;
        },
        t.div(
            { className: "txt-hint txt-sm m-t-sm" },
            "The mapping reflects the saved collection (unsaved changes are not included).",
        ),
    );
}
