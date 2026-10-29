import { graphqlFieldsSelection, loadGraphQLInfo } from "@/collections/graphqlInfo";
import { clientCredentialsInfo } from "./clientCredentialsInfo";

export function docsGraphQL(collection) {
    const baseURL = app.utils.getApiExampleURL();

    const local = store({
        isLoading: true,
        enabled: true,
        limits: null,
        info: null,
        query: "",
        isRunning: false,
        result: "",
    });

    load();

    async function load() {
        try {
            const result = await loadGraphQLInfo("graphql_api_preview");
            local.enabled = !!result?.enabled;
            local.limits = result?.limits || null;
            local.info = (result?.collections || []).find((c) => c.collectionId == collection.id) || null;
            if (local.info?.included) {
                local.query = listQuery(local.info, 5);
            }
            local.isLoading = false;
        } catch (err) {
            if (!err?.isAbort) {
                local.isLoading = false;
                app.checkApiError(err);
            }
        }
    }

    async function run() {
        if (local.isRunning || !local.query.trim()) {
            return;
        }

        local.isRunning = true;

        try {
            const result = await app.pb.send("/api/graphql", {
                method: "POST",
                body: { query: local.query },
                requestKey: "graphql_api_preview_run",
            });
            local.result = JSON.stringify(result, null, 2);
        } catch (err) {
            if (err?.isAbort) {
                local.isRunning = false;
                return;
            }
            local.result = JSON.stringify(err?.response || { message: err?.message }, null, 2);
        }

        local.isRunning = false;
    }

    function indent(str, spaces) {
        const pad = " ".repeat(spaces);
        return str.split("\n").map((line) => pad + line).join("\n");
    }

    function listQuery(info, first = 10) {
        const sort = (info.sortFields || []).includes("created") ? `, sort: "-created"` : "";

        return [
            "query {",
            `  ${info.pluralField}(first: ${first}${sort}) {`,
            "    totalCount",
            "    edges {",
            "      cursor",
            "      node {",
            indent(graphqlFieldsSelection(info), 8),
            "      }",
            "    }",
            "    pageInfo {",
            "      hasNextPage",
            "      endCursor",
            "    }",
            "  }",
            "}",
        ].join("\n");
    }

    function singularQuery(info) {
        const lines = [
            "query ($id: ID!) {",
            `  ${info.singularField}(id: $id) {`,
            indent(graphqlFieldsSelection(info), 4),
            "  }",
            "}",
        ];

        const uniqueArg = info.uniqueArgs?.[0];
        if (uniqueArg) {
            lines.push(
                "",
                `# or by the unique "${uniqueArg}" field`,
                "query {",
                `  ${info.singularField}(${uniqueArg}: "VALUE") {`,
                "    id",
                "  }",
                "}",
            );
        }

        return lines.join("\n");
    }

    function examples(info) {
        const query = `query ($after: String) {
  ${info.pluralField}(first: 20, after: $after) {
    nodes {
      id
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}`;

        return app.components.codeBlockTabs({
            className: "sdk-examples m-t-sm",
            historyKey: "pbLastGraphQLExample",
            tabs: [
                {
                    title: "fetch (public key)",
                    language: "js",
                    value: `
                        // e.g. a storefront with a browser-safe public API key
                        const res = await fetch('${baseURL}/api/graphql', {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/json',
                            'X-PB-Public-Key': 'pb_pk_...',
                          },
                          body: JSON.stringify({
                            query: \`${query.replaceAll("\n", "\n                            ")}\`,
                            variables: { after: null },
                          }),
                        });

                        const { data, errors } = await res.json();
                    `,
                },
                {
                    title: "curl",
                    language: "bash",
                    value: `
                        curl -X POST \\
                          -H 'Content-Type: application/json' \\
                          -H 'Authorization: TOKEN' \\
                          -d '{"query":"{ ${info.pluralField}(first: 10) { nodes { id } } }"}' \\
                          '${baseURL}/api/graphql'
                    `,
                },
            ],
        });
    }

    function limitsInfo() {
        const limits = local.limits || {};

        const row = (name, value, description) =>
            t.tr(
                null,
                t.td({ className: "min-width" }, name),
                t.td({ className: "min-width" }, t.span({ className: "label" }, String(value ?? "-"))),
                t.td(null, description),
            );

        return t.table(
            { className: "api-preview-table graphql-limits" },
            t.thead(
                null,
                t.tr(
                    null,
                    t.th({ className: "min-width txt-primary" }, "Limits"),
                    t.th({ className: "min-width" }, "Value"),
                    t.th(null, "Description"),
                ),
            ),
            t.tbody(
                null,
                row("maxDepth", limits.maxDepth, "Max selection depth (the introspection fields are not counted)."),
                row(
                    "maxCost",
                    limits.maxCost,
                    "Max static cost: each record costs 1 and the lists multiply their children cost by first/last (default 50) or the relation max select.",
                ),
                row("maxPageSize", limits.maxPageSize, "Max first/last value."),
                row("maxQuerySize", limits.maxQuerySize, "Max query size in bytes."),
                row("timeout", limits.timeout ? limits.timeout + "s" : "-", "Max execution time."),
            ),
        );
    }

    function content() {
        const info = local.info;

        if (!info || !info.included) {
            return t.div(
                { className: "alert warning graphql-preview-skipped" },
                "This collection is not exposed in GraphQL",
                info?.reason ? ": " + info.reason : ".",
            );
        }

        return [
            t.p(
                null,
                `Read-only GraphQL API (queries only). The ${collection.name} records are available as `,
                t.code(null, info.typeName),
                " objects with the same access checks as the records API (API rules, API keys, OAuth2 scopes).",
            ),
            examples(info),
            t.div({ className: "block m-t-base" }, t.strong(null, "API details")),
            t.div(
                { className: "alert info api-preview-alert" },
                t.span({ className: "label method" }, "POST"),
                t.span({ className: "path" }, "/api/graphql"),
                t.small({ className: "extra" }, "or GET /api/graphql?query=..."),
            ),
            clientCredentialsInfo(),
            limitsInfo(),
            t.div({ className: "block m-t-base m-b-sm" }, t.strong(null, "List (Relay connection, cursor pagination)")),
            app.components.codeBlock({ language: "graphql", value: listQuery(info) }),
            t.div({ className: "block m-t-base m-b-sm" }, t.strong(null, "Single record")),
            app.components.codeBlock({ language: "graphql", value: singularQuery(info) }),
            t.div({ className: "block m-t-base m-b-sm" }, t.strong(null, "Try it (as the current dashboard user)")),
            t.div(
                { className: "field graphql-preview-query" },
                t.textarea({
                    rows: 10,
                    spellcheck: false,
                    value: () => local.query,
                    oninput: (e) => (local.query = e.target.value),
                }),
            ),
            t.div(
                { className: "flex m-t-sm" },
                t.button(
                    {
                        type: "button",
                        className: () => `btn sm graphql-preview-run ${local.isRunning ? "loading" : ""}`,
                        disabled: () => local.isRunning,
                        onclick: run,
                    },
                    t.i({ className: "ri-play-line", ariaHidden: true }),
                    t.span({ className: "txt" }, "Run query"),
                ),
            ),
            t.div({ className: "graphql-preview-result-wrapper" }, () => {
                if (local.result) {
                    return app.components.codeBlock({
                        className: "graphql-preview-result m-t-sm",
                        value: local.result,
                    });
                }
            }),
        ];
    }

    return t.div(
        { pbEvent: "apiPreviewGraphQL", className: "content" },
        () => {
            if (local.isLoading) {
                return t.div({ className: "block txt-center" }, t.span({ className: "loader" }));
            }

            const result = [];

            if (!local.enabled) {
                result.push(t.div({ className: "alert warning" }, "The GraphQL API is disabled (Settings > GraphQL)."));
            }

            result.push(...[].concat(content()));

            return result;
        },
    );
}
