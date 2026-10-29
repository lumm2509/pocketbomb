import { OAUTH2_CLIENTS_COLLECTION, oauth2AuthCollections } from "@/settings/oauth2/oauth2Utils";
import { settingsSidebar } from "../settingsSidebar";
import { openOAuth2ClientUpsertModal } from "./oauth2ClientUpsertModal";

export function pageOAuth2Clients(route) {
    app.store.title = "OAuth2 clients";

    const data = store({
        isLoading: false,
        clients: [],
        search: "",
        collectionId: route.query.collection?.[0] || "",
        get collectionOptions() {
            return [{ value: "", label: "All issuers" }].concat(
                oauth2AuthCollections().map((c) => ({
                    value: c.id,
                    label: c.name,
                })),
            );
        },
        get filteredClients() {
            const search = data.search.trim().toLowerCase();

            return data.clients.filter((c) => {
                if (data.collectionId && c.collectionRef != data.collectionId) {
                    return false;
                }

                if (search) {
                    return c.name.toLowerCase().includes(search) || c.clientId.toLowerCase().includes(search);
                }

                return true;
            });
        },
        // the filtered clients grouped by their issuer collection
        get groups() {
            const groups = [];

            for (const client of data.filteredClients) {
                let group = groups.find((g) => g.collectionId == client.collectionRef);
                if (!group) {
                    const collection = app.store.collections.find((c) => c.id == client.collectionRef);
                    group = {
                        collectionId: client.collectionRef,
                        collection,
                        clients: [],
                    };
                    groups.push(group);
                }
                group.clients.push(client);
            }

            return groups.sort((a, b) => (a.collection?.name || "").localeCompare(b.collection?.name || ""));
        },
    });

    // resolve possible collection name in the url query param
    if (data.collectionId) {
        const collection = app.store.collections.find((c) => c.id == data.collectionId || c.name == data.collectionId);
        data.collectionId = collection?.id || "";
    }

    loadClients();

    async function loadClients() {
        data.isLoading = true;

        try {
            data.clients = await app.pb.collection(OAUTH2_CLIENTS_COLLECTION).getFullList({
                sort: "name",
                requestKey: "oauth2_apps_list",
            });
            data.isLoading = false;
        } catch (err) {
            if (!err.isAbort) {
                app.checkApiError(err);
                data.isLoading = false;
            }
        }
    }

    function openUpsert(client = null) {
        openOAuth2ClientUpsertModal(client, {
            collectionId: data.collectionId,
            onsave: (saved) => {
                const index = data.clients.findIndex((c) => c.id == saved.id);
                if (index >= 0) {
                    data.clients[index] = Object.assign({}, data.clients[index], saved);
                } else {
                    data.clients.push(saved);
                }
            },
            ondelete: (deleted) => {
                data.clients = data.clients.filter((c) => c.id != deleted.id);
            },
        });
    }

    function changeCollectionFilter(collectionId) {
        data.collectionId = collectionId;
        app.utils.replaceHashQueryParams({ collection: collectionId || null });
    }

    function clientRow(client) {
        return t.div(
            {
                className: () => `list-item handle oauth2-app-item ${client.disabled ? "faded" : ""}`,
                tabIndex: 0,
                onclick: () => openUpsert(client),
                onkeydown: (e) => {
                    if (e.key == "Enter") {
                        openUpsert(client);
                    }
                },
            },
            t.figure(
                { className: "oauth2-app-logo-thumb" },
                () => {
                    if (client.logo) {
                        return t.img({ src: client.logo, alt: "", loading: "lazy" });
                    }
                    return t.i({ className: "ri-apps-2-line", ariaHidden: true });
                },
            ),
            t.div(
                { className: "content" },
                t.span({ className: "txt-bold txt-ellipsis" }, () => client.name),
                t.small({ className: "txt-hint txt-code txt-ellipsis" }, () => client.clientId),
            ),
            t.div(
                { className: "oauth2-app-labels" },
                t.span(
                    { className: () => `label ${client.type == "confidential" ? "info" : ""}` },
                    () => client.type,
                ),
                () => (client.firstParty ? t.span({ className: "label success" }, "first-party") : null),
                () => (client.applicationInstallationRef
                    ? t.span(
                        {
                            className: "label info",
                            ariaDescription: app.attrs.tooltip("Application installation credentials (read-only)"),
                        },
                        t.i({ className: "ri-apps-2-add-line", ariaHidden: true }),
                        " managed",
                    )
                    : null),
                () => (client.clientId == "pb_dashboard"
                    ? t.span(
                        {
                            className: "label warning",
                            ariaDescription: app.attrs.tooltip("Built-in dashboard client (protected)"),
                        },
                        t.i({ className: "ri-lock-line", ariaHidden: true }),
                        " built-in, read-only",
                    )
                    : null),
                () => (client.disabled ? t.span({ className: "label danger" }, "disabled") : null),
                () => {
                    if (client.type == "confidential" && client.hasClientSecret === false) {
                        return t.span(
                            {
                                className: "label warning",
                                ariaDescription: app.attrs.tooltip("Generate a client secret to use the app"),
                            },
                            "no secret",
                        );
                    }
                },
            ),
            t.small(
                { className: "txt-hint txt-nowrap oauth2-app-uris" },
                () => {
                    if (client.applicationInstallationRef) {
                        return "client_credentials";
                    }
                    const n = client.redirectURIs?.length || 0;
                    return n + (n == 1 ? " redirect URI" : " redirect URIs");
                },
            ),
            t.i({ className: "ri-arrow-right-s-line txt-hint", ariaHidden: true }),
        );
    }

    return t.div(
        { pbEvent: "pageOAuth2Clients", className: "page page-oauth2-clients" },
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
                app.components.refreshButton({
                    className: "btn sm transparent secondary circle",
                    onclick: loadClients,
                }),
                t.div(
                    { className: "page-header-primary-btns" },
                    t.button(
                        { type: "button", className: "btn sm", onclick: () => openUpsert() },
                        t.i({ className: "ri-add-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "New OAuth2 client"),
                    ),
                ),
            ),
            t.div(
                { className: "wrapper m-b-base" },
                t.div(
                    { className: "txt-hint m-b-sm" },
                    "The OAuth2 / OpenID Connect client applications that can sign in users via an auth collection issuer (",
                    t.a({ href: "#/settings/oauth2" }, "provider settings"),
                    ").",
                ),
                t.div(
                    { className: "flex gap-10 m-b-sm oauth2-clients-filters" },
                    t.div(
                        { className: "field oauth2-clients-search" },
                        t.input({
                            type: "search",
                            placeholder: "Search by name or client ID...",
                            ariaLabel: "Search OAuth2 clients",
                            value: () => data.search,
                            oninput: (e) => (data.search = e.target.value),
                        }),
                    ),
                    t.div(
                        { className: "field oauth2-clients-collection-filter" },
                        app.components.select({
                            options: () => data.collectionOptions,
                            required: true,
                            value: () => data.collectionId,
                            onchange: (opts) => changeCollectionFilter(opts?.[0]?.value || ""),
                        }),
                    ),
                ),
                () => {
                    if (data.isLoading && !data.clients.length) {
                        return t.div(
                            { className: "list" },
                            t.div({ className: "list-item" }, t.div({ className: "skeleton-loader" })),
                            t.div({ className: "list-item" }, t.div({ className: "skeleton-loader" })),
                        );
                    }

                    if (!data.groups.length) {
                        return t.div(
                            { className: "list" },
                            t.div(
                                { className: "list-item" },
                                t.div(
                                    { className: "content block txt-hint txt-center" },
                                    data.clients.length
                                        ? "No OAuth2 clients match the filters."
                                        : "No OAuth2 clients registered yet.",
                                ),
                            ),
                        );
                    }

                    return data.groups.map((group) => {
                        return t.div(
                            { className: "oauth2-clients-group" },
                            t.div(
                                { className: "oauth2-clients-group-title" },
                                t.i({ className: "ri-key-2-line", ariaHidden: true }),
                                t.strong(null, group.collection?.name || group.collectionId),
                                () => {
                                    if (group.collection?.name == "_superusers") {
                                        return t.span({ className: "label" }, "staff issuer");
                                    }
                                },
                            ),
                            t.div({ className: "list" }, group.clients.map((c) => clientRow(c))),
                        );
                    });
                },
            ),
            t.footer({ className: "page-footer" }, app.components.credits()),
        ),
    );
}
