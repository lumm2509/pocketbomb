import {
    oauth2AppURL,
    oauth2AuthCollections,
    oauth2DiscoveryURL,
    oauth2IssuerURL,
} from "@/settings/oauth2/oauth2Utils";
import { settingsSidebar } from "../settingsSidebar";

export function pageOAuth2Settings(route) {
    app.store.title = "OAuth2 / OIDC";

    const data = store({
        isLoading: false,
        isSaving: false,
        defaultCollection: "",
        initialDefaultCollection: "",
        appsCount: {},
        get hasChanges() {
            return data.defaultCollection != data.initialDefaultCollection;
        },
        get issuers() {
            return oauth2AuthCollections();
        },
    });

    load();

    async function load() {
        data.isLoading = true;

        try {
            const [settings, clients] = await Promise.all([
                app.pb.settings.getAll(),
                app.pb.collection("_oauth2Clients").getFullList({ fields: "id,collectionRef", requestKey: null }),
                app.store.silentlyReloadCollections(),
            ]);

            init(settings);

            const counts = {};
            for (const c of clients) {
                counts[c.collectionRef] = (counts[c.collectionRef] || 0) + 1;
            }
            data.appsCount = counts;

            data.isLoading = false;
        } catch (err) {
            if (!err.isAbort) {
                app.checkApiError(err);
            }
        }
    }

    function init(settings) {
        app.store.settings = JSON.parse(JSON.stringify(settings));

        const value = settings?.oauth2Server?.defaultCollection || "";

        // normalize to collection id
        const collection = app.store.collections.find((c) => c.id == value || c.name == value);

        data.defaultCollection = collection?.id || value;
        data.initialDefaultCollection = data.defaultCollection;
    }

    async function save() {
        if (data.isSaving || !data.hasChanges) {
            return;
        }

        data.isSaving = true;

        try {
            const settings = await app.pb.settings.update({
                oauth2Server: { defaultCollection: data.defaultCollection },
            });
            init(settings);

            app.toasts.success("Successfully saved the OAuth2 / OIDC settings.");
        } catch (err) {
            app.checkApiError(err);
        }

        data.isSaving = false;
    }

    function linkRow(label, url) {
        return t.div(
            { className: "oauth2-url-row" },
            t.span({ className: "oauth2-url-label txt-hint txt-sm" }, label),
            t.a(
                {
                    className: "oauth2-url-value txt-code txt-ellipsis",
                    href: url,
                    target: "_blank",
                    rel: "noopener noreferrer",
                    title: url,
                },
                url,
            ),
            app.components.copyButton(url),
        );
    }

    function issuersSection() {
        return t.div(
            { className: "col-lg-12" },
            t.div(
                { className: "oauth2-settings-section-title" },
                t.h6(null, "Issuers"),
                t.div(
                    { className: "txt-hint txt-sm" },
                    "Every auth collection is a separate OpenID Connect issuer. Configure it from the collection ",
                    t.em(null, "Options > Identity provider"),
                    " settings.",
                ),
            ),
            () => {
                if (!data.issuers.length) {
                    return t.div(
                        { className: "list" },
                        t.div(
                            { className: "list-item" },
                            t.div(
                                { className: "content block txt-hint txt-center" },
                                "No auth collections.",
                            ),
                        ),
                    );
                }

                return t.div(
                    { className: "oauth2-issuers" },
                    data.issuers.map((collection) => {
                        const count = data.appsCount[collection.id] || 0;

                        return t.div(
                            { className: "oauth2-issuer-card" },
                            t.div(
                                { className: "oauth2-issuer-card-header" },
                                t.i({ className: "ri-key-2-line", ariaHidden: true }),
                                t.strong(null, collection.name),
                                () => {
                                    if (collection.name == "_superusers") {
                                        return t.span({ className: "label" }, "staff issuer");
                                    }
                                },
                                () => {
                                    if (collection.id == data.initialDefaultCollection) {
                                        return t.span({ className: "label success" }, "default");
                                    }
                                },
                                t.div({ className: "flex-fill" }),
                                t.a(
                                    {
                                        href: "#/settings/oauth2-clients?collection="
                                            + encodeURIComponent(collection.id),
                                        className: "btn sm secondary transparent",
                                    },
                                    t.i({ className: "ri-apps-2-line", ariaHidden: true }),
                                    t.span(
                                        { className: "txt" },
                                        count + (count == 1 ? " OAuth2 client" : " OAuth2 clients"),
                                    ),
                                ),
                                t.a(
                                    {
                                        href: "#/collections?collection=" + encodeURIComponent(collection.id),
                                        className: "btn sm secondary transparent",
                                        ariaDescription: app.attrs.tooltip("Open collection"),
                                    },
                                    t.i({ className: "ri-database-2-line", ariaHidden: true }),
                                ),
                            ),
                            linkRow("Issuer", oauth2IssuerURL(collection)),
                            linkRow("Discovery", oauth2DiscoveryURL(collection)),
                            linkRow("JWKS", oauth2IssuerURL(collection) + "/jwks.json"),
                        );
                    }),
                );
            },
        );
    }

    function defaultIssuerSection() {
        return t.div(
            { className: "col-lg-12" },
            t.div(
                { className: "oauth2-settings-section-title" },
                t.h6(null, "Default issuer"),
                t.div(
                    { className: "txt-hint txt-sm" },
                    "The default issuer metadata is also served at the app root ",
                    t.code(null, "/.well-known/openid-configuration"),
                    ", ",
                    t.code(null, "/.well-known/oauth-authorization-server"),
                    " and ",
                    t.code(null, "/.well-known/oauth-protected-resource"),
                    ".",
                ),
            ),
            t.div(
                { className: "grid" },
                t.div(
                    { className: "col-lg-6" },
                    t.div(
                        { className: "field" },
                        t.label({ htmlFor: "oauth2Server.defaultCollection" }, "Default issuer collection"),
                        app.components.select({
                            id: "oauth2Server.defaultCollection",
                            name: "oauth2Server.defaultCollection",
                            options: () =>
                                [{ value: "", label: "None (disable the root discovery)" }].concat(
                                    oauth2AuthCollections().map((c) => ({
                                        value: c.id,
                                        label: c.name,
                                    })),
                                ),
                            value: () => data.defaultCollection,
                            onchange: (opts) => (data.defaultCollection = opts?.[0]?.value || ""),
                        }),
                    ),
                ),
                t.div(
                    { className: "col-lg-6" },
                    () => {
                        if (!oauth2AppURL() || !data.initialDefaultCollection) {
                            return;
                        }

                        return t.div(
                            { className: "oauth2-urls" },
                            linkRow("Root discovery", oauth2AppURL() + "/.well-known/openid-configuration"),
                        );
                    },
                ),
            ),
        );
    }

    return t.div(
        { pbEvent: "pageOAuth2Settings", className: "page page-oauth2-settings" },
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
                        { href: "#/settings/oauth2-clients", className: "btn sm transparent secondary" },
                        t.i({ className: "ri-apps-2-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "OAuth2 clients"),
                    ),
                ),
            ),
            t.div(
                { className: "wrapper m-b-base" },
                () => {
                    if (data.isLoading) {
                        return t.div({ className: "block txt-center" }, t.span({ className: "loader lg" }));
                    }

                    return t.form(
                        {
                            pbEvent: "oauth2SettingsForm",
                            className: "grid oauth2-settings-form",
                            inert: () => data.isSaving,
                            onsubmit: (e) => {
                                e.preventDefault();
                                save();
                            },
                        },
                        () => {
                            if (oauth2AppURL()) {
                                return;
                            }

                            return t.div(
                                { className: "col-lg-12" },
                                t.div(
                                    { className: "alert warning" },
                                    t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                                    t.div(
                                        { className: "content" },
                                        "The issuer identifiers are based on the Application URL. Set it in ",
                                        t.a({ href: "#/settings" }, "Settings > Application"),
                                        ".",
                                    ),
                                ),
                            );
                        },
                        defaultIssuerSection(),
                        t.div({ className: "col-lg-12" }, t.hr()),
                        issuersSection(),
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
                                        onclick: () => (data.defaultCollection = data.initialDefaultCollection),
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
                },
            ),
            t.footer({ className: "page-footer" }, app.components.credits()),
        ),
    );
}
