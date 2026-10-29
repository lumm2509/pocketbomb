import { openApplicationCatalogPanel } from "./applicationCatalogPanel";
import { openApplicationCreateModal } from "./applicationCreateModal";
import { applicationsSidebar } from "./applicationExtensions";
import { openApplicationPanel } from "./applicationPanel";
import {
    applicationGrantSummary,
    applicationIcon,
    loadApplicationCatalog,
    loadApplications,
} from "./applicationsUtils";

const TAB_INSTALLED = "installed";
const TAB_CATALOG = "catalog";

export function pageApplications(route) {
    app.store.title = "Applications";

    const data = store({
        activeTab: route?.query?.tab?.[0] == TAB_CATALOG ? TAB_CATALOG : TAB_INSTALLED,
        isLoading: false,
        isCatalogLoading: false,
        items: [],
        resources: [],
        superuserIPsRestricted: false,
        catalogSources: [],
        catalogItems: [],
        search: "",
        get filteredCatalog() {
            const search = data.search.trim().toLowerCase();
            if (!search) {
                return data.catalogItems;
            }

            return data.catalogItems.filter((e) =>
                e.name.toLowerCase().includes(search) || e.handle.toLowerCase().includes(search)
            );
        },
        get filtered() {
            const search = data.search.trim().toLowerCase();
            if (!search) {
                return data.items;
            }

            return data.items.filter((a) =>
                a.name.toLowerCase().includes(search) || a.handle.toLowerCase().includes(search)
            );
        },
        get installed() {
            return data.filtered.filter((a) => a.installation);
        },
        get notInstalled() {
            return data.filtered.filter((a) => !a.installation);
        },
    });

    async function load() {
        data.isLoading = true;

        try {
            const result = await loadApplications();
            data.items = result.items || [];
            data.resources = result.resources || [];
            data.superuserIPsRestricted = !!result.superuserIPsRestricted;
            data.isLoading = false;

            // e.g. after install, update or uninstall
            app.store.loadApplicationExtensions();
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
                data.isLoading = false;
            }
        }
    }

    async function loadCatalog(refresh = false) {
        data.isCatalogLoading = true;

        try {
            const result = await loadApplicationCatalog(refresh);
            data.catalogSources = result.sources || [];
            data.catalogItems = result.items || [];
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        data.isCatalogLoading = false;
    }

    load();
    loadCatalog();

    function refresh() {
        load();
        loadCatalog(true);
    }

    // the catalog entry of an installed catalog application (e.g. for the update review)
    function catalogEntryOf(application) {
        if (application.source != "catalog") {
            return null;
        }
        return data.catalogItems.find((e) => e.applicationId == application.id) || null;
    }

    function openPanel(application, tab = "") {
        openApplicationPanel(application, data.resources, {
            tab: tab,
            superuserIPsRestricted: data.superuserIPsRestricted,
            catalogEntry: catalogEntryOf(application),
            onchange: () => {
                load();
                loadCatalog();
            },
        });
    }

    function openCatalogEntry(entry) {
        const installed = entry.applicationId && data.items.find((a) => a.id == entry.applicationId && a.installation);
        if (installed) {
            openPanel(installed);
            return;
        }

        openApplicationCatalogPanel(entry, data.resources, {
            oninstall: () => {
                load();
                loadCatalog();
            },
        });
    }

    function applicationRow(application) {
        return t.div(
            {
                className: "list-item handle oauth2-app-item application-item",
                "html-data-handle": application.handle,
                tabIndex: 0,
                onclick: () => openPanel(application),
                onkeydown: (e) => {
                    if (e.key == "Enter") {
                        openPanel(application);
                    }
                },
            },
            applicationIcon(application.iconURL),
            t.div(
                { className: "content" },
                t.span({ className: "txt-bold txt-ellipsis" }, application.name),
                t.small(
                    { className: "txt-hint txt-ellipsis" },
                    application.installation
                        ? applicationGrantSummary(application.installation.permissions)
                        : (application.description || application.handle),
                ),
            ),
            t.div(
                { className: "oauth2-app-labels" },
                t.span({ className: "label" }, application.source),
                application.latestVersion
                    ? t.span({ className: "label" }, "v" + application.latestVersion.version)
                    : null,
                () =>
                    catalogEntryOf(application)?.updateAvailable
                        ? t.span({ className: "label warning application-update-badge" }, "update available")
                        : null,
                application.installation?.status == "pending"
                    ? t.span({ className: "label warning" }, "pending")
                    : application.installation
                    ? t.span({ className: "label success" }, "installed")
                    : t.span({ className: "label" }, "not installed"),
            ),
            t.i({ className: "ri-arrow-right-s-line txt-hint", ariaHidden: true }),
        );
    }

    function catalogRow(entry) {
        return t.div(
            {
                className: "list-item handle oauth2-app-item application-catalog-item",
                "html-data-handle": entry.handle,
                "html-data-source": entry.source,
                tabIndex: 0,
                onclick: () => openCatalogEntry(entry),
                onkeydown: (e) => {
                    if (e.key == "Enter") {
                        openCatalogEntry(entry);
                    }
                },
            },
            applicationIcon(entry.iconURL),
            t.div(
                { className: "content" },
                t.span({ className: "txt-bold txt-ellipsis" }, entry.name),
                t.small({ className: "txt-hint txt-ellipsis" }, entry.description || entry.handle),
            ),
            t.div(
                { className: "oauth2-app-labels" },
                t.span({ className: "label" }, "v" + entry.version),
                entry.updateAvailable
                    ? t.span({ className: "label warning" }, "update available")
                    : null,
                entry.conflict
                    ? t.span({ className: "label danger" }, "handle conflict")
                    : entry.installed
                    ? t.span({ className: "label success" }, "installed")
                    : null,
            ),
            t.i({ className: "ri-arrow-right-s-line txt-hint", ariaHidden: true }),
        );
    }

    function catalogTab() {
        if (data.isCatalogLoading && !data.catalogSources.length) {
            return t.div(
                { className: "list" },
                t.div({ className: "list-item" }, t.div({ className: "skeleton-loader" })),
            );
        }

        if (!data.catalogSources.length) {
            return t.div(
                { className: "alert info application-catalog-empty" },
                t.div(
                    { className: "content" },
                    "No catalog sources are configured. ",
                    app.perms.isOwner()
                        ? t.a({ href: "#/settings/applications" }, "Configure the catalog sources")
                        : "Ask an Owner to configure the catalog sources.",
                ),
            );
        }

        return data.catalogSources.map((source) => {
            const items = data.filteredCatalog.filter((e) => e.source == source.name);

            return t.div(
                {
                    className: "oauth2-clients-group applications-group application-catalog-source",
                    "html-data-source": source.name,
                },
                t.div(
                    { className: "oauth2-clients-group-title" },
                    t.strong(null, source.name),
                    source.error
                        ? t.span({ className: "label danger" }, "error")
                        : source.signed
                        ? t.span({ className: "label success sm application-catalog-signed" }, "signed")
                        : t.span({ className: "label warning sm application-catalog-unsigned" }, "unsigned catalog"),
                    t.span({ className: "label sm" }, items.length),
                ),
                source.error
                    ? t.div(
                        { className: "alert danger application-catalog-error" },
                        t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                        t.div({ className: "content" }, source.error),
                    )
                    : t.div(
                        { className: "list" },
                        items.length
                            ? items.map((e) => catalogRow(e))
                            : t.div(
                                { className: "list-item" },
                                t.div({ className: "content block txt-center txt-hint" }, "No applications."),
                            ),
                    ),
            );
        });
    }

    function group(title, items, emptyText) {
        return t.div(
            { className: "oauth2-clients-group applications-group" },
            t.div(
                { className: "oauth2-clients-group-title" },
                t.strong(null, title),
                t.span({ className: "label sm" }, items.length),
            ),
            t.div(
                { className: "list" },
                items.length
                    ? items.map((a) => applicationRow(a))
                    : t.div(
                        { className: "list-item" },
                        t.div({ className: "content block txt-hint txt-center" }, emptyText),
                    ),
            ),
        );
    }

    return t.div(
        { pbEvent: "pageApplications", className: "page page-applications" },
        applicationsSidebar(),
        t.div(
            { className: "page-content full-height" },
            t.header(
                { className: "page-header" },
                t.nav({ className: "breadcrumbs" }, t.div(null, "Applications")),
                app.components.refreshButton({ onclick: refresh }),
                t.div(
                    { className: "page-header-primary-btns" },
                    t.button(
                        {
                            type: "button",
                            className: "btn sm new-application-btn",
                            hidden: () => !app.perms.can("applications", "write"),
                            onclick: () =>
                                openApplicationCreateModal({
                                    onsave: async (application) => {
                                        await load();
                                        const fresh = data.items.find((a) => a.id == application.id);
                                        if (fresh && !fresh.installation) {
                                            openPanel(fresh, "permissions");
                                        }
                                    },
                                }),
                        },
                        t.i({ className: "ri-add-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "Create custom application"),
                    ),
                ),
            ),
            t.div(
                { className: "wrapper m-b-base" },
                t.p(
                    { className: "txt-hint m-b-sm" },
                    "The applications are integrations (extensions, scripts, external services) installed with an explicit permissions grant. ",
                    "Each installation has its own Admin API access credentials: an OAuth2 client that exchanges its client ID and secret for short-lived access tokens (",
                    t.code(null, "client_credentials"),
                    ").",
                ),
                t.div(
                    { className: "field m-b-sm applications-search" },
                    t.input({
                        type: "search",
                        placeholder: "Search by name or handle...",
                        ariaLabel: "Search applications",
                        value: () => data.search,
                        oninput: (e) => (data.search = e.target.value),
                    }),
                ),
                t.nav(
                    { className: "tabs-header m-b-sm applications-tabs" },
                    t.button(
                        {
                            type: "button",
                            className: () =>
                                `tab-item applications-tab-installed ${
                                    data.activeTab == TAB_INSTALLED ? "active" : ""
                                }`,
                            onclick: () => (data.activeTab = TAB_INSTALLED),
                        },
                        t.span({ className: "txt" }, "Installed"),
                    ),
                    t.button(
                        {
                            type: "button",
                            className: () =>
                                `tab-item applications-tab-catalog ${data.activeTab == TAB_CATALOG ? "active" : ""}`,
                            onclick: () => (data.activeTab = TAB_CATALOG),
                        },
                        t.span({ className: "txt" }, "Catalog"),
                    ),
                ),
                () => {
                    if (data.activeTab == TAB_CATALOG) {
                        return catalogTab();
                    }

                    if (data.isLoading && !data.items.length) {
                        return t.div(
                            { className: "list" },
                            t.div({ className: "list-item" }, t.div({ className: "skeleton-loader" })),
                            t.div({ className: "list-item" }, t.div({ className: "skeleton-loader" })),
                        );
                    }

                    return [
                        group("Installed", data.installed, "No installed applications."),
                        group(
                            "Not installed",
                            data.notInstalled,
                            data.items.length ? "All applications are installed." : "No applications yet.",
                        ),
                    ];
                },
            ),
            t.footer({ className: "page-footer" }, app.components.credits()),
        ),
    );
}
