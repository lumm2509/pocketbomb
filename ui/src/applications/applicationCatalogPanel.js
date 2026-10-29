import { permissionsCollectionsMatrix, permissionsSystemMatrix } from "@/auth/permissionsEditor";
import { normalizePermissions } from "@/auth/rolesUtils";
import { applicationIcon, applicationScopesAllows, applicationScopesToPermissions } from "./applicationsUtils";

const STEP_DETAILS = "details";
const STEP_REVIEW = "review";

/**
 * Opens the catalog application detail drawer (with the install review).
 *
 * The credentials of the catalog applications are delivered only to the application
 * (signed install notification) and they are never shown in the dashboard.
 *
 * @param {Object}   entry     The /api/applications/catalog item.
 * @param {Array}    resources The permissions registry system resources.
 * @param {Object}   [settings]
 * @param {function} [settings.oninstall] Called after a successful install.
 */
export function openApplicationCatalogPanel(entry, resources, settings = {}) {
    app.store.errors = null;

    const modal = applicationCatalogPanel(entry, resources, settings);

    document.body.appendChild(modal);

    app.modals.open(modal);
}

function applicationCatalogPanel(entry, resources, settings) {
    const data = store({
        step: STEP_DETAILS,
        isLoading: true,
        isInstalling: false,
        loadError: "",
        installError: "",
        manifest: null,
        scopes: [],
        grant: normalizePermissions({}),
        get allowedScopes() {
            return data.scopes.map((s) => s.scope);
        },
        get canInstall() {
            return app.perms.can("applications", "write") && !entry.installed && !entry.conflict && !!data.manifest;
        },
    });

    async function loadManifest() {
        data.isLoading = true;
        data.loadError = "";

        try {
            const params = new URLSearchParams({ source: entry.source, handle: entry.handle });
            const result = await app.pb.send("/api/applications/catalog/manifest?" + params.toString(), {
                requestKey: "application_catalog_manifest",
            });
            data.manifest = result.manifest;
            data.scopes = result.scopes || [];
            // prefilled with the requested (not optional) scopes
            data.grant = normalizePermissions(
                applicationScopesToPermissions(data.scopes.filter((s) => !s.optional).map((s) => s.scope)),
            );
        } catch (err) {
            if (!err?.isAbort) {
                data.loadError = err?.response?.message || err?.message || "Failed to load the application manifest.";
            }
        }

        data.isLoading = false;
    }

    loadManifest();

    async function install() {
        if (data.isInstalling) {
            return;
        }

        data.isInstalling = true;
        data.installError = "";

        try {
            await app.pb.send("/api/applications/catalog/install", {
                method: "POST",
                body: { source: entry.source, handle: entry.handle, permissions: data.grant },
            });

            app.store.errors = null;
            app.toasts.success(
                `Successfully installed "${entry.name}". The credentials were delivered to the application.`,
            );

            settings.oninstall?.();

            data.isInstalling = false;
            app.modals.close(modal, true);

            return;
        } catch (err) {
            if (!err?.isAbort) {
                // e.g. the application rejected the install notification (the installation was rolled back)
                data.installError = err?.response?.message || err?.message || "Failed to install the application.";
                app.checkApiError(err, false);
            }
        }

        data.isInstalling = false;
    }

    function scopesList() {
        if (!data.scopes.length) {
            return t.div({ className: "txt-hint txt-sm" }, "The application doesn't request any scope.");
        }

        return t.div(
            { className: "list application-catalog-scopes" },
            data.scopes.map((s) =>
                t.div(
                    { className: "list-item" },
                    t.div(
                        { className: "content" },
                        t.code(null, s.scope),
                        s.optional ? t.span({ className: "label sm" }, "optional") : null,
                        t.small({ className: "txt-hint" }, s.label || ""),
                    ),
                )
            ),
        );
    }

    function detailsStep() {
        return t.div(
            { className: "application-catalog-details" },
            entry.description ? t.p(null, entry.description) : null,
            infoRow("Handle", t.code(null, entry.handle)),
            infoRow("Version", "v" + entry.version),
            infoRow(
                "Catalog",
                [
                    entry.source + " ",
                    entry.signed
                        ? t.span({ className: "label success sm" }, "signed")
                        : t.span({ className: "label warning sm" }, "unsigned catalog"),
                ],
            ),
            entry.developer?.name || entry.developer?.url
                ? infoRow(
                    "Developer",
                    entry.developer.url
                        ? t.a(
                            { href: entry.developer.url, target: "_blank", rel: "noopener noreferrer" },
                            entry.developer.name || entry.developer.url,
                        )
                        : entry.developer.name,
                )
                : null,
            entry.conflict
                ? t.div(
                    { className: "alert warning m-t-sm" },
                    t.div({ className: "content" }, "A custom application with the same handle already exists."),
                )
                : null,
            t.h6({ className: "m-t-base m-b-xs" }, "Requested scopes"),
            () => {
                if (data.isLoading) {
                    return t.div({ className: "skeleton-loader" });
                }
                if (data.loadError) {
                    return t.div(
                        { className: "alert danger application-catalog-load-error" },
                        t.div({ className: "content" }, data.loadError),
                    );
                }
                return scopesList();
            },
        );
    }

    function reviewStep() {
        const editorSettings = {
            application: true,
            resources: resources,
            permissions: () => data.grant,
            onchange: (permissions) => (data.grant = permissions),
            readOnly: () => data.isInstalling,
            // only the requested and the optional scopes could be granted
            allows: applicationScopesAllows(data.allowedScopes),
        };

        return t.div(
            { className: "application-permissions application-catalog-review" },
            t.p(
                { className: "txt-hint txt-sm" },
                "Review the installation grant: it is prefilled with the requested scopes and it could only be reduced or extended with the optional scopes. ",
                "The credentials are delivered only to the application (signed install notification); the install is rolled back if the application doesn't acknowledge it.",
            ),
            () => {
                if (data.installError) {
                    return t.div(
                        { className: "alert danger application-install-error" },
                        t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                        t.div({ className: "content" }, data.installError),
                    );
                }
            },
            t.h6({ className: "m-b-xs" }, "Collections"),
            permissionsCollectionsMatrix(editorSettings),
            t.h6({ className: "m-t-sm m-b-xs" }, "System"),
            permissionsSystemMatrix(editorSettings),
        );
    }

    function infoRow(label, value) {
        return t.div(
            { className: "application-info-row" },
            t.span({ className: "txt-hint txt-sm" }, label),
            t.div({ className: "content" }, value),
        );
    }

    const modal = t.div(
        {
            pbEvent: "applicationCatalogPanel",
            className: "modal application-panel application-catalog-panel",
            onbeforeclose: () => {
                if (data.isInstalling) {
                    return false;
                }
            },
            onafterclose: (el) => {
                app.store.errors = null;
                el?.remove();
            },
        },
        t.header(
            { className: "modal-header" },
            t.div(
                { className: "flex gap-10" },
                applicationIcon(entry.iconURL),
                t.h6(
                    { className: "modal-title application-panel-title" },
                    entry.name,
                    t.span({ className: "label sm" }, "v" + entry.version),
                    entry.installed ? t.span({ className: "label success sm" }, "installed") : null,
                ),
            ),
        ),
        t.div(
            { className: "modal-content" },
            () => (data.step == STEP_REVIEW ? reviewStep() : detailsStep()),
        ),
        t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn transparent m-r-auto application-catalog-back-btn",
                    disabled: () => data.isInstalling,
                    onclick: () => {
                        if (data.step == STEP_REVIEW) {
                            data.step = STEP_DETAILS;
                            return;
                        }
                        app.modals.close(modal);
                    },
                },
                t.span({ className: "txt" }, () => (data.step == STEP_REVIEW ? "Back" : "Close")),
            ),
            t.button(
                {
                    type: "button",
                    className: () =>
                        `btn expanded-lg application-catalog-install-btn ${data.isInstalling ? "loading" : ""}`,
                    hidden: () => !data.canInstall,
                    disabled: () => data.isInstalling || data.isLoading,
                    onclick: () => {
                        if (data.step != STEP_REVIEW) {
                            data.step = STEP_REVIEW;
                            return;
                        }
                        install();
                    },
                },
                t.span(
                    { className: "txt" },
                    () => (data.step == STEP_REVIEW ? "Install with these permissions" : "Review and install..."),
                ),
            ),
        ),
    );

    return modal;
}
