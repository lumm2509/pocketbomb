import { permissionsCollectionsMatrix, permissionsSystemMatrix } from "@/auth/permissionsEditor";
import { actorCovers, normalizePermissions } from "@/auth/rolesUtils";
import { recordSessionsConsents } from "@/records/recordSessionsConsents";
import { openApplicationSecretModal } from "./applicationSecretModal";
import {
    applicationCurlExample,
    applicationGrantSummary,
    applicationIcon,
    applicationScopeCovered,
    applicationScopesAllows,
} from "./applicationsUtils";

const TAB_OVERVIEW = "overview";
const TAB_PERMISSIONS = "permissions";
const TAB_CREDENTIALS = "credentials";
const TAB_ACTIVITY = "activity";
const TAB_UPDATE = "update";

/**
 * Opens the application details panel.
 *
 * @param {Object}   application The /api/applications list item.
 * @param {Array}    resources   The permissions registry system resources.
 * @param {Object}   [settings]
 * @param {string}   [settings.tab]      The initial tab.
 * @param {Object}   [settings.catalogEntry] The catalog entry of a catalog application (for the update review).
 * @param {boolean}  [settings.superuserIPsRestricted] Whether the staff access is restricted to the SuperuserIPs.
 * @param {function} [settings.onchange] Called after each change (install, grant, rotate, uninstall, delete).
 */
export function openApplicationPanel(application, resources, settings = {}) {
    app.store.errors = null;

    const modal = applicationPanel(application, resources, settings);

    document.body.appendChild(modal);

    app.modals.open(modal);
}

function applicationPanel(application, resources, settings) {
    const data = store({
        application: application,
        activeTab: settings.tab || TAB_OVERVIEW,
        isBusy: false,
        grant: normalizePermissions(application.installation?.permissions),
        get installation() {
            return data.application.installation;
        },
        get isInstalled() {
            return !!data.application.installation;
        },
        get canWrite() {
            return app.perms.can("applications", "write");
        },
        // nobody grants (or hands over the credentials of) what they don't have
        get coversCurrentGrant() {
            return !data.isInstalled || actorCovers(data.installation.permissions);
        },
        get isGrantReadOnly() {
            return !data.canWrite || !data.coversCurrentGrant;
        },
        get hasGrantChanges() {
            return JSON.stringify(normalizePermissions(data.installation?.permissions)) != JSON.stringify(data.grant);
        },
        // the dashboard extensions of the installed (or latest) version manifest
        get extensions() {
            const versionId = data.installation?.versionRef || data.application.latestVersion?.id;
            const version = (data.application.versions || []).find((v) => v.id == versionId);
            return version?.manifest?.extensions || [];
        },
        get versionLabel() {
            return data.installation?.version || data.application.latestVersion?.version || "";
        },
        // the app proxy of the installed (or latest) version manifest
        get proxyManifest() {
            const versionId = data.installation?.versionRef || data.application.latestVersion?.id;
            const version = (data.application.versions || []).find((v) => v.id == versionId);
            return version?.manifest?.app_proxy || null;
        },
        proxyPrefix: application.installation?.proxyPrefix || "",
        proxySubpath: application.installation?.proxySubpath || "",
        // the catalog entry of a catalog application (cleared after an update)
        catalogEntry: settings.catalogEntry || null,
        get updateAvailable() {
            return data.isInstalled && !!data.catalogEntry?.updateAvailable;
        },
        // the update review state (the new catalog version is imported on review)
        update: null,
        updateGrant: null,
        isUpdateLoading: false,
    });

    async function reload() {
        try {
            const result = await app.pb.send("/api/applications", {
                requestKey: "application_panel_" + application.id,
            });
            const fresh = (result.items || []).find((a) => a.id == application.id);
            if (fresh) {
                data.application = fresh;
                data.grant = normalizePermissions(fresh.installation?.permissions);
                data.proxyPrefix = fresh.installation?.proxyPrefix || "";
                data.proxySubpath = fresh.installation?.proxySubpath || "";
            }
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        settings.onchange?.(data.application);
    }

    async function run(fn) {
        if (data.isBusy) {
            return;
        }

        data.isBusy = true;

        try {
            await fn();
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        data.isBusy = false;
    }

    function install() {
        run(async () => {
            const result = await app.pb.send(`/api/applications/${encodeURIComponent(data.application.id)}/install`, {
                method: "POST",
                body: { permissions: data.grant },
            });

            app.store.errors = null;
            app.toasts.success(`Successfully installed "${data.application.name}".`);

            await reload();
            data.activeTab = TAB_CREDENTIALS;

            // the credentials were delivered only to the application install_url
            if (result.notified) {
                app.toasts.info("The credentials were delivered to the application.");
                return;
            }

            openApplicationSecretModal(result, data.application);
        });
    }

    function saveProxyPath() {
        run(async () => {
            await app.pb.send(`/api/applications/installations/${encodeURIComponent(data.installation.id)}`, {
                method: "PATCH",
                body: { proxyPrefix: data.proxyPrefix, proxySubpath: data.proxySubpath },
            });

            app.store.errors = null;
            app.toasts.success("Successfully updated the app proxy path.");

            await reload();
        });
    }

    function saveGrant() {
        run(async () => {
            await app.pb.send(`/api/applications/installations/${encodeURIComponent(data.installation.id)}`, {
                method: "PATCH",
                body: { permissions: data.grant },
            });

            app.store.errors = null;
            app.toasts.success("Successfully updated the application permissions.");

            await reload();
        });
    }

    function updateVersion(versionId) {
        run(async () => {
            await app.pb.send(`/api/applications/installations/${encodeURIComponent(data.installation.id)}`, {
                method: "PATCH",
                body: { versionRef: versionId },
            });

            app.toasts.success("Successfully updated the installed version.");

            await reload();
        });
    }

    function rotateSecret() {
        app.modals.confirm(
            t.div(
                null,
                t.p(null, "Do you really want to rotate the client secret?"),
                t.p(
                    { className: "txt-hint txt-sm" },
                    "The current secret and every access token issued with it stop working immediately.",
                ),
            ),
            () =>
                run(async () => {
                    const result = await app.pb.send(
                        `/api/applications/installations/${encodeURIComponent(data.installation.id)}/rotate-secret`,
                        { method: "POST" },
                    );

                    await reload();

                    if (result.notified) {
                        app.toasts.success("Successfully rotated the secrets (delivered to the application).");
                        return;
                    }

                    openApplicationSecretModal(result, data.application);
                }),
            null,
            { yesButton: "Rotate secret" },
        );
    }

    function uninstall() {
        app.modals.confirm(
            t.div(
                null,
                t.p(null, "Do you really want to uninstall ", t.strong(null, data.application.name), "?"),
                t.p(
                    { className: "txt-hint txt-sm" },
                    "Its credentials and every active session are deleted and the issued access tokens stop working immediately.",
                ),
            ),
            () =>
                run(async () => {
                    await app.pb.send(`/api/applications/installations/${encodeURIComponent(data.installation.id)}`, {
                        method: "DELETE",
                    });

                    app.toasts.success(`Successfully uninstalled "${data.application.name}".`);

                    await reload();
                    data.activeTab = TAB_OVERVIEW;
                }),
            null,
            { yesButton: "Uninstall" },
        );
    }

    function deleteApplication() {
        app.modals.confirm(
            t.div(
                null,
                t.p(null, "Do you really want to delete ", t.strong(null, data.application.name), "?"),
                t.p({ className: "txt-hint txt-sm" }, "The application and all its versions are deleted."),
            ),
            () =>
                run(async () => {
                    await app.pb.send(`/api/applications/${encodeURIComponent(data.application.id)}`, {
                        method: "DELETE",
                    });

                    app.toasts.success(`Successfully deleted "${data.application.name}".`);

                    settings.onchange?.(null);

                    app.modals.close(modal, true);
                }),
            null,
            { yesButton: "Delete" },
        );
    }

    async function reviewUpdate() {
        if (data.isUpdateLoading || !data.catalogEntry) {
            return;
        }

        data.activeTab = TAB_UPDATE;
        data.isUpdateLoading = true;
        data.update = null;

        try {
            // imports the current catalog version (verified signed index + manifest digest)
            const result = await app.pb.send("/api/applications/catalog/import", {
                method: "POST",
                body: { source: data.catalogEntry.source, handle: data.catalogEntry.handle },
            });

            const installed = (data.application.versions || []).find((v) => v.id == data.installation.versionRef);
            const oldScopes = [
                ...(installed?.manifest?.access?.scopes || []),
                ...(installed?.manifest?.access?.optional_scopes || []),
            ];
            const newAccess = result.version?.manifest?.access || {};
            const newScopes = [...(newAccess.scopes || []), ...(newAccess.optional_scopes || [])];

            data.update = {
                version: result.version,
                allowedScopes: newScopes,
                added: newScopes.filter((s) => !applicationScopeCovered(s, oldScopes)),
                removed: oldScopes.filter((s) => !applicationScopeCovered(s, newScopes)),
            };
            data.updateGrant = normalizePermissions(data.installation.permissions);
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
                data.activeTab = TAB_OVERVIEW;
            }
        }

        data.isUpdateLoading = false;
    }

    function applyUpdate() {
        run(async () => {
            await app.pb.send(`/api/applications/installations/${encodeURIComponent(data.installation.id)}`, {
                method: "PATCH",
                // note: the grant is always explicitly (re)approved
                body: { versionRef: data.update.version.id, permissions: data.updateGrant },
            });

            app.store.errors = null;
            app.toasts.success(`Successfully updated "${data.application.name}" to v${data.update.version.version}.`);

            data.catalogEntry = null;
            data.update = null;
            await reload();
            data.activeTab = TAB_OVERVIEW;
        });
    }

    // --- tabs

    function infoRow(label, value) {
        return t.div(
            { className: "application-info-row" },
            t.span({ className: "txt-hint txt-sm" }, label),
            t.div({ className: "content" }, value),
        );
    }

    function overviewTab() {
        const a = data.application;

        return t.div(
            { className: "application-overview" },
            data.updateAvailable
                ? t.div(
                    { className: "alert warning application-update-alert" },
                    t.i({ className: "ri-arrow-up-circle-line", ariaHidden: true }),
                    t.div(
                        { className: "content" },
                        `Version ${data.catalogEntry?.version} is available in the ${data.catalogEntry?.source} catalog.`,
                    ),
                    data.canWrite && data.coversCurrentGrant
                        ? t.button(
                            {
                                type: "button",
                                className: "btn sm application-review-update-btn",
                                disabled: () => data.isBusy,
                                onclick: reviewUpdate,
                            },
                            t.span({ className: "txt" }, "Review update"),
                        )
                        : null,
                )
                : null,
            settings.superuserIPsRestricted && data.extensions.length
                ? t.div(
                    { className: "alert warning application-superuser-ips-alert" },
                    t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                    t.div(
                        { className: "content" },
                        "The staff access is restricted to the allowed superuser IPs. ",
                        "The application extensions act on behalf of the staff member that launched them, ",
                        "so the application server requests are rejected unless its IP is also allowed.",
                    ),
                )
                : null,
            a.description ? t.p(null, a.description) : null,
            infoRow("Handle", t.code(null, a.handle)),
            infoRow("Source", a.source),
            a.developerName || a.developerURL
                ? infoRow(
                    "Developer",
                    a.developerURL
                        ? t.a(
                            { href: a.developerURL, target: "_blank", rel: "noopener noreferrer" },
                            a.developerName || a.developerURL,
                        )
                        : a.developerName,
                )
                : null,
            a.applicationURL
                ? infoRow(
                    "Application URL",
                    t.a({ href: a.applicationURL, target: "_blank", rel: "noopener noreferrer" }, a.applicationURL),
                )
                : null,
            infoRow(
                "Status",
                data.isInstalled
                    ? [
                        data.installation.status == "pending"
                            ? t.span({ className: "label warning" }, "pending")
                            : t.span({ className: "label success" }, "installed"),
                        " ",
                        t.span(
                            { className: "txt-hint txt-sm" },
                            applicationGrantSummary(data.installation.permissions),
                        ),
                    ]
                    : t.span({ className: "label" }, "not installed"),
            ),
            data.extensions.length
                ? infoRow(
                    "Extensions",
                    t.div(
                        { className: "application-scopes application-extensions" },
                        data.extensions.map((ext) =>
                            t.span(
                                {
                                    className: "label",
                                    title: ext.type + (ext.collection ? " (" + ext.collection + ")" : ""),
                                },
                                ext.label,
                            )
                        ),
                    ),
                )
                : null,
            appProxy(),
            managedWebhooks(),
            t.h6({ className: "m-t-base m-b-xs" }, "Versions"),
            t.div(
                { className: "list application-versions" },
                (a.versions || []).map((v) => {
                    const isInstalled = data.installation?.versionRef == v.id;

                    return t.div(
                        { className: "list-item" },
                        t.div(
                            { className: "content" },
                            t.strong(null, v.version),
                            isInstalled ? t.span({ className: "label success sm" }, "installed") : null,
                            v.id == a.latestVersion?.id ? t.span({ className: "label sm" }, "latest") : null,
                            t.small({ className: "txt-hint" }, v.sourceFormat),
                            t.small(
                                { className: "txt-hint txt-code", title: v.manifestDigest },
                                "sha256:" + (v.manifestDigest || "").slice(0, 12),
                            ),
                        ),
                        app.components.formattedDate({ value: v.created, short: true }),
                        data.isInstalled && !isInstalled && data.canWrite && data.coversCurrentGrant
                            ? t.button(
                                {
                                    type: "button",
                                    className: "btn sm secondary",
                                    disabled: () => data.isBusy,
                                    onclick: () => updateVersion(v.id),
                                },
                                t.span({ className: "txt" }, "Install this version"),
                            )
                            : null,
                    );
                }),
            ),
        );
    }

    // the public path of the app proxy (customizable per installation)
    function appProxy() {
        if (!data.proxyManifest) {
            return null;
        }

        const canEdit = data.isInstalled && !!data.installation.proxySubpath && data.canWrite
            && data.coversCurrentGrant;

        return [
            t.h6({ className: "m-t-base m-b-xs" }, "App proxy"),
            t.div(
                { className: "txt-hint txt-sm m-b-xs application-proxy-info" },
                "The public requests of this path are forwarded (signed) to ",
                t.code(null, data.proxyManifest.url),
                ". They are sandboxed and never carry the visitor cookies or tokens.",
            ),
            data.isInstalled && !data.installation.proxySubpath
                ? t.div(
                    { className: "txt-hint txt-sm" },
                    "Not active (grant the App proxy permission to activate ",
                    t.code(null, `/${data.proxyManifest.prefix}/${data.proxyManifest.subpath}`),
                    ").",
                )
                : t.div(
                    { className: "flex gap-10 application-proxy-form" },
                    t.div(
                        { className: "field" },
                        t.label({ htmlFor: "application_proxy_prefix" }, "Prefix"),
                        t.select(
                            {
                                id: "application_proxy_prefix",
                                name: "proxyPrefix",
                                disabled: () => !canEdit || data.isBusy,
                                value: () => data.proxyPrefix || data.proxyManifest.prefix,
                                onchange: (e) => (data.proxyPrefix = e.target.value),
                            },
                            ["a", "apps", "community", "tools"].map((p) => t.option({ value: p }, "/" + p)),
                        ),
                    ),
                    t.div(
                        { className: "field" },
                        t.label({ htmlFor: "application_proxy_subpath" }, "Subpath"),
                        t.input({
                            id: "application_proxy_subpath",
                            type: "text",
                            name: "proxySubpath",
                            disabled: () => !canEdit || data.isBusy,
                            value: () => data.proxySubpath || data.proxyManifest.subpath,
                            oninput: (e) => (data.proxySubpath = e.target.value),
                        }),
                    ),
                    canEdit
                        ? t.button(
                            {
                                type: "button",
                                className: () =>
                                    `btn sm secondary m-t-auto application-proxy-save-btn ${
                                        data.isBusy ? "loading" : ""
                                    }`,
                                disabled: () =>
                                    data.isBusy
                                    || (data.proxyPrefix == data.installation.proxyPrefix
                                        && data.proxySubpath == data.installation.proxySubpath),
                                onclick: saveProxyPath,
                            },
                            t.span({ className: "txt" }, "Save path"),
                        )
                        : null,
                ),
        ];
    }

    // the installation managed webhooks (read-only; synced with the installed manifest version)
    function managedWebhooks() {
        const webhooks = data.installation?.webhooks || [];
        if (!webhooks.length) {
            return null;
        }

        return [
            t.h6({ className: "m-t-base m-b-xs" }, "Managed webhooks"),
            t.div(
                { className: "list application-webhooks" },
                webhooks.map((w) =>
                    t.div(
                        { className: "list-item application-webhook-item" },
                        t.div(
                            { className: "content" },
                            t.span({ className: "txt-ellipsis" }, w.uri),
                            t.small({ className: "txt-hint" }, (w.topics || []).join(", ")),
                        ),
                        w.active
                            ? t.span({ className: "label success sm" }, "active")
                            : t.span({ className: "label sm", title: w.disabledReason || "" }, "inactive"),
                        t.span(
                            { className: "label sm" },
                            t.i({ className: "ri-lock-line", ariaHidden: true }),
                            " managed",
                        ),
                    )
                ),
            ),
            t.div(
                { className: "txt-hint txt-sm m-t-xs" },
                "The managed webhooks are defined by the application manifest and they are read-only.",
            ),
        ];
    }

    function updateTab() {
        if (data.isUpdateLoading || !data.update) {
            return t.div({ className: "skeleton-loader" });
        }

        const u = data.update;

        const editorSettings = {
            application: true,
            resources: resources,
            permissions: () => data.updateGrant,
            onchange: (permissions) => (data.updateGrant = permissions),
            readOnly: () => data.isBusy,
            allows: applicationScopesAllows(u.allowedScopes),
        };

        const scopeLabels = (scopes, className) =>
            scopes.length
                ? scopes.map((s) => t.span({ className: "label sm " + className }, s))
                : t.em({ className: "txt-hint txt-sm" }, "none");

        return t.div(
            { className: "application-permissions application-update-review" },
            t.p(
                { className: "txt-hint txt-sm" },
                `Update from v${data.installation.version} to v${u.version.version}. `,
                "The grant never grows automatically: review and approve the permissions of the new version.",
            ),
            t.div(
                { className: "application-scopes application-update-added m-b-xs" },
                t.small({ className: "txt-hint" }, "Added scopes: "),
                scopeLabels(u.added, "warning"),
            ),
            t.div(
                { className: "application-scopes application-update-removed m-b-sm" },
                t.small({ className: "txt-hint" }, "Removed scopes: "),
                scopeLabels(u.removed, ""),
            ),
            t.h6({ className: "m-b-xs" }, "Collections"),
            permissionsCollectionsMatrix(editorSettings),
            t.h6({ className: "m-t-sm m-b-xs" }, "System"),
            permissionsSystemMatrix(editorSettings),
        );
    }

    function permissionsTab() {
        const editorSettings = {
            application: true,
            resources: resources,
            permissions: () => data.grant,
            onchange: (permissions) => (data.grant = permissions),
            readOnly: () => data.isGrantReadOnly || data.isBusy,
        };

        return t.div(
            { className: "application-permissions" },
            t.p(
                { className: "txt-hint txt-sm" },
                "The installation grant: the application access tokens are limited to these permissions (and to the requested token scopes) and they bypass the collection API rules for the granted actions. ",
                "You could grant only the permissions you hold yourself. Narrowing the grant applies immediately to the already issued tokens.",
            ),
            () => {
                if (data.isInstalled && !data.coversCurrentGrant) {
                    return t.div(
                        { className: "alert warning m-b-sm" },
                        t.div(
                            { className: "content" },
                            "You can't change this installation because its grant has permissions you don't hold.",
                        ),
                    );
                }
            },
            t.h6({ className: "m-b-xs" }, "Collections"),
            permissionsCollectionsMatrix(editorSettings),
            t.h6({ className: "m-t-sm m-b-xs" }, "System"),
            permissionsSystemMatrix(editorSettings),
            t.div(
                { className: "txt-hint txt-sm m-t-xs" },
                "Staff, roles, sessions, impersonation, OAuth2 clients, applications, backups and SQL can never be granted to an application.",
            ),
            () => {
                if (!data.installation?.scopes) {
                    return;
                }

                return t.div(
                    { className: "m-t-sm application-scopes" },
                    t.small({ className: "txt-hint" }, "Token scopes: "),
                    data.installation.scopes.length
                        ? data.installation.scopes.map((s) => t.span({ className: "label sm" }, s))
                        : t.em({ className: "txt-hint txt-sm" }, "none"),
                );
            },
        );
    }

    function credentialsTab() {
        if (!data.isInstalled) {
            return t.div({ className: "txt-hint" }, "Install the application to get its credentials.");
        }

        const inst = data.installation;

        return t.div(
            { className: "application-credentials" },
            t.p(
                { className: "txt-hint txt-sm" },
                "The application Admin API access uses its installation OAuth2 client credentials: exchange them at the token endpoint (",
                t.code(null, "grant_type=client_credentials"),
                ") for a short-lived access token. The secret is shown only once on install and on rotation.",
            ),
            t.div(
                { className: "oauth2-secret-rows m-b-base" },
                credentialRow("Client ID", inst.clientId, "application-client-id"),
                credentialRow("Token URL", inst.tokenURL, "application-token-url"),
                credentialRow("Client secret", "••••••••••••", "application-client-secret-masked", false),
            ),
            t.div(
                { className: "flex gap-10 m-b-base" },
                t.button(
                    {
                        type: "button",
                        className: () =>
                            `btn sm secondary application-rotate-secret-btn ${data.isBusy ? "loading" : ""}`,
                        hidden: () => !data.canWrite || !data.coversCurrentGrant,
                        disabled: () => data.isBusy,
                        onclick: rotateSecret,
                    },
                    t.i({ className: "ri-refresh-line", ariaHidden: true }),
                    t.span({ className: "txt" }, "Rotate secret"),
                ),
                inst.secretRotatedAt
                    ? t.small(
                        { className: "txt-hint" },
                        "Last rotated: ",
                        app.components.formattedDate({ value: inst.secretRotatedAt, short: true }),
                    )
                    : null,
            ),
            app.components.codeBlock({
                language: "bash",
                value: applicationCurlExample(inst.tokenURL, inst.clientId),
            }),
        );
    }

    function credentialRow(label, value, className, copy = true) {
        return t.div(
            { className: "oauth2-secret-row" },
            t.span({ className: "txt-hint txt-sm" }, label),
            t.code({ className: "oauth2-secret-value " + className }, value),
            copy ? app.components.copyButton(value) : null,
        );
    }

    function tabButton(tab, label, disabled = () => false) {
        return t.button(
            {
                type: "button",
                className: () => `tab-item application-tab-${tab} ${data.activeTab == tab ? "active" : ""}`,
                disabled: () => disabled() || data.isBusy,
                onclick: () => {
                    app.store.errors = null;
                    data.activeTab = tab;
                },
            },
            t.span({ className: "txt" }, label),
        );
    }

    function footer() {
        return t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn transparent m-r-auto",
                    disabled: () => data.isBusy,
                    onclick: () => app.modals.close(modal),
                },
                t.span({ className: "txt" }, "Close"),
            ),
            () => {
                if (!data.canWrite) {
                    return;
                }

                if (data.isInstalled) {
                    return [
                        t.button(
                            {
                                type: "button",
                                className: "btn transparent danger application-uninstall-btn",
                                hidden: () => !data.coversCurrentGrant,
                                disabled: () => data.isBusy,
                                onclick: uninstall,
                            },
                            t.span({ className: "txt" }, "Uninstall"),
                        ),
                        t.button(
                            {
                                type: "button",
                                className: () =>
                                    `btn expanded-lg application-apply-update-btn ${data.isBusy ? "loading" : ""}`,
                                hidden: () => data.activeTab != TAB_UPDATE || !data.update,
                                disabled: () => data.isBusy,
                                onclick: applyUpdate,
                            },
                            t.span({ className: "txt" }, () => "Update to v" + (data.update?.version?.version || "")),
                        ),
                        t.button(
                            {
                                type: "button",
                                className: () =>
                                    `btn expanded-lg application-save-grant-btn ${data.isBusy ? "loading" : ""}`,
                                hidden: () => data.activeTab != TAB_PERMISSIONS || data.isGrantReadOnly,
                                disabled: () => data.isBusy || !data.hasGrantChanges,
                                onclick: saveGrant,
                            },
                            t.span({ className: "txt" }, "Save permissions"),
                        ),
                    ];
                }

                return [
                    t.button(
                        {
                            type: "button",
                            className: "btn transparent danger application-delete-btn",
                            disabled: () => data.isBusy,
                            onclick: deleteApplication,
                        },
                        t.span({ className: "txt" }, "Delete"),
                    ),
                    t.button(
                        {
                            type: "button",
                            className: () => `btn expanded-lg application-install-btn ${data.isBusy ? "loading" : ""}`,
                            disabled: () => data.isBusy,
                            onclick: () => {
                                if (data.activeTab != TAB_PERMISSIONS) {
                                    data.activeTab = TAB_PERMISSIONS;
                                    return;
                                }
                                install();
                            },
                        },
                        t.span(
                            { className: "txt" },
                            () => (data.activeTab == TAB_PERMISSIONS ? "Install with these permissions" : "Install..."),
                        ),
                    ),
                ];
            },
        );
    }

    const modal = t.div(
        {
            pbEvent: "applicationPanel",
            className: "modal application-panel",
            onbeforeclose: () => {
                if (data.isBusy) {
                    return false;
                }
            },
            onafterclose: (el) => {
                app.store.errors = null;
                el?.remove();
            },
        },
        t.header(
            { className: "modal-header isolated" },
            t.div(
                { className: "grid" },
                t.div(
                    { className: "col-12 flex gap-10" },
                    applicationIcon(data.application.iconURL),
                    t.h6(
                        { className: "modal-title application-panel-title" },
                        () => data.application.name,
                        () => (data.versionLabel ? t.span({ className: "label sm" }, "v" + data.versionLabel) : null),
                        () => (data.isInstalled ? t.span({ className: "label success sm" }, "installed") : null),
                        () =>
                            data.updateAvailable
                                ? t.span({ className: "label warning sm" }, "update available")
                                : null,
                    ),
                ),
                t.div(
                    { className: "col-12" },
                    t.nav(
                        { className: "tabs-header equal-width" },
                        tabButton(TAB_OVERVIEW, "Overview"),
                        tabButton(TAB_PERMISSIONS, "Permissions"),
                        tabButton(TAB_CREDENTIALS, "Credentials", () => !data.isInstalled),
                        tabButton(TAB_ACTIVITY, "Activity", () => !data.isInstalled || !app.perms.can("sessions")),
                    ),
                ),
            ),
        ),
        () => {
            // the installation sessions (aka. the issued client_credentials tokens)
            if (data.activeTab == TAB_ACTIVITY && data.isInstalled) {
                return recordSessionsConsents(
                    { id: data.installation.collectionId, name: "_applicationInstallations" },
                    { id: data.installation.id },
                    {
                        hideConsents: true,
                        description:
                            "The active sessions of the application (one per issued access token). Revoking a session invalidates its access token immediately.",
                    },
                );
            }

            return [
                t.div(
                    { className: "modal-content" },
                    () => {
                        switch (data.activeTab) {
                            case TAB_PERMISSIONS:
                                return permissionsTab();
                            case TAB_CREDENTIALS:
                                return credentialsTab();
                            case TAB_UPDATE:
                                return updateTab();
                            default:
                                return overviewTab();
                        }
                    },
                ),
                footer(),
            ];
        },
    );

    return modal;
}
