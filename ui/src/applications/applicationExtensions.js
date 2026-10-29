// Application extensions (manifest [[extensions]]) dashboard helpers.
//
// The extensions are launched with a short-lived single use launch token that is POSTed
// to the extension URL with an auto-submitted form opened in a new tab (the token never
// travels in a URL). The application exchanges it for an online access token
// (the staff member on behalf of the installation; effective = staff ∩ installation grant).

import { applicationIcon } from "./applicationsUtils";

export const EXTENSION_TYPE_NAVIGATION = "dashboard.navigation";
export const EXTENSION_TYPE_RECORD_ACTION = "dashboard.record_action";

/**
 * Returns the loaded navigation extensions of the current staff member.
 *
 * @return {Array<Object>}
 */
export function navigationExtensions() {
    return (app.store.applicationExtensions || []).filter((e) => e.type == EXTENSION_TYPE_NAVIGATION);
}

/**
 * Returns the loaded record actions of the provided collection.
 *
 * @param  {Object} collection
 * @return {Array<Object>}
 */
export function recordActionExtensions(collection) {
    if (!collection?.id) {
        return [];
    }

    return (app.store.applicationExtensions || []).filter((e) =>
        e.type == EXTENSION_TYPE_RECORD_ACTION && e.collectionId == collection.id
    );
}

/**
 * Requests a launch token for the provided extension and opens the extension
 * in a new tab with an auto-submitted POST form (target=_blank, rel=noopener).
 *
 * @param  {Object} ext        The extension item (see GET /api/applications/extensions).
 * @param  {string} [recordId] The record id (record actions only).
 * @return {Promise<boolean>}
 */
export async function launchApplicationExtension(ext, recordId = "") {
    let result;
    try {
        result = await app.pb.send(`/api/applications/installations/${encodeURIComponent(ext.installationId)}/launch`, {
            method: "POST",
            body: { extension: ext.handle, recordId: recordId || "" },
            requestKey: null,
        });
    } catch (err) {
        app.checkApiError(err);
        return false;
    }

    const form = document.createElement("form");
    form.method = "POST";
    form.action = result.url;
    form.target = "_blank";
    form.rel = "noopener noreferrer";
    form.className = "hidden application-extension-launch-form";

    const input = document.createElement("input");
    input.type = "hidden";
    input.name = "launch_token";
    input.value = result.launchToken;
    form.appendChild(input);

    document.body.appendChild(form);
    try {
        form.submit();
    } finally {
        form.remove();
    }

    return true;
}

/**
 * Returns the applications page sidebar with the navigation extensions
 * (or nothing if there are no navigation extensions).
 *
 * @return {Function}
 */
export function applicationsSidebar() {
    return () => {
        const items = navigationExtensions();
        if (!items.length) {
            return;
        }

        return app.components.pageSidebar(
            {
                pbEvent: "applicationsSidebar",
                className: "applications-sidebar",
            },
            t.nav(
                { className: "sidebar-content scrollable" },
                t.details(
                    { className: "nav-group", "html-data-group": "Applications", open: true },
                    t.summary(
                        { tabIndex: -1, onfocusout: () => false, onclick: () => false, onkeyup: () => false },
                        "Applications",
                    ),
                    t.a(
                        {
                            href: "#/applications",
                            className: (el) =>
                                `nav-item ${app.utils.isActivePath("#/applications", false) ? "active" : ""}`,
                        },
                        t.i({ className: "ri-apps-2-add-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "All applications"),
                    ),
                    items.map((ext) => {
                        return t.button(
                            {
                                type: "button",
                                className: "nav-item application-extension-nav-item",
                                "html-data-application": ext.applicationHandle,
                                "html-data-handle": ext.handle,
                                title: `${ext.label} (${ext.applicationName}, opens in a new tab)`,
                                onclick: () => launchApplicationExtension(ext),
                            },
                            applicationIcon(ext.iconURL),
                            t.span({ className: "txt txt-ellipsis" }, ext.label),
                            t.i({ className: "ri-external-link-line txt-hint", ariaHidden: true }),
                        );
                    }),
                ),
            ),
        );
    };
}

/**
 * Returns the record panel buttons of the provided collection record actions
 * (call it within a reactive render function so that it is updated on extensions change).
 *
 * @param  {Object} collection
 * @param  {string} recordId
 * @return {Array<Element>}
 */
export function recordActionButtons(collection, recordId) {
    if (!recordId) {
        return [];
    }

    return recordActionExtensions(collection).map((ext) => {
        return t.button(
            {
                type: "button",
                className: "btn sm transparent secondary m-r-5 application-record-action",
                "html-data-application": ext.applicationHandle,
                "html-data-handle": ext.handle,
                title: `${ext.applicationName} (opens in a new tab)`,
                onclick: () => launchApplicationExtension(ext, recordId),
            },
            t.i({ className: "ri-external-link-line", ariaHidden: true }),
            t.span({ className: "txt" }, ext.label),
        );
    });
}
