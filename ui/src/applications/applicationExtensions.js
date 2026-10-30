// Application extensions (manifest [[extensions]]) dashboard helpers.
//
// The extensions render inside the dashboard: see pageApplicationFrame.js
// for the #/apps/{handle}/{subpath...} route.

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
 * Returns the dashboard route of the provided extension.
 *
 * @param  {Object} ext        The extension item (see GET /api/applications/extensions).
 * @param  {string} [recordId] The record id (record actions only).
 * @return {string}
 */
export function applicationExtensionRoute(ext, recordId = "") {
    const query = new URLSearchParams({ extension: ext.handle });
    if (recordId) {
        query.set("recordId", recordId);
    }

    return `#/apps/${encodeURIComponent(ext.applicationHandle)}?${query}`;
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
                        return t.a(
                            {
                                href: applicationExtensionRoute(ext),
                                className: () =>
                                    `nav-item application-extension-nav-item ${
                                        app.utils.isActivePath("#/apps/" + ext.applicationHandle, false) ? "active" : ""
                                    }`,
                                "html-data-application": ext.applicationHandle,
                                "html-data-handle": ext.handle,
                                title: `${ext.label} (${ext.applicationName})`,
                            },
                            applicationIcon(ext.iconURL),
                            t.span({ className: "txt txt-ellipsis" }, ext.label),
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
                title: ext.applicationName,
                onclick: () => {
                    window.location.hash = applicationExtensionRoute(ext, recordId);
                },
            },
            t.i({ className: "ri-apps-2-add-line", ariaHidden: true }),
            t.span({ className: "txt" }, ext.label),
        );
    });
}
