import { settingsSidebar } from "@/settings/settingsSidebar";

// Permission-aware dashboard helpers (RBAC).
//
// The permissions of the current superuser (staff member) are loaded from
// GET /api/permissions/me and are used only to hide/disable the UI elements
// that the staff member can't use (the server stays the authority).

window.app = window.app || {};

const READ_ACTIONS = ["list", "view"];

// the RBAC registry is loaded from the server together with the actor permissions
// (GET /api/permissions/me "registry"; see core/permissions.go)
function systemCollectionResource(collectionName) {
    return app.store.permissions?.registry?.systemCollections?.[collectionName] || "";
}

function isOwnerOnlyLevel(resource, level) {
    const r = app.store.permissions?.registry?.resources?.find((r) => r.name == resource);
    if (!r) {
        return true; // unknown resource (fail closed)
    }
    return !!r.ownerOnlyLevels?.includes(level);
}

window.app.perms = {
    /**
     * Loads (or reloads) the current actor permissions into app.store.permissions.
     *
     * @return {Promise<void>}
     */
    async load() {
        if (!app.pb.authStore.isValid) {
            app.store.permissions = null;
            return;
        }

        try {
            app.store.permissions = await app.pb.send("/api/permissions/me", {
                requestKey: "app.perms.load",
            });
        } catch (err) {
            if (!err?.isAbort) {
                console.warn("Failed to load the current permissions:", err);
                // fail closed
                app.store.permissions = {
                    kind: "staff",
                    owner: false,
                    roles: [],
                    permissions: { collections: {}, system: {} },
                    collections: [],
                };
            }
        }
    },

    /**
     * @return {boolean} Whether the current staff member is an Owner.
     */
    isOwner() {
        return !!app.store.permissions?.owner;
    },

    /**
     * Reports whether the current staff member has the system resource level (write implies read).
     *
     * @param  {string} resource
     * @param  {string} [level]
     * @return {boolean}
     */
    can(resource, level = "read") {
        const perms = app.store.permissions;
        if (!perms) {
            return false;
        }

        if (perms.owner) {
            return true;
        }

        if (isOwnerOnlyLevel(resource, level)) {
            return false; // Owner only
        }

        const granted = perms.permissions?.system?.[resource] || "";
        if (level == "write") {
            return granted == "write";
        }

        return granted == "read" || granted == "write";
    },

    /**
     * Reports whether the current staff member could perform the collection action
     * with the staff (rules bypass) access.
     *
     * @param  {Object} collection
     * @param  {string} action One of list, view, create, update, delete.
     * @return {boolean}
     */
    canCollection(collection, action) {
        const perms = app.store.permissions;
        if (!perms || !collection) {
            return false;
        }

        if (perms.owner) {
            return true;
        }

        if (collection.system) {
            const resource = systemCollectionResource(collection.name);
            if (!resource) {
                return false;
            }
            return app.perms.can(resource, READ_ACTIONS.includes(action) ? "read" : "write");
        }

        const collections = perms.permissions?.collections || {};

        return !!(collections[collection.id]?.includes(action) || collections["*"]?.includes(action));
    },

    /**
     * @return {boolean} Whether the current staff member could see at least one collection.
     */
    hasAnyCollection() {
        return app.perms.isOwner() || (app.store.permissions?.collections?.length || 0) > 0;
    },

    /**
     * @return {boolean} Whether the current staff member has any dashboard permission.
     */
    hasAnyAccess() {
        const perms = app.store.permissions;
        if (!perms) {
            return false;
        }

        return perms.owner
            || app.perms.hasAnyCollection()
            || Object.values(perms.permissions?.system || {}).some(Boolean);
    },
};

/**
 * Returns the "no access" page content.
 *
 * @param  {string} [message]
 * @param  {Object} [route]
 * @return {Element}
 */
export function noAccessPage(message = "", route = null) {
    app.store.title = "No access";

    const isSettings = (route?.path || window.location.hash).startsWith("#/settings");

    return t.div(
        { pbEvent: "pageNoAccess", className: "page page-no-access" },
        isSettings ? settingsSidebar() : null,
        t.div(
            { className: "page-content full-height flex-column flex-center txt-center" },
            t.i({ className: "ri-lock-2-line txt-hint", style: "font-size: 48px", ariaHidden: true }),
            t.h5({ className: "m-t-sm" }, "You don't have access to this section"),
            t.p(
                { className: "txt-hint" },
                message
                    || "Your staff roles don't grant this permission. Ask an Owner to update your roles if you need access.",
            ),
            () => {
                const roles = app.store.permissions?.roles || [];
                return t.p(
                    { className: "txt-hint" },
                    "Your roles: ",
                    roles.length ? t.strong(null, roles.join(", ")) : t.em(null, "none"),
                );
            },
        ),
    );
}
