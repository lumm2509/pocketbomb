// Shared RBAC UI helpers.

export const COLLECTION_ACTIONS = ["list", "view", "create", "update", "delete"];

let rolesCache = null;

/**
 * Loads (and caches) the roles list and the permissions registry.
 *
 * @param  {boolean} [force]
 * @return {Promise<{items: Array, resources: Array, actions: Array}>}
 */
export async function loadRoles(force = false) {
    if (!force && rolesCache) {
        return rolesCache;
    }

    rolesCache = await app.pb.send("/api/roles", { requestKey: null });

    return rolesCache;
}

export function resetRolesCache() {
    rolesCache = null;
}

/**
 * Normalizes the provided permissions object.
 *
 * @param  {Object} [permissions]
 * @return {{collections: Object, system: Object}}
 */
export function normalizePermissions(permissions) {
    return {
        collections: JSON.parse(JSON.stringify(permissions?.collections || {})),
        system: JSON.parse(JSON.stringify(permissions?.system || {})),
    };
}

function hasSystem(permissions, resource, level) {
    const granted = permissions?.system?.[resource] || "";
    if (level == "write") {
        return granted == "write";
    }
    if (level == "read") {
        return granted == "read" || granted == "write";
    }
    return false;
}

function canCollection(permissions, key, action) {
    const collections = permissions?.collections || {};
    if (key == "*") {
        return !!collections["*"]?.includes(action);
    }
    return !!(collections[key]?.includes(action) || collections["*"]?.includes(action));
}

/**
 * Reports whether the current staff member holds the specified permission
 * (the no-escalation rule; the server stays the authority).
 *
 * @param  {string} kind     "collection" or "system"
 * @param  {string} key      Collection id (or "*") or system resource name.
 * @param  {string} value    Collection action or system level.
 * @return {boolean}
 */
export function actorHolds(kind, key, value) {
    const me = app.store.permissions;
    if (!me) {
        return false;
    }

    if (me.owner) {
        return true;
    }

    if (kind == "collection") {
        return canCollection(me.permissions, key, value);
    }

    return hasSystem(me.permissions, key, value);
}

/**
 * Reports whether the current staff member holds every permission of the provided set.
 *
 * @param  {Object} permissions
 * @return {boolean}
 */
export function actorCovers(permissions) {
    for (const key in permissions?.collections || {}) {
        for (const action of permissions.collections[key] || []) {
            if (!actorHolds("collection", key, action)) {
                return false;
            }
        }
    }

    for (const resource in permissions?.system || {}) {
        const level = permissions.system[resource];
        if (level && !actorHolds("system", resource, level)) {
            return false;
        }
    }

    return true;
}

/**
 * Returns a short human readable summary of the permissions set.
 *
 * @param  {Object}  permissions
 * @param  {boolean} [owner]
 * @return {Array<string>}
 */
export function permissionsSummary(permissions, owner = false) {
    if (owner) {
        return ["Full access (Owner)"];
    }

    const result = [];

    for (const key in permissions?.collections || {}) {
        const actions = permissions.collections[key] || [];
        if (!actions.length) {
            continue;
        }

        const name = key == "*"
            ? "All collections"
            : (app.store.collections.find((c) => c.id == key)?.name || key);

        result.push(name + ": " + (actions.length == COLLECTION_ACTIONS.length ? "all actions" : actions.join(", ")));
    }

    for (const resource in permissions?.system || {}) {
        if (permissions.system[resource]) {
            result.push(resource + ": " + permissions.system[resource]);
        }
    }

    return result.length ? result : ["No permissions"];
}
