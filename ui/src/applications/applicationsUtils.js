// Shared applications (extensions) dashboard helpers.

export const APPLICATION_INSTALLATIONS_COLLECTION = "_applicationInstallations";

/**
 * Loads the applications list and the permissions registry.
 *
 * @return {Promise<{items: Array, resources: Array, actions: Array}>}
 */
export async function loadApplications() {
    return app.pb.send("/api/applications", { requestKey: "applications_list" });
}

/**
 * Returns a lowercase handle suggestion from the provided application name.
 *
 * @param  {string} name
 * @return {string}
 */
export function applicationHandleFromName(name) {
    return (name || "")
        .toLowerCase()
        .normalize("NFKD")
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 63);
}

/**
 * Returns the client_credentials curl example of the provided credentials.
 *
 * @param  {string} tokenURL
 * @param  {string} clientId
 * @param  {string} [clientSecret]
 * @return {string}
 */
export function applicationCurlExample(tokenURL, clientId, clientSecret = "CLIENT_SECRET") {
    const baseURL = app.utils.getApiExampleURL();

    return [
        "# 1. exchange the client credentials for a short-lived access token",
        `curl -X POST '${tokenURL}' \\`,
        `  -u '${clientId}:${clientSecret}' \\`,
        `  -d 'grant_type=client_credentials'`,
        "",
        "# 2. use the access token with the regular PocketBase APIs",
        `curl '${baseURL}/api/collections/COLLECTION/records' \\`,
        `  -H 'Authorization: Bearer ACCESS_TOKEN'`,
    ].join("\n");
}

/**
 * Returns a short human readable summary of an installation grant.
 *
 * @param  {Object} permissions
 * @return {string}
 */
export function applicationGrantSummary(permissions) {
    const parts = [];

    for (const key in permissions?.collections || {}) {
        const actions = permissions.collections[key] || [];
        if (!actions.length) {
            continue;
        }

        const name = key == "*" ? "All collections" : (app.store.collections.find((c) => c.id == key)?.name || key);

        parts.push(name + ": " + actions.join(", "));
    }

    for (const resource in permissions?.system || {}) {
        if (permissions.system[resource]) {
            parts.push(resource + ": " + permissions.system[resource]);
        }
    }

    return parts.length ? parts.join(" · ") : "No permissions";
}

/**
 * Loads the applications catalogs (sources and merged entries).
 *
 * @param  {boolean} [refresh] Whether to bypass the server cache.
 * @return {Promise<{sources: Array, items: Array}>}
 */
export async function loadApplicationCatalog(refresh = false) {
    return app.pb.send("/api/applications/catalog" + (refresh ? "?refresh=1" : ""), {
        requestKey: "applications_catalog",
    });
}

/**
 * Returns only the server inlined png, jpeg, webp and gif data: icons (otherwise empty string).
 *
 * The remote icons are always inlined by the server so that the dashboard CSP never allows remote images.
 *
 * @param  {string} url
 * @return {string}
 */
export function safeApplicationIconURL(url) {
    if (typeof url != "string") {
        return "";
    }

    const types = ["image/png", "image/jpeg", "image/webp", "image/gif"];
    if (types.some((t) => url.startsWith("data:" + t + ";base64,"))) {
        return url;
    }

    return "";
}

/**
 * Returns the application icon figure (only the inlined data: icons are rendered).
 *
 * @param  {string} url
 * @return {Element}
 */
export function applicationIcon(url) {
    const src = safeApplicationIconURL(url);

    return t.figure(
        { className: "oauth2-app-logo-thumb" },
        src
            ? t.img({ src: src, alt: "", loading: "lazy" })
            : t.i({ className: "ri-apps-2-add-line", ariaHidden: true }),
    );
}

/**
 * Reports whether the scope is in the provided scopes
 * (write_x implies read_x and system:write_x implies system:read_x).
 *
 * @param  {string}        scope
 * @param  {Array<string>} scopes
 * @return {boolean}
 */
export function applicationScopeCovered(scope, scopes) {
    if (scopes.includes(scope)) {
        return true;
    }

    if (scope.startsWith("system:read_")) {
        return scopes.includes("system:write_" + scope.substring("system:read_".length));
    }

    if (scope.startsWith("read_")) {
        return scopes.includes("write_" + scope.substring("read_".length));
    }

    return false;
}

/**
 * Converts the provided scopes into an installation grant
 * (read_x => list/view, write_x => list/view/create/update/delete, system:{level}_r => level).
 *
 * @param  {Array<string>} scopes
 * @return {Object}
 */
export function applicationScopesToPermissions(scopes) {
    const result = { collections: {}, system: {} };

    for (const scope of scopes || []) {
        if (scope.startsWith("system:write_")) {
            result.system[scope.substring("system:write_".length)] = "write";
            continue;
        }

        if (scope.startsWith("system:read_")) {
            const resource = scope.substring("system:read_".length);
            if (result.system[resource] != "write") {
                result.system[resource] = "read";
            }
            continue;
        }

        const isWrite = scope.startsWith("write_");
        const name = scope.replace(/^(read|write)_/, "");
        const collection = app.store.collections.find((c) => c.name == name && !c.system);
        if (!collection || (!isWrite && !scope.startsWith("read_"))) {
            continue;
        }

        const actions = new Set(result.collections[collection.id] || []);
        actions.add("list");
        actions.add("view");
        if (isWrite) {
            actions.add("create");
            actions.add("update");
            actions.add("delete");
        }
        result.collections[collection.id] = Array.from(actions);
    }

    return result;
}

/**
 * Returns a permissions editor "allows" function limited to the provided scopes.
 *
 * @param  {Array<string>} scopes
 * @return {function(string, string, string): boolean}
 */
export function applicationScopesAllows(scopes) {
    return (kind, key, actionOrLevel) => {
        if (kind == "system") {
            return applicationScopeCovered(`system:${actionOrLevel}_${key}`, scopes);
        }

        // note: "*" grants all (incl. future) collections
        const collection = app.store.collections.find((c) => c.id == key);
        if (!collection) {
            return false;
        }

        const prefix = actionOrLevel == "list" || actionOrLevel == "view" ? "read_" : "write_";

        return applicationScopeCovered(prefix + collection.name, scopes);
    };
}
