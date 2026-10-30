import { pageDashboardLogin } from "@/auth/pageDashboardLogin";
import { noAccessPage } from "@/auth/permissions";
import { pageCollections } from "@/collections/pageCollections";
import { pageLogs } from "@/logs/pageLogs";
import { pageApplicationSettings } from "@/settings/application/pageApplicationSettings";
import { pageBackupsSettings } from "@/settings/backups/pageBackupsSettings";
import { pageCronsSettings } from "@/settings/crons/pageCronsSettings";
import { pageMailSettings } from "@/settings/mail/pageMailSettings";
import { pageSQLConsole } from "@/settings/sql/pageSQLConsole";
import { pageStorageSettings } from "@/settings/storage/pageStorageSettings";
import { pageExportCollections } from "@/settings/sync/pageExportCollections";
import { pageImportCollections } from "@/settings/sync/pageImportCollections";

window.app = window.app || {};
window.app.routes = window.app.routes || {};

window.app.routes.fallbackPath = "#/collections";

/**
 * @callback RouteHandler
 * @param {Object} route
 * @param {string} route.path
 * @param {Object} route.query
 * @param {Object} route.params
 * @param {RegExp} route.regex
 * @param {string} route.pattern
 * @return {HtmlElement|Promise<HtmlElement>} The page to render.
 */

/**
 * Registers a new guest-only route.
 * If the user is authenticated, they are redirected to the home page.
 *
 * Example:
 *
 * ```js
 * app.routes.guestOnly("#/guest", (route) => {
 *     return t.div({ className: "page" }, "Guest page")
 * })
 * ```
 *
 * @param {string} path
 * @param {RouteHandler} handler
 */
app.routes.guestOnly = function(path, handler) {
    if (app.store._ready) {
        throw new Error("the router is already initialized");
    }

    routeDefs[path] = async (route) => {
        if (app.pb.authStore.isValid && app.pb.authStore.record?.id) {
            window.location.hash = "#/";
            return;
        }

        app.store.showHeader = false;
        app.store.page = await handler(route);
    };
};

/**
 * Registers a new superuser-only route (the layout has a top-nav header).
 * If the user is not authenticated, they are redirected to the login page.
 *
 * Example:
 *
 * ```js
 * app.routes.superuserOnly("#/example", (route) => {
 *     return t.div({ className: "page" }, "Superuser accessible page")
 * })
 * ```
 *
 * @param {string} path
 * @param {RouteHandler} handler
 * @param {Function} [optCan] Optional permission check (a "no access" page is rendered if it returns false).
 */
app.routes.superuserOnly = function(path, handler, optCan) {
    if (app.store._ready) {
        throw new Error("the router is already initialized");
    }

    routeDefs[path] = async (route) => {
        if (!app.pb.authStore.isValid || !app.pb.authStore.record?.id) {
            window.location.hash = "#/login";
            return;
        }

        app.store.showHeader = true;

        if (optCan && !optCan(route)) {
            app.store.page = noAccessPage("", route);
            return;
        }

        app.store.page = await handler(route);
    };
};

/**
 * Registers a new route with a blank layout.
 * This route layout doesn't perform any access check to allow more advanced customizations.
 *
 * Example:
 *
 * ```js
 * app.routes.blank("#/blank", (route) => {
 *     return t.div({ className: "page" }, "Blank layout page")
 * })
 * ```
 *
 * @param {string} path
 * @param {RouteHandler} handler
 */
app.routes.blank = function(path, handler) {
    if (app.store._ready) {
        throw new Error("the router is already initialized");
    }

    routeDefs[path] = async (route) => {
        app.store.showHeader = false;
        app.store.page = await handler(route);
    };
};

const routeDefs = {};
let destroyRouter;
export function initRouter() {
    if (destroyRouter) {
        destroyRouter();
    }

    destroyRouter = router(routeDefs, { fallbackPath: app.routes.fallbackPath });
}

// -------------------------------------------------------------------

app.routes.guestOnly("#/pbinstall/{token}", async (route) => {
    const { pageInstaller } = await import("@/auth/pageInstaller");
    return pageInstaller(route);
});
app.routes.guestOnly("#/login", (route) => {
    return pageDashboardLogin(route);
});

app.routes.superuserOnly("#/collections", pageCollections, () => app.perms.hasAnyCollection());
app.routes.superuserOnly("#/logs", pageLogs, () => app.perms.can("logs"));
app.routes.superuserOnly("#/llm", async (route) => {
    const { pageLLM } = await import("@/llm/pageLLM");
    return pageLLM(route);
}, () => app.perms.can("llm"));
app.routes.superuserOnly("#/webhooks", async (route) => {
    const { pageWebhooks } = await import("@/webhooks/pageWebhooks");
    return pageWebhooks(route);
}, () => app.perms.can("webhooks"));
app.routes.superuserOnly("#/applications", async (route) => {
    const { pageApplications } = await import("@/applications/pageApplications");
    return pageApplications(route);
}, () => app.perms.can("applications"));
app.routes.superuserOnly("#/apps/{handle}/{subpath...}", async (route) => {
    const { pageApplicationFrame } = await import("@/applications/pageApplicationFrame");
    return pageApplicationFrame(route);
}, () => app.perms.can("applications"));
app.routes.superuserOnly("#/settings", pageApplicationSettings, () => app.perms.can("settings"));
app.routes.superuserOnly("#/settings/mail", pageMailSettings, () => app.perms.can("settings"));
app.routes.superuserOnly("#/settings/storage", pageStorageSettings, () => app.perms.can("settings"));
app.routes.superuserOnly("#/settings/llm", async (route) => {
    const { pageLLMSettings } = await import("@/settings/llm/pageLLMSettings");
    return pageLLMSettings(route);
}, () => app.perms.can("llm"));
app.routes.superuserOnly("#/settings/webhooks", async (route) => {
    const { pageWebhooksSettings } = await import("@/settings/webhooks/pageWebhooksSettings");
    return pageWebhooksSettings(route);
}, () => app.perms.can("webhooks"));
app.routes.superuserOnly("#/settings/applications", async (route) => {
    const { pageApplicationsSettings } = await import("@/settings/applicationsCatalogs/pageApplicationsSettings");
    return pageApplicationsSettings(route);
}, () => app.perms.isOwner());
app.routes.superuserOnly("#/settings/graphql", async (route) => {
    const { pageGraphQLSettings } = await import("@/settings/graphql/pageGraphQLSettings");
    return pageGraphQLSettings(route);
}, () => app.perms.isOwner());
app.routes.superuserOnly("#/settings/oauth2", async (route) => {
    const { pageOAuth2Settings } = await import("@/settings/oauth2/pageOAuth2Settings");
    return pageOAuth2Settings(route);
}, () => app.perms.can("collections"));
app.routes.superuserOnly("#/settings/oauth2-clients", async (route) => {
    const { pageOAuth2Clients } = await import("@/settings/oauth2/pageOAuth2Clients");
    return pageOAuth2Clients(route);
}, () => app.perms.can("oauth2_clients"));
app.routes.superuserOnly("#/settings/roles", async (route) => {
    const { pageRoles } = await import("@/settings/roles/pageRoles");
    return pageRoles(route);
}, () => app.perms.can("roles"));
app.routes.superuserOnly("#/settings/backups", pageBackupsSettings, () => app.perms.can("backups"));
app.routes.superuserOnly("#/settings/crons", pageCronsSettings, () => app.perms.can("crons"));
app.routes.superuserOnly("#/settings/export-collections", pageExportCollections, () => app.perms.can("collections"));
app.routes.superuserOnly(
    "#/settings/import-collections",
    pageImportCollections,
    () => app.perms.can("collections", "write"),
);
app.routes.superuserOnly("#/settings/sql", pageSQLConsole, () => app.perms.isOwner());
