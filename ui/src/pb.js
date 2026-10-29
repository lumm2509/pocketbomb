import { createDashboardClient, handleCallback, impersonate, login } from "@/auth/dashboardOAuth2";
import "@/auth/permissions";
import { isTokenExpired } from "pocketbase";

const LOGIN_PATH = "#/login";

window.app = window.app || {};

// the SDK account client of the built-in pb_dashboard OAuth2 client
// (the access token is refreshed before it expires and once on 401)
window.app.pb = createDashboardClient(import.meta.env.PB_BACKEND_URL);

// add UI specific header to all requests
app.pb.beforeSend = function(url, options) {
    options.headers["x-request-source"] = "pbui";
    return { url, options };
};

app.store.superuser = app.pb.authStore.record;
app.pb.authStore.onChange((_, record) => {
    // don't redirect to the login page while the OAuth2 logout is in progress,
    // otherwise the login page could start a new authorize request that races
    // with the issuer logout navigation and silently reuses the SSO session
    if (app.pb.account.isLoggingOut()) {
        return;
    }

    if (!record && window.location.hash != LOGIN_PATH) {
        app.modals.close();
        window.location.hash = LOGIN_PATH;
    }

    app.store.superuser = record;
});

// dashboard OAuth2 (pb_dashboard client) auth helpers
window.app.auth = {
    login,
    logout: () => app.pb.account.logout(),
    refresh: () => app.pb.account.refresh(),
    impersonate,
    isLoggingOut: () => app.pb.account.isLoggingOut(),
};

// handle the OAuth2 authorization response (if any) and
// refresh the existing access token if it has expired
window.app.auth.ready = (async () => {
    await handleCallback();

    await app.pb.account.restore();

    // load the RBAC permissions before the routes initialization
    await app.perms.load();
})().catch((err) => {
    console.warn("Failed to initialize the dashboard auth:", err);
});

// load initial store data
app.pb.authStore.onChange(async (_, record) => {
    if (record?.id) {
        // (re)load the permissions (e.g. after login or token refresh in case the roles were changed)
        await app.perms.load();

        app.store.loadCollections();

        if (app.perms.can("settings")) {
            app.store.loadSettings();
        }

        if (app.perms.can("collections")) {
            app.store.loadOAuth2Providers();
        }

        app.store.loadApplicationExtensions();
    } else {
        app.store.permissions = null;
        app.store.applicationExtensions = [];
    }
});

// Modify the default RecordService to fire global events on record
// create, update, delete without relying on the realtime service
// -------------------------------------------------------------------

const originalRecordService = app.pb.collection;
app.pb.collection = function(idOrName) {
    const service = originalRecordService.call(this, idOrName);

    bindRecordServiceEvents(service);

    return service;
};

function bindRecordServiceEvents(service) {
    if (service.__customUIEvents) {
        return;
    }

    service.__customUIEvents = true;

    const originalCreate = service.create;
    service.create = function() {
        return originalCreate.apply(service, arguments).then((r) => {
            setTimeout(() => {
                document.dispatchEvent(new CustomEvent("record:create", { detail: r }));
                document.dispatchEvent(new CustomEvent("record:save", { detail: r }));
            }, 0);
            return r;
        });
    };

    const originalUpdate = service.update;
    service.update = function() {
        return originalUpdate.apply(service, arguments).then((r) => {
            setTimeout(() => {
                document.dispatchEvent(new CustomEvent("record:update", { detail: r }));
                document.dispatchEvent(new CustomEvent("record:save", { detail: r }));
            }, 0);
            return r;
        });
    };

    const originalDelete = service.delete;
    service.delete = function() {
        return originalDelete.apply(service, arguments).then((r) => {
            const minimalRecord = {
                id: arguments[0],
                collectionId: service.collectionIdOrName,
                collectionName: service.collectionIdOrName,
            };
            setTimeout(() => {
                document.dispatchEvent(new CustomEvent("record:delete", { detail: minimalRecord }));
            }, 0);

            return r;
        });
    };
}

// File token helpers
// -------------------------------------------------------------------

const LAST_FILE_TOKEN_KEY = "pbLastFileToken";
let isFileTokenLoading = false;
let fileTokenPromises = [];

// clear stored token on logout
app.pb.authStore.onChange((_, record) => {
    if (!record?.id) {
        window.localStorage.removeItem(LAST_FILE_TOKEN_KEY);
    }
});

/**
 * Return a superuser file token.
 * Optionally you can provide a collection identifier, to avoid unnecessary
 * calls in case the collection doesn't have protected files.
 *
 * @param  {String} optCollectionIdORName
 * @return {Promise<string>}
 */
window.app.getFileToken = async function(optCollectionIdORName = "") {
    // check if the collection needs a file token
    const collection = optCollectionIdORName
        && app.store.collections?.find((c) => c.id == optCollectionIdORName || c.name == optCollectionIdORName);
    if (collection) {
        const hasProtectedFile = collection.fields?.find((f) => f.type == "file" && f.protected);
        if (!hasProtectedFile) {
            return;
        }
    }

    let token = window.localStorage.getItem(LAST_FILE_TOKEN_KEY);

    if (!token || isTokenExpired(token, 60)) {
        token = await fetchFileToken();
    }

    return token;
};

async function fetchFileToken() {
    return new Promise(async (resolve, reject) => {
        fileTokenPromises.push({ resolve, reject });

        if (isFileTokenLoading) {
            return;
        }

        isFileTokenLoading = true;

        try {
            const token = await app.pb.files.getToken();

            window.localStorage.setItem(LAST_FILE_TOKEN_KEY, token);

            fileTokenPromises.forEach((p) => p.resolve(token));
        } catch (err) {
            fileTokenPromises.forEach((p) => p.reject(err));
        }

        isFileTokenLoading = false;
        fileTokenPromises = [];
    });
}

/**
 * Generic API error handler that loads the response error into the app store
 * with the option to show a generic toast message.
 *
 * Example:
 *
 * ```js
 * try {
 *     await app.pb.collection("example").getFullList()
 * } catch (err) {
 *     if (!err?.isAbort) {
 *         app.checkApiError(err)
 *     }
 * }
 * ```
 *
 * @param {Error}   err
 * @param {boolean} [showToast]
 */
window.app.checkApiError = function(err, showToast = true) {
    if (!err || !(err instanceof Error) || err.isAbort) {
        console.warn("checkApiError - unexpected error type:", err);
        return;
    }

    const statusCode = err?.status << 0;
    const response = err?.response || {};

    // add toast error notification
    let msg = showToast && (response.message || err.message || "Something went wrong!");
    if (msg) {
        app.toasts.error(msg);
    }

    // unknown client-side error
    if (statusCode == 0) {
        console.log(err);
    }

    // populate form field errors
    if (!app.utils.isEmpty(response.data)) {
        app.store.errors = response.data;
    }

    // unauthorized
    if (statusCode === 401 && window.location.hash != LOGIN_PATH) {
        app.pb.cancelAllRequests();
        return app.pb.authStore.clear();
    }
};
