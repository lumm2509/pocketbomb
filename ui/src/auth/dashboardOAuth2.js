import { LocalAuthStore } from "@pocketbomb/primer";
import { createDashboardClient as createDashboardAccountClient } from "@pocketbomb/primer/internal";

// Dashboard OAuth2 (Authorization Code + PKCE) client of the _superusers issuer.
//
// The OAuth2 flow itself (PKCE, callback, cross-tab refresh with navigator.locks and
// the localStorage lease fallback, logout guard, impersonation token exchange) is
// implemented by @pocketbomb/primer (the dashboard account client / app.pb.account).
// This module contains only the dashboard specific glue:
//   - the built-in pb_dashboard client configuration (same-origin redirect URI)
//   - the "return to the previous dashboard page" state and the callback URL cleanup
//   - the sign-in error shown on the login page

export const DASHBOARD_CLIENT_ID = "pb_dashboard";
export const DASHBOARD_ISSUER_COLLECTION = "_superusers";

/**
 * Returns the dashboard OAuth2 callback URL (aka. the current dashboard URL without query and hash).
 *
 * @return {string}
 */
export function dashboardRedirectURI() {
    return window.location.origin + window.location.pathname;
}

/**
 * Creates the dashboard client (pb_dashboard account client of the _superusers issuer
 * with the dashboard internal services of @pocketbomb/primer/internal).
 *
 * The OAuth2 state (access token, record, refresh token, id_token) is stored
 * in localStorage and shared between the dashboard tabs.
 *
 * @param  {string} url The PocketBase backend URL.
 * @return {import("@pocketbomb/primer/internal").DashboardClient}
 */
export function createDashboardClient(url) {
    // concatenate the path in case hosted under subpath alongside other apps
    const path = window.location.pathname;

    return createDashboardAccountClient({
        url,
        collection: DASHBOARD_ISSUER_COLLECTION,
        clientId: DASHBOARD_CLIENT_ID,
        redirectUri: dashboardRedirectURI(),
        scopes: ["openid", "email"],
        authStore: new LocalAuthStore("__pb_dashboard_oauth2__" + path),
        lockName: "__pb_dashboard_oauth2_refresh__" + path,
        backgroundRefresh: true,
    });
}

/**
 * Starts the dashboard login (redirect to the hosted login page of the _superusers issuer).
 *
 * The current dashboard page is restored after the sign-in.
 *
 * @param {Object} [options]
 * @param {string} [options.prompt] Optional OpenID Connect prompt (e.g. "login").
 */
export function login(options = {}) {
    const returnHash = window.location.hash && !window.location.hash.startsWith("#/login")
        ? window.location.hash
        : "";

    return app.pb.account.login({ prompt: options.prompt, state: { returnHash } });
}

/**
 * Handles the OAuth2 authorization response (if any) of the current dashboard URL.
 *
 * The authorization response params are removed from the URL before the code exchange
 * and on failure the error is shown on the login page.
 *
 * @return {Promise<void>}
 */
export async function handleCallback() {
    const account = app.pb.account;

    if (!account.isCallbackURL(window.location.href)) {
        return;
    }

    const callbackURL = window.location.href;

    // remove the authorization response params from the URL
    window.history.replaceState(null, "", dashboardRedirectURI() + "#/");

    try {
        const result = await account.handleCallback(callbackURL);

        const returnHash = result?.state?.returnHash;
        if (returnHash) {
            window.history.replaceState(null, "", dashboardRedirectURI() + returnHash);
        }
    } catch (err) {
        console.warn("Failed to complete the dashboard sign-in:", err);
        app.store.authError = err?.message || "Failed to complete the sign-in.";
    }
}

/**
 * Issues an impersonation access token for the provided auth record
 * (RFC 8693 token exchange with the pb_dashboard client and the current superuser token as actor).
 *
 * @param  {Object} record
 * @return {Promise<Object>} The token response.
 */
export function impersonate(record) {
    return app.pb.impersonate(record.collectionName, record.id);
}
