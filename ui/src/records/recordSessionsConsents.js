import { AUTH_SESSIONS_COLLECTION, OAUTH2_CONSENTS_COLLECTION } from "@/settings/oauth2/oauth2Utils";

/**
 * Returns the auth record "Sessions & consents" panel content
 * (the remembered OAuth2 consents and the active auth sessions).
 *
 * @param  {Object} collection The auth record collection.
 * @param  {Object} record     The auth record.
 * @param  {Object} [options]
 * @param  {string|Element} [options.description] Custom description (e.g. for the application installations).
 * @param  {boolean} [options.hideConsents]       Hide the consents list (e.g. for the application installations).
 * @return {Array<Element>}
 */
export function recordSessionsConsents(collection, record, options = {}) {
    const local = store({
        isLoading: false,
        consents: [],
        sessions: [],
        revoking: {},
    });

    async function load() {
        local.isLoading = true;

        const filter = app.pb.filter("collectionRef={:collectionId} && recordRef={:recordId}", {
            collectionId: collection.id,
            recordId: record.id,
        });

        try {
            const [consents, sessions] = await Promise.all([
                options.hideConsents ? [] : app.pb.collection(OAUTH2_CONSENTS_COLLECTION).getFullList({
                    filter: filter,
                    sort: "-updated",
                    expand: "client",
                    requestKey: "record_authorized_apps_consents_" + record.id,
                }),
                app.pb.collection(AUTH_SESSIONS_COLLECTION).getFullList({
                    filter: filter + " && status='active' && expiresAt>@now",
                    sort: "-lastUsedAt",
                    expand: "client",
                    requestKey: "record_authorized_apps_sessions_" + record.id,
                }),
            ]);

            local.consents = consents;
            local.sessions = sessions;
            local.isLoading = false;
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
                local.isLoading = false;
            }
        }
    }

    function clientName(item) {
        // the root SSO sessions are not bound to any client
        if (item.sso) {
            return "Browser session";
        }

        return item.expand?.client?.name || item.client;
    }

    function confirmAndRevokeSession(session) {
        app.modals.confirm(
            t.div(
                null,
                t.p(
                    null,
                    "Do you really want to revoke ",
                    session.sso
                        ? t.strong(null, "the browser (SSO) session")
                        : ["the session of ", t.strong(null, clientName(session))],
                    "?",
                ),
                t.p(
                    { className: "txt-hint txt-sm" },
                    session.sso
                        ? "The user will be signed out from the hosted login and all OAuth2 client sessions created through it (except the ones with offline access)."
                        : "The access and refresh tokens issued for this session will stop working immediately.",
                ),
            ),
            async () => {
                local.revoking[session.id] = true;

                try {
                    // POST /api/sessions/{id}/end (allowed with the sessions write permission)
                    await app.pb.sessions.end(session.id);
                    app.toasts.success("Successfully revoked the session.");
                    await load();
                } catch (err) {
                    app.checkApiError(err);
                }

                local.revoking[session.id] = false;
            },
            null,
            { yesButton: "Revoke" },
        );
    }

    function confirmAndForgetConsent(consent) {
        app.modals.confirm(
            t.div(
                null,
                t.p(null, "Do you really want to forget the consent for ", t.strong(null, clientName(consent)), "?"),
                t.p(
                    { className: "txt-hint txt-sm" },
                    "The user will be asked for consent on the next sign in. The already active sessions are not affected.",
                ),
            ),
            async () => {
                local.revoking[consent.id] = true;

                try {
                    await app.pb.collection(OAUTH2_CONSENTS_COLLECTION).delete(consent.id);
                    app.toasts.success(`Successfully removed the ${clientName(consent)} consent.`);
                    await load();
                } catch (err) {
                    app.checkApiError(err);
                }

                local.revoking[consent.id] = false;
            },
            null,
            { yesButton: "Forget" },
        );
    }

    function dateCell(label, value) {
        return t.div(
            { className: "oauth2-grant-date" },
            t.small({ className: "txt-hint" }, label),
            app.components.formattedDate({ value: value, short: true }),
        );
    }

    function clientLogo(item) {
        if (item.sso) {
            return t.figure(
                { className: "oauth2-app-logo-thumb" },
                t.i({ className: "ri-global-line", ariaHidden: true }),
            );
        }

        return t.figure(
            { className: "oauth2-app-logo-thumb" },
            item.expand?.client?.logo
                ? t.img({ src: item.expand.client.logo, alt: "", loading: "lazy" })
                : t.i({ className: "ri-apps-2-line", ariaHidden: true }),
        );
    }

    function actionButton(item, label, onclick) {
        return t.div(
            { className: "actions" },
            t.button(
                {
                    type: "button",
                    className: () => `btn sm secondary oauth2-grant-revoke ${local.revoking[item.id] ? "loading" : ""}`,
                    disabled: () => local.revoking[item.id],
                    onclick: onclick,
                },
                t.span({ className: "txt" }, label),
            ),
        );
    }

    function emptyItem(text) {
        return t.div({ className: "list-item" }, t.div({ className: "block txt-hint txt-center" }, text));
    }

    function sessionItem(session) {
        const methods = (session.amr || []).map((m) => (m.provider ? m.method + ":" + m.provider : m.method));

        return t.div(
            { className: "list-item oauth2-grant-item oauth2-session-item" },
            clientLogo(session),
            t.div(
                { className: "content" },
                t.div(
                    { className: "flex gap-5" },
                    t.strong({ className: "txt-ellipsis oauth2-grant-client" }, clientName(session)),
                    session.sso ? t.span({ className: "label info" }, "SSO") : null,
                    session.sso
                        ? t.small(
                            { className: "txt-hint" },
                            "hosted login - signs in the OAuth2 clients without offline access",
                        )
                        : null,
                    session.impersonator
                        ? t.span({ className: "label warning", title: session.impersonator }, "impersonated")
                        : null,
                    session.expand?.client?.disabled ? t.span({ className: "label warning" }, "client disabled") : null,
                ),
                t.div(
                    { className: "oauth2-grant-scopes" },
                    (session.scopes || []).map((s) => t.span({ className: "label sm" }, s)),
                    methods.map((m) => t.span({ className: "label sm info" }, m)),
                ),
                t.div(
                    { className: "txt-hint txt-sm txt-ellipsis", title: session.userAgent },
                    [session.ip, session.userAgent].filter(Boolean).join(" - "),
                ),
                t.div(
                    { className: "oauth2-grant-dates" },
                    dateCell("Signed in", session.authTime),
                    dateCell("Last used", session.lastUsedAt),
                    dateCell("Expires", session.expiresAt),
                ),
            ),
            actionButton(session, "Revoke", () => confirmAndRevokeSession(session)),
        );
    }

    function consentItem(consent) {
        return t.div(
            { className: "list-item oauth2-grant-item" },
            clientLogo(consent),
            t.div(
                { className: "content" },
                t.div(
                    { className: "flex gap-5" },
                    t.strong({ className: "txt-ellipsis oauth2-grant-client" }, clientName(consent)),
                ),
                t.div(
                    { className: "oauth2-grant-scopes" },
                    (consent.scopes || []).map((s) => t.span({ className: "label sm" }, s)),
                ),
                t.div(
                    { className: "oauth2-grant-dates" },
                    dateCell("Consented", consent.created),
                    dateCell("Updated", consent.updated),
                ),
            ),
            actionButton(consent, "Forget", () => confirmAndForgetConsent(consent)),
        );
    }

    return [
        t.div(
            {
                pbEvent: "recordSessionsConsents",
                className: "modal-content record-sessions-consents",
                onmount: () => {
                    load();
                },
            },
            t.div(
                { className: "txt-hint txt-sm m-b-sm" },
                options.description || [
                    "The active sessions and the OAuth2 clients that this user has authorized via the ",
                    t.code(null, collection.name),
                    " issuer.",
                ],
            ),
            t.h6({ className: "m-b-xs" }, "Active sessions"),
            t.div(
                { className: "list m-b-base" },
                () => {
                    if (local.isLoading && !local.sessions.length) {
                        return t.div({ className: "list-item" }, t.div({ className: "skeleton-loader" }));
                    }

                    if (!local.sessions.length) {
                        return emptyItem("No active sessions found.");
                    }

                    return local.sessions.map(sessionItem);
                },
            ),
            options.hideConsents ? null : t.h6({ className: "m-b-xs" }, "Consents"),
            options.hideConsents ? null : t.div(
                { className: "list" },
                () => {
                    if (local.isLoading && !local.consents.length) {
                        return t.div({ className: "list-item" }, t.div({ className: "skeleton-loader" }));
                    }

                    if (!local.consents.length) {
                        return emptyItem("No consents found.");
                    }

                    return local.consents.map(consentItem);
                },
            ),
        ),
        t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn transparent m-r-auto",
                    onclick: () => app.modals.close(),
                },
                t.span({ className: "txt" }, "Close"),
            ),
            app.components.refreshButton({
                className: "btn sm transparent secondary circle",
                onclick: load,
            }),
        ),
    ];
}
