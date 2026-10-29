import {
    docsApiDetails,
    docsClientId,
    docsCodeTabs,
    docsIssuerURL,
    docsJSSDKFootnote,
    docsOAuth2Error,
    docsParamsTable,
    docsResponses,
} from "./docsOAuth2Shared";

/**
 * Userinfo endpoint docs.
 */
export function docsOAuth2Userinfo(collection) {
    const issuer = docsIssuerURL(collection);

    return t.div(
        { pbEvent: "apiPreviewOAuth2Userinfo", className: "content" },
        t.p(
            null,
            "Returns the OpenID Connect standard claims of the authenticated record (requires the ",
            t.code(null, "openid"),
            " scope; the ",
            t.code(null, "email"),
            " and ",
            t.code(null, "profile"),
            " scopes add the related claims).",
        ),
        docsCodeTabs([
            {
                title: "JS SDK",
                language: "js",
                value: `
                    const claims = await pb.send('/oauth2/${collection.name}/userinfo', {
                        headers: { Authorization: 'Bearer ' + pb.authStore.token },
                    });
                `,
                footnote: docsJSSDKFootnote(),
            },
            {
                title: "fetch",
                language: "js",
                value: `
                    const res = await fetch('${issuer}/userinfo', {
                        headers: { Authorization: 'Bearer ACCESS_TOKEN' },
                    });
                    const claims = await res.json();
                `,
            },
        ]),
        docsApiDetails(
            "GET",
            `/oauth2/${collection.name}/userinfo`,
            t.span(null, "Requires", t.br(), "Authorization: Bearer TOKEN"),
        ),
        ...docsResponses([
            {
                title: 200,
                value: JSON.stringify({ sub: "RECORD_ID", email: "test@example.com", email_verified: true }, null, 2),
            },
            docsOAuth2Error(401, "invalid_token", "Invalid or expired access token."),
            docsOAuth2Error(403, "insufficient_scope", "The access token doesn't have the openid scope."),
        ]),
    );
}

/**
 * Revoke endpoint docs.
 */
export function docsOAuth2Revoke(collection) {
    const issuer = docsIssuerURL(collection);
    const clientId = docsClientId(collection);

    return t.div(
        { pbEvent: "apiPreviewOAuth2Revoke", className: "content" },
        t.p(
            null,
            "Revokes an access or refresh token (RFC 7009). Revoking any of them ends the whole auth session ",
            "(all its access and refresh tokens stop working immediately).",
        ),
        docsCodeTabs([
            {
                title: "fetch",
                language: "js",
                value: `
                    await fetch('${issuer}/revoke', {
                        method: 'POST',
                        headers: { 'content-type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams({
                            client_id:       '${clientId}',
                            token:           'REFRESH_TOKEN',
                            token_type_hint: 'refresh_token',
                        }),
                    });

                    pb.authStore.clear();
                `,
                footnote: docsJSSDKFootnote(),
            },
            {
                title: "curl",
                language: "bash",
                value: `
                    curl -X POST '${issuer}/revoke' \\
                      -d 'client_id=${clientId}' \\
                      -d 'token=REFRESH_TOKEN'
                `,
            },
        ]),
        docsApiDetails("POST", `/oauth2/${collection.name}/revoke`, "application/x-www-form-urlencoded"),
        docsParamsTable("Body params", [
            ["token", "String", "The access or refresh token to revoke.", true],
            ["client_id", "String", "The client id (or HTTP Basic client authentication).", true],
            [
                "token_type_hint",
                "String",
                t.span(null, t.code(null, "access_token"), " or ", t.code(null, "refresh_token"), "."),
            ],
        ]),
        ...docsResponses([
            { title: 200, value: "(empty; also for invalid or already revoked tokens)" },
            docsOAuth2Error(401, "invalid_client", "Client authentication failed."),
        ]),
    );
}

/**
 * Logout (end session) endpoint docs.
 */
export function docsOAuth2Logout(collection) {
    const issuer = docsIssuerURL(collection);
    const clientId = docsClientId(collection);

    return t.div(
        { pbEvent: "apiPreviewOAuth2Logout", className: "content" },
        t.p(
            null,
            "OpenID Connect RP-initiated logout. Ends the browser SSO session of the issuer (and its sessions without ",
            t.code(null, "offline_access"),
            ") and the session of the ",
            t.code(null, "id_token_hint"),
            ". Without a valid ",
            t.code(null, "id_token_hint"),
            " the end-user is asked to confirm the logout.",
        ),
        docsCodeTabs([
            {
                title: "JS (browser)",
                language: "js",
                value: `
                    const params = new URLSearchParams({
                        client_id:                '${clientId}',
                        id_token_hint:            ID_TOKEN,
                        post_logout_redirect_uri: 'https://example.com/',
                        state:                    'STATE',
                    });

                    pb.authStore.clear();

                    window.location.href = '${issuer}/logout?' + params;
                `,
                footnote: docsJSSDKFootnote(),
            },
        ]),
        docsApiDetails("GET", `/oauth2/${collection.name}/logout`, "Browser redirect"),
        docsParamsTable("?query params", [
            ["id_token_hint", "String", "A previously issued id_token (skips the logout confirmation)."],
            ["post_logout_redirect_uri", "String", "One of the client registered post logout redirect URIs."],
            ["client_id", "String", "The client id (required with post_logout_redirect_uri without id_token_hint)."],
            ["state", "String", "Opaque value returned with the post logout redirect."],
        ]),
    );
}

/**
 * Hosted account pages and the related authenticated actor APIs docs.
 */
export function docsHostedAccountPages(collection) {
    const baseURL = app.utils.getApiExampleURL();
    const issuer = docsIssuerURL(collection);
    const isSuperusers = collection.name == "_superusers";

    const pages = [
        [
            "Password reset request",
            `${issuer}/password-reset`,
            "Sends a password reset email (linked from the login page).",
        ],
        [
            "Password reset confirm",
            `${issuer}/password-reset/confirm?token=TOKEN`,
            "The reset password mail link ({ISSUER_URL}/password-reset/confirm?token={TOKEN}).",
        ],
        [
            "Email change confirm",
            `${issuer}/email-change/confirm?token=TOKEN`,
            "The email change mail link ({ISSUER_URL}/email-change/confirm?token={TOKEN}).",
        ],
    ];

    if (!isSuperusers) {
        pages.push(
            [
                "Verification request",
                `${issuer}/verify-email/request`,
                "Sends a new verification email (enumeration safe).",
            ],
            [
                "Verification confirm",
                `${issuer}/verify-email?token=TOKEN`,
                "The verification mail link ({ISSUER_URL}/verify-email?token={TOKEN}).",
            ],
        );

        if (collection.createRule !== null && collection.passwordAuth?.enabled) {
            pages.push([
                "Sign up",
                `${issuer}/signup?auth_state=...`,
                "Linked from the hosted login page (the collection create rule allows guests).",
            ]);
        }
    }

    return t.div(
        { pbEvent: "apiPreviewHostedAccountPages", className: "content" },
        t.p(
            null,
            "The account flows are hosted pages of the issuer (server-rendered forms with CSRF protection) ",
            "and the default mail templates link to them. They fire the regular ",
            t.code(null, "onRecordRequestPasswordResetRequest"),
            ", ",
            t.code(null, "onRecordConfirmPasswordResetRequest"),
            ", ",
            t.code(null, "onRecordConfirmVerificationRequest"),
            " and ",
            t.code(null, "onRecordConfirmEmailChangeRequest"),
            " hooks.",
        ),
        t.table(
            { className: "api-preview-table" },
            t.thead(null, t.tr(null, t.th(null, "Page"), t.th(null, "URL"), t.th(null, "Description"))),
            t.tbody(
                null,
                pages.map(([name, url, description]) =>
                    t.tr(
                        null,
                        t.td({ className: "min-width txt-nowrap" }, name),
                        t.td(null, t.code(null, url)),
                        t.td(null, description),
                    )
                ),
            ),
        ),
        t.div({ className: "m-t-base" }, t.strong(null, "Authenticated actor APIs")),
        t.p(
            null,
            "The email change (and, for the non-staff issuers, the verification email) is requested by the authenticated record:",
        ),
        docsCodeTabs([
            {
                title: "JS SDK",
                language: "js",
                value: `
                    import PocketBase from 'pocketbase';

                    const pb = new PocketBase('${baseURL}');

                    // pb.authStore.save(accessToken, record) - see the Token tab

                    await pb.collection('${collection.name}').requestEmailChange('new@example.com');
                    ${
                    isSuperusers
                        ? ""
                        : `\n                    await pb.collection('${collection.name}').requestVerification(pb.authStore.record.email);`
                }
                `,
                footnote: docsJSSDKFootnote(),
            },
            {
                title: "fetch",
                language: "js",
                value: `
                    await fetch('${baseURL}/api/collections/${collection.name}/request-email-change', {
                        method: 'POST',
                        headers: { 'content-type': 'application/json', Authorization: ACCESS_TOKEN },
                        body: JSON.stringify({ newEmail: 'new@example.com' }),
                    });
                    ${
                    isSuperusers ? "" : `
                    await fetch('${baseURL}/api/collections/${collection.name}/request-verification', {
                        method: 'POST',
                        headers: { Authorization: ACCESS_TOKEN },
                    });`
                }
                `,
            },
        ]),
        docsApiDetails(
            "POST",
            `/api/collections/${collection.name}/request-email-change`,
            t.span(null, "Requires", t.br(), "Authorization:TOKEN header"),
        ),
        isSuperusers ? null : docsApiDetails(
            "POST",
            `/api/collections/${collection.name}/request-verification`,
            t.span(null, "Requires", t.br(), "Authorization:TOKEN header"),
        ),
    );
}
