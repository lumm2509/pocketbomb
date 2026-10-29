import {
    docsApiDetails,
    docsClientId,
    docsCodeTabs,
    docsIssuerURL,
    docsJSSDKFootnote,
    docsParamsTable,
} from "./docsOAuth2Shared";

export function docsOAuth2Authorize(collection) {
    const issuer = docsIssuerURL(collection);
    const clientId = docsClientId(collection);

    const methods = [
        collection.passwordAuth?.enabled ? "password" : "",
        collection.otp?.enabled ? "one-time code" : "",
        collection.oauth2?.enabled && collection.name != "_superusers" ? "OAuth2 providers" : "",
    ].filter(Boolean);

    return t.div(
        {
            pbEvent: "apiPreviewOAuth2Authorize",
            className: "content",
        },
        t.p(
            null,
            "Every auth collection is an OAuth2 / OpenID Connect issuer and the ",
            t.strong(null, "only way to authenticate"),
            " a ",
            t.code(null, collection.name),
            " record is the Authorization Code flow with PKCE using the issuer hosted login pages.",
        ),
        t.p(
            null,
            "Redirect the browser to the authorization endpoint. After the end-user signs in on the hosted pages (",
            methods.length ? methods.join(", ") : "no sign-in methods are enabled",
            collection.mfa?.enabled ? "; MFA enabled" : "",
            ") the browser is redirected back to your ",
            t.code(null, "redirect_uri"),
            " with ",
            t.code(null, "code"),
            ", ",
            t.code(null, "state"),
            " and ",
            t.code(null, "iss"),
            " query parameters that you exchange for tokens (see the Token tab).",
        ),
        docsCodeTabs([
            {
                title: "JS (browser)",
                language: "js",
                value: `
                    // generate the PKCE verifier and challenge (S256)
                    const random = (n) => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(n))))
                        .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');

                    const verifier = random(48);
                    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
                    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
                        .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');

                    const state = random(24);
                    sessionStorage.setItem('pb_oauth2', JSON.stringify({ verifier, state }));

                    const params = new URLSearchParams({
                        client_id:             '${clientId}',
                        redirect_uri:          'https://example.com/callback',
                        response_type:         'code',
                        scope:                 'openid email offline_access',
                        state:                 state,
                        nonce:                 random(24),
                        code_challenge:        challenge,
                        code_challenge_method: 'S256',
                    });

                    window.location.href = '${issuer}/authorize?' + params;
                `,
                footnote: docsJSSDKFootnote(),
            },
            {
                title: "URL",
                language: "bash",
                value: `
                    ${issuer}/authorize
                      ?client_id=${clientId}
                      &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback
                      &response_type=code
                      &scope=openid%20email%20offline_access
                      &state=STATE
                      &nonce=NONCE
                      &code_challenge=S256_CHALLENGE
                      &code_challenge_method=S256
                `,
            },
        ]),
        docsApiDetails("GET", `/oauth2/${collection.name}/authorize`, "Browser redirect"),
        docsParamsTable("?query params", [
            ["client_id", "String", "The registered OAuth2 client id (Settings > OAuth2 clients).", true],
            ["redirect_uri", "String", "Exact match of one of the client registered redirect URIs.", true],
            ["response_type", "String", t.span(null, "Must be ", t.code(null, "code"), "."), true],
            [
                "scope",
                "String",
                t.span(
                    null,
                    "Space separated scopes allowed for the client (deny by default). The third-party clients need the collection scopes (",
                    t.code(null, "read_{collection}"),
                    " for list/view, ",
                    t.code(null, "write_{collection}"),
                    " for create/update/delete) — their access is the user roles permissions ∩ the granted collection scopes. The system resources scopes have their own ",
                    t.code(null, "system:read_{resource}"),
                    "/",
                    t.code(null, "system:write_{resource}"),
                    " namespace (reserved, not grantable to the OAuth2 clients) so a ",
                    t.code(null, "read_{collection}"),
                    " scope never maps to a system resource.",
                ),
                true,
            ],
            ["code_challenge", "String", "PKCE S256 code challenge (required for all clients).", true],
            ["code_challenge_method", "String", t.span(null, "Must be ", t.code(null, "S256"), "."), true],
            ["state", "String", "Opaque value returned unchanged with the redirect (CSRF protection)."],
            ["nonce", "String", "Value returned in the id_token nonce claim."],
            [
                "prompt",
                "String",
                t.span(
                    null,
                    t.code(null, "none"),
                    " (no UI; reuse the SSO session or return login_required), ",
                    t.code(null, "login"),
                    " (force re-authentication), ",
                    t.code(null, "consent"),
                    " or ",
                    t.code(null, "create"),
                    " (open the hosted sign up page; only if the collection allows the sign up).",
                ),
            ],
            ["max_age", "Number", "Max allowed seconds since the last interactive authentication."],
            ["login_hint", "String", "Prefilled identity on the hosted login page."],
        ]),
        t.div({ className: "m-t-base m-b-sm" }, t.strong(null, "Redirect responses")),
        app.components.codeBlockTabs({
            tabs: [
                {
                    title: "Success",
                    language: "bash",
                    value: "https://example.com/callback?code=CODE&state=STATE&iss=" + encodeURIComponent(issuer),
                },
                {
                    title: "Error",
                    language: "bash",
                    value: "https://example.com/callback?error=access_denied&error_description=...&state=STATE&iss="
                        + encodeURIComponent(issuer),
                },
            ],
        }),
    );
}
