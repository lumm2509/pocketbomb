import {
    docsApiDetails,
    docsCodeTabs,
    docsIssuerURL,
    docsOAuth2Error,
    docsParamsTable,
    docsResponses,
} from "./docsOAuth2Shared";

/**
 * The client_credentials token endpoint docs of the application installations issuer.
 *
 * @param  {Object} collection The _applicationInstallations collection.
 * @return {Element}
 */
export function docsOAuth2ClientCredentials(collection) {
    const baseURL = app.utils.getApiExampleURL();
    const issuer = docsIssuerURL(collection);

    return t.div(
        {
            pbEvent: "apiPreviewOAuth2ClientCredentials",
            className: "content",
        },
        t.p(
            null,
            "An installed application authenticates with the OAuth2 client of its installation (",
            t.a({ href: "#/applications" }, "Applications"),
            "). The client exchanges its ",
            t.code(null, "client_id"),
            " and ",
            t.code(null, "client_secret"),
            " for a short-lived access token with the ",
            t.code(null, "client_credentials"),
            " grant (the only application authentication mechanism).",
        ),
        t.p(
            null,
            "The access token is a regular auth token (",
            t.code(null, "Authorization: TOKEN"),
            " header) of the installation. It expires after ",
            t.strong(null, (collection.authToken?.duration || 0) + "s"),
            " (no refresh token - request a new one) and its access is the installation grant ∩ the token scopes ",
            "(the granted collection actions bypass the API rules). Rotating the secret or uninstalling the application invalidates the issued tokens.",
        ),
        docsCodeTabs([
            {
                title: "fetch",
                language: "js",
                value: `
                    const res = await fetch('${issuer}/token', {
                        method: 'POST',
                        headers: {
                            'content-type': 'application/x-www-form-urlencoded',
                            'authorization': 'Basic ' + btoa(CLIENT_ID + ':' + CLIENT_SECRET),
                        },
                        body: new URLSearchParams({
                            grant_type: 'client_credentials',
                            // optional, narrows the installation grant scopes
                            // scope: 'read_posts',
                        }),
                    });

                    const { access_token, expires_in, scope } = await res.json();

                    // use the access token with the regular PocketBase APIs
                    const records = await fetch('${baseURL}/api/collections/posts/records', {
                        headers: { Authorization: access_token },
                    });
                `,
            },
            {
                title: "curl",
                language: "bash",
                value: `
                    curl -X POST '${issuer}/token' \\
                      -u 'CLIENT_ID:CLIENT_SECRET' \\
                      -d 'grant_type=client_credentials'

                    curl '${baseURL}/api/collections/posts/records' \\
                      -H 'Authorization: Bearer ACCESS_TOKEN'
                `,
            },
        ]),
        docsApiDetails(
            "POST",
            `/oauth2/${collection.name}/token`,
            t.span(null, "application/x-www-form-urlencoded", t.br(), "client_secret_basic or client_secret_post"),
        ),
        docsParamsTable("Body params", [
            ["grant_type", "String", t.code(null, "client_credentials"), true],
            [
                "client_id",
                "String",
                "The installation client id (or HTTP Basic client authentication; never in the URL query).",
                true,
            ],
            ["client_secret", "String", "The installation client secret (if not using HTTP Basic).", false],
            [
                "scope",
                "String",
                "Optional space-separated subset of the installation grant scopes (read_{collection}, write_{collection}, system:read_{resource}, system:write_{resource}). Default to the full grant.",
                false,
            ],
        ]),
        ...docsResponses([
            {
                title: 200,
                value: JSON.stringify(
                    {
                        access_token: "...JWT...",
                        token_type: "Bearer",
                        expires_in: collection.authToken?.duration || 3600,
                        scope: "read_posts write_posts system:read_logs",
                    },
                    null,
                    2,
                ),
            },
            docsOAuth2Error(
                400,
                "invalid_scope",
                "The scope write_posts is not granted to the application installation.",
            ),
            docsOAuth2Error(401, "invalid_client", "Client authentication failed."),
        ]),
    );
}
