import { oauth2AppURL, oauth2DiscoveryURL, oauth2IssuerURL } from "./oauth2Utils";

/**
 * Returns the OAuth2 client quickstart tab content (issuer urls and integration snippets).
 *
 * @param  {Object} data The client upsert modal state (collection and original client).
 * @return {Element}
 */
export function oauth2ClientQuickstartTab(data) {
    const issuer = () => oauth2IssuerURL(data.collection);
    const redirectURI = () => data.original.redirectURIs?.[0] || "https://example.com/auth/callback";
    const scope = () => {
        const scopes = data.original.scopes?.length ? data.original.scopes : ["openid", "email", "profile"];
        return scopes.join(" ");
    };

    const authorizeExample = () => {
        const params = new URLSearchParams({
            response_type: "code",
            client_id: data.original.clientId,
            redirect_uri: redirectURI(),
            scope: scope(),
            state: "RANDOM_STATE",
            nonce: "RANDOM_NONCE",
            code_challenge: "BASE64URL(SHA256(code_verifier))",
            code_challenge_method: "S256",
        });
        return issuer() + "/authorize?" + params.toString().replaceAll("+", "%20");
    };

    const isConfidential = () => data.original.type == "confidential";

    return t.div(
        { className: "grid oauth2-quickstart" },
        () => {
            if (!oauth2AppURL()) {
                return t.div(
                    { className: "col-sm-12" },
                    t.div(
                        { className: "alert warning" },
                        t.div(
                            { className: "content" },
                            "Set the Application URL in ",
                            t.a({ href: "#/settings" }, "Settings > Application"),
                            " - it is used as base of the issuer identifier.",
                        ),
                    ),
                );
            }
        },
        t.div(
            { className: "col-sm-12" },
            t.div(
                { className: "oauth2-url-list" },
                quickRow("Issuer", issuer),
                quickRow("Discovery URL", () => oauth2DiscoveryURL(data.collection)),
                quickRow("Client ID", () => data.original.clientId),
                quickRow("Authorize URL example", authorizeExample),
            ),
            t.div(
                { className: "field-help" },
                "Authorization code flow with PKCE (S256) is required for all OAuth2 clients. The issued access tokens work with the regular PocketBase APIs (",
                t.code(null, "Authorization: Bearer ..."),
                ") limited by the granted scopes.",
            ),
        ),
        t.div(
            { className: "col-sm-12" },
            app.components.codeBlockTabs({
                className: "oauth2-quickstart-snippets",
                historyKey: "pbOAuth2QuickstartTab",
                tabs: () => [
                    {
                        title: "openid-client (Node.js)",
                        language: "js",
                        value: `
import * as client from "openid-client";

// discovers the endpoints from ${oauth2DiscoveryURL(data.collection)}
const config = await client.discovery(
    new URL("${issuer()}"),
    "${data.original.clientId}",${
                            isConfidential()
                                ? `\n    process.env.PB_CLIENT_SECRET, // shown once on generation`
                                : ""
                        }
);

// 1. redirect the user to the hosted login page
const codeVerifier = client.randomPKCECodeVerifier();
const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
const state = client.randomState();
const nonce = client.randomNonce();

const authorizeURL = client.buildAuthorizationUrl(config, {
    redirect_uri: "${redirectURI()}",
    scope: "${scope()}",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
    nonce,
});

// 2. in the redirect_uri handler exchange the code for tokens
const tokens = await client.authorizationCodeGrant(config, currentURL, {
    pkceCodeVerifier: codeVerifier,
    expectedState: state,
    expectedNonce: nonce,
});

// tokens.access_token -> use with the PocketBase APIs
// tokens.claims()     -> verified id_token claims (sub, email, ...)
`.trim(),
                    },
                    {
                        title: "Hydrogen-like env",
                        language: "bash",
                        value: `
# similar to the Shopify Customer Account API settings
PUBLIC_OAUTH2_ISSUER="${issuer()}"
PUBLIC_OAUTH2_CLIENT_ID="${data.original.clientId}"${
                            isConfidential() ? `\nOAUTH2_CLIENT_SECRET="<generated secret>"` : ""
                        }
OAUTH2_REDIRECT_URI="${redirectURI()}"
OAUTH2_SCOPE="${scope()}"

# endpoints (also available via the discovery document)
OAUTH2_AUTHORIZE_URL="${issuer()}/authorize"
OAUTH2_TOKEN_URL="${issuer()}/token"
OAUTH2_USERINFO_URL="${issuer()}/userinfo"
OAUTH2_LOGOUT_URL="${issuer()}/logout"
OAUTH2_JWKS_URL="${issuer()}/jwks.json"
`.trim(),
                    },
                    {
                        title: "Token request (curl)",
                        language: "bash",
                        value: `
curl -X POST "${issuer()}/token" \\
    -H "Content-Type: application/x-www-form-urlencoded" \\${
                            isConfidential()
                                ? `\n    -u "${data.original.clientId}:$PB_CLIENT_SECRET" \\`
                                : `\n    -d "client_id=${data.original.clientId}" \\`
                        }
    -d "grant_type=authorization_code" \\
    -d "code=$CODE" \\
    -d "redirect_uri=${redirectURI()}" \\
    -d "code_verifier=$CODE_VERIFIER"
`.trim(),
                    },
                ],
            }),
        ),
    );
}

function quickRow(label, valueFunc) {
    return t.div(
        { className: "oauth2-url-row" },
        t.span({ className: "oauth2-url-label txt-hint txt-sm" }, label),
        t.code({ className: "oauth2-url-value", title: valueFunc }, valueFunc),
        app.components.copyButton(valueFunc),
    );
}
