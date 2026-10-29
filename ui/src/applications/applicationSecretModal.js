import { applicationCurlExample } from "./applicationsUtils";

/**
 * Opens a "reveal once" modal with the generated application installation credentials
 * (the install and rotate-secret endpoints responses).
 *
 * @param {Object} result
 * @param {string} result.clientId
 * @param {string} result.clientSecret
 * @param {string} result.tokenURL
 * @param {string} [result.webhookSecret]
 * @param {Object} [application]
 */
export function openApplicationSecretModal(result, application = null) {
    const data = store({
        acknowledged: false,
    });

    const modal = t.div(
        {
            pbEvent: "applicationSecretModal",
            className: "modal popup application-secret-modal",
            onbeforeclose: (el, forceClosed) => {
                if (forceClosed || data.acknowledged) {
                    return;
                }

                return new Promise((r) => {
                    app.modals.confirm(
                        "The client secret will not be shown again. Did you copy it?",
                        () => r(true),
                        () => r(false),
                        { yesButton: "Yes, close", noButton: "Go back" },
                    );
                });
            },
            onafterclose: (el) => {
                el?.remove();
            },
        },
        t.header(
            { className: "modal-header" },
            t.h6(
                { className: "modal-title" },
                "Admin API access credentials",
                application?.name ? [" of ", t.strong(null, application.name)] : null,
            ),
        ),
        t.div(
            { className: "modal-content" },
            t.div(
                { className: "alert warning" },
                t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                t.div(
                    { className: "content" },
                    "Copy the client secret now and store it securely - ",
                    t.strong(null, "it is shown only once"),
                    ". Only its hash is stored on the server and any previous secret (and the access tokens issued with it) no longer work.",
                ),
            ),
            t.div(
                { className: "oauth2-secret-rows m-b-base" },
                secretRow("Client ID", result.clientId, "application-client-id-value"),
                secretRow("Client secret", result.clientSecret, "application-client-secret-value"),
                secretRow("Token URL", result.tokenURL, "application-token-url-value"),
                // the signing secret of the managed webhooks (X-PB-Hmac-Sha256)
                result.webhookSecret
                    ? secretRow("Webhook secret", result.webhookSecret, "application-webhook-secret-value")
                    : null,
            ),
            t.p(
                { className: "txt-hint txt-sm" },
                "The client exchanges its credentials for a short-lived access token (",
                t.code(null, "grant_type=client_credentials"),
                ") and uses it as a regular auth token. The access is limited to the installation permissions.",
            ),
            app.components.codeBlock({
                language: "bash",
                value: applicationCurlExample(result.tokenURL, result.clientId, result.clientSecret),
            }),
        ),
        t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn expanded-lg m-l-auto application-secret-ack-btn",
                    onclick: () => {
                        data.acknowledged = true;
                        app.modals.close(modal);
                    },
                },
                t.span({ className: "txt" }, "I've copied the secret"),
            ),
        ),
    );

    document.body.appendChild(modal);

    app.modals.open(modal);
}

function secretRow(label, value, className) {
    return t.div(
        { className: "oauth2-secret-row" },
        t.span({ className: "txt-hint txt-sm" }, label),
        t.code({ className: "oauth2-secret-value " + className }, value),
        app.components.copyButton(value),
    );
}
