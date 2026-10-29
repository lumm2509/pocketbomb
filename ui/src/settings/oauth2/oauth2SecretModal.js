/**
 * Opens a "reveal once" modal with the provided generated client secret.
 *
 * @param {Object} result         The generate secret endpoint response.
 * @param {string} result.clientId
 * @param {string} result.clientSecret
 */
export function openOAuth2SecretModal(result) {
    const data = store({
        acknowledged: false,
    });

    const modal = t.div(
        {
            pbEvent: "oauth2SecretModal",
            className: "modal popup oauth2-secret-modal",
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
        t.header({ className: "modal-header" }, t.h6(null, "Client secret")),
        t.div(
            { className: "modal-content" },
            t.div(
                { className: "alert warning" },
                t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                t.div(
                    { className: "content" },
                    "Copy the client secret now and store it securely - ",
                    t.strong(null, "it is shown only once"),
                    ". Only its hash is stored on the server and any previous secret is no longer valid.",
                ),
            ),
            t.div(
                { className: "oauth2-secret-rows" },
                secretRow("Client ID", result.clientId, "oauth2-client-id-value"),
                secretRow("Client secret", result.clientSecret, "oauth2-client-secret-value"),
            ),
        ),
        t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn expanded-lg m-l-auto",
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
