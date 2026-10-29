/**
 * Opens a modal with the provided webhook signing secret
 * (adapted from the OAuth2 "reveal once" client secret modal).
 *
 * Unlike the OAuth2 client secrets, the webhook secrets are stored
 * in plain text (they are required for the HMAC signatures) and
 * could be revealed again by superusers.
 *
 * @param {Object}  result         The reveal/rotate endpoint response.
 * @param {string}  result.id
 * @param {string}  result.secret
 * @param {Object}  [options]
 * @param {string}  [options.name]    The subscription name.
 * @param {string}  [options.mode]    "reveal" (default), "rotate" or "create".
 */
export function openWebhookSecretModal(result, options = {}) {
    const mode = options.mode || "reveal";

    const data = store({
        masked: mode == "reveal",
    });

    function alertContent() {
        if (mode == "rotate") {
            return [
                "The secret was rotated - ",
                t.strong(null, "the previous secret is no longer valid"),
                ". Update the receiver verification with the new one.",
            ];
        }
        if (mode == "create") {
            return [
                "Use this secret in your receiver to verify the ",
                t.code(null, "X-PB-Hmac-Sha256"),
                " signature of each request. You can reveal it again later from the subscription settings.",
            ];
        }
        return [
            "Keep the signing secret private. Anyone with it can forge webhook requests to your receiver.",
        ];
    }

    const modal = t.div(
        {
            pbEvent: "webhookSecretModal",
            className: "modal popup oauth2-secret-modal webhook-secret-modal",
            onafterclose: (el) => {
                el?.remove();
            },
        },
        t.header(
            { className: "modal-header" },
            t.h6(
                null,
                mode == "rotate" ? "New signing secret" : "Signing secret",
                options.name ? t.span({ className: "txt-hint" }, " - " + options.name) : null,
            ),
        ),
        t.div(
            { className: "modal-content" },
            t.div(
                { className: `alert ${mode == "reveal" ? "info" : "warning"}` },
                t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                t.div({ className: "content" }, alertContent()),
            ),
            t.div(
                { className: "oauth2-secret-rows" },
                t.div(
                    { className: "oauth2-secret-row" },
                    t.span({ className: "txt-hint txt-sm" }, "Secret"),
                    t.code(
                        { className: "oauth2-secret-value webhook-secret-value" },
                        () => (data.masked ? "•".repeat(Math.min(result.secret?.length || 0, 40)) : result.secret),
                    ),
                    t.button(
                        {
                            type: "button",
                            className: "btn xs circle transparent secondary",
                            ariaLabel: app.attrs.tooltip(() => (data.masked ? "Show" : "Hide")),
                            onclick: () => data.masked = !data.masked,
                        },
                        t.i({ className: () => (data.masked ? "ri-eye-line" : "ri-eye-off-line"), ariaHidden: true }),
                    ),
                    app.components.copyButton(result.secret),
                ),
            ),
        ),
        t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn expanded-lg m-l-auto",
                    onclick: () => app.modals.close(modal),
                },
                t.span({ className: "txt" }, "Done"),
            ),
        ),
    );

    document.body.appendChild(modal);

    app.modals.open(modal);
}
