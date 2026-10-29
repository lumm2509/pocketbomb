window.app = window.app || {};
window.app.modals = window.app.modals || {};

// @todo events for the generated token
/**
 * Opens an auth record impersonate token generation modal.
 *
 * @example
 * ```js
 * app.modals.openRecordImpersontate(record)
 * ```
 *
 * @param {Object} record
 */
window.app.modals.openRecordImpersontate = function(record) {
    const modal = recordImpersonateModal(record);

    document.body.appendChild(modal);

    app.modals.open(modal);
};

function recordImpersonateModal(record) {
    const uniqueId = "impersonate_" + app.utils.randomString();

    const data = store({
        isLoading: false,
        token: "",
        expiresIn: 0,
        get collection() {
            return app.store.collections.find((c) => {
                return c.id == record.collectionId || c.name == record.collectionName;
            });
        },
    });

    const baseURL = app.utils.getApiExampleURL();

    async function createToken() {
        if (data.isLoading) {
            return;
        }

        data.isLoading = true;

        try {
            // RFC 8693 token exchange with the pb_dashboard client
            // (the issued token has an "act" claim with the current superuser)
            const result = await app.auth.impersonate({
                id: record.id,
                collectionName: data.collection?.name || record.collectionName,
            });

            data.token = result.access_token;
            data.expiresIn = result.expires_in;
        } catch (err) {
            app.checkApiError(err);
        }

        data.isLoading = false;
    }

    function reset() {
        data.token = "";
        data.expiresIn = 0;
    }

    return t.div(
        {
            className: "modal popup record-impersonate-auth-modal",
            onbeforeclose: () => {
                return !data.isLoading;
            },
            onafterclose: (el) => {
                el?.remove();
            },
        },
        t.header(
            { className: "modal-header" },
            t.h6(
                null,
                "Generate impersonation access token for ",
                t.strong(null, () => record.email || record.id),
            ),
        ),
        t.div(
            { className: "modal-content" },
            t.form(
                {
                    id: uniqueId + "_form",
                    hidden: () => data.token,
                    className: "block",
                    onsubmit: (e) => {
                        e.preventDefault();
                        createToken();
                    },
                },
                t.p(
                    { className: "txt-hint" },
                    "The token is issued with the OAuth2 token exchange grant (",
                    t.code(null, "act"),
                    " claim with your superuser id) and it is valid for the collection auth token duration (",
                    () => (data.collection?.authToken?.duration || 0) + "s",
                    "). It is non-renewable and could be revoked from the record ",
                    t.em(null, "Sessions & consents"),
                    " tab.",
                ),
            ),
            t.div(
                {
                    hidden: () => !data.token,
                    className: "alert success impersonate-success",
                },
                t.strong(null, () => data.token),
                " ",
                app.components.copyButton(() => data.token),
            ),
            // SDKs example
            app.components.codeBlockTabs({
                hidden: () => !data.token,
                className: "sdk-examples m-t-base",
                tabs: [
                    {
                        title: "JS SDK",
                        language: "js",
                        value: `
                            import PocketBase from 'pocketbase';

                            const pb = new PocketBase('${baseURL}');

                            // load the token into the store
                            const token = '...';
                            pb.authStore.save(token, null);
                        `,
                        footnote: t.div(
                            { className: "txt-right" },
                            t.a({
                                href: import.meta.env.PB_JS_SDK_URL,
                                target: "_blank",
                                rel: "noopener noreferrer",
                                textContent: "JS SDK docs",
                            }),
                        ),
                    },
                    {
                        title: "Dart SDK",
                        language: "dart",
                        value: `
                            import 'package:pocketbase/pocketbase.dart';

                            final pb = PocketBase('${baseURL}');

                            // load the token into the store
                            final token = '...';
                            pb.authStore.save(token, null);
                        `,
                        footnote: t.div(
                            { className: "txt-right" },
                            t.a({
                                href: import.meta.env.PB_DART_SDK_URL,
                                target: "_blank",
                                rel: "noopener noreferrer",
                                textContent: "Dart SDK docs",
                            }),
                        ),
                    },
                ],
            }),
        ),
        t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn transparent m-r-auto",
                    disabled: () => data.isLoading,
                    onclick: () => app.modals.close(),
                },
                t.span({ className: "txt" }, "Close"),
            ),
            t.button(
                {
                    "hidden": () => data.token,
                    "type": "submit",
                    "html-form": uniqueId + "_form",
                    "className": () => `btn expanded-lg ${data.isLoading ? "loading" : ""}`,
                    "disabled": () => data.isLoading,
                },
                t.span({ className: "txt" }, "Generate token"),
            ),
            t.button(
                {
                    hidden: () => !data.token,
                    type: "button",
                    className: () => `btn secondary expanded-lg ${data.isLoading ? "loading" : ""}`,
                    onclick: () => reset(),
                },
                t.span({ className: "txt" }, "Generate new one"),
            ),
        ),
    );
}
