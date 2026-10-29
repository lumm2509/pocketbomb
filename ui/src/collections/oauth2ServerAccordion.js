import {
    OAUTH2_BUILTIN_SCOPES,
    oauth2AppURL,
    oauth2DiscoveryURL,
    oauth2IssuerURL,
    oauth2TagsInput,
} from "@/settings/oauth2/oauth2Utils";

/**
 * Auth collection "OAuth2 / OIDC provider" (aka. OAuth2Server) options accordion.
 *
 * @param  {Object} upsertData The collection upsert modal data store.
 * @return {Element}
 */
export function oauth2ServerAccordion(upsertData) {
    const uniqueId = "oauth2Server_" + app.utils.randomString();

    const data = store({
        isRotating: false,
        rotateAlg: "RS256",
        get collection() {
            return upsertData.collection;
        },
        get config() {
            const c = upsertData.collection;
            if (!c.oauth2Server) {
                c.oauth2Server = {
                    sessionDuration: 1209600,
                    refreshTokenDuration: 2592000,
                    codeDuration: 60,
                    consentRequired: true,
                    scopes: [],
                    signingKeys: [],
                    loginPage: { title: "", logoURL: "", primaryColor: "" },
                };
            }
            c.oauth2Server.loginPage = c.oauth2Server.loginPage || {};
            c.oauth2Server.scopes = c.oauth2Server.scopes || [];
            c.oauth2Server.signingKeys = c.oauth2Server.signingKeys || [];
            return c.oauth2Server;
        },
        get isNew() {
            return app.utils.isEmpty(upsertData.originalCollection?.id);
        },
        get isSuperusers() {
            return upsertData.collection.name == "_superusers";
        },
        get savedName() {
            return upsertData.originalCollection?.name || upsertData.collection.name;
        },
        get hasErrors() {
            return !app.utils.isEmpty(app.store.errors?.oauth2Server);
        },
    });

    // the hosted login page methods are the collection enabled auth methods
    const loginMethods = [
        { label: "Password", configKey: "passwordAuth" },
        { label: "One-time password (OTP)", configKey: "otp" },
        { label: "OAuth2 providers", configKey: "oauth2" },
    ];

    async function rotateKey() {
        if (data.isRotating || data.isNew) {
            return;
        }

        data.isRotating = true;

        try {
            const updated = await app.pb.send(
                `/api/oauth2/${encodeURIComponent(upsertData.originalCollection.id)}/keys/rotate`,
                { method: "POST", body: { alg: data.rotateAlg } },
            );

            const keys = JSON.parse(JSON.stringify(updated?.oauth2Server?.signingKeys || []));

            // sync both the original and the form state to avoid reporting false changes
            // (the other unsaved form changes are preserved)
            if (upsertData.originalCollection?.oauth2Server) {
                upsertData.originalCollection.oauth2Server.signingKeys = JSON.parse(JSON.stringify(keys));
            }
            data.config.signingKeys = keys;

            app.store.addOrUpdateCollection(updated);

            app.toasts.success("Successfully generated a new active signing key.");
        } catch (err) {
            app.checkApiError(err);
        }

        data.isRotating = false;
    }

    function removeKey(index) {
        const key = data.config.signingKeys[index];
        app.modals.confirm(
            t.div(
                null,
                t.p(null, "Do you really want to remove signing key ", t.strong(null, key.kid), "?"),
                t.p(
                    { className: "txt-hint txt-sm" },
                    "The id_tokens signed with it will no longer be verifiable after saving the collection.",
                ),
            ),
            () => {
                data.config.signingKeys.splice(index, 1);
                app.utils.deleteByPath(app.store.errors, "oauth2Server.signingKeys");
            },
            null,
            { yesButton: "Remove" },
        );
    }

    function urlRow(label, value) {
        return t.div(
            { className: "oauth2-url-row" },
            t.span({ className: "oauth2-url-label txt-hint txt-sm" }, label),
            t.code({ className: "oauth2-url-value txt-ellipsis", title: value }, value),
            app.components.copyButton(value),
        );
    }

    function numberField(key, label, help) {
        return t.div(
            { className: "col-sm-4" },
            t.div(
                { className: "field" },
                t.label({ htmlFor: uniqueId + "." + key }, label),
                t.input({
                    type: "number",
                    id: uniqueId + "." + key,
                    name: "oauth2Server." + key,
                    min: 10,
                    step: 1,
                    required: true,
                    value: () => data.config[key] || "",
                    oninput: (e) => (data.config[key] = parseInt(e.target.value, 10) || 0),
                }),
            ),
            help ? t.div({ className: "field-help" }, help) : null,
        );
    }

    function signingKeysTable() {
        return t.div(
            { className: "col-sm-12" },
            t.div(
                { className: "oauth2-section-title" },
                t.strong(null, "Signing keys"),
                t.i({
                    className: "ri-information-line link-hint",
                    ariaDescription: app.attrs.tooltip(
                        "The latest created active key is used to sign the OpenID Connect id_tokens. All keys (incl. inactive) are published in the JWKS so that already issued tokens could be verified.",
                    ),
                }),
                t.div({ className: "flex-fill" }),
                () => {
                    if (data.isNew) {
                        return t.small({ className: "txt-hint" }, "Keys are generated on save");
                    }

                    return [
                        app.components.select({
                            className: "oauth2-alg-select",
                            options: [
                                { value: "RS256", label: "RS256" },
                                { value: "ES256", label: "ES256" },
                            ],
                            required: true,
                            value: () => data.rotateAlg,
                            onchange: (opts) => (data.rotateAlg = opts?.[0]?.value || "RS256"),
                        }),
                        t.button(
                            {
                                type: "button",
                                className: () => `btn sm secondary ${data.isRotating ? "loading" : ""}`,
                                disabled: () => data.isRotating,
                                onclick: rotateKey,
                            },
                            t.i({ className: "ri-refresh-line", ariaHidden: true }),
                            t.span({ className: "txt" }, "Rotate key"),
                        ),
                    ];
                },
            ),
            t.div(
                { className: "oauth2-keys-field" },
                t.table(
                    { className: "table oauth2-keys-table" },
                    t.thead(
                        null,
                        t.tr(
                            null,
                            t.th(null, "Kid"),
                            t.th(null, "Alg"),
                            t.th(null, "Created"),
                            t.th({ className: "txt-center" }, "Active"),
                            t.th({ className: "col-actions" }),
                        ),
                    ),
                    t.tbody(null, () => {
                        const keys = data.config.signingKeys;

                        if (!keys.length) {
                            return t.tr(
                                null,
                                t.td(
                                    { colSpan: 99, className: "txt-hint txt-center" },
                                    "A new active key will be generated on save.",
                                ),
                            );
                        }

                        // the key used for signing new tokens
                        let signingKid = "";
                        let signingDate = "";
                        for (const k of keys) {
                            if (k.active && (!signingKid || k.createdAt > signingDate)) {
                                signingKid = k.kid;
                                signingDate = k.createdAt;
                            }
                        }

                        return keys.map((key, i) => {
                            return t.tr(
                                { className: () => (key.active ? "" : "faded") },
                                t.td(
                                    null,
                                    t.span({ className: "txt-code" }, key.kid),
                                    () => {
                                        if (key.kid == signingKid) {
                                            return t.span({ className: "label success sm m-l-5" }, "signing");
                                        }
                                    },
                                ),
                                t.td(null, t.span({ className: "label" }, key.alg)),
                                t.td(null, app.components.formattedDate({ value: key.createdAt, short: true })),
                                t.td(
                                    { className: "txt-center" },
                                    t.div(
                                        { className: "field inline-flex" },
                                        t.input({
                                            type: "checkbox",
                                            id: uniqueId + ".key." + i,
                                            className: "switch sm",
                                            checked: () => !!key.active,
                                            onchange: (e) => {
                                                key.active = e.target.checked;
                                                app.utils.deleteByPath(app.store.errors, "oauth2Server.signingKeys");
                                            },
                                        }),
                                        t.label({ htmlFor: uniqueId + ".key." + i, ariaLabel: "Active" }),
                                    ),
                                ),
                                t.td(
                                    { className: "col-actions" },
                                    t.button(
                                        {
                                            type: "button",
                                            className: "btn sm circle transparent secondary",
                                            ariaLabel: app.attrs.tooltip("Remove key", "left"),
                                            onclick: () => removeKey(i),
                                        },
                                        t.i({ className: "ri-delete-bin-7-line", ariaHidden: true }),
                                    ),
                                ),
                            );
                        });
                    }),
                ),
            ),
            () => {
                const errs = app.store.errors?.oauth2Server?.signingKeys;
                if (app.utils.isEmpty(errs)) {
                    return;
                }

                let msg = errs.message;
                if (!msg) {
                    // nested key errors (e.g. duplicated kid)
                    msg = Object.values(errs)
                        .map((e) => e?.message || Object.values(e || {}).map((ie) => ie?.message).join(" "))
                        .filter(Boolean)
                        .join(" ");
                }

                return t.div({ className: "field-help error" }, msg);
            },
        );
    }

    return t.details(
        {
            pbEvent: "oauth2ServerAccordion",
            className: "accordion oauth2-server-accordion",
        },
        t.summary(
            null,
            t.i({ className: "ri-key-2-line", ariaHidden: true }),
            t.span({ className: "txt" }, "OAuth2 / OIDC provider"),
            t.span({ className: "label success m-l-auto" }, "Issuer"),
            () => {
                if (!data.hasErrors) {
                    return;
                }

                return t.i({
                    className: "ri-error-warning-fill txt-danger",
                    ariaDescription: app.attrs.tooltip("Has errors", "left"),
                });
            },
        ),
        t.div(
            { className: "grid sm" },
            t.div(
                { className: "col-sm-12" },
                t.div(
                    { className: "alert info" },
                    t.div(
                        { className: "content" },
                        t.p(
                            null,
                            "Every auth collection is an OAuth2 / OpenID Connect issuer. Third-party and first-party OAuth2 clients sign in the records of this collection (authorization code + PKCE) using the hosted login pages. ",
                            "The issued access tokens are backed by auth sessions and limited to the granted scopes. ",
                            "The OAuth2 clients are managed from ",
                            t.a({ href: "#/settings/oauth2-clients" }, "Settings > OAuth2 clients"),
                            ".",
                        ),
                    ),
                ),
            ),
            () => {
                if (!data.isSuperusers) {
                    return;
                }

                return t.div(
                    { className: "col-sm-12" },
                    t.div(
                        { className: "alert warning" },
                        t.i({ className: "ri-shield-user-line", ariaHidden: true }),
                        t.div(
                            { className: "content" },
                            t.strong(null, "Staff issuer"),
                            " — only first-party OAuth2 clients allowed. The superuser tokens bypass all collection API rules.",
                        ),
                    ),
                );
            },
            // issuer urls
            t.div(
                { className: "col-sm-12" },
                t.div(
                    { className: "oauth2-urls" },
                    () => {
                        if (!oauth2AppURL()) {
                            return t.div(
                                { className: "txt-hint txt-sm" },
                                "Set the Application URL in ",
                                t.a({ href: "#/settings" }, "Settings > Application"),
                                " to see the issuer URLs.",
                            );
                        }

                        return [
                            urlRow("Issuer", oauth2IssuerURL(data.savedName)),
                            urlRow("Discovery", oauth2DiscoveryURL(data.savedName)),
                        ];
                    },
                    () => {
                        if (!data.isNew && upsertData.collection.name != upsertData.originalCollection?.name) {
                            return t.div(
                                { className: "txt-warning txt-sm" },
                                "Renaming the collection changes the issuer and breaks the existing OAuth2 clients integrations.",
                            );
                        }
                    },
                ),
            ),
            numberField("sessionDuration", "SSO session duration (s)", "Default 1209600 (14 days)."),
            numberField(
                "refreshTokenDuration",
                "Refresh token duration (s)",
                "Default 2592000 (30 days). Without offline_access the refresh tokens also end with the SSO session.",
            ),
            numberField("codeDuration", "Authorization code duration (s)", "Max 600. Default 60."),
            t.div(
                { className: "col-sm-12" },
                t.div(
                    { className: "txt-hint txt-sm" },
                    "The access tokens duration is the collection ",
                    t.em(null, "Tokens options > Auth duration"),
                    " (",
                    () => (data.collection.authToken?.duration || 0) + "s",
                    ").",
                ),
            ),
            t.div(
                { className: "col-sm-12" },
                t.div(
                    { className: "field" },
                    t.input({
                        type: "checkbox",
                        id: uniqueId + ".consentRequired",
                        name: "oauth2Server.consentRequired",
                        className: "switch",
                        checked: () => !!data.config.consentRequired,
                        onchange: (e) => (data.config.consentRequired = e.target.checked),
                    }),
                    t.label(
                        { htmlFor: uniqueId + ".consentRequired" },
                        "Require user consent",
                        t.i({
                            className: "ri-information-line link-hint",
                            ariaDescription: app.attrs.tooltip("First-party apps always skip the consent screen."),
                        }),
                    ),
                ),
            ),
            t.div(
                { className: "col-sm-12" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".scopes" }, "Custom scopes"),
                    oauth2TagsInput({
                        id: uniqueId + ".scopes",
                        name: "oauth2Server.scopes",
                        placeholder: "e.g. posts:read (Enter to add)",
                        value: () => data.config.scopes,
                        onchange: (list) => (data.config.scopes = list),
                    }),
                ),
                t.div(
                    { className: "field-help" },
                    "Built-in scopes: ",
                    OAUTH2_BUILTIN_SCOPES.map((s, i) => [i > 0 ? ", " : "", t.code(null, s)]),
                    ". Use ",
                    t.code(null, "@request.oauth2.scopes:each ?= 'posts:read'"),
                    " in the API rules to require a scope. The ",
                    t.code(null, "read_"),
                    ", ",
                    t.code(null, "write_"),
                    " and ",
                    t.code(null, "system:"),
                    " prefixes are reserved for the collection and system scopes.",
                ),
            ),
            // login page branding
            t.div(
                { className: "col-sm-12" },
                t.div({ className: "oauth2-section-title" }, t.strong(null, "Hosted login page")),
            ),
            t.div(
                { className: "col-sm-6" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".title" }, "Title"),
                    t.input({
                        type: "text",
                        id: uniqueId + ".title",
                        name: "oauth2Server.loginPage.title",
                        placeholder: () => app.store.settings?.meta?.appName || "Fallback to the app name",
                        value: () => data.config.loginPage.title || "",
                        oninput: (e) => (data.config.loginPage.title = e.target.value),
                    }),
                ),
            ),
            t.div(
                { className: "col-sm-6" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".logoURL" }, "Logo URL"),
                    t.input({
                        type: "url",
                        id: uniqueId + ".logoURL",
                        name: "oauth2Server.loginPage.logoURL",
                        placeholder: "https://example.com/logo.svg",
                        value: () => data.config.loginPage.logoURL || "",
                        oninput: (e) => (data.config.loginPage.logoURL = e.target.value),
                    }),
                ),
            ),
            t.div(
                { className: "col-sm-6" },
                t.div(
                    { className: "field oauth2-color-field" },
                    t.label({ htmlFor: uniqueId + ".primaryColor" }, "Primary color"),
                    app.components.colorPicker({
                        id: uniqueId + ".primaryColor",
                        name: "oauth2Server.loginPage.primaryColor",
                        predefinedColors: () => app.store.predefinedAccentColors,
                        // fallback to the hosted page default color
                        value: () =>
                            data.config.loginPage.primaryColor || app.store.settings?.meta?.accentColor || "#16161a",
                        onchange: (color) => (data.config.loginPage.primaryColor = color),
                    }),
                ),
                t.div(
                    { className: "field-help" },
                    () => {
                        if (!data.config.loginPage.primaryColor) {
                            return "Defaults to the application accent color.";
                        }

                        return t.button(
                            {
                                type: "button",
                                className: "link-hint txt-sm",
                                onclick: () => (data.config.loginPage.primaryColor = ""),
                            },
                            "Reset to the application accent color",
                        );
                    },
                ),
            ),
            t.div(
                { className: "col-sm-12" },
                t.div(
                    { className: "oauth2-methods-field" },
                    t.div({ className: "oauth2-methods-label" }, "Sign-in methods"),
                    t.div(
                        { className: "oauth2-methods" },
                        loginMethods.map((method) => {
                            return t.span(
                                {
                                    className: () =>
                                        `label ${data.collection[method.configKey]?.enabled ? "success" : ""}`,
                                },
                                method.label,
                                () => (data.collection[method.configKey]?.enabled ? "" : " (disabled)"),
                            );
                        }),
                    ),
                ),
                t.div(
                    { className: "field-help" },
                    "The hosted login page offers the auth methods enabled in this collection options",
                    () => (data.collection.mfa?.enabled ? " (MFA requires 2 different methods)." : "."),
                ),
            ),
            signingKeysTable(),
        ),
    );
}
