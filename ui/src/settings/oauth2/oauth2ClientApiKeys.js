import { permissionsCollectionsMatrix } from "@/auth/permissionsEditor";
import { actorHolds, normalizePermissions, permissionsSummary } from "@/auth/rolesUtils";
import { oauth2URIsInput } from "@/settings/oauth2/oauth2Utils";

// OAuth2 client API keys (Shopify Storefront API tokens model).
//
// An API key identifies the client (the channel), never a person:
//   - public keys (pb_pk_) are browser-safe and always visible (X-PB-Public-Key header or ?pk=)
//   - private keys (pb_sk_) are server-only and shown only once (X-PB-Private-Key + X-PB-Buyer-IP)
//
// The key permissions are only a ceiling of the regular collections actions (the collection rules
// and the bearer token permissions still apply) and therefore they are not limited by the actor permissions.

export const API_KEY_PUBLIC_HEADER = "X-PB-Public-Key";
export const API_KEY_PRIVATE_HEADER = "X-PB-Private-Key";
export const API_KEY_BUYER_IP_HEADER = "X-PB-Buyer-IP";

function apiKeysURL(clientId, keyId = "") {
    return `/api/oauth2/clients/${encodeURIComponent(clientId)}/api-keys`
        + (keyId ? "/" + encodeURIComponent(keyId) : "");
}

function canWrite() {
    return actorHolds("system", "oauth2_clients", "write");
}

function apiKeyStatus(key) {
    if (key.disabled) {
        return { label: "Disabled", className: "label sm" };
    }
    if (key.expired) {
        return { label: "Expired", className: "label sm warning" };
    }
    return { label: "Active", className: "label sm success" };
}

/**
 * Returns the OAuth2 client "API keys" tab content.
 *
 * @param  {function(): Object} getClient Getter of the (saved) OAuth2 client record.
 * @return {Element}
 */
export function oauth2ClientApiKeysTab(getClient) {
    const data = store({
        keys: [],
        isLoading: false,
        busyKeyId: "",
    });

    async function load() {
        const client = getClient();
        if (!client?.id) {
            return;
        }

        data.isLoading = true;

        try {
            data.keys = await app.pb.send(apiKeysURL(client.id), { requestKey: "oauth2_client_api_keys" });
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        data.isLoading = false;
    }

    async function update(key, body, successMessage) {
        data.busyKeyId = key.id;

        try {
            await app.pb.send(apiKeysURL(getClient().id, key.id), { method: "PATCH", body });
            app.toasts.success(successMessage);
            await load();
        } catch (err) {
            app.checkApiError(err);
        }

        data.busyKeyId = "";
    }

    function rotate(key) {
        app.modals.confirm(
            t.div(
                null,
                t.p(null, "Do you really want to rotate API key ", t.strong(null, key.name), "?"),
                t.p(
                    { className: "txt-hint txt-sm" },
                    "The current key will stop working immediately and the storefront will have to be reconfigured with the new one.",
                ),
            ),
            async () => {
                data.busyKeyId = key.id;
                try {
                    const result = await app.pb.send(apiKeysURL(getClient().id, key.id) + "/rotate-secret", {
                        method: "POST",
                    });
                    openApiKeyTokenModal(result);
                    await load();
                } catch (err) {
                    app.checkApiError(err);
                }
                data.busyKeyId = "";
            },
            null,
            { yesButton: "Rotate key" },
        );
    }

    function remove(key) {
        app.modals.confirm(
            t.div(
                null,
                t.p(null, "Do you really want to delete API key ", t.strong(null, key.name), "?"),
                t.p({ className: "txt-hint txt-sm" }, "The requests with this key will be rejected immediately."),
            ),
            async () => {
                data.busyKeyId = key.id;
                try {
                    await app.pb.send(apiKeysURL(getClient().id, key.id), { method: "DELETE" });
                    app.toasts.success(`Successfully deleted API key "${key.name}".`);
                    await load();
                } catch (err) {
                    app.checkApiError(err);
                }
                data.busyKeyId = "";
            },
            null,
            { yesButton: "Delete" },
        );
    }

    function keyRow(key) {
        const status = apiKeyStatus(key);
        const summary = permissionsSummary(key.permissions);

        return t.div(
            {
                className: () =>
                    `list-item oauth2-api-key ${key.disabled || key.expired ? "faded" : ""} ${
                        data.busyKeyId == key.id ? "loading" : ""
                    }`,
                "html-data-key-id": key.id,
                "html-data-kind": key.kind,
            },
            t.i({
                className: key.kind == "private" ? "ri-lock-2-line txt-hint" : "ri-global-line txt-hint",
                ariaHidden: true,
            }),
            t.div(
                { className: "content" },
                t.div(
                    { className: "inline-flex flex-wrap gap-5" },
                    t.span({ className: "txt-bold txt-ellipsis oauth2-api-key-name" }, key.name),
                    t.span({ className: "label sm oauth2-api-key-kind" }, key.kind),
                    key.kind == "private"
                        ? t.span(
                            { className: "label sm" },
                            key.buyerContext == "none" ? "no buyer context" : "buyer IP required",
                        )
                        : null,
                    t.span({ className: status.className + " oauth2-api-key-status" }, status.label),
                ),
                key.kind == "public"
                    ? t.div(
                        { className: "inline-flex gap-5" },
                        t.code({ className: "txt-sm txt-ellipsis oauth2-api-key-token" }, key.token),
                        app.components.copyButton(key.token),
                    )
                    : t.code({ className: "txt-sm oauth2-api-key-prefix" }, key.tokenPrefix + "…"),
                t.small(
                    { className: "txt-hint oauth2-api-key-permissions" },
                    summary.length ? summary.join("; ") : "No collections access",
                ),
                key.kind == "public" && key.allowedOrigins?.length
                    ? t.small({ className: "txt-hint" }, "Origins: " + key.allowedOrigins.join(", "))
                    : null,
                t.small(
                    { className: "txt-hint" },
                    "Last used: ",
                    key.lastUsedAt ? app.components.formattedDate({ value: key.lastUsedAt, short: true }) : "never",
                ),
            ),
            () => {
                if (!canWrite()) {
                    return;
                }

                return t.div(
                    { className: "inline-flex gap-5 oauth2-api-key-actions" },
                    t.button(
                        {
                            type: "button",
                            className: "btn sm transparent secondary oauth2-api-key-toggle",
                            disabled: () => data.busyKeyId == key.id,
                            onclick: () =>
                                update(
                                    key,
                                    { disabled: !key.disabled },
                                    `Successfully ${key.disabled ? "enabled" : "disabled"} API key "${key.name}".`,
                                ),
                        },
                        t.span({ className: "txt" }, key.disabled ? "Enable" : "Disable"),
                    ),
                    t.button(
                        {
                            type: "button",
                            className: "btn sm transparent secondary oauth2-api-key-rotate",
                            disabled: () => data.busyKeyId == key.id,
                            onclick: () => rotate(key),
                        },
                        t.span({ className: "txt" }, "Rotate"),
                    ),
                    t.button(
                        {
                            type: "button",
                            className: "btn sm circle transparent danger oauth2-api-key-delete",
                            ariaLabel: app.attrs.tooltip("Delete API key", "left"),
                            disabled: () => data.busyKeyId == key.id,
                            onclick: () => remove(key),
                        },
                        t.i({ className: "ri-delete-bin-7-line", ariaHidden: true }),
                    ),
                );
            },
        );
    }

    return t.div(
        {
            className: "oauth2-client-api-keys",
            onmount: () => load(),
        },
        t.p(
            { className: "txt-hint" },
            "API keys identify this client (the storefront/channel), never a person. Public keys are browser-safe (",
            t.code(null, API_KEY_PUBLIC_HEADER),
            " header or ",
            t.code(null, "?pk="),
            "); private keys are server-only (",
            t.code(null, API_KEY_PRIVATE_HEADER),
            " + the end-user ",
            t.code(null, API_KEY_BUYER_IP_HEADER),
            "). The key permissions are a ceiling - the collection API rules always still apply and a key never grants system access. ",
            "The records API requests without a key or an access token are rejected.",
        ),
        t.div(
            { className: "list oauth2-api-keys-list" },
            () => {
                if (data.isLoading && !data.keys.length) {
                    return t.div({ className: "list-item" }, t.div({ className: "skeleton-loader" }));
                }

                if (!data.keys.length) {
                    return t.div(
                        { className: "list-item" },
                        t.div({ className: "content block txt-hint txt-center" }, "No API keys yet."),
                    );
                }

                return data.keys.map((key) => keyRow(key));
            },
        ),
        () => {
            if (!canWrite()) {
                return;
            }

            return t.div(
                { className: "flex m-t-sm" },
                t.button(
                    {
                        type: "button",
                        className: "btn sm secondary oauth2-api-key-new",
                        onclick: () => openApiKeyCreateModal(getClient(), { onsave: () => load() }),
                    },
                    t.i({ className: "ri-add-line", ariaHidden: true }),
                    t.span({ className: "txt" }, "New API key"),
                ),
            );
        },
    );
}

/**
 * Opens the API key create modal.
 *
 * @param {Object}   client            The OAuth2 client record.
 * @param {Object}   [settings]
 * @param {function} [settings.onsave] function(result) {}
 */
export function openApiKeyCreateModal(client, settings = {}) {
    app.store.errors = null;

    const uniqueId = "api_key_" + app.utils.randomString();

    const data = store({
        isSaving: false,
        key: {
            name: "",
            kind: "public",
            buyerContext: "required",
            allowedOrigins: [],
            permissions: { collections: { "*": ["list", "view"] }, system: {} },
        },
    });

    async function save() {
        if (data.isSaving) {
            return;
        }

        data.isSaving = true;

        const isPrivate = data.key.kind == "private";

        const body = {
            name: data.key.name,
            kind: data.key.kind,
            buyerContext: isPrivate ? data.key.buyerContext : "",
            allowedOrigins: isPrivate ? [] : data.key.allowedOrigins.map((o) => o.trim()).filter(Boolean),
            permissions: { collections: normalizePermissions(data.key.permissions).collections },
        };

        try {
            const result = await app.pb.send(apiKeysURL(client.id), { method: "POST", body });

            app.store.errors = null;
            app.toasts.success(`Successfully created API key "${result.apiKey.name}".`);
            settings.onsave?.(result);
            app.modals.close(modal, true);

            // the private keys are shown only once
            if (isPrivate) {
                openApiKeyTokenModal(result);
            }
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        data.isSaving = false;
    }

    const modal = t.div(
        {
            pbEvent: "apiKeyCreateModal",
            className: "modal oauth2-api-key-create-modal",
            onbeforeclose: () => {
                if (data.isSaving) {
                    return false;
                }
            },
            onafterclose: (el) => {
                app.store.errors = null;
                el?.remove();
            },
        },
        t.header(
            { className: "modal-header" },
            t.h6({ className: "modal-title" }, "New API key for ", t.strong(null, client.name)),
        ),
        t.div(
            { className: "modal-content" },
            t.form(
                {
                    id: uniqueId + "_form",
                    className: "grid",
                    inert: () => data.isSaving,
                    onsubmit: (e) => {
                        e.preventDefault();
                        save();
                    },
                },
                t.div(
                    { className: "col-sm-6" },
                    t.div(
                        { className: "field" },
                        t.label({ htmlFor: uniqueId + ".name" }, "Name"),
                        t.input({
                            type: "text",
                            id: uniqueId + ".name",
                            name: "name",
                            required: true,
                            maxLength: 100,
                            placeholder: "Storefront",
                            value: () => data.key.name,
                            oninput: (e) => (data.key.name = e.target.value),
                        }),
                    ),
                ),
                t.div(
                    { className: "col-sm-6" },
                    t.div(
                        { className: "field" },
                        t.label({ htmlFor: uniqueId + ".kind" }, "Kind"),
                        app.components.select({
                            id: uniqueId + ".kind",
                            name: "kind",
                            className: "oauth2-api-key-kind-select",
                            required: true,
                            options: [
                                { value: "public", label: "Public (browser-safe)" },
                                { value: "private", label: "Private (server-only, shown once)" },
                            ],
                            value: () => data.key.kind,
                            onchange: (opts) => (data.key.kind = opts?.[0]?.value || "public"),
                        }),
                    ),
                ),
                () => {
                    if (data.key.kind != "private") {
                        return;
                    }

                    return t.div(
                        { className: "col-sm-12" },
                        t.div(
                            { className: "field" },
                            t.label({ htmlFor: uniqueId + ".buyerContext" }, "Buyer context"),
                            app.components.select({
                                id: uniqueId + ".buyerContext",
                                name: "buyerContext",
                                className: "oauth2-api-key-buyer-context-select",
                                required: true,
                                options: [
                                    {
                                        value: "required",
                                        label: `Required (the server forwards the end-user ${API_KEY_BUYER_IP_HEADER})`,
                                    },
                                    { value: "none", label: "None (background jobs without an end-user)" },
                                ],
                                value: () => data.key.buyerContext,
                                onchange: (opts) => (data.key.buyerContext = opts?.[0]?.value || "required"),
                            }),
                        ),
                    );
                },
                () => {
                    if (data.key.kind != "public") {
                        return;
                    }

                    return t.div(
                        { className: "col-sm-12" },
                        oauth2URIsInput({
                            name: "allowedOrigins",
                            label: "Allowed origins",
                            addLabel: "Add origin",
                            placeholder: "https://shop.example.com",
                            value: () => data.key.allowedOrigins,
                            onchange: (list) => (data.key.allowedOrigins = list),
                        }),
                        t.div(
                            { className: "field-help" },
                            "Exact scheme://host[:port] matches of the browser Origin header (empty = any origin). They are also CORS allowed.",
                        ),
                    );
                },
                t.div(
                    { className: "col-sm-12" },
                    t.div({ className: "oauth2-methods-label" }, "Collections permissions (ceiling)"),
                    permissionsCollectionsMatrix({
                        ceiling: true,
                        permissions: () => data.key.permissions,
                        onchange: (permissions) => (data.key.permissions = permissions),
                    }),
                    t.div(
                        { className: "field-help" },
                        "The requests with this key can perform only the checked actions. The collection API rules still apply.",
                    ),
                ),
            ),
        ),
        t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn transparent m-r-auto",
                    disabled: () => data.isSaving,
                    onclick: () => app.modals.close(modal),
                },
                t.span({ className: "txt" }, "Cancel"),
            ),
            t.button(
                {
                    "type": "submit",
                    "html-form": uniqueId + "_form",
                    "className": () => `btn expanded-lg oauth2-api-key-create-submit ${data.isSaving ? "loading" : ""}`,
                    "disabled": () => data.isSaving,
                },
                t.span({ className: "txt" }, "Create API key"),
            ),
        ),
    );

    document.body.appendChild(modal);

    app.modals.open(modal);
}

/**
 * Opens a "reveal once" modal with the created or rotated API key token.
 *
 * @param {Object} result        The create/rotate endpoint response.
 * @param {Object} result.apiKey
 * @param {string} result.token
 */
export function openApiKeyTokenModal(result) {
    const isPrivate = result.apiKey?.kind == "private";

    const data = store({
        acknowledged: !isPrivate,
    });

    const header = isPrivate ? API_KEY_PRIVATE_HEADER : API_KEY_PUBLIC_HEADER;

    const modal = t.div(
        {
            pbEvent: "apiKeyTokenModal",
            className: "modal popup oauth2-secret-modal oauth2-api-key-token-modal",
            onbeforeclose: (el, forceClosed) => {
                if (forceClosed || data.acknowledged) {
                    return;
                }

                return new Promise((r) => {
                    app.modals.confirm(
                        "The private API key will not be shown again. Did you copy it?",
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
        t.header({ className: "modal-header" }, t.h6(null, "API key ", t.strong(null, result.apiKey?.name))),
        t.div(
            { className: "modal-content" },
            isPrivate
                ? t.div(
                    { className: "alert warning" },
                    t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                    t.div(
                        { className: "content" },
                        "Copy the private key now and store it securely on your server - ",
                        t.strong(null, "it is shown only once"),
                        ". Only its hash is stored and any previous value no longer works. Never use it in a browser.",
                    ),
                )
                : null,
            t.div(
                { className: "oauth2-secret-rows" },
                t.div(
                    { className: "oauth2-secret-row" },
                    t.span({ className: "txt-hint txt-sm" }, header),
                    t.code({ className: "oauth2-secret-value oauth2-api-key-token-value" }, result.token),
                    app.components.copyButton(result.token),
                ),
            ),
        ),
        t.footer(
            { className: "modal-footer" },
            t.button(
                {
                    type: "button",
                    className: "btn expanded-lg m-l-auto oauth2-api-key-token-ack",
                    onclick: () => {
                        data.acknowledged = true;
                        app.modals.close(modal);
                    },
                },
                t.span({ className: "txt" }, isPrivate ? "I've copied the key" : "Close"),
            ),
        ),
    );

    document.body.appendChild(modal);

    app.modals.open(modal);
}
