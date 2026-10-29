import { DASHBOARD_CLIENT_ID } from "@/auth/dashboardOAuth2";
import {
    OAUTH2_CLIENTS_COLLECTION,
    oauth2AllowedScopes,
    oauth2AuthCollections,
    oauth2URIsInput,
} from "@/settings/oauth2/oauth2Utils";
import { webhookActiveLabel } from "@/webhooks/webhookSubscriptionsList";
import { WEBHOOK_SCOPE_ALL, webhooksLoadClients, webhookTopicChips } from "@/webhooks/webhooksUtils";
import { openWebhookUpsertModal } from "@/webhooks/webhookUpsertModal";
import { oauth2ClientApiKeysTab } from "./oauth2ClientApiKeys";
import { oauth2ClientQuickstartTab } from "./oauth2ClientQuickstart";
import { openOAuth2SecretModal } from "./oauth2SecretModal";

const TAB_SETTINGS = "settings";
const TAB_QUICKSTART = "quickstart";
const TAB_WEBHOOKS = "webhooks";
const TAB_API_KEYS = "apiKeys";

/**
 * Opens the OAuth2 client create/edit panel.
 *
 * @param {Object} [client]          The client record to edit (leave empty to create).
 * @param {Object} [settings]
 * @param {string} [settings.collectionId] Default issuer collection on create.
 * @param {function} [settings.onsave]     function(client, isNew) {}
 * @param {function} [settings.ondelete]   function(client) {}
 */
export function openOAuth2ClientUpsertModal(client = null, settings = {}) {
    app.store.errors = null;

    const modal = oauth2ClientUpsertModal(client, settings);

    document.body.appendChild(modal);

    app.modals.open(modal);
}

function newClientData(collectionId) {
    return {
        name: "",
        clientId: app.utils.randomString(24, "abcdefghijklmnopqrstuvwxyz0123456789"),
        type: "public",
        collectionRef: collectionId || "",
        redirectURIs: [""],
        postLogoutRedirectURIs: [],
        scopes: ["openid", "email", "profile"],
        firstParty: false,
        logo: "",
        disabled: false,
    };
}

function normalizeClient(raw) {
    const c = JSON.parse(JSON.stringify(raw || {}));
    c.redirectURIs = Array.isArray(c.redirectURIs) ? c.redirectURIs : [];
    c.postLogoutRedirectURIs = Array.isArray(c.postLogoutRedirectURIs) ? c.postLogoutRedirectURIs : [];
    c.scopes = Array.isArray(c.scopes) ? c.scopes : [];
    return c;
}

const editableKeys = [
    "name",
    "clientId",
    "type",
    "collectionRef",
    "redirectURIs",
    "postLogoutRedirectURIs",
    "scopes",
    "firstParty",
    "logo",
    "disabled",
];

function serialize(client) {
    const result = {};
    for (const key of editableKeys) {
        result[key] = client[key];
    }
    result.redirectURIs = (result.redirectURIs || []).map((u) => u.trim()).filter(Boolean);
    result.postLogoutRedirectURIs = (result.postLogoutRedirectURIs || []).map((u) => u.trim()).filter(Boolean);
    return result;
}

function oauth2ClientUpsertModal(rawClient, settings) {
    const uniqueId = "oauth2_app_" + app.utils.randomString();

    let defaultCollectionId = settings.collectionId;
    if (
        !defaultCollectionId
        || app.store.collections.find((c) => c.id == defaultCollectionId)?.name == "_applicationInstallations"
    ) {
        defaultCollectionId = oauth2AuthCollections().find((c) => c.name != "_applicationInstallations")?.id;
    }

    const data = store({
        isSaving: false,
        isGeneratingSecret: false,
        activeTab: TAB_SETTINGS,
        webhooks: [],
        isLoadingWebhooks: false,
        original: normalizeClient(rawClient?.id ? rawClient : newClientData(defaultCollectionId)),
        client: normalizeClient(rawClient?.id ? rawClient : newClientData(defaultCollectionId)),
        get isNew() {
            return !data.original.id;
        },
        // the built-in protected dashboard client (only the name, logo and scopes could be changed)
        get isDashboard() {
            return data.original.clientId == DASHBOARD_CLIENT_ID;
        },
        // the application installations managed clients are read-only
        // (they are changed only through their installation)
        get isManaged() {
            return !!data.original.applicationInstallationRef;
        },
        get hasChanges() {
            return JSON.stringify(serialize(data.original)) != JSON.stringify(serialize(data.client));
        },
        get collection() {
            return app.store.collections.find((c) => c.id == data.client.collectionRef);
        },
        get isSuperusersIssuer() {
            return data.collection?.name == "_superusers";
        },
        get allowedScopes() {
            return oauth2AllowedScopes(data.collection);
        },
        get isConfidential() {
            return data.client.type == "confidential";
        },
        get needsSecret() {
            return !data.isNew && data.isConfidential && !data.original.hasClientSecret;
        },
        // the API keys are available only for the regular clients (see core.APIKey)
        get hasApiKeys() {
            return !data.isNew && !data.isDashboard && !data.isManaged;
        },
    });

    function changeIssuer(collectionId) {
        data.client.collectionRef = collectionId;

        // keep only the scopes supported by the new issuer
        const allowed = oauth2AllowedScopes(data.collection);
        data.client.scopes = data.client.scopes.filter((s) => allowed.includes(s));

        if (data.isSuperusersIssuer) {
            data.client.firstParty = true;
        }
    }

    function toggleScope(scope, checked) {
        const scopes = data.client.scopes.filter((s) => s != scope);
        if (checked) {
            scopes.push(scope);
        }
        // keep the predefined order
        data.client.scopes = data.allowedScopes.filter((s) => scopes.includes(s));
    }

    async function save() {
        if (data.isSaving) {
            return;
        }

        data.isSaving = true;

        const wasNew = data.isNew;
        const collection = app.pb.collection(OAUTH2_CLIENTS_COLLECTION);

        try {
            const payload = serialize(data.client);

            let saved;
            if (wasNew) {
                saved = await collection.create(payload);
            } else {
                saved = await collection.update(data.original.id, payload);
            }

            data.original = normalizeClient(saved);
            data.client = normalizeClient(saved);

            app.store.errors = null;

            settings.onsave?.(saved, wasNew);

            app.toasts.success(
                wasNew
                    ? `Successfully created OAuth2 client "${saved.name}".`
                    : `Successfully updated OAuth2 client "${saved.name}".`,
            );

            // confidential clients are created without a secret -> generate one right away
            if (wasNew && saved.type == "confidential" && !saved.hasClientSecret) {
                data.isSaving = false;
                await generateSecret(false);
                return;
            }
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        data.isSaving = false;
    }

    async function generateSecret(withConfirm = true) {
        if (data.isGeneratingSecret || data.isNew) {
            return;
        }

        if (withConfirm && data.original.hasClientSecret) {
            app.modals.confirm(
                t.div(
                    null,
                    t.p(null, "Do you really want to rotate the client secret?"),
                    t.p(
                        { className: "txt-hint txt-sm" },
                        "The current secret will stop working immediately and the client will have to be reconfigured with the new one.",
                    ),
                ),
                () => generateSecret(false),
                null,
                { yesButton: "Rotate secret" },
            );
            return;
        }

        data.isGeneratingSecret = true;

        try {
            const result = await app.pb.send(
                `/api/oauth2/clients/${encodeURIComponent(data.original.id)}/rotate-secret`,
                {
                    method: "POST",
                },
            );

            data.original.hasClientSecret = true;
            data.client.hasClientSecret = true;

            settings.onsave?.(data.original, false);

            openOAuth2SecretModal(result);
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        data.isGeneratingSecret = false;
    }

    function deleteClient() {
        app.modals.confirm(
            t.div(
                null,
                t.p(null, "Do you really want to delete OAuth2 client ", t.strong(null, data.original.name), "?"),
                t.p(
                    { className: "txt-hint txt-sm" },
                    "All its auth sessions and remembered consents will be deleted and the issued tokens will stop working.",
                ),
            ),
            async () => {
                try {
                    await app.pb.collection(OAUTH2_CLIENTS_COLLECTION).delete(data.original.id);
                    app.toasts.success(`Successfully deleted app "${data.original.name}".`);
                    settings.ondelete?.(data.original);
                    app.modals.close(modal, true);
                } catch (err) {
                    app.checkApiError(err);
                }
            },
            null,
            { yesButton: "Delete" },
        );
    }

    // --- tabs content

    function settingsTab() {
        return t.form(
            {
                id: uniqueId + "_form",
                className: "grid oauth2-app-form",
                inert: () => data.isSaving || data.isManaged,
                onsubmit: (e) => {
                    e.preventDefault();
                    save();
                },
            },
            () => {
                if (!data.isManaged) {
                    return;
                }

                return t.div(
                    { className: "col-sm-12" },
                    t.div(
                        { className: "alert info oauth2-managed-client-alert" },
                        t.i({ className: "ri-lock-line", ariaHidden: true }),
                        t.div(
                            { className: "content" },
                            t.strong(null, "Managed by an application installation (read-only)"),
                            " — the Admin API access credentials of an installed application (",
                            t.code(null, "client_credentials"),
                            " grant only). Manage its permissions, secret and uninstall it from ",
                            t.a(
                                { href: "#/applications", onclick: () => app.modals.close(modal, true) },
                                "Applications",
                            ),
                            ".",
                        ),
                    ),
                );
            },
            () => {
                if (data.isNew) {
                    return;
                }

                return t.div(
                    { className: "col-sm-12" },
                    t.div(
                        { className: "field-help oauth2-client-grant-types" },
                        "Grant types: ",
                        (data.original.grantTypes || []).map((g) => t.span({ className: "label sm" }, g)),
                    ),
                );
            },
            () => {
                if (!data.isDashboard) {
                    return;
                }

                return t.div(
                    { className: "col-sm-12" },
                    t.div(
                        { className: "alert info" },
                        t.i({ className: "ri-lock-line", ariaHidden: true }),
                        t.div(
                            { className: "content" },
                            t.strong(null, "Built-in dashboard client (read-only)"),
                            " — the superusers dashboard signs in with this first-party public PKCE client. ",
                            "It can't be deleted or disabled and its redirect URI is always the same-origin dashboard URL ",
                            t.code(null, window.location.origin + window.location.pathname),
                            ".",
                        ),
                    ),
                );
            },
            t.div(
                { className: "col-sm-12" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".name" }, "Name"),
                    t.input({
                        type: "text",
                        id: uniqueId + ".name",
                        name: "name",
                        required: true,
                        maxLength: 255,
                        placeholder: "My OAuth2 client",
                        value: () => data.client.name || "",
                        oninput: (e) => (data.client.name = e.target.value),
                    }),
                ),
            ),
            t.div(
                { className: "col-sm-6" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".clientId" }, "Client ID"),
                    t.input({
                        type: "text",
                        id: uniqueId + ".clientId",
                        name: "clientId",
                        required: true,
                        spellcheck: false,
                        readOnly: () => !data.isNew,
                        value: () => data.client.clientId || "",
                        oninput: (e) => (data.client.clientId = e.target.value),
                    }),
                ),
                () => {
                    if (data.isNew) {
                        return t.div(
                            { className: "field-help" },
                            "Letters, digits, _, - and . (can't be changed later).",
                        );
                    }
                },
            ),
            t.div(
                { className: "col-sm-6" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".type" }, "Type"),
                    app.components.select({
                        id: uniqueId + ".type",
                        name: "type",
                        required: true,
                        disabled: () => data.isDashboard,
                        options: [
                            { value: "public", label: "Public (SPA, mobile, CLI - PKCE only)" },
                            { value: "confidential", label: "Confidential (server-side, with secret)" },
                        ],
                        value: () => data.client.type,
                        onchange: (opts) => (data.client.type = opts?.[0]?.value || "public"),
                    }),
                ),
            ),
            t.div(
                { className: "col-sm-6" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".collectionRef" }, "Issuer (auth collection)"),
                    app.components.select({
                        id: uniqueId + ".collectionRef",
                        name: "collectionRef",
                        required: true,
                        disabled: () => !data.isNew,
                        options: () =>
                            // note: the _superusers issuer clients are Owner only and the
                            // _applicationInstallations issuer has only managed clients
                            oauth2AuthCollections()
                                .filter((c) => c.name != "_superusers" || app.perms.isOwner())
                                .filter((c) => c.name != "_applicationInstallations" || !data.isNew)
                                .map((c) => ({
                                    value: c.id,
                                    label: c.name,
                                })),
                        value: () => data.client.collectionRef,
                        onchange: (opts) => changeIssuer(opts?.[0]?.value || ""),
                    }),
                ),
            ),
            t.div(
                { className: "col-sm-6" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".logo" }, "Logo URL"),
                    t.input({
                        type: "url",
                        id: uniqueId + ".logo",
                        name: "logo",
                        placeholder: "https://example.com/logo.png",
                        value: () => data.client.logo || "",
                        oninput: (e) => (data.client.logo = e.target.value),
                    }),
                ),
            ),
            () => {
                if (!data.isDashboard) {
                    return;
                }

                return t.div(
                    { className: "col-sm-12" },
                    t.div(
                        { className: "field-help" },
                        "Redirect and post logout URI: the same-origin dashboard URL (validated by the server, not editable).",
                    ),
                );
            },
            t.div(
                { className: "col-sm-12", hidden: () => data.isDashboard },
                oauth2URIsInput({
                    name: "redirectURIs",
                    label: "Redirect URIs",
                    required: true,
                    addLabel: "Add redirect URI",
                    placeholder: "https://example.com/auth/callback",
                    value: () => data.client.redirectURIs,
                    onchange: (list) => (data.client.redirectURIs = list),
                }),
            ),
            t.div(
                { className: "col-sm-12", hidden: () => data.isDashboard },
                oauth2URIsInput({
                    name: "postLogoutRedirectURIs",
                    label: "Post logout redirect URIs",
                    addLabel: "Add post logout URI",
                    placeholder: "https://example.com",
                    value: () => data.client.postLogoutRedirectURIs,
                    onchange: (list) => (data.client.postLogoutRedirectURIs = list),
                }),
            ),
            t.div(
                { className: "col-sm-12" },
                t.div(
                    { className: "oauth2-scopes-field" },
                    t.div({ className: "oauth2-methods-label" }, "Allowed scopes"),
                    t.div(
                        { className: "oauth2-scopes" },
                        () => {
                            return data.allowedScopes.map((scope) => {
                                const id = uniqueId + ".scope." + scope;
                                return t.div(
                                    { className: "field oauth2-scope" },
                                    t.input({
                                        type: "checkbox",
                                        id: id,
                                        checked: () => data.client.scopes.includes(scope),
                                        onchange: (e) => toggleScope(scope, e.target.checked),
                                    }),
                                    t.label({ htmlFor: id }, t.span({ className: "txt-code" }, scope)),
                                );
                            });
                        },
                    ),
                ),
                () => {
                    const errs = app.store.errors?.scopes;
                    if (app.utils.isEmpty(errs)) {
                        return;
                    }
                    const msg = errs.message || Object.values(errs).map((e) => e?.message).filter(Boolean).join(" ");
                    return t.div({ className: "field-help error" }, msg);
                },
                t.div(
                    { className: "field-help" },
                    "The client can request only the checked scopes. The custom scopes are defined in the issuer collection options.",
                ),
            ),
            t.div(
                { className: "col-sm-6" },
                t.div(
                    { className: "field" },
                    t.input({
                        type: "checkbox",
                        id: uniqueId + ".firstParty",
                        name: "firstParty",
                        className: "switch",
                        // note: the first-party clients (no consent screen) are Owner only
                        disabled: () => data.isSuperusersIssuer || data.isDashboard || !app.perms.isOwner(),
                        checked: () => !!data.client.firstParty,
                        onchange: (e) => (data.client.firstParty = e.target.checked),
                    }),
                    t.label(
                        { htmlFor: uniqueId + ".firstParty" },
                        "First-party",
                        t.i({
                            className: "ri-information-line link-hint",
                            ariaDescription: app.attrs.tooltip(
                                "First-party (trusted) clients skip the consent screen. Only first-party clients are allowed for the _superusers (staff) issuer.",
                            ),
                        }),
                    ),
                ),
            ),
            t.div(
                { className: "col-sm-6" },
                t.div(
                    { className: "field" },
                    t.input({
                        type: "checkbox",
                        id: uniqueId + ".disabled",
                        name: "disabled",
                        className: "switch",
                        disabled: () => data.isDashboard,
                        checked: () => !!data.client.disabled,
                        onchange: (e) => (data.client.disabled = e.target.checked),
                    }),
                    t.label(
                        { htmlFor: uniqueId + ".disabled" },
                        "Disabled",
                        t.i({
                            className: "ri-information-line link-hint",
                            ariaDescription: app.attrs.tooltip(
                                "The tokens issued to a disabled client stop working immediately on all APIs.",
                            ),
                        }),
                    ),
                ),
            ),
            // client secret
            () => {
                if (!data.isConfidential || data.isManaged) {
                    return;
                }

                return t.div(
                    { className: "col-sm-12" },
                    t.div(
                        { className: () => `oauth2-secret-box ${data.needsSecret ? "warning" : ""}` },
                        t.i({ className: "ri-lock-password-line", ariaHidden: true }),
                        t.div(
                            { className: "content" },
                            t.strong(null, "Client secret"),
                            t.div({ className: "txt-hint txt-sm" }, () => {
                                if (data.isNew) {
                                    return "A secret will be generated and shown once after the client is created.";
                                }
                                if (!data.original.hasClientSecret) {
                                    return "The client has no secret and can't be used until one is generated.";
                                }
                                return "A secret is set. Only its hash is stored - rotate it if it was lost or leaked.";
                            }),
                        ),
                        () => {
                            if (data.isNew) {
                                return;
                            }

                            return t.button(
                                {
                                    type: "button",
                                    className: () =>
                                        `btn sm ${data.original.hasClientSecret ? "secondary" : ""} ${
                                            data.isGeneratingSecret ? "loading" : ""
                                        }`,
                                    disabled: () => data.isGeneratingSecret || data.original.type != "confidential",
                                    ariaDescription: app.attrs.tooltip(() =>
                                        data.original.type != "confidential" ? "Save the type change first" : ""
                                    ),
                                    onclick: () => generateSecret(true),
                                },
                                t.i({ className: "ri-key-line", ariaHidden: true }),
                                t.span(
                                    { className: "txt" },
                                    () => (data.original.hasClientSecret ? "Rotate secret" : "Generate secret"),
                                ),
                            );
                        },
                    ),
                );
            },
        );
    }

    async function loadWebhooks() {
        if (data.isNew) {
            return;
        }

        data.isLoadingWebhooks = true;

        try {
            const [webhooks] = await Promise.all([
                app.pb.collection("_webhooks").getFullList({
                    filter: app.pb.filter("client = {:client}", { client: data.original.id }),
                    sort: "name,created",
                    expand: "client",
                    requestKey: "oauth2_app_webhooks",
                }),
                // refresh the cached OAuth2 clients list used by the subscription panel
                webhooksLoadClients(true),
            ]);
            data.webhooks = webhooks;
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        data.isLoadingWebhooks = false;
    }

    function openWebhook(webhook = null) {
        openWebhookUpsertModal(webhook, {
            clientId: data.original.id,
            clientName: data.original.name,
            onsave: () => loadWebhooks(),
            ondelete: () => loadWebhooks(),
        });
    }

    function webhooksTab() {
        const webhookScopes = () =>
            (data.original.scopes || []).filter((s) => s == WEBHOOK_SCOPE_ALL || s.endsWith(":read"));

        return t.div(
            {
                className: "oauth2-app-webhooks",
                onmount: () => loadWebhooks(),
            },
            t.p(
                { className: "txt-hint" },
                "Webhook subscriptions owned by this app. Their topics are limited by the app scopes - ",
                t.code(null, "{collection}:read"),
                " for the collection topics (or ",
                t.code(null, "{namespace}:read"),
                " for the custom ones) and ",
                t.code(null, WEBHOOK_SCOPE_ALL),
                " for any topic. The subscriptions are deleted together with the app.",
            ),
            () => {
                const scopes = webhookScopes();
                if (!scopes.length) {
                    return t.div(
                        { className: "alert warning" },
                        t.i({ className: "ri-error-warning-line", ariaHidden: true }),
                        t.div(
                            { className: "content" },
                            "The OAuth2 client has no webhook scopes yet. Add for example ",
                            t.code(null, "posts:read"),
                            " or ",
                            t.code(null, WEBHOOK_SCOPE_ALL),
                            " to the issuer collection custom scopes (",
                            t.a({ href: "#/settings/oauth2" }, "OAuth2 / OIDC settings"),
                            ") and allow it in the client Settings tab.",
                        ),
                    );
                }
                return t.div(
                    { className: "inline-flex flex-wrap gap-5 m-b-sm" },
                    t.span({ className: "txt-hint txt-sm" }, "Webhook scopes:"),
                    scopes.map((s) => t.span({ className: "label sm" }, s)),
                );
            },
            t.div(
                { className: "list oauth2-app-webhooks-list" },
                () => {
                    if (data.isLoadingWebhooks && !data.webhooks.length) {
                        return t.div({ className: "list-item" }, t.div({ className: "skeleton-loader" }));
                    }

                    if (!data.webhooks.length) {
                        return t.div(
                            { className: "list-item" },
                            t.div({ className: "content block txt-hint txt-center" }, "No webhook subscriptions yet."),
                        );
                    }

                    return data.webhooks.map((w) =>
                        t.div(
                            {
                                className: `list-item handle ${w.active ? "" : "faded"}`,
                                tabIndex: 0,
                                onclick: () => openWebhook(w),
                                onkeydown: (e) => e.key == "Enter" && openWebhook(w),
                            },
                            t.i({ className: "ri-webhook-line txt-hint", ariaHidden: true }),
                            t.div(
                                { className: "content" },
                                t.span({ className: "txt-bold txt-ellipsis" }, w.name),
                                t.small({ className: "txt-hint txt-code txt-ellipsis" }, w.uri),
                                webhookTopicChips(w.topics, w.topicNames, 5),
                            ),
                            webhookActiveLabel(w),
                            t.i({ className: "ri-arrow-right-s-line txt-hint", ariaHidden: true }),
                        )
                    );
                },
            ),
            t.div(
                { className: "flex m-t-sm" },
                t.button(
                    { type: "button", className: "btn sm secondary", onclick: () => openWebhook() },
                    t.i({ className: "ri-add-line", ariaHidden: true }),
                    t.span({ className: "txt" }, "New subscription"),
                ),
                t.a(
                    { href: "#/webhooks", className: "btn sm transparent secondary m-l-auto" },
                    t.span({ className: "txt" }, "All webhooks"),
                    t.i({ className: "ri-arrow-right-line", ariaHidden: true }),
                ),
            ),
        );
    }

    function tabButton(tab, label, disabled = false, tooltip = "") {
        return t.button(
            {
                type: "button",
                disabled: () => disabled || data.isSaving || (tab != TAB_SETTINGS && data.isNew),
                className: () => `tab-item ${data.activeTab == tab ? "active" : ""}`,
                ariaDescription: tooltip ? app.attrs.tooltip(tooltip) : undefined,
                onclick: () => (data.activeTab = tab),
            },
            t.span({ className: "txt" }, label),
        );
    }

    const modal = t.div(
        {
            pbEvent: "oauth2ClientUpsertModal",
            className: "modal oauth2-app-upsert-modal",
            onbeforeclose: (el, forceClosed) => {
                if (forceClosed) {
                    return;
                }

                if (data.isSaving || data.isGeneratingSecret) {
                    return false;
                }

                if (!data.hasChanges) {
                    return;
                }

                return new Promise((r) => {
                    app.modals.confirm(
                        "You have unsaved changes. Do you really want to discard them?",
                        () => r(true),
                        () => r(false),
                        { yesButton: "Yes, discard" },
                    );
                });
            },
            onafterclose: (el) => {
                app.store.errors = null;
                el?.remove();
            },
        },
        t.header(
            { className: "modal-header isolated" },
            t.div(
                { className: "grid" },
                t.div(
                    { className: "col-12 flex" },
                    () => {
                        if (data.original.logo) {
                            return t.img({
                                className: "oauth2-app-logo",
                                src: data.original.logo,
                                alt: "",
                                loading: "lazy",
                            });
                        }
                    },
                    t.h6(
                        { className: "modal-title" },
                        () => (data.isNew
                            ? "New OAuth2 client"
                            : t.span(null, "Edit OAuth2 client ", t.strong(null, data.original.name))),
                    ),
                    t.div({ className: "flex-fill" }),
                    () => {
                        if (data.isNew || data.isDashboard || data.isManaged) {
                            return;
                        }

                        return t.button(
                            {
                                type: "button",
                                className: "btn sm circle transparent danger",
                                ariaLabel: app.attrs.tooltip("Delete OAuth2 client", "left"),
                                onclick: deleteClient,
                            },
                            t.i({ className: "ri-delete-bin-7-line", ariaHidden: true }),
                        );
                    },
                ),
                t.div(
                    { className: "col-12" },
                    t.nav(
                        { className: "tabs-header equal-width" },
                        tabButton(TAB_SETTINGS, "Settings"),
                        tabButton(TAB_QUICKSTART, "Quickstart"),
                        tabButton(TAB_WEBHOOKS, "Webhooks"),
                        () => {
                            if (data.hasApiKeys) {
                                return tabButton(TAB_API_KEYS, "API keys");
                            }
                        },
                    ),
                ),
            ),
        ),
        t.div(
            { className: "modal-content" },
            () => {
                if (data.activeTab == TAB_QUICKSTART && !data.isNew) {
                    return oauth2ClientQuickstartTab(data);
                }

                if (data.activeTab == TAB_WEBHOOKS && !data.isNew) {
                    return webhooksTab();
                }

                if (data.activeTab == TAB_API_KEYS && data.hasApiKeys) {
                    return oauth2ClientApiKeysTab(() => data.original);
                }

                return settingsTab();
            },
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
                t.span({ className: "txt" }, "Close"),
            ),
            t.button(
                {
                    "type": "submit",
                    "html-form": uniqueId + "_form",
                    "hidden": () => data.activeTab != TAB_SETTINGS || data.isManaged,
                    "className": () => `btn expanded-lg ${data.isSaving ? "loading" : ""}`,
                    "disabled": () => data.isSaving || (!data.isNew && !data.hasChanges),
                },
                t.span({ className: "txt" }, () => (data.isNew ? "Create OAuth2 client" : "Save changes")),
            ),
        ),
    );

    return modal;
}
