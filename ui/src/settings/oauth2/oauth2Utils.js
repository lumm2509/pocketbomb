// Shared OAuth2 server (aka. OpenID Connect provider) dashboard helpers.

export const OAUTH2_BUILTIN_SCOPES = ["openid", "email", "profile", "offline_access"];

export const OAUTH2_CLIENTS_COLLECTION = "_oauth2Clients";
export const OAUTH2_CONSENTS_COLLECTION = "_oauth2Consents";
export const AUTH_SESSIONS_COLLECTION = "_authSessions";

/**
 * Returns the app base URL (Settings.Meta.AppURL) without trailing slash.
 *
 * @return {string}
 */
export function oauth2AppURL() {
    return (app.store.settings?.meta?.appURL || "").replace(/\/+$/, "");
}

/**
 * Returns the issuer identifier of the provided auth collection
 * (must match with the server core.OAuth2Issuer).
 *
 * @param  {Object|string} collectionOrName
 * @return {string}
 */
export function oauth2IssuerURL(collectionOrName) {
    const name = typeof collectionOrName == "string" ? collectionOrName : collectionOrName?.name;

    return oauth2AppURL() + "/oauth2/" + encodeURIComponent(name || "");
}

/**
 * @param  {Object|string} collectionOrName
 * @return {string}
 */
export function oauth2DiscoveryURL(collectionOrName) {
    return oauth2IssuerURL(collectionOrName) + "/.well-known/openid-configuration";
}

/**
 * Returns the builtin and custom scopes of the provided auth collection.
 *
 * @param  {Object} collection
 * @return {Array<string>}
 */
export function oauth2AllowedScopes(collection) {
    const result = OAUTH2_BUILTIN_SCOPES.slice();

    for (const scope of collection?.oauth2Server?.scopes || []) {
        if (scope && !result.includes(scope)) {
            result.push(scope);
        }
    }

    // the collection scopes of every regular collection (read_{name}, write_{name})
    for (const scope of oauth2CollectionScopes()) {
        if (!result.includes(scope)) {
            result.push(scope);
        }
    }

    return result;
}

/**
 * Returns the RBAC collection scopes of all regular collections
 * (read_{name} for list/view; write_{name} for create/update/delete).
 *
 * @return {Array<string>}
 */
export function oauth2CollectionScopes() {
    const result = [];

    for (const c of app.store.collections) {
        if (c.system) {
            continue;
        }

        result.push("read_" + c.name);

        if (c.type != "view") {
            result.push("write_" + c.name);
        }
    }

    return result;
}

/**
 * Returns the loaded auth collections (every auth collection is an issuer).
 *
 * @return {Array<Object>}
 */
export function oauth2AuthCollections() {
    return app.store.collections.filter((c) => c.type == "auth");
}

/**
 * Tags like input for a list of strings (e.g. scopes).
 *
 * New tags are added on Enter, comma or space (and on blur).
 *
 * @param  {Object} propsArg
 * @return {Element}
 */
export function oauth2TagsInput(propsArg = {}) {
    const props = store({
        id: undefined,
        name: undefined,
        placeholder: "Add and press Enter",
        value: [],
        onchange: (newList) => {},
    });

    const watchers = app.utils.extendStore(props, propsArg);

    const local = store({
        input: "",
    });

    function add(rawValue) {
        const values = app.utils.splitNonEmpty((rawValue || "").replaceAll(" ", ","), ",");
        if (!values.length) {
            return;
        }

        const list = (props.value || []).slice();
        for (const v of values) {
            if (!list.includes(v)) {
                list.push(v);
            }
        }

        local.input = "";
        props.onchange?.(list);
    }

    function remove(index) {
        const list = (props.value || []).slice();
        list.splice(index, 1);
        props.onchange?.(list);
    }

    return t.div(
        {
            className: "oauth2-tags-input",
            onunmount: () => {
                watchers.forEach((w) => w?.unwatch());
            },
        },
        () => {
            return (props.value || []).map((tag, i) => {
                return t.span(
                    { className: "label oauth2-tag" },
                    t.span({ className: "txt" }, tag),
                    t.button(
                        {
                            type: "button",
                            className: "oauth2-tag-remove",
                            ariaLabel: "Remove " + tag,
                            onclick: () => remove(i),
                        },
                        t.i({ className: "ri-close-line", ariaHidden: true }),
                    ),
                );
            });
        },
        t.input({
            type: "text",
            id: () => props.id,
            name: () => props.name,
            placeholder: () => props.placeholder,
            value: () => local.input,
            oninput: (e) => {
                local.input = e.target.value;
                if (/[,\s]$/.test(local.input)) {
                    add(local.input);
                }
            },
            onkeydown: (e) => {
                if (e.key == "Enter") {
                    e.preventDefault();
                    add(local.input);
                } else if (e.key == "Backspace" && !local.input && props.value?.length) {
                    remove(props.value.length - 1);
                }
            },
            onblur: () => add(local.input),
        }),
    );
}

/**
 * List of URI inputs with add/remove buttons.
 *
 * The errors are matched by the input name in the format "{name}.{index}".
 *
 * @param  {Object} propsArg
 * @return {Element}
 */
export function oauth2URIsInput(propsArg = {}) {
    const props = store({
        name: "",
        label: "",
        required: false,
        placeholder: "https://example.com/callback",
        addLabel: "Add URI",
        value: [],
        onchange: (newList) => {},
    });

    // internal rows state to avoid rerendering (and losing the input focus) on every keystroke
    const local = store({
        rows: [],
    });

    const watchers = app.utils.extendStore(props, propsArg);

    watchers.push(
        watch(
            () => JSON.stringify(props.value || []),
            (newHash) => {
                if (newHash != JSON.stringify(local.rows.map((r) => r.v))) {
                    local.rows = (props.value || []).map((v) => ({ v }));
                }
            },
        ),
    );

    function emit() {
        props.onchange?.(local.rows.map((r) => r.v));
    }

    function remove(index) {
        local.rows.splice(index, 1);
        emit();

        // the indexes are shifted
        app.utils.deleteByPath(app.store.errors, props.name);
    }

    function add() {
        local.rows.push({ v: "" });
        emit();
    }

    return t.div(
        {
            className: "oauth2-uris-input",
            onunmount: () => {
                watchers.forEach((w) => w?.unwatch());
            },
        },
        t.label(
            { className: () => `oauth2-uris-label ${props.required ? "required" : ""}` },
            () => props.label,
        ),
        () => {
            return local.rows.map((row, i) => {
                return t.div(
                    { className: "fields oauth2-uri-row" },
                    t.div(
                        { className: "field" },
                        t.input({
                            type: "text",
                            name: props.name + "." + i,
                            ariaLabel: props.label + " " + (i + 1),
                            placeholder: () => props.placeholder,
                            required: () => props.required && i == 0,
                            spellcheck: false,
                            value: () => row.v,
                            oninput: (e) => {
                                row.v = e.target.value;
                                emit();
                            },
                        }),
                    ),
                    t.div(
                        { className: "field addon" },
                        t.button(
                            {
                                type: "button",
                                className: "btn sm secondary transparent circle",
                                ariaLabel: app.attrs.tooltip("Remove"),
                                onclick: () => remove(i),
                            },
                            t.i({ className: "ri-close-line", ariaHidden: true }),
                        ),
                    ),
                );
            });
        },
        // generic (non-indexed) list error (e.g. "cannot be blank")
        () => {
            const msg = app.utils.getByPath(app.store.errors, props.name)?.message;
            if (msg) {
                return t.div({ className: "field-help error" }, msg);
            }
        },
        t.button(
            { type: "button", className: "btn sm secondary transparent", onclick: add },
            t.i({ className: "ri-add-line", ariaHidden: true }),
            t.span({ className: "txt" }, () => props.addLabel),
        ),
    );
}
