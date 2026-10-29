// Shared helpers of the OAuth2 server (aka. OpenID Connect provider) API preview docs.

/**
 * Returns the issuer identifier URL of the provided auth collection.
 *
 * @param  {Object} collection
 * @return {string}
 */
export function docsIssuerURL(collection) {
    return app.utils.getApiExampleURL() + "/oauth2/" + encodeURIComponent(collection.name);
}

/**
 * Returns an example first-party/third-party client id of the provided collection.
 *
 * @param  {Object} collection
 * @return {string}
 */
export function docsClientId(collection) {
    return collection.name == "_superusers" ? "pb_dashboard" : "YOUR_CLIENT_ID";
}

/**
 * @param  {Array<Object>} tabs
 * @return {Element}
 */
export function docsCodeTabs(tabs) {
    return app.components.codeBlockTabs({
        className: "sdk-examples m-t-sm",
        historyKey: "pbLastOAuth2Example",
        tabs: tabs,
    });
}

/**
 * @param  {string} method
 * @param  {string} path
 * @param  {string|Element} [extra]
 * @return {Element}
 */
export function docsApiDetails(method, path, extra) {
    return [
        t.div({ className: "m-t-base" }, t.strong(null, "API details")),
        t.div(
            { className: `alert ${method == "GET" ? "info" : "success"} api-preview-alert` },
            t.span({ className: "label method" }, method),
            t.span({ className: "path" }, path),
            extra ? t.small({ className: "extra" }, extra) : null,
        ),
    ];
}

/**
 * @param  {string} title
 * @param  {Array<Array>} rows List of [name, type, description, required?] rows.
 * @return {Element}
 */
export function docsParamsTable(title, rows) {
    return t.table(
        { className: "api-preview-table" },
        t.thead(
            null,
            t.tr(
                null,
                t.th({ className: "min-width txt-primary" }, title),
                t.th({ className: "min-width" }, "Type"),
                t.th(null, "Description"),
            ),
        ),
        t.tbody(
            null,
            rows.map(([name, type, description, required]) =>
                t.tr(
                    null,
                    t.td(
                        { className: "min-width" },
                        t.div(
                            { className: "flex gap-5" },
                            t.span(
                                { className: `label ${required ? "success" : "warning"}` },
                                required ? "Required" : "Optional",
                            ),
                            t.span(null, name),
                        ),
                    ),
                    t.td({ className: "min-width" }, t.span({ className: "label" }, type)),
                    t.td(null, description),
                )
            ),
        ),
    );
}

/**
 * @param  {Array<Object>} responses
 * @return {Array<Element>}
 */
export function docsResponses(responses) {
    return [
        t.div({ className: "m-t-base m-b-sm" }, t.strong(null, "Example responses")),
        app.components.codeBlockTabs({ tabs: responses }),
    ];
}

/**
 * JS SDK footnote link.
 *
 * @return {Element}
 */
export function docsJSSDKFootnote() {
    return t.div(
        { className: "txt-right" },
        t.a({
            href: import.meta.env.PB_JS_SDK_URL,
            target: "_blank",
            rel: "noopener noreferrer",
            textContent: "JS SDK docs",
        }),
    );
}

/**
 * Returns the standard OAuth2 JSON error response example.
 *
 * @param  {number} status
 * @param  {string} error
 * @param  {string} description
 * @return {Object}
 */
export function docsOAuth2Error(status, error, description) {
    return {
        title: status,
        value: JSON.stringify({ error: error, error_description: description }, null, 2),
    };
}
