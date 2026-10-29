import { applicationHandleFromName } from "./applicationsUtils";

const TAB_FORM = "form";
const TAB_IMPORT = "import";

const MANIFEST_PLACEHOLDER = `handle = "my-app"
name = "My app"
version = "1.0.0"
description = "What the app does"
application_url = "https://my-app.example.com"

[developer]
name = "ACME"
url = "https://acme.example.com"

[access]
scopes = ["read_posts", "write_posts"]`;

/**
 * Opens the "Create custom application" modal (from a form or by importing a TOML/JSON manifest).
 *
 * @param {Object}   [settings]
 * @param {function} [settings.onsave] function(application) {}
 */
export function openApplicationCreateModal(settings = {}) {
    app.store.errors = null;

    const modal = applicationCreateModal(settings);

    document.body.appendChild(modal);

    app.modals.open(modal);
}

function applicationCreateModal(settings) {
    const uniqueId = "application_create_" + app.utils.randomString();

    const data = store({
        activeTab: TAB_FORM,
        isSaving: false,
        handleTouched: false,
        form: {
            name: "",
            handle: "",
            description: "",
            applicationURL: "",
            developerName: "",
            developerURL: "",
        },
        manifest: "",
        format: "toml",
    });

    async function save() {
        if (data.isSaving) {
            return;
        }

        data.isSaving = true;

        try {
            let result;
            if (data.activeTab == TAB_IMPORT) {
                result = await app.pb.send("/api/applications/manifests", {
                    method: "POST",
                    headers: {
                        "Content-Type": data.format == "json" ? "application/json" : "application/toml",
                    },
                    body: data.manifest,
                });
            } else {
                result = await app.pb.send("/api/applications", {
                    method: "POST",
                    body: data.form,
                });
            }

            app.store.errors = null;

            app.toasts.success(
                result.unchanged
                    ? `The application "${result.application.name}" version ${result.version.version} is already deployed.`
                    : `Successfully deployed "${result.application.name}" version ${result.version.version}.`,
            );

            settings.onsave?.(result.application);

            app.modals.close(modal, true);
        } catch (err) {
            if (!err?.isAbort) {
                app.checkApiError(err);
            }
        }

        data.isSaving = false;
    }

    function loadFile(file) {
        if (!file) {
            return;
        }

        data.format = file.name.toLowerCase().endsWith(".json") ? "json" : "toml";

        const reader = new FileReader();
        reader.onload = () => {
            data.manifest = String(reader.result || "");
        };
        reader.readAsText(file);
    }

    function field(name, label, input, help = "") {
        return t.div(
            { className: "field" },
            t.label({ htmlFor: uniqueId + "." + name }, label),
            input,
            help ? t.div({ className: "field-help" }, help) : null,
        );
    }

    function textInput(name, attrs = {}) {
        return t.input(Object.assign({
            id: uniqueId + "." + name,
            name: name,
            type: "text",
            value: () => data.form[name] || "",
            oninput: (e) => (data.form[name] = e.target.value),
        }, attrs));
    }

    function formTab() {
        return t.form(
            {
                id: uniqueId + "_form",
                className: "grid application-create-form",
                inert: () => data.isSaving,
                onsubmit: (e) => {
                    e.preventDefault();
                    save();
                },
            },
            t.div(
                { className: "col-sm-6" },
                field(
                    "name",
                    "Name",
                    textInput("name", {
                        required: true,
                        maxLength: 100,
                        placeholder: "My integration",
                        oninput: (e) => {
                            data.form.name = e.target.value;
                            if (!data.handleTouched) {
                                data.form.handle = applicationHandleFromName(e.target.value);
                            }
                        },
                    }),
                ),
            ),
            t.div(
                { className: "col-sm-6" },
                field(
                    "handle",
                    "Handle",
                    textInput("handle", {
                        required: true,
                        spellcheck: false,
                        maxLength: 63,
                        placeholder: "my-integration",
                        oninput: (e) => {
                            data.handleTouched = true;
                            data.form.handle = e.target.value;
                        },
                    }),
                    "Lowercase letters, digits and dashes (it identifies the application in the manifests; can't be changed later).",
                ),
            ),
            t.div(
                { className: "col-sm-12" },
                field("description", "Description", textInput("description", { maxLength: 1000 })),
            ),
            t.div(
                { className: "col-sm-12" },
                field(
                    "applicationURL",
                    "Application URL",
                    textInput("applicationURL", { type: "url", placeholder: "https://my-app.example.com" }),
                ),
            ),
            t.div({ className: "col-sm-6" }, field("developerName", "Developer name", textInput("developerName"))),
            t.div(
                { className: "col-sm-6" },
                field(
                    "developerURL",
                    "Developer URL",
                    textInput("developerURL", { type: "url", placeholder: "https://example.com" }),
                ),
            ),
            t.div(
                { className: "col-sm-12" },
                t.div(
                    { className: "txt-hint txt-sm" },
                    "A version 1.0.0 manifest is created from the form. The permissions are granted on install.",
                ),
            ),
        );
    }

    function importTab() {
        return t.form(
            {
                id: uniqueId + "_form",
                className: "grid application-import-form",
                inert: () => data.isSaving,
                onsubmit: (e) => {
                    e.preventDefault();
                    save();
                },
            },
            t.div(
                { className: "col-sm-12" },
                t.p(
                    { className: "txt-hint txt-sm" },
                    "Paste or upload a ",
                    t.code(null, "pocketbase.app.toml"),
                    " (or JSON) manifest. A new handle creates a custom application and a new version of an existing one is added as an immutable version. ",
                    "The same can be done from the CLI with ",
                    t.code(null, "pocketbase applications deploy ./pocketbase.app.toml --url ... --token ..."),
                    ".",
                ),
            ),
            t.div(
                { className: "col-sm-6" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".format" }, "Format"),
                    app.components.select({
                        id: uniqueId + ".format",
                        name: "format",
                        required: true,
                        options: [
                            { value: "toml", label: "TOML" },
                            { value: "json", label: "JSON" },
                        ],
                        value: () => data.format,
                        onchange: (opts) => (data.format = opts?.[0]?.value || "toml"),
                    }),
                ),
            ),
            t.div(
                { className: "col-sm-6" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".file" }, "Manifest file"),
                    t.input({
                        id: uniqueId + ".file",
                        type: "file",
                        accept: ".toml,.json,application/json,application/toml",
                        onchange: (e) => loadFile(e.target.files?.[0]),
                    }),
                ),
            ),
            t.div(
                { className: "col-sm-12" },
                t.div(
                    { className: "field" },
                    t.label({ htmlFor: uniqueId + ".manifest" }, "Manifest"),
                    t.textarea({
                        id: uniqueId + ".manifest",
                        name: "manifest",
                        className: "txt-mono application-manifest-input",
                        rows: 14,
                        required: true,
                        spellcheck: false,
                        placeholder: MANIFEST_PLACEHOLDER,
                        value: () => data.manifest,
                        oninput: (e) => (data.manifest = e.target.value),
                    }),
                ),
            ),
        );
    }

    function tabButton(tab, label) {
        return t.button(
            {
                type: "button",
                className: () => `tab-item ${data.activeTab == tab ? "active" : ""}`,
                disabled: () => data.isSaving,
                onclick: () => {
                    app.store.errors = null;
                    data.activeTab = tab;
                },
            },
            t.span({ className: "txt" }, label),
        );
    }

    const modal = t.div(
        {
            pbEvent: "applicationCreateModal",
            className: "modal application-create-modal",
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
            { className: "modal-header isolated" },
            t.div(
                { className: "grid" },
                t.div({ className: "col-12" }, t.h6({ className: "modal-title" }, "Create custom application")),
                t.div(
                    { className: "col-12" },
                    t.nav(
                        { className: "tabs-header equal-width" },
                        tabButton(TAB_FORM, "Form"),
                        tabButton(TAB_IMPORT, "Import manifest (TOML/JSON)"),
                    ),
                ),
            ),
        ),
        t.div(
            { className: "modal-content" },
            () => (data.activeTab == TAB_IMPORT ? importTab() : formTab()),
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
                    "className": () => `btn expanded-lg application-create-submit ${data.isSaving ? "loading" : ""}`,
                    "disabled": () => data.isSaving,
                },
                t.span({ className: "txt" }, () => (data.activeTab == TAB_IMPORT ? "Import manifest" : "Create")),
            ),
        ),
    );

    return modal;
}
