import { settingsSidebar } from "../settingsSidebar";

export function pageApplicationsSettings(route) {
    app.store.title = "Applications settings";

    const data = store({
        isLoading: false,
        isSaving: false,
        formSettings: null,
        initSerialized: "null",
        get hasChanges() {
            return data.initSerialized != JSON.stringify(data.formSettings);
        },
    });

    loadSettings();

    async function loadSettings() {
        data.isLoading = true;

        try {
            const settings = await app.pb.settings.getAll();
            init(settings);
            data.isLoading = false;
        } catch (err) {
            if (!err.isAbort) {
                app.checkApiError(err);
            }
        }
    }

    function init(settings = {}) {
        // refresh local app settings
        app.store.settings = JSON.parse(JSON.stringify(settings));

        data.formSettings = {
            applications: {
                catalogs: JSON.parse(JSON.stringify(settings?.applications?.catalogs || [])),
            },
        };

        data.initSerialized = JSON.stringify(data.formSettings);
    }

    async function save() {
        if (data.isSaving || !data.hasChanges) {
            return;
        }

        data.isSaving = true;

        try {
            const settings = await app.pb.settings.update(JSON.parse(JSON.stringify(data.formSettings)));
            init(settings);
            app.store.errors = null;
            app.toasts.success("Successfully saved applications settings.");
        } catch (err) {
            app.checkApiError(err);
        }

        data.isSaving = false;
    }

    function reset() {
        data.formSettings = JSON.parse(data.initSerialized);
        app.store.errors = null;
    }

    function addSource() {
        data.formSettings.applications.catalogs.push({ name: "", url: "", publicKey: "" });
    }

    function removeSource(index) {
        data.formSettings.applications.catalogs.splice(index, 1);
    }

    function sourceField(source, index, key, label, opts = {}) {
        const id = `applications.catalogs.${index}.${key}`;

        return t.div(
            { className: opts.col || "col-lg-6" },
            t.div(
                { className: "field" },
                t.label({ htmlFor: id }, label),
                t.input({
                    id,
                    name: id,
                    type: opts.type || "text",
                    required: !!opts.required,
                    placeholder: opts.placeholder || "",
                    value: () => source[key] || "",
                    oninput: (e) => (source[key] = e.target.value),
                }),
            ),
            opts.help ? t.div({ className: "field-help" }, opts.help) : null,
        );
    }

    function sourceItem(source, index) {
        return t.div(
            { className: "application-catalog-source-item" },
            t.div(
                { className: "grid sm" },
                sourceField(source, index, "name", "Name", { required: true, placeholder: "e.g. ACME internal" }),
                sourceField(source, index, "url", "Index URL", {
                    required: true,
                    type: "url",
                    placeholder: "https://apps.example.com/catalog/index.json",
                }),
                sourceField(source, index, "publicKey", "Public key (Ed25519, base64)", {
                    col: "col-lg-12",
                    help:
                        "Optional. When set, the catalog index must be signed with the related private key (\"pocketbase applications catalog keygen\" and \"build\"). Without it the catalog is listed as unsigned.",
                }),
            ),
            t.button(
                {
                    type: "button",
                    className: "btn sm transparent danger application-catalog-source-remove",
                    onclick: () => removeSource(index),
                },
                t.i({ className: "ri-delete-bin-7-line", ariaHidden: true }),
                t.span({ className: "txt" }, "Remove"),
            ),
        );
    }

    function form() {
        const catalogs = data.formSettings.applications.catalogs;

        return t.form(
            {
                pbEvent: "applicationsSettingsForm",
                className: "grid applications-settings-form",
                inert: () => data.isSaving,
                onsubmit: (e) => {
                    e.preventDefault();
                    save();
                },
            },
            t.div(
                { className: "col-lg-12" },
                t.h6(null, "Catalog sources"),
                t.div(
                    { className: "txt-hint txt-sm m-b-sm" },
                    "The dashboard discovers the installable applications from these catalogs. ",
                    "Everything is fetched server-side (https only, SSRF protected) and the catalog applications receive their credentials only through their signed install notification.",
                ),
            ),
            t.div(
                { className: "col-lg-12 application-catalog-sources" },
                () => {
                    if (!catalogs.length) {
                        return t.div({ className: "txt-hint" }, "No catalog sources.");
                    }
                    return catalogs.map((source, i) => sourceItem(source, i));
                },
                t.button(
                    {
                        type: "button",
                        className: "btn sm secondary m-t-sm application-catalog-source-add",
                        onclick: addSource,
                    },
                    t.i({ className: "ri-add-line", ariaHidden: true }),
                    t.span({ className: "txt" }, "Add catalog source"),
                ),
            ),
            t.div({ className: "col-lg-12" }, t.hr()),
            t.div(
                { className: "col-lg-12" },
                t.div(
                    { className: "flex" },
                    t.div({ className: "m-r-auto" }),
                    t.button(
                        {
                            type: "button",
                            hidden: () => !data.hasChanges,
                            className: "btn transparent secondary",
                            onclick: reset,
                        },
                        t.span({ className: "txt" }, "Cancel"),
                    ),
                    t.button(
                        {
                            className: () =>
                                `btn expanded-lg application-settings-save-btn ${data.isSaving ? "loading" : ""}`,
                            disabled: () => !data.hasChanges || data.isSaving,
                        },
                        t.span({ className: "txt" }, "Save changes"),
                    ),
                ),
            ),
        );
    }

    return t.div(
        { pbEvent: "pageApplicationsSettings", className: "page page-applications-settings" },
        settingsSidebar(),
        t.div(
            { className: "page-content full-height" },
            t.header(
                { className: "page-header" },
                t.nav(
                    { className: "breadcrumbs" },
                    t.div({ className: "breadcrumb-item" }, "Settings"),
                    t.div({ className: "breadcrumb-item" }, () => app.store.title),
                ),
                t.div(
                    { className: "page-header-primary-btns" },
                    t.a(
                        { href: "#/applications?tab=catalog", className: "btn sm transparent secondary" },
                        t.i({ className: "ri-apps-2-add-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "Applications catalog"),
                    ),
                ),
            ),
            t.div(
                { className: "wrapper m-b-base" },
                () => {
                    if (data.isLoading || !data.formSettings) {
                        return t.div({ className: "block txt-center" }, t.span({ className: "loader lg" }));
                    }
                    return form();
                },
            ),
            t.footer({ className: "page-footer" }, app.components.credits()),
        ),
    );
}
