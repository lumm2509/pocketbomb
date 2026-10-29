import { permissionsCollectionsMatrix, permissionsSystemMatrix } from "@/auth/permissionsEditor";
import { actorCovers, loadRoles, normalizePermissions, permissionsSummary, resetRolesCache } from "@/auth/rolesUtils";
import { settingsSidebar } from "@/settings/settingsSidebar";

export function pageRoles(route) {
    app.store.title = "Roles";

    const data = store({
        isLoading: false,
        roles: [],
        resources: [],
    });

    async function load() {
        data.isLoading = true;

        try {
            const result = await loadRoles(true);
            data.roles = result.items || [];
            data.resources = result.resources || [];
        } catch (err) {
            app.checkApiError(err);
        }

        data.isLoading = false;
    }

    load();

    function openUpsert(role = null) {
        openRoleUpsertModal(role, data.resources, {
            onsave: () => load(),
            ondelete: () => load(),
        });
    }

    function roleItem(role) {
        return t.div(
            {
                className: "list-item handle role-item",
                tabIndex: 0,
                onclick: () => openUpsert(role),
                onkeydown: (e) => e.key == "Enter" && openUpsert(role),
            },
            t.i({
                className: role.owner ? "ri-vip-crown-line txt-warning" : "ri-shield-user-line txt-hint",
                ariaHidden: true,
            }),
            t.div(
                { className: "content" },
                t.span({ className: "txt-bold" }, role.name),
                t.small({ className: "txt-hint txt-ellipsis" }, role.description || ""),
                t.small(
                    { className: "txt-hint txt-ellipsis" },
                    permissionsSummary(role.permissions, role.owner).join(" · "),
                ),
            ),
            role.system
                ? t.span(
                    { className: "label warning" },
                    t.i({ className: "ri-lock-line", ariaHidden: true }),
                    " built-in",
                )
                : null,
            t.i({ className: "ri-arrow-right-s-line txt-hint", ariaHidden: true }),
        );
    }

    return t.div(
        { pbEvent: "pageRoles", className: "page page-roles" },
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
                app.components.refreshButton({
                    className: "btn sm transparent secondary circle",
                    onclick: load,
                }),
                t.div(
                    { className: "page-header-primary-btns" },
                    t.button(
                        {
                            type: "button",
                            className: "btn sm new-role-btn",
                            hidden: () => !app.perms.can("roles", "write"),
                            onclick: () => openUpsert(),
                        },
                        t.i({ className: "ri-add-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "New role"),
                    ),
                ),
            ),
            t.div(
                { className: "wrapper m-b-base" },
                t.p(
                    { className: "txt-hint m-b-sm" },
                    "The roles grant the collection actions and system permissions to the staff members (superusers) ",
                    "and to the auth records of the other collections (customers; the collection API rules still apply). ",
                    "The staff with a collection permission bypass its API rules. ",
                    "You could grant only the permissions you hold yourself.",
                ),
                () => {
                    if (data.isLoading && !data.roles.length) {
                        return t.div({ className: "block txt-center p-base" }, t.span({ className: "loader lg" }));
                    }

                    return t.div({ className: "list roles-list" }, data.roles.map((r) => roleItem(r)));
                },
            ),
        ),
    );
}

/**
 * Opens the role create/edit modal.
 *
 * @param {Object} [role]
 * @param {Array}  resources The permissions registry system resources.
 * @param {Object} [settings]
 * @param {function} [settings.onsave]
 * @param {function} [settings.ondelete]
 */
export function openRoleUpsertModal(role, resources, settings = {}) {
    app.store.errors = null;

    const modal = roleUpsertModal(role, resources, settings);

    document.body.appendChild(modal);

    app.modals.open(modal);
}

function roleUpsertModal(rawRole, resources, settings) {
    const uniqueId = "role_" + app.utils.randomString();

    const original = {
        id: rawRole?.id || "",
        name: rawRole?.name || "",
        description: rawRole?.description || "",
        permissions: normalizePermissions(rawRole?.permissions),
        system: !!rawRole?.system,
        owner: !!rawRole?.owner,
    };

    const data = store({
        isSaving: false,
        role: JSON.parse(JSON.stringify(original)),
        get isNew() {
            return !original.id;
        },
        get isReadOnly() {
            return original.system || !app.perms.can("roles", "write")
                || (!data.isNew && !actorCovers(original.permissions));
        },
        get hasChanges() {
            return JSON.stringify(original) != JSON.stringify(data.role);
        },
    });

    async function save() {
        if (data.isSaving || data.isReadOnly) {
            return;
        }

        data.isSaving = true;

        try {
            const body = {
                name: data.role.name,
                description: data.role.description,
                permissions: data.role.permissions,
            };

            const saved = data.isNew
                ? await app.pb.collection("_roles").create(body)
                : await app.pb.collection("_roles").update(original.id, body);

            resetRolesCache();
            app.toasts.success(`Successfully saved role "${saved.name}".`);
            settings.onsave?.(saved);
            app.modals.close(modal, true);
        } catch (err) {
            app.checkApiError(err);
        }

        data.isSaving = false;
    }

    function deleteRole() {
        app.modals.confirm(
            t.p(null, "Do you really want to delete role ", t.strong(null, original.name), "?"),
            async () => {
                try {
                    await app.pb.collection("_roles").delete(original.id);
                    resetRolesCache();
                    app.toasts.success(`Successfully deleted role "${original.name}".`);
                    settings.ondelete?.(original);
                    app.modals.close(modal, true);
                } catch (err) {
                    app.checkApiError(err);
                }
            },
            null,
            { yesButton: "Delete" },
        );
    }

    const editorSettings = {
        permissions: () => data.role.permissions,
        onchange: (permissions) => (data.role.permissions = permissions),
        resources: resources,
        readOnly: () => data.isReadOnly,
    };

    const modal = t.div(
        {
            pbEvent: "roleUpsertModal",
            className: "modal role-upsert-modal",
            onafterclose: (el) => {
                app.store.errors = null;
                el?.remove();
            },
        },
        t.header(
            { className: "modal-header" },
            t.h6(
                { className: "modal-title" },
                () => (data.isNew ? "New role" : t.span(null, "Edit role ", t.strong(null, original.name))),
            ),
            t.div({ className: "flex-fill" }),
            () => {
                if (data.isNew || data.isReadOnly) {
                    return;
                }

                return t.button(
                    {
                        type: "button",
                        className: "btn sm circle transparent danger",
                        ariaLabel: app.attrs.tooltip("Delete role", "left"),
                        onclick: deleteRole,
                    },
                    t.i({ className: "ri-delete-bin-7-line", ariaHidden: true }),
                );
            },
        ),
        t.div(
            { className: "modal-content" },
            () => {
                if (original.owner) {
                    return t.div(
                        { className: "alert info m-b-base" },
                        t.i({ className: "ri-lock-line", ariaHidden: true }),
                        t.div(
                            { className: "content" },
                            t.strong(null, "Built-in Owner role (read-only)"),
                            " — full access to everything, including the SQL console. ",
                            "It could be assigned only by an Owner and at least one Owner must always exist.",
                        ),
                    );
                }

                if (data.isReadOnly && !data.isNew) {
                    return t.div(
                        { className: "alert warning m-b-base" },
                        t.div(
                            { className: "content" },
                            original.system
                                ? "Built-in role (read-only)."
                                : "You can't change this role because it grants permissions you don't hold.",
                        ),
                    );
                }
            },
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
                            id: uniqueId + ".name",
                            name: "name",
                            type: "text",
                            required: true,
                            disabled: () => data.isReadOnly,
                            value: () => data.role.name,
                            oninput: (e) => (data.role.name = e.target.value),
                        }),
                    ),
                ),
                t.div(
                    { className: "col-sm-6" },
                    t.div(
                        { className: "field" },
                        t.label({ htmlFor: uniqueId + ".description" }, "Description"),
                        t.input({
                            id: uniqueId + ".description",
                            name: "description",
                            type: "text",
                            disabled: () => data.isReadOnly,
                            value: () => data.role.description,
                            oninput: (e) => (data.role.description = e.target.value),
                        }),
                    ),
                ),
                () => {
                    if (original.owner) {
                        return;
                    }

                    return [
                        t.div(
                            { className: "col-12" },
                            t.h6({ className: "m-b-xs" }, "Collections"),
                            permissionsCollectionsMatrix(editorSettings),
                        ),
                        t.div(
                            { className: "col-12" },
                            t.h6({ className: "m-b-xs" }, "System"),
                            permissionsSystemMatrix(editorSettings),
                        ),
                    ];
                },
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
                t.span({ className: "txt" }, "Close"),
            ),
            t.button(
                {
                    "type": "submit",
                    "html-form": uniqueId + "_form",
                    "hidden": () => data.isReadOnly,
                    "className": () => `btn expanded-lg ${data.isSaving ? "loading" : ""}`,
                    "disabled": () => data.isSaving || (!data.isNew && !data.hasChanges),
                },
                t.span({ className: "txt" }, () => (data.isNew ? "Create role" : "Save changes")),
            ),
        ),
    );

    return modal;
}
