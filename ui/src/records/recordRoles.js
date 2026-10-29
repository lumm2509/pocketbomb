import { actorCovers, loadRoles, permissionsSummary } from "@/auth/rolesUtils";

/**
 * Returns the auth record "Roles" panel content
 * (the explicit role assignments and the effective permissions preview).
 *
 * @param  {Object} collection The auth record collection.
 * @param  {Object} record     The auth record.
 * @return {Element}
 */
export function recordRoles(collection, record) {
    const isStaffCollection = collection.name == "_superusers";

    const local = store({
        isLoading: false,
        isSaving: false,
        roles: [],
        assignments: null,
        selected: [],
        get isSelf() {
            return app.store.superuser?.id == record.id && isStaffCollection;
        },
        get canWrite() {
            return app.perms.can("roles", "write") && !local.isSelf;
        },
        get hasChanges() {
            return JSON.stringify([...local.selected].sort())
                != JSON.stringify([...(local.assignments?.roles || [])].sort());
        },
        get defaultRoleNames() {
            return (collection.defaultRoles || [])
                .map((id) => local.roles.find((r) => r.id == id)?.name || id);
        },
    });

    async function load() {
        local.isLoading = true;

        try {
            const [rolesResult, assignments] = await Promise.all([
                loadRoles(true),
                app.pb.send("/api/roles/assignments", {
                    query: { collection: collection.id, record: record.id },
                    requestKey: null,
                }),
            ]);

            local.roles = (rolesResult.items || []).filter((r) => isStaffCollection || !r.owner);
            local.assignments = assignments;
            local.selected = [...(assignments.roles || [])];
        } catch (err) {
            app.checkApiError(err);
        }

        local.isLoading = false;
    }

    async function save() {
        if (local.isSaving || !local.canWrite) {
            return;
        }

        local.isSaving = true;

        try {
            local.assignments = await app.pb.send("/api/roles/assignments", {
                method: "PUT",
                body: { collection: collection.id, record: record.id, roles: local.selected },
            });
            local.selected = [...(local.assignments.roles || [])];
            app.toasts.success("Successfully saved the role assignments.");
        } catch (err) {
            app.checkApiError(err);
        }

        local.isSaving = false;
    }

    function canToggle(role) {
        if (!local.canWrite) {
            return false;
        }

        // note: the server enforces the same rules (no escalation, Owner only by an Owner)
        if (role.owner) {
            return app.perms.isOwner();
        }

        return actorCovers(role.permissions);
    }

    function roleOption(role) {
        const id = "record_role_" + role.id;

        return t.div(
            { className: "field record-role-option" },
            t.input({
                type: "checkbox",
                id: id,
                className: "switch",
                "html-data-role": role.name,
                disabled: () => local.isSaving || !canToggle(role),
                checked: () => local.selected.includes(role.id),
                onchange: (e) => {
                    if (e.target.checked) {
                        local.selected = [...local.selected, role.id];
                    } else {
                        local.selected = local.selected.filter((r) => r != role.id);
                    }
                },
            }),
            t.label(
                { htmlFor: id },
                t.span({ className: "txt" }, role.name),
                role.owner ? t.span({ className: "label warning sm m-l-5" }, "Owner") : null,
                () => {
                    if (!canToggle(role) && local.canWrite) {
                        return t.small({ className: "txt-hint m-l-5" }, "(you don't hold all its permissions)");
                    }
                },
            ),
        );
    }

    load();

    return t.div(
        { pbEvent: "recordRoles", className: "record-roles" },
        t.p(
            { className: "txt-hint" },
            isStaffCollection
                ? "The roles of the staff member. A staff member without roles has no dashboard access."
                : "The roles of the record (when none is assigned the collection default roles apply). The collection API rules still apply.",
        ),
        () => {
            if (local.isSelf) {
                return t.div(
                    { className: "alert warning" },
                    t.div({ className: "content" }, "You can't change your own role assignments."),
                );
            }
        },
        () => {
            if (local.isLoading && !local.roles.length) {
                return t.div({ className: "block txt-center p-base" }, t.span({ className: "loader" }));
            }

            return t.div({ className: "record-roles-list" }, local.roles.map((r) => roleOption(r)));
        },
        () => {
            if (!local.assignments) {
                return;
            }

            return t.div(
                { className: "record-effective-permissions m-t-sm" },
                t.h6({ className: "m-b-xs" }, "Effective permissions"),
                () => {
                    if (!local.assignments.explicit && !isStaffCollection) {
                        return t.p(
                            { className: "txt-hint txt-sm" },
                            "Using the collection default roles: ",
                            t.strong(null, local.defaultRoleNames.join(", ") || "none"),
                        );
                    }
                },
                t.ul(
                    { className: "txt-sm" },
                    () =>
                        permissionsSummary(local.assignments.permissions, local.assignments.owner).map((line) =>
                            t.li(null, line)
                        ),
                ),
            );
        },
        t.div(
            { className: "flex m-t-sm", hidden: () => !local.canWrite },
            t.button(
                {
                    type: "button",
                    className: () => `btn sm save-roles-btn ${local.isSaving ? "loading" : ""}`,
                    disabled: () => local.isSaving || !local.hasChanges,
                    onclick: save,
                },
                t.span({ className: "txt" }, "Save roles"),
            ),
        ),
    );
}
