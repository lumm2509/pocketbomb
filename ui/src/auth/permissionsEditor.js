import { actorHolds, COLLECTION_ACTIONS, normalizePermissions } from "./rolesUtils";

// Shared RBAC permissions editor (the roles permissions and the applications installation grant).
//
// The permissions the actor doesn't hold are disabled (no escalation) and the Owner-equivalent
// levels are never assignable (the server stays the authority).

/**
 * @typedef {Object} PermissionsEditorSettings
 * @property {function(): Object}       permissions  Getter of the current permissions object.
 * @property {function(Object): void}   onchange     Called with the new (normalized) permissions object.
 * @property {Array}                    resources    The permissions registry system resources.
 * @property {function(): boolean}      [readOnly]   Getter whether the editor is read-only.
 * @property {boolean}                  [application] Show only the application grantable system resources.
 * @property {boolean}                  [ceiling]     The permissions are only a ceiling (e.g. the API keys)
 *                                                    and therefore they are not limited by the actor permissions.
 * @property {function(string, string, string): boolean} [allows] Optional extra limit of the grantable permissions
 *                                                    (kind "collection"|"system", key, action|level; e.g. the catalog
 *                                                    application requested scopes). The already granted ones could be removed.
 */

/**
 * Returns the collections actions matrix ("All collections" + each regular collection).
 *
 * @param  {PermissionsEditorSettings} settings
 * @return {Element}
 */
export function permissionsCollectionsMatrix(settings) {
    const isReadOnly = () => !!settings.readOnly?.();

    const regularCollections = () => app.store.collections.filter((c) => !c.system);

    function hasAction(key, action) {
        return !!settings.permissions().collections?.[key]?.includes(action);
    }

    function toggleAction(key, action, enabled) {
        const permissions = normalizePermissions(settings.permissions());

        const actions = new Set(permissions.collections[key] || []);
        if (enabled) {
            actions.add(action);
        } else {
            actions.delete(action);
        }

        permissions.collections[key] = Array.from(actions);
        if (!permissions.collections[key].length) {
            delete permissions.collections[key];
        }

        settings.onchange(permissions);
    }

    function actionCheckbox(key, action) {
        // note: a ceiling never grants anything on its own (no escalation)
        const holds = (settings.ceiling || actorHolds("collection", key, action))
            && (!settings.allows || settings.allows("collection", key, action));

        return t.td(
            { className: "txt-center" },
            t.input({
                type: "checkbox",
                className: "role-action-checkbox",
                "html-data-key": key,
                "html-data-action": action,
                ariaLabel: key + " " + action,
                // note: the permissions the actor doesn't hold can't be granted (no escalation)
                disabled: () => isReadOnly() || (!holds && !hasAction(key, action)),
                title: holds ? "" : "You don't hold this permission",
                checked: () => hasAction(key, action),
                onchange: (e) => toggleAction(key, action, e.target.checked),
            }),
        );
    }

    return t.table(
        { className: "table role-matrix" },
        t.thead(
            null,
            t.tr(
                null,
                t.th(null, "Collection"),
                COLLECTION_ACTIONS.map((a) => t.th({ className: "txt-center" }, a)),
            ),
        ),
        t.tbody(
            null,
            t.tr(
                { className: "role-matrix-all" },
                t.td(
                    null,
                    t.strong(null, "All collections"),
                    t.small({ className: "txt-hint" }, " (incl. future ones)"),
                ),
                COLLECTION_ACTIONS.map((a) => actionCheckbox("*", a)),
            ),
            () =>
                regularCollections().map((c) =>
                    t.tr(
                        null,
                        t.td(null, c.name),
                        COLLECTION_ACTIONS.map((a) => actionCheckbox(c.id, a)),
                    )
                ),
        ),
    );
}

/**
 * Returns the system resources levels matrix.
 *
 * @param  {PermissionsEditorSettings} settings
 * @return {Element}
 */
export function permissionsSystemMatrix(settings) {
    const isReadOnly = () => !!settings.readOnly?.();

    const resources = settings.application
        ? (settings.resources || []).filter((r) => r.applicationGrantable)
        : (settings.resources || []);

    function setLevel(resource, level) {
        const permissions = normalizePermissions(settings.permissions());
        if (level) {
            permissions.system[resource] = level;
        } else {
            delete permissions.system[resource];
        }
        settings.onchange(permissions);
    }

    return t.table(
        { className: "table role-system-matrix" },
        t.thead(null, t.tr(null, t.th(null, "System resource"), t.th(null, "Access"))),
        t.tbody(
            null,
            resources.map((r) => {
                const levels = ["", ...(r.levels || [])];
                const ownerOnly = r.ownerOnlyLevels || [];

                if (!r.assignable) {
                    return t.tr(
                        { className: "role-owner-only-row" },
                        t.td(
                            null,
                            r.label,
                            t.small({ className: "txt-hint" }, " (" + r.name + ")"),
                            r.note ? t.div({ className: "txt-hint txt-sm" }, r.note) : null,
                        ),
                        t.td(
                            null,
                            t.span(
                                { className: "label warning", "html-data-resource": r.name },
                                t.i({ className: "ri-lock-line", ariaHidden: true }),
                                " Owner only",
                            ),
                        ),
                    );
                }

                return t.tr(
                    null,
                    t.td(
                        null,
                        r.label,
                        t.small({ className: "txt-hint" }, " (" + r.name + ")"),
                        r.note ? t.div({ className: "txt-hint txt-sm" }, r.note) : null,
                    ),
                    t.td(
                        null,
                        t.select(
                            {
                                className: "role-level-select",
                                "html-data-resource": r.name,
                                disabled: () => isReadOnly(),
                                onchange: (e) => setLevel(r.name, e.target.value),
                            },
                            levels.map((level) =>
                                t.option(
                                    {
                                        value: level,
                                        selected: () => (settings.permissions().system?.[r.name] || "") == level,
                                        // note: the levels the actor doesn't hold can't be granted (no escalation)
                                        // and the Owner-equivalent levels are never assignable
                                        disabled: () =>
                                            ownerOnly.includes(level)
                                            || (level != ""
                                                && (!actorHolds("system", r.name, level)
                                                    || (settings.allows && !settings.allows("system", r.name, level)))
                                                && settings.permissions().system?.[r.name] != level),
                                    },
                                    ownerOnly.includes(level) ? level + " (Owner only)" : (level || "none"),
                                )
                            ),
                        ),
                    ),
                );
            }),
        ),
    );
}
