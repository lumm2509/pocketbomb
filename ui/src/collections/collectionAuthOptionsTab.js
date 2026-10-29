import { loadRoles } from "@/auth/rolesUtils";
import { emailTemplateAccordion } from "./emailTemplateAccordion";
import { mfaAccordion } from "./mfaAccordion";
import { oauth2Accordion } from "./oauth2Accordion";
import { oauth2ServerAccordion } from "./oauth2ServerAccordion";
import { otpAccordion } from "./otpAccordion";
import { passwordAuthAccordion } from "./passwordAuthAccordion";
import { tokenOptionsAccordion } from "./tokenOptionsAccordion";

export function collectionAuthOptionsTab(upsertData) {
    const uniqueId = "options_" + app.utils.randomString();

    return t.div(
        { className: "collection-tab-content collection-options-tab-content" },
        t.div(
            { className: "grid" },
            t.div(
                { className: "col-12" },
                t.div(
                    { className: "section-heading" },
                    t.strong(null, "Auth methods"),
                    t.div({ className: "flex-fill" }),
                    t.div(
                        { className: "field" },
                        t.input({
                            id: uniqueId + ".authAlert",
                            name: "authAlert.enabled",
                            type: "checkbox",
                            className: "switch sm",
                            checked: () => !!upsertData.collection.authAlert?.enabled,
                            onchange: (e) => {
                                upsertData.collection.authAlert = upsertData.collection.authAlert || {};
                                upsertData.collection.authAlert.enabled = e.target.checked;
                            },
                        }),
                        t.label({ htmlFor: uniqueId + ".authAlert" }, "Send email alert for new logins"),
                    ),
                ),
                passwordAuthAccordion(upsertData.collection),
                () => {
                    if (upsertData.originalCollection?.name == "_superusers") {
                        return;
                    }

                    return oauth2Accordion(upsertData.collection);
                },
                otpAccordion(upsertData.collection),
                mfaAccordion(upsertData.collection),
            ),
            () => {
                // the _superusers collection has no default roles (staff without roles has no access)
                if (
                    upsertData.originalCollection?.name == "_superusers" || upsertData.collection.name == "_superusers"
                ) {
                    return;
                }

                return t.div(
                    { className: "col-12" },
                    t.div({ className: "section-heading" }, t.strong(null, "Default roles")),
                    defaultRolesField(upsertData, uniqueId),
                );
            },
            t.div(
                { className: "col-12" },
                t.div({ className: "section-heading" }, t.strong(null, "Identity provider")),
                oauth2ServerAccordion(upsertData),
            ),
            t.div(
                { className: "col-12" },
                t.div(
                    { className: "section-heading" },
                    t.strong(null, "Mail templates"),
                    t.button({
                        tabIndex: -1,
                        type: "buttton",
                        className: "m-l-auto label handle txt-bold",
                        textContent: "Send test email",
                        onclick: () => app.modals.openMailTest(upsertData.collection?.name),
                    }),
                ),
                emailTemplateAccordion(upsertData.collection, "verificationTemplate", {
                    title: "Default Verification email template",
                    placeholders: ["{APP_NAME}", "{APP_URL}", "{ISSUER_URL}", "{RECORD:*}", "{TOKEN}"],
                }),
                emailTemplateAccordion(upsertData.collection, "resetPasswordTemplate", {
                    title: "Default Password reset email template",
                    placeholders: ["{APP_NAME}", "{APP_URL}", "{ISSUER_URL}", "{RECORD:*}", "{TOKEN}"],
                }),
                emailTemplateAccordion(upsertData.collection, "confirmEmailChangeTemplate", {
                    title: "Default Confirm email change email template",
                    placeholders: ["{APP_NAME}", "{APP_URL}", "{ISSUER_URL}", "{RECORD:*}", "{TOKEN}"],
                }),
                emailTemplateAccordion(upsertData.collection, "otp.emailTemplate", {
                    title: "Default OTP email template",
                    placeholders: ["{APP_NAME}", "{APP_URL}", "{RECORD:*}", "{OTP}", "{OTP_ID}"],
                }),
                emailTemplateAccordion(upsertData.collection, "authAlert.emailTemplate", {
                    title: "Default Login alert email template",
                    placeholders: ["{APP_NAME}", "{APP_URL}", "{RECORD:*}", "{ALERT_INFO}"],
                }),
            ),
            t.div(
                { className: "col-12" },
                t.div({ className: "section-heading" }, t.strong(null, "Other")),
                tokenOptionsAccordion(upsertData.collection),
            ),
        ),
    );
}

function defaultRolesField(upsertData, uniqueId) {
    const local = store({
        roles: [],
    });

    if (app.perms.can("roles")) {
        loadRoles().then((result) => {
            local.roles = (result.items || []).filter((r) => !r.owner);
        }).catch((err) => console.warn("Failed to load the roles:", err));
    }

    return t.div(
        { className: "field" },
        t.label({ htmlFor: uniqueId + ".defaultRoles" }, "Roles of the records without explicit role assignments"),
        app.components.select({
            id: uniqueId + ".defaultRoles",
            name: "defaultRoles",
            max: 99,
            placeholder: "No default roles (no collection access)",
            disabled: () => !app.perms.can("roles"),
            options: () => {
                const ids = new Set([...(upsertData.collection.defaultRoles || []), ...local.roles.map((r) => r.id)]);
                return Array.from(ids).map((id) => ({
                    value: id,
                    label: local.roles.find((r) => r.id == id)?.name || id,
                }));
            },
            value: () => upsertData.collection.defaultRoles || [],
            onchange: (opts) => (upsertData.collection.defaultRoles = opts.map((o) => o.value)),
        }),
        t.div(
            { className: "field-help" },
            "The customers need a role permission for each collection action (the API rules still apply). ",
            "The built-in Customer role grants all collection actions (aka. only the API rules decide).",
        ),
    );
}
