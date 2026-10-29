package migrations

import (
	"fmt"
	"strings"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

// legacyCollectionNameMFAs is the name of the upstream MFA sessions collection
// (it is created by the init migration and dropped by the auth v2 migration).
const legacyCollectionNameMFAs = "_mfas"

// oauth2RateLimitLabel is the default OAuth2 server routes rate limit rule label.
const oauth2RateLimitLabel = "/oauth2/"

// oauth2ConsentsOwnerRule is the _oauth2Consents list/view/delete rule (the record owner).
const oauth2ConsentsOwnerRule = "@request.auth.id != '' && recordRef = @request.auth.id && collectionRef = @request.auth.collectionId"

// Auth v2 - OAuth2/OIDC is the only auth system:
//   - creates the _oauth2Clients, _authSessions and _oauth2Consents system collections
//     and the built-in protected pb_dashboard client of the _superusers issuer
//   - adds _otps.sessionRef and drops the vanilla auth _mfas collection
//   - every auth collection becomes an issuer (default OAuth2Server options, the access tokens
//     duration is AuthToken.Duration) and the mail templates links point to the hosted pages
//   - rewrites (or drops) the rate limit rules of the removed vanilla auth endpoints
//     and appends the default "/oauth2/" rule
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		clients, err := createOAuth2ClientsCollection(txApp)
		if err != nil {
			return fmt.Errorf("_oauth2Clients error: %w", err)
		}

		if err := createAuthSessionsCollection(txApp, clients); err != nil {
			return fmt.Errorf("_authSessions error: %w", err)
		}

		if err := createOAuth2ConsentsCollection(txApp, clients); err != nil {
			return fmt.Errorf("_oauth2Consents error: %w", err)
		}

		if err := addOTPsSessionRef(txApp); err != nil {
			return fmt.Errorf("_otps error: %w", err)
		}

		if _, err := txApp.FindCollectionByNameOrId(legacyCollectionNameMFAs); err == nil {
			if err := dropRawCollection(txApp, legacyCollectionNameMFAs); err != nil {
				return fmt.Errorf("_mfas error: %w", err)
			}
		}

		if err := migrateAuthCollectionsToIssuers(txApp); err != nil {
			return err
		}

		if err := createDashboardOAuth2Client(txApp); err != nil {
			return fmt.Errorf("pb_dashboard client error: %w", err)
		}

		return migrateRateLimitRules(txApp)
	}, func(txApp core.App) error {
		for _, name := range []string{core.CollectionNameOAuth2Consents, core.CollectionNameAuthSessions, core.CollectionNameOAuth2Clients} {
			if err := dropRawCollection(txApp, name); err != nil {
				return err
			}
		}

		otps, err := txApp.FindCollectionByNameOrId(core.CollectionNameOTPs)
		if err != nil {
			return err
		}
		otps.Fields.RemoveByName("sessionRef")
		otps.RemoveIndex("idx_otps_sessionRef")
		// note: without validation because the system fields can't be removed otherwise
		if err := txApp.SaveNoValidate(otps); err != nil {
			return err
		}

		if _, err := txApp.FindCollectionByNameOrId(legacyCollectionNameMFAs); err != nil {
			if err := createMFAsCollection(txApp); err != nil {
				return err
			}
		}

		// note: the rewritten templates links, rate limit labels and token durations are not restored
		if err := txApp.ReloadSettings(); err != nil {
			return err
		}
		settings := txApp.Settings()
		rules := make([]core.RateLimitRule, 0, len(settings.RateLimits.Rules))
		for _, r := range settings.RateLimits.Rules {
			if r.Label != oauth2RateLimitLabel {
				rules = append(rules, r)
			}
		}
		settings.RateLimits.Rules = rules

		return txApp.Save(settings)
	})
}

// dropRawCollection drops the specified system collection
// (the system collections cannot be deleted with app.Delete).
func dropRawCollection(txApp core.App, name string) error {
	if _, err := txApp.DB().DropTable(name).Execute(); err != nil {
		return err
	}

	if _, err := txApp.DB().Delete("_collections", dbx.HashExp{"name": name}).Execute(); err != nil {
		return err
	}

	return txApp.ReloadCachedCollections()
}

func createOAuth2ClientsCollection(txApp core.App) (*core.Collection, error) {
	col := core.NewBaseCollection(core.CollectionNameOAuth2Clients)
	col.System = true

	col.Fields.Add(&core.TextField{
		Name:     "name",
		System:   true,
		Required: true,
		Max:      255,
	})
	col.Fields.Add(&core.TextField{
		Name:     "clientId",
		System:   true,
		Required: true,
		Max:      255,
	})
	col.Fields.Add(&core.TextField{
		Name:   "clientSecretHash",
		System: true,
		Hidden: true,
	})
	col.Fields.Add(&core.SelectField{
		Name:      "type",
		System:    true,
		Required:  true,
		MaxSelect: 1,
		Values:    []string{core.OAuth2ClientTypePublic, core.OAuth2ClientTypeConfidential},
	})
	col.Fields.Add(&core.TextField{
		Name:     "collectionRef",
		System:   true,
		Required: true,
	})
	col.Fields.Add(&core.JSONField{
		Name:   "redirectURIs",
		System: true,
	})
	col.Fields.Add(&core.JSONField{
		Name:   "postLogoutRedirectURIs",
		System: true,
	})
	col.Fields.Add(&core.JSONField{
		Name:   "scopes",
		System: true,
	})
	col.Fields.Add(&core.BoolField{
		Name:   "firstParty",
		System: true,
	})
	col.Fields.Add(&core.URLField{
		Name:   "logo",
		System: true,
	})
	col.Fields.Add(&core.BoolField{
		Name:   "disabled",
		System: true,
	})
	col.Fields.Add(&core.AutodateField{
		Name:     "created",
		System:   true,
		OnCreate: true,
	})
	col.Fields.Add(&core.AutodateField{
		Name:     "updated",
		System:   true,
		OnCreate: true,
		OnUpdate: true,
	})
	col.AddIndex("idx_oauth2Clients_clientId", true, "clientId", "")
	col.AddIndex("idx_oauth2Clients_collectionRef", false, "collectionRef", "")

	return col, txApp.Save(col)
}

func createAuthSessionsCollection(txApp core.App, clients *core.Collection) error {
	col := core.NewBaseCollection(core.CollectionNameAuthSessions)
	col.System = true

	// note: all API rules are nil (aka. superusers only)

	text := func(name string, required bool, hidden bool) {
		col.Fields.Add(&core.TextField{Name: name, System: true, Required: required, Hidden: hidden})
	}
	json := func(name string) {
		col.Fields.Add(&core.JSONField{Name: name, System: true})
	}
	date := func(name string, required bool) {
		col.Fields.Add(&core.DateField{Name: name, System: true, Required: required})
	}
	boolean := func(name string) {
		col.Fields.Add(&core.BoolField{Name: name, System: true})
	}

	text("collectionRef", true, false)
	// note: required for all sessions except the root SSO ones (enforced by the model validator)
	col.Fields.Add(&core.RelationField{
		Name:          "client",
		System:        true,
		Required:      false,
		MaxSelect:     1,
		CollectionId:  clients.Id,
		CascadeDelete: true,
	})
	col.Fields.Add(&core.SelectField{
		Name:      "status",
		System:    true,
		Required:  true,
		MaxSelect: 1,
		Values:    core.AuthSessionStatuses,
	})
	text("handleHash", false, true)
	text("bindingHash", false, true)

	// authorize request
	text("redirectURI", false, false)
	text("responseMode", false, false)
	text("state", false, false)
	text("nonce", false, false)
	text("codeChallenge", false, false)
	text("codeChallengeMethod", false, false)
	text("prompt", false, false)
	col.Fields.Add(&core.NumberField{Name: "maxAge", System: true, OnlyInt: true})
	text("loginHint", false, false)
	text("uiLocales", false, false)
	json("scopesRequested")
	json("scopes")

	// actor and factors
	text("recordRef", false, false)
	json("amr")
	date("authTime", false)
	boolean("mfaRequired")

	// federated login step (+ the pending resolved record that is applied as
	// factor only after the browser binding check of the continue step)
	text("upstreamProvider", false, true)
	text("upstreamState", false, true)
	text("upstreamCodeVerifier", false, true)
	text("upstreamRecordRef", false, true)

	// authorization code
	text("codeHash", false, true)
	date("codeExpiresAt", false)
	boolean("codeConsumed")

	// refresh token family
	text("refreshTokenHash", false, true)
	text("prevRefreshTokenHash", false, true)
	date("refreshExpiresAt", false)

	// SSO
	text("parent", false, false)
	text("ssoSecretHash", false, true)

	text("impersonator", false, false)

	text("ip", false, false)
	text("userAgent", false, false)
	date("lastUsedAt", false)
	date("expiresAt", true)

	col.Fields.Add(&core.AutodateField{
		Name:     "created",
		System:   true,
		OnCreate: true,
	})
	col.Fields.Add(&core.AutodateField{
		Name:     "updated",
		System:   true,
		OnCreate: true,
		OnUpdate: true,
	})

	col.Fields.Add(&core.TextField{Name: "impersonatorSession", System: true, Hidden: true})
	col.Fields.Add(&core.TextField{Name: "impersonatorKeyHash", System: true, Hidden: true})
	col.Fields.Add(&core.DateField{Name: "refreshRotatedAt", System: true})
	col.Fields.Add(&core.TextField{Name: "otpRecordRef", System: true, Hidden: true})

	col.AddIndex("idx_authSessions_handleHash", true, "handleHash", "handleHash != ''")
	col.AddIndex("idx_authSessions_codeHash", true, "codeHash", "codeHash != ''")
	col.AddIndex("idx_authSessions_refreshTokenHash", true, "refreshTokenHash", "refreshTokenHash != ''")
	col.AddIndex("idx_authSessions_prevRefreshTokenHash", false, "prevRefreshTokenHash", "prevRefreshTokenHash != ''")
	col.AddIndex("idx_authSessions_recordRef_collectionRef", false, "recordRef, collectionRef", "")
	col.AddIndex("idx_authSessions_parent", false, "parent", "parent != ''")
	col.AddIndex("idx_authSessions_expiresAt", false, "expiresAt", "")
	col.AddIndex("idx_authSessions_impersonatorSession", false, "impersonatorSession", "impersonatorSession != ''")
	col.AddIndex("idx_authSessions_impersonator", false, "impersonator", "impersonator != ''")

	return txApp.Save(col)
}

func createOAuth2ConsentsCollection(txApp core.App, clients *core.Collection) error {
	col := core.NewBaseCollection(core.CollectionNameOAuth2Consents)
	col.System = true
	col.ListRule = types.Pointer(oauth2ConsentsOwnerRule)
	col.ViewRule = types.Pointer(oauth2ConsentsOwnerRule)
	col.DeleteRule = types.Pointer(oauth2ConsentsOwnerRule)

	col.Fields.Add(&core.TextField{
		Name:     "collectionRef",
		System:   true,
		Required: true,
	})
	col.Fields.Add(&core.TextField{
		Name:     "recordRef",
		System:   true,
		Required: true,
	})
	col.Fields.Add(&core.RelationField{
		Name:          "client",
		System:        true,
		Required:      true,
		MaxSelect:     1,
		CollectionId:  clients.Id,
		CascadeDelete: true,
	})
	col.Fields.Add(&core.JSONField{
		Name:   "scopes",
		System: true,
	})
	col.Fields.Add(&core.AutodateField{
		Name:     "created",
		System:   true,
		OnCreate: true,
	})
	col.Fields.Add(&core.AutodateField{
		Name:     "updated",
		System:   true,
		OnCreate: true,
		OnUpdate: true,
	})
	col.AddIndex("idx_oauth2Consents_collectionRef_recordRef_client", true, "collectionRef, recordRef, client", "")
	col.AddIndex("idx_oauth2Consents_client", false, "client", "")

	return txApp.Save(col)
}

func addOTPsSessionRef(txApp core.App) error {
	otps, err := txApp.FindCollectionByNameOrId(core.CollectionNameOTPs)
	if err != nil {
		return err
	}

	otps.Fields.Add(&core.TextField{
		Name:   "sessionRef",
		System: true,
	})
	otps.AddIndex("idx_otps_sessionRef", false, "sessionRef", "sessionRef != ''")

	return txApp.Save(otps)
}

// the default auth mail templates links before the hosted account pages
var legacyAuthTemplatesLinks = map[string][2]string{
	"verification": {
		core.EmailPlaceholderAppURL + "/_/#/auth/confirm-verification/" + core.EmailPlaceholderToken,
		core.EmailPlaceholderIssuerURL + "/verify-email?token=" + core.EmailPlaceholderToken,
	},
	"resetPassword": {
		core.EmailPlaceholderAppURL + "/_/#/auth/confirm-password-reset/" + core.EmailPlaceholderToken,
		core.EmailPlaceholderIssuerURL + "/password-reset/confirm?token=" + core.EmailPlaceholderToken,
	},
	"confirmEmailChange": {
		core.EmailPlaceholderAppURL + "/_/#/auth/confirm-email-change/" + core.EmailPlaceholderToken,
		core.EmailPlaceholderIssuerURL + "/email-change/confirm?token=" + core.EmailPlaceholderToken,
	},
}

// migrateAuthCollectionsToIssuers initializes the OAuth2Server options of the auth collections,
// replaces the previous upstream default auth token durations with the access token default
// and rewrites the mail templates links to the removed dashboard account confirmation pages.
func migrateAuthCollectionsToIssuers(txApp core.App) error {
	collections, err := txApp.FindAllCollections(core.CollectionTypeAuth)
	if err != nil {
		return err
	}

	// the previous upstream default auth token durations
	legacyAuthTokenDurations := []int64{604800, 432000, 86400}

	replacer := strings.NewReplacer(
		legacyAuthTemplatesLinks["verification"][0], legacyAuthTemplatesLinks["verification"][1],
		legacyAuthTemplatesLinks["resetPassword"][0], legacyAuthTemplatesLinks["resetPassword"][1],
		legacyAuthTemplatesLinks["confirmEmailChange"][0], legacyAuthTemplatesLinks["confirmEmailChange"][1],
	)

	for _, c := range collections {
		if c.OAuth2Server.CodeDuration <= 0 {
			c.OAuth2Server = core.NewAuthCollection("up").OAuth2Server
		}

		if list.ExistInSlice(c.AuthToken.Duration, legacyAuthTokenDurations) {
			c.AuthToken.Duration = 3600
		}

		c.VerificationTemplate.Body = replacer.Replace(c.VerificationTemplate.Body)
		c.ResetPasswordTemplate.Body = replacer.Replace(c.ResetPasswordTemplate.Body)
		c.ConfirmEmailChangeTemplate.Body = replacer.Replace(c.ConfirmEmailChangeTemplate.Body)

		// note: the signing keys are generated by the collection save normalization
		if err := txApp.Save(c); err != nil {
			return fmt.Errorf("failed to migrate %q to issuer: %w", c.Name, err)
		}
	}

	return nil
}

func createDashboardOAuth2Client(txApp core.App) error {
	superusers, err := txApp.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		return err
	}

	client, err := txApp.FindOAuth2ClientByClientId(core.OAuth2DashboardClientId)
	if err != nil {
		client = core.NewOAuth2Client(txApp)
		client.SetClientId(core.OAuth2DashboardClientId)
	}

	client.SetName("PocketBase dashboard")
	client.SetType(core.OAuth2ClientTypePublic)
	client.SetClientSecret("")
	client.SetFirstParty(true)
	client.SetDisabled(false)
	client.SetCollectionRef(superusers.Id)
	client.SetRedirectURIs([]string{})
	client.SetPostLogoutRedirectURIs([]string{})
	client.SetScopes([]string{core.OAuth2ScopeOpenId, core.OAuth2ScopeEmail})

	return txApp.Save(client)
}

// legacyRateLimitTags maps the removed vanilla auth rate limit tags to the
// related hosted login tags (empty value means that the rule is dropped).
var legacyRateLimitTags = map[string]string{
	"authWithPassword":     "oauth2LoginPassword",
	"authWithOTP":          "oauth2LoginOTPVerify",
	"requestOTP":           "oauth2LoginOTP",
	"authWithOAuth2":       "oauth2LoginOAuth2",
	"requestPasswordReset": "oauth2PasswordReset",
	"confirmPasswordReset": "oauth2PasswordResetConfirm",
	"confirmVerification":  "oauth2VerifyEmail",
	"confirmEmailChange":   "oauth2EmailChangeConfirm",
	"listAuthMethods":      "",
	"authRefresh":          "",
}

// legacyRateLimitPaths is the list of the removed vanilla auth endpoints path parts.
var legacyRateLimitPaths = []string{
	"/auth-methods",
	"/auth-refresh",
	"/auth-with-",
	"/request-otp",
	"/impersonate/",
	"/request-password-reset",
	"/confirm-password-reset",
	"/confirm-verification",
	"/confirm-email-change",
}

// rewriteLegacyRateLimitRules rewrites (or drops) the rules with removed vanilla auth labels.
func rewriteLegacyRateLimitRules(rules []core.RateLimitRule) []core.RateLimitRule {
	result := make([]core.RateLimitRule, 0, len(rules))

RulesLoop:
	for _, rule := range rules {
		for _, p := range legacyRateLimitPaths {
			if strings.Contains(rule.Label, p) {
				continue RulesLoop
			}
		}

		if prefix, tag, ok := strings.Cut(rule.Label, ":"); ok && !strings.HasPrefix(rule.Label, "/") {
			if replacement, legacy := legacyRateLimitTags[tag]; legacy {
				if replacement == "" {
					continue
				}
				rule.Label = prefix + ":" + replacement
			}
		}

		result = append(result, rule)
	}

	return result
}

// migrateRateLimitRules rewrites the rules of the removed vanilla auth endpoints
// and appends the default "/oauth2/" rule (unless a rule with the same label exists).
func migrateRateLimitRules(txApp core.App) error {
	// ensure that the latest stored settings are loaded
	if err := txApp.ReloadSettings(); err != nil {
		return err
	}

	settings := txApp.Settings()
	settings.RateLimits.Rules = rewriteLegacyRateLimitRules(settings.RateLimits.Rules)

	for _, rule := range settings.RateLimits.Rules {
		if rule.Label == oauth2RateLimitLabel {
			return txApp.Save(settings)
		}
	}

	settings.RateLimits.Rules = append(settings.RateLimits.Rules, core.RateLimitRule{
		Label:       oauth2RateLimitLabel,
		MaxRequests: 300,
		Duration:    10,
	})

	return txApp.Save(settings)
}
