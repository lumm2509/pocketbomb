package core

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

const CollectionNameOAuth2Clients = "_oauth2Clients"

// OAuth2DashboardClientId is the public client_id of the built-in protected
// first-party OAuth2 client of the superusers dashboard (created by migration).
//
// It is a public PKCE client of the _superusers issuer and its only allowed
// redirect URI is the same-origin dashboard callback "{origin}/_/" (see [isDashboardRedirectURI]).
const OAuth2DashboardClientId = "pb_dashboard"

// OAuth2DashboardPath is the dashboard (and its OAuth2 callback) URL path.
const OAuth2DashboardPath = "/_/"

// Supported OAuth2 client types (RFC 6749 section 2.1).
const (
	OAuth2ClientTypePublic       = "public"
	OAuth2ClientTypeConfidential = "confidential"
)

// Supported OAuth2 client grant types (the stored "grantTypes" values).
//
// Note that the token exchange grant is sent on the wire as
// "urn:ietf:params:oauth:grant-type:token-exchange" (RFC 8693).
const (
	OAuth2GrantTypeAuthorizationCode = "authorization_code"
	OAuth2GrantTypeRefreshToken      = "refresh_token"
	OAuth2GrantTypeClientCredentials = "client_credentials"
	OAuth2GrantTypeTokenExchange     = "token_exchange"
)

// OAuth2GrantTypes is the list of all supported OAuth2 client grant types.
var OAuth2GrantTypes = []string{
	OAuth2GrantTypeAuthorizationCode,
	OAuth2GrantTypeRefreshToken,
	OAuth2GrantTypeClientCredentials,
	OAuth2GrantTypeTokenExchange,
}

// OAuth2DefaultGrantTypes is the list of the grant types of the regular
// (aka. not managed by an application installation) OAuth2 clients
// (it is also the behavior of the clients created before the grantTypes field).
//
// The client_credentials grant is available only for the managed clients of
// the application installations (see [OAuth2Client.IsManaged]).
var OAuth2DefaultGrantTypes = []string{
	OAuth2GrantTypeAuthorizationCode,
	OAuth2GrantTypeRefreshToken,
	OAuth2GrantTypeTokenExchange,
}

// OAuth2ManagedClientGrantTypes is the list of the (fixed) grant types of the application
// installations managed clients: client_credentials (the installation offline tokens) and
// token_exchange (the extension launch tokens exchange for the staff online tokens).
var OAuth2ManagedClientGrantTypes = []string{
	OAuth2GrantTypeClientCredentials,
	OAuth2GrantTypeTokenExchange,
}

var oauth2ClientIdRegex = regexp.MustCompile(`^[\w\-\.]+$`)

var (
	_ Model        = (*OAuth2Client)(nil)
	_ PreValidator = (*OAuth2Client)(nil)
	_ RecordProxy  = (*OAuth2Client)(nil)
)

// OAuth2Client defines a Record proxy for working with the OAuth2 server clients collection
// (aka. the applications registered to authenticate users via an auth collection OAuth2 server).
type OAuth2Client struct {
	*Record
}

// NewOAuth2Client instantiates and returns a new blank *OAuth2Client model.
//
// Example usage:
//
//	secret := security.RandomString(50)
//
//	client := core.NewOAuth2Client(app)
//	client.SetName("My app")
//	client.SetClientId("my_app")
//	client.SetClientSecret(secret) // confidential clients without secret are not usable
//	client.SetType(core.OAuth2ClientTypeConfidential)
//	client.SetCollectionRef(usersCollection.Id)
//	client.SetRedirectURIs([]string{"https://example.com/callback"})
//	app.Save(client)
func NewOAuth2Client(app App) *OAuth2Client {
	m := &OAuth2Client{}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameOAuth2Clients)
	if err != nil {
		// this is just to make tests easier since it is a system collection and it is expected to be always accessible
		// (note: the loaded record is further checked on OAuth2Client.PreValidate())
		c = NewBaseCollection("@__invalid__")
	}

	m.Record = NewRecord(c)

	return m
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *OAuth2Client) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameOAuth2Clients {
		return errors.New("missing or invalid oauth2 client ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *OAuth2Client) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *OAuth2Client) SetProxyRecord(record *Record) {
	m.Record = record
}

// Name returns the "name" record field value.
func (m *OAuth2Client) Name() string {
	return m.GetString("name")
}

// SetName updates the "name" record field value.
func (m *OAuth2Client) SetName(name string) {
	m.Set("name", name)
}

// ClientId returns the "clientId" record field value.
func (m *OAuth2Client) ClientId() string {
	return m.GetString("clientId")
}

// SetClientId updates the "clientId" record field value.
func (m *OAuth2Client) SetClientId(clientId string) {
	m.Set("clientId", clientId)
}

// ClientSecretHash returns the "clientSecretHash" record field value.
func (m *OAuth2Client) ClientSecretHash() string {
	return m.GetString("clientSecretHash")
}

// SetClientSecret hashes the provided plain client secret and
// stores it in the "clientSecretHash" record field.
//
// Set an empty string to clear the secret.
func (m *OAuth2Client) SetClientSecret(plainSecret string) {
	if plainSecret == "" {
		m.Set("clientSecretHash", "")
	} else {
		m.Set("clientSecretHash", security.SHA256(plainSecret))
	}
}

// ValidateClientSecret reports whether the provided plain secret
// matches with the stored client secret hash.
func (m *OAuth2Client) ValidateClientSecret(plainSecret string) bool {
	hash := m.ClientSecretHash()
	if hash == "" || plainSecret == "" {
		return false
	}

	return security.Equal(hash, security.SHA256(plainSecret))
}

// IsUsable reports whether the client could be used for authorization
// (aka. it is not disabled and confidential clients have a secret).
func (m *OAuth2Client) IsUsable() bool {
	return !m.Disabled() && (!m.IsConfidential() || m.ClientSecretHash() != "")
}

// Type returns the "type" record field value.
func (m *OAuth2Client) Type() string {
	return m.GetString("type")
}

// SetType updates the "type" record field value.
func (m *OAuth2Client) SetType(clientType string) {
	m.Set("type", clientType)
}

// IsConfidential reports whether the client is a confidential client
// (aka. it is required to authenticate with a client secret).
func (m *OAuth2Client) IsConfidential() bool {
	return m.Type() == OAuth2ClientTypeConfidential
}

// CollectionRef returns the "collectionRef" record field value
// (aka. the id of the auth collection acting as issuer).
func (m *OAuth2Client) CollectionRef() string {
	return m.GetString("collectionRef")
}

// SetCollectionRef updates the "collectionRef" record field value.
func (m *OAuth2Client) SetCollectionRef(collectionId string) {
	m.Set("collectionRef", collectionId)
}

// RedirectURIs returns the "redirectURIs" record field value.
func (m *OAuth2Client) RedirectURIs() []string {
	return m.GetStringSlice("redirectURIs")
}

// SetRedirectURIs updates the "redirectURIs" record field value.
func (m *OAuth2Client) SetRedirectURIs(uris []string) {
	m.Set("redirectURIs", uris)
}

// GrantTypes returns the "grantTypes" record field value.
func (m *OAuth2Client) GrantTypes() []string {
	return m.GetStringSlice("grantTypes")
}

// SetGrantTypes updates the "grantTypes" record field value.
func (m *OAuth2Client) SetGrantTypes(grantTypes []string) {
	m.Set("grantTypes", grantTypes)
}

// AllowsGrantType reports whether the client is allowed to use the provided grant type (see [OAuth2GrantTypes]).
func (m *OAuth2Client) AllowsGrantType(grantType string) bool {
	return grantType != "" && slices.Contains(m.GrantTypes(), grantType)
}

// ApplicationInstallationRef returns the "applicationInstallationRef" record field value
// (aka. the id of the application installation that manages the client).
func (m *OAuth2Client) ApplicationInstallationRef() string {
	return m.GetString("applicationInstallationRef")
}

// IsManaged reports whether the client is managed by an application installation
// (confidential, client_credentials + token_exchange only, read-only outside of the installation).
func (m *OAuth2Client) IsManaged() bool {
	return m.ApplicationInstallationRef() != ""
}

// IsDashboard reports whether the client is the built-in protected dashboard client.
func (m *OAuth2Client) IsDashboard() bool {
	return m.ClientId() == OAuth2DashboardClientId
}

// AllowsRedirectURI reports whether the provided uri is an allowed redirect URI of the client
// in the context of the provided app URL and the current request origin ("{scheme}://{host}", see [RequestEvent.RequestOrigin]).
//
// For the regular clients this is the same as [OAuth2Client.HasRedirectURI].
// The dashboard client allows only its same-origin callback (see [isDashboardRedirectURI]).
func (m *OAuth2Client) AllowsRedirectURI(uri string, appURL string, requestOrigin string) bool {
	if m.IsDashboard() {
		return isDashboardRedirectURI(uri, appURL, requestOrigin)
	}

	return m.HasRedirectURI(uri)
}

// AllowsPostLogoutRedirectURI is similar to [OAuth2Client.AllowsRedirectURI] but for the post logout redirect URIs.
func (m *OAuth2Client) AllowsPostLogoutRedirectURI(uri string, appURL string, requestOrigin string) bool {
	if m.IsDashboard() {
		return isDashboardRedirectURI(uri, appURL, requestOrigin)
	}

	return m.HasPostLogoutRedirectURI(uri)
}

// isDashboardRedirectURI reports whether the provided uri is the dashboard callback URL
// "{scheme}://{host}/_/" (without userinfo, query or fragment) where the host is either:
//   - the host of the provided app URL (Settings.Meta.AppURL) with the same scheme
//   - or the current request origin host with the same scheme ("{scheme}://{host}", see [RequestEvent.RequestOrigin];
//     the scheme is resolved from TLS or the trusted proxy forwarded proto so an http redirect
//     is never accepted for an https request)
//
// It works even when the app URL is empty or differs from the request host
// (aka. the way the dashboard is served) without being an open redirect
// (the browser always sends its own Host header).
func isDashboardRedirectURI(uri string, appURL string, requestOrigin string) bool {
	if uri == "" || len(uri) > 2000 {
		return false
	}

	u, err := url.Parse(uri)
	if err != nil ||
		(u.Scheme != "http" && u.Scheme != "https") ||
		u.Host == "" ||
		u.User != nil ||
		u.Opaque != "" ||
		u.RawQuery != "" ||
		u.Fragment != "" ||
		strings.Contains(uri, "#") ||
		u.EscapedPath() != OAuth2DashboardPath {
		return false
	}

	host := strings.ToLower(u.Host)

	if appURL != "" {
		if app, err := url.Parse(appURL); err == nil && app.Host != "" &&
			strings.EqualFold(app.Host, host) && strings.EqualFold(app.Scheme, u.Scheme) {
			return true
		}
	}

	if requestOrigin != "" {
		if req, err := url.Parse(requestOrigin); err == nil && req.Host != "" &&
			strings.EqualFold(req.Host, host) && strings.EqualFold(req.Scheme, u.Scheme) {
			return true
		}
	}

	return false
}

// HasRedirectURI reports whether the provided uri is one of the client
// registered redirect URIs (exact string match as recommended by RFC 9700).
func (m *OAuth2Client) HasRedirectURI(uri string) bool {
	return uri != "" && slices.Contains(m.RedirectURIs(), uri)
}

// PostLogoutRedirectURIs returns the "postLogoutRedirectURIs" record field value.
func (m *OAuth2Client) PostLogoutRedirectURIs() []string {
	return m.GetStringSlice("postLogoutRedirectURIs")
}

// SetPostLogoutRedirectURIs updates the "postLogoutRedirectURIs" record field value.
func (m *OAuth2Client) SetPostLogoutRedirectURIs(uris []string) {
	m.Set("postLogoutRedirectURIs", uris)
}

// HasPostLogoutRedirectURI reports whether the provided uri is one of
// the client registered post logout redirect URIs (exact string match).
func (m *OAuth2Client) HasPostLogoutRedirectURI(uri string) bool {
	return uri != "" && slices.Contains(m.PostLogoutRedirectURIs(), uri)
}

// Scopes returns the "scopes" record field value
// (aka. the scopes that the client is allowed to request).
func (m *OAuth2Client) Scopes() []string {
	return m.GetStringSlice("scopes")
}

// SetScopes updates the "scopes" record field value.
func (m *OAuth2Client) SetScopes(scopes []string) {
	m.Set("scopes", scopes)
}

// FirstParty returns the "firstParty" record field value.
func (m *OAuth2Client) FirstParty() bool {
	return m.GetBool("firstParty")
}

// SetFirstParty updates the "firstParty" record field value.
func (m *OAuth2Client) SetFirstParty(firstParty bool) {
	m.Set("firstParty", firstParty)
}

// Logo returns the "logo" record field value.
func (m *OAuth2Client) Logo() string {
	return m.GetString("logo")
}

// SetLogo updates the "logo" record field value.
func (m *OAuth2Client) SetLogo(logoURL string) {
	m.Set("logo", logoURL)
}

// Disabled returns the "disabled" record field value.
func (m *OAuth2Client) Disabled() bool {
	return m.GetBool("disabled")
}

// SetDisabled updates the "disabled" record field value.
func (m *OAuth2Client) SetDisabled(disabled bool) {
	m.Set("disabled", disabled)
}

// Created returns the "created" record field value.
func (m *OAuth2Client) Created() types.DateTime {
	return m.GetDateTime("created")
}

// Updated returns the "updated" record field value.
func (m *OAuth2Client) Updated() types.DateTime {
	return m.GetDateTime("updated")
}

func (app *BaseApp) registerOAuth2ClientHooks() {
	app.OnRecordValidate(CollectionNameOAuth2Clients).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			client := &OAuth2Client{e.Record}

			errs := validation.Errors{}

			collectionId := client.CollectionRef()
			err := validation.Validate(collectionId, validation.Required, validation.By(validateCollectionId(e.App, CollectionTypeAuth)))
			if err != nil {
				errs["collectionRef"] = err
			}

			if err := validation.Validate(client.ClientId(), validation.Match(oauth2ClientIdRegex)); err != nil {
				errs["clientId"] = err
			}

			// note: confidential clients are allowed to be created without a secret
			// (e.g. from the dashboard before calling the generate secret endpoint)
			// but they can't be used until a secret is set (see [OAuth2Client.IsUsable])

			// note: the new regular clients without grant types get the defaults on create
			grantTypesRules := []validation.Rule{validation.Each(validation.In(list.ToInterfaceSlice(OAuth2GrantTypes)...))}
			if !e.Record.IsNew() {
				grantTypesRules = append(grantTypesRules, validation.Required)
			}
			if err := validation.Validate(client.GrantTypes(), grantTypesRules...); err != nil {
				errs["grantTypes"] = err
			}

			isInstallationsIssuer := false
			if installations, err := e.App.FindCachedCollectionByNameOrId(CollectionNameApplicationInstallations); err == nil {
				isInstallationsIssuer = collectionId == installations.Id
			}

			if client.IsManaged() || e.Record.Original().GetString("applicationInstallationRef") != "" || isInstallationsIssuer {
				validateManagedOAuth2Client(e.App, client, isInstallationsIssuer, errs)
			} else if client.IsDashboard() || e.Record.Original().GetString("clientId") == OAuth2DashboardClientId {
				validateDashboardClient(e.App, client, errs)
			} else if err := validation.Validate(client.RedirectURIs(), validation.Required, validation.Each(validation.By(checkOAuth2RedirectURI))); err != nil {
				errs["redirectURIs"] = err
			}

			// the client_credentials grant is available only for the managed clients
			if !client.IsManaged() && client.AllowsGrantType(OAuth2GrantTypeClientCredentials) {
				errs["grantTypes"] = validation.NewError(
					"validation_client_credentials_managed_only",
					"The client_credentials grant is available only for the application installations clients.",
				)
			}

			if err := validation.Validate(client.PostLogoutRedirectURIs(), validation.Each(validation.By(checkOAuth2RedirectURI))); err != nil {
				errs["postLogoutRedirectURIs"] = err
			}

			if errs["collectionRef"] == nil {
				collection, _ := e.App.FindCachedCollectionByNameOrId(collectionId)

				// the superuser tokens bypass all collection rules and therefore
				// only trusted (aka. first-party) clients are allowed for the superusers issuer
				if collection != nil && collection.Name == CollectionNameSuperusers && !client.FirstParty() {
					errs["firstParty"] = validation.NewError(
						"validation_superusers_first_party_only",
						"Only first-party clients are allowed for the "+CollectionNameSuperusers+" collection.",
					)
				}

				if collection != nil {
					allowed := OAuth2AllowedScopes(e.App, collection)
					err := validation.Validate(client.Scopes(), validation.Each(validation.By(func(value any) error {
						v, _ := value.(string)
						if !slices.Contains(allowed, v) {
							return validation.NewError("validation_unknown_scope", "Unknown or unsupported scope {{.scope}}.").
								SetParams(map[string]any{"scope": v})
						}
						return nil
					})))
					if err != nil {
						errs["scopes"] = err
					}
				}
			}

			if len(errs) > 0 {
				return errs
			}

			return e.Next()
		},
		Priority: 99,
	})

	// the regular clients created without explicit grant types have the default ones
	// (aka. the behavior of the clients before the grantTypes field)
	app.OnRecordCreate(CollectionNameOAuth2Clients).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if len(e.Record.GetStringSlice("grantTypes")) == 0 && e.Record.GetString("applicationInstallationRef") == "" {
				e.Record.Set("grantTypes", slices.Clone(OAuth2DefaultGrantTypes))
			}

			return e.Next()
		},
		Priority: -100,
	})

	// the built-in dashboard client cannot be deleted
	app.OnRecordDelete(CollectionNameOAuth2Clients).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if e.Record.GetString("clientId") == OAuth2DashboardClientId {
				return errors.New("the built-in dashboard OAuth2 client cannot be deleted")
			}

			return e.Next()
		},
		Priority: -99,
	})

	// delete the related clients on auth collection delete
	// (the grants and codes are deleted by the relation cascade)
	app.OnCollectionDeleteExecute().Bind(&hook.Handler[*CollectionEvent]{
		Func: func(e *CollectionEvent) error {
			if !e.Collection.IsAuth() {
				return e.Next()
			}

			originalApp := e.App
			txErr := e.App.RunInTransaction(func(txApp App) error {
				e.App = txApp

				if err := e.Next(); err != nil {
					return err
				}

				clients, err := txApp.FindAllRecords(CollectionNameOAuth2Clients, dbx.HashExp{"collectionRef": e.Collection.Id})
				if err != nil {
					return err
				}

				for _, c := range clients {
					if err := txApp.Delete(c); err != nil {
						return err
					}
				}

				return nil
			})
			e.App = originalApp

			return txErr
		},
		Priority: 99,
	})
}

func checkOAuth2RedirectURI(value any) error {
	v, _ := value.(string)

	u, err := url.Parse(v)
	if v == "" || err != nil || u.Scheme == "" || u.Opaque != "" || u.Fragment != "" || u.User != nil {
		return validation.NewError("validation_invalid_redirect_uri", "Must be an absolute URI without fragment and user info.")
	}

	if (u.Scheme == "http" || u.Scheme == "https") && u.Host == "" {
		return validation.NewError("validation_invalid_redirect_uri", "Missing redirect URI host.")
	}

	return nil
}

// validateManagedOAuth2Client checks the fixed fields of an application installation managed client:
// a confidential, not first-party, client_credentials + token_exchange (see [OAuth2ManagedClientGrantTypes]) client of the _applicationInstallations
// issuer without redirect URIs and scopes (the token scopes are derived from the installation grant),
// bound to an existing installation (the binding cannot change).
func validateManagedOAuth2Client(app App, client *OAuth2Client, isInstallationsIssuer bool, errs validation.Errors) {
	fixed := func(field string) {
		errs[field] = validation.NewError(
			"validation_managed_client_fixed",
			"The application installation managed OAuth2 client field cannot have this value.",
		)
	}

	installationId := client.ApplicationInstallationRef()

	if installationId == "" || (!client.IsNew() && client.Original().GetString("applicationInstallationRef") != installationId) {
		fixed("applicationInstallationRef")
	} else if installation, err := app.FindApplicationInstallationById(installationId); err != nil ||
		installation.Collection().Id != client.CollectionRef() {
		fixed("applicationInstallationRef")
	}

	if !isInstallationsIssuer {
		fixed("collectionRef")
	}

	if client.Type() != OAuth2ClientTypeConfidential {
		fixed("type")
	}

	if client.FirstParty() {
		fixed("firstParty")
	}

	if gt := slices.Clone(client.GrantTypes()); len(gt) != len(OAuth2ManagedClientGrantTypes) ||
		!slices.Equal(slices.Sorted(slices.Values(gt)), slices.Sorted(slices.Values(OAuth2ManagedClientGrantTypes))) {
		fixed("grantTypes")
	}

	if len(client.RedirectURIs()) > 0 {
		fixed("redirectURIs")
	}

	if len(client.PostLogoutRedirectURIs()) > 0 {
		fixed("postLogoutRedirectURIs")
	}

	if len(client.Scopes()) > 0 {
		fixed("scopes")
	}
}

// validateDashboardClient checks the protected fields of the built-in dashboard client:
// it must remain an enabled public first-party client of the _superusers issuer
// without stored redirect URIs (its callback is the same-origin dashboard URL).
func validateDashboardClient(app App, client *OAuth2Client, errs validation.Errors) {
	protected := func(field string) {
		errs[field] = validation.NewError(
			"validation_dashboard_client_protected",
			"The built-in dashboard OAuth2 client field cannot be changed.",
		)
	}

	if !client.IsDashboard() {
		protected("clientId")
	}

	if client.Disabled() {
		protected("disabled")
	}

	if client.Type() != OAuth2ClientTypePublic {
		protected("type")
	}

	if !client.FirstParty() {
		protected("firstParty")
	}

	if len(client.RedirectURIs()) > 0 {
		protected("redirectURIs")
	}

	if len(client.PostLogoutRedirectURIs()) > 0 {
		protected("postLogoutRedirectURIs")
	}

	superusers, err := app.FindCachedCollectionByNameOrId(CollectionNameSuperusers)
	if err != nil || client.CollectionRef() != superusers.Id {
		protected("collectionRef")
	}
}

// CheckOAuth2ClientChange checks whether the request actor is allowed to create, update or delete
// the provided OAuth2 client record (the clients of the _superusers issuer and the
// first-party clients, aka. the consent bypass, are Owner only).
//
// A nil info is treated as a trusted programmatic change.
func CheckOAuth2ClientChange(app App, info *RequestInfo, client *Record) error {
	if info == nil || info.IsOwner(app) {
		return nil
	}

	superusers, err := app.FindCachedCollectionByNameOrId(CollectionNameSuperusers)
	if err != nil {
		return err
	}

	if client.GetString("collectionRef") == superusers.Id ||
		(!client.IsNew() && client.Original().GetString("collectionRef") == superusers.Id) {
		return errPermissionDenied
	}

	// creating, changing (e.g. its redirect URIs) or deleting a first-party client
	// (aka. no consent screen) is Owner only
	if client.GetBool("firstParty") || (!client.IsNew() && client.Original().GetBool("firstParty")) {
		return errPermissionDenied
	}

	return nil
}
