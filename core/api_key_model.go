package core

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/lumm2509/pocketbomb/tools/types"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

const CollectionNameAPIKeys = "_apiKeys"

// API key kinds.
//
// An API key is a credential of an OAuth2 client (the "storefront"/channel), never an actor:
//   - public keys are browser-safe (always viewable, optionally restricted to allowed origins)
//   - private keys are server-only (shown once, rejected from browsers and from the query string)
const (
	APIKeyKindPublic  = "public"
	APIKeyKindPrivate = "private"
)

// Private API key buyer context modes.
const (
	// APIKeyBuyerContextRequired requires the X-PB-Buyer-IP header (the end-user IP forwarded by the server).
	APIKeyBuyerContextRequired = "required"

	// APIKeyBuyerContextNone is for the requests without end-user (e.g. background jobs).
	APIKeyBuyerContextNone = "none"
)

// API key token prefixes.
const (
	APIKeyPublicTokenPrefix  = "pb_pk_"
	APIKeyPrivateTokenPrefix = "pb_sk_"
)

// apiKeyTokenDisplayLength is the number of the token characters stored for display ("tokenPrefix").
const apiKeyTokenDisplayLength = 10

// apiKeyTokenRandomLength is the length of the random base62 token part (~256 bits).
const apiKeyTokenRandomLength = 43

const base62Alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var (
	_ Model        = (*APIKey)(nil)
	_ PreValidator = (*APIKey)(nil)
	_ RecordProxy  = (*APIKey)(nil)
)

// APIKey defines a Record proxy for working with the OAuth2 clients API keys collection.
//
// The key permissions are a ceiling of the regular collections actions of the requests
// carrying the key (the collection rules always still apply; see [Authorize]).
type APIKey struct {
	*Record
}

// NewAPIKey instantiates and returns a new blank *APIKey model.
//
// Example usage:
//
//	key := core.NewAPIKey(app)
//	key.SetName("Storefront")
//	key.SetClientRef(client.Id)
//	key.SetKind(core.APIKeyKindPublic)
//	key.SetPermissions(core.Permissions{Collections: map[string][]string{"*": {"list", "view"}}})
//	token := key.GenerateToken() // the plain token (store it, the private ones are not retrievable)
//	app.Save(key)
func NewAPIKey(app App) *APIKey {
	m := &APIKey{}

	c, err := app.FindCachedCollectionByNameOrId(CollectionNameAPIKeys)
	if err != nil {
		// this is just to make tests easier since it is a system collection and it is expected to be always accessible
		// (note: the loaded record is further checked on APIKey.PreValidate())
		c = NewBaseCollection("@__invalid__")
	}

	m.Record = NewRecord(c)

	return m
}

// PreValidate implements the [PreValidator] interface and checks
// whether the proxy is properly loaded.
func (m *APIKey) PreValidate(ctx context.Context, app App) error {
	if m.Record == nil || m.Record.Collection().Name != CollectionNameAPIKeys {
		return errors.New("missing or invalid API key ProxyRecord")
	}

	return nil
}

// ProxyRecord returns the proxied Record model.
func (m *APIKey) ProxyRecord() *Record {
	return m.Record
}

// SetProxyRecord loads the specified record model into the current proxy.
func (m *APIKey) SetProxyRecord(record *Record) {
	m.Record = record
}

// Name returns the "name" record field value.
func (m *APIKey) Name() string {
	return m.GetString("name")
}

// SetName updates the "name" record field value.
func (m *APIKey) SetName(name string) {
	m.Set("name", name)
}

// ClientRef returns the "clientRef" record field value (the OAuth2 client record id).
func (m *APIKey) ClientRef() string {
	return m.GetString("clientRef")
}

// SetClientRef updates the "clientRef" record field value.
func (m *APIKey) SetClientRef(clientId string) {
	m.Set("clientRef", clientId)
}

// Kind returns the "kind" record field value (public or private).
func (m *APIKey) Kind() string {
	return m.GetString("kind")
}

// SetKind updates the "kind" record field value.
func (m *APIKey) SetKind(kind string) {
	m.Set("kind", kind)
}

// BuyerContext returns the "buyerContext" record field value of a private key (required or none).
func (m *APIKey) BuyerContext() string {
	return m.GetString("buyerContext")
}

// SetBuyerContext updates the "buyerContext" record field value.
func (m *APIKey) SetBuyerContext(buyerContext string) {
	m.Set("buyerContext", buyerContext)
}

// TokenHash returns the "tokenHash" record field value (the sha256 hex of the plain token).
func (m *APIKey) TokenHash() string {
	return m.GetString("tokenHash")
}

// TokenPrefix returns the "tokenPrefix" record field value (the first characters of the token for display).
func (m *APIKey) TokenPrefix() string {
	return m.GetString("tokenPrefix")
}

// Token returns the plain token of a public key (always empty for the private keys).
func (m *APIKey) Token() string {
	return m.GetString("token")
}

// SetToken stores the provided plain token (its hash and display prefix; the public keys plain value too).
//
// Use [APIKey.GenerateToken] for a new random token.
func (m *APIKey) SetToken(plainToken string) {
	m.Set("tokenHash", security.SHA256(plainToken))
	m.Set("tokenPrefix", plainToken[:min(len(plainToken), apiKeyTokenDisplayLength)])

	if m.Kind() == APIKeyKindPublic {
		m.Set("token", plainToken)
	} else {
		m.Set("token", "")
	}
}

// GenerateToken generates, stores and returns a new random plain token for the key kind
// ("pb_pk_" or "pb_sk_" + 32 random bytes base62 encoded); the kind must be set first.
//
// The plain private tokens are not stored and they can't be retrieved later.
func (m *APIKey) GenerateToken() string {
	prefix := APIKeyPublicTokenPrefix
	if m.Kind() == APIKeyKindPrivate {
		prefix = APIKeyPrivateTokenPrefix
	}

	token := prefix + security.RandomStringWithAlphabet(apiKeyTokenRandomLength, base62Alphabet)

	m.SetToken(token)

	return token
}

// Permissions returns the "permissions" record field value (the regular collections actions ceiling).
func (m *APIKey) Permissions() Permissions {
	p := parseRolePermissions(m.Get("permissions"))
	p.Normalize()
	return p
}

// SetPermissions updates the "permissions" record field value.
func (m *APIKey) SetPermissions(permissions Permissions) {
	permissions = permissions.Clone()
	permissions.Normalize()
	m.Set("permissions", permissions)
}

// AllowedOrigins returns the "allowedOrigins" record field value of a public key
// (empty = any origin).
func (m *APIKey) AllowedOrigins() []string {
	return m.GetStringSlice("allowedOrigins")
}

// SetAllowedOrigins updates the "allowedOrigins" record field value.
func (m *APIKey) SetAllowedOrigins(origins []string) {
	m.Set("allowedOrigins", origins)
}

// AllowsOrigin reports whether the public key allows the provided request Origin header value
// (exact scheme, host and port match; any origin if the key doesn't have allowed origins).
func (m *APIKey) AllowsOrigin(origin string) bool {
	allowed := m.AllowedOrigins()
	if len(allowed) == 0 {
		return true
	}

	normalized, err := NormalizeAPIKeyOrigin(origin)
	if err != nil {
		return false
	}

	return slices.Contains(allowed, normalized)
}

// Disabled returns the "disabled" record field value.
func (m *APIKey) Disabled() bool {
	return m.GetBool("disabled")
}

// SetDisabled updates the "disabled" record field value.
func (m *APIKey) SetDisabled(disabled bool) {
	m.Set("disabled", disabled)
}

// ExpiresAt returns the "expiresAt" record field value (zero = never).
func (m *APIKey) ExpiresAt() types.DateTime {
	return m.GetDateTime("expiresAt")
}

// SetExpiresAt updates the "expiresAt" record field value.
func (m *APIKey) SetExpiresAt(date types.DateTime) {
	m.Set("expiresAt", date)
}

// IsExpired reports whether the key has an expiration date in the past.
func (m *APIKey) IsExpired() bool {
	expiresAt := m.ExpiresAt()
	return !expiresAt.IsZero() && !expiresAt.Time().After(types.NowDateTime().Time())
}

// IsUsable reports whether the key is enabled and not expired
// (the client state is checked separately).
func (m *APIKey) IsUsable() bool {
	return !m.Disabled() && !m.IsExpired()
}

// LastUsedAt returns the "lastUsedAt" record field value (updated at most once per minute).
func (m *APIKey) LastUsedAt() types.DateTime {
	return m.GetDateTime("lastUsedAt")
}

// CreatedBy returns the "createdBy" record field value (the creator staff record id, if any).
func (m *APIKey) CreatedBy() string {
	return m.GetString("createdBy")
}

// SetCreatedBy updates the "createdBy" record field value.
func (m *APIKey) SetCreatedBy(staffId string) {
	m.Set("createdBy", staffId)
}

// Created returns the "created" record field value.
func (m *APIKey) Created() types.DateTime {
	return m.GetDateTime("created")
}

// Updated returns the "updated" record field value.
func (m *APIKey) Updated() types.DateTime {
	return m.GetDateTime("updated")
}

// NormalizeAPIKeyOrigin validates and normalizes the provided origin
// to its lowercased "scheme://host[:port]" form (the default ports are removed).
func NormalizeAPIKeyOrigin(origin string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil {
		return "", err
	}

	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("must be an http(s) origin in the format scheme://host[:port]")
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}

	result := scheme + "://" + host
	if strings.Contains(host, ":") {
		result = scheme + "://[" + host + "]"
	}
	if port != "" {
		result += ":" + port
	}

	return result, nil
}

func (app *BaseApp) registerAPIKeyHooks() {
	// note: a key created without a token gets a random one
	// (the plain value of a private key is then not retrievable; rotate it to get one)
	app.OnRecordCreate(CollectionNameAPIKeys).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if key := (&APIKey{e.Record}); key.TokenHash() == "" {
				key.GenerateToken()
			}

			return e.Next()
		},
		Priority: -100,
	})

	app.OnRecordValidate(CollectionNameAPIKeys).Bind(&hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			key := &APIKey{e.Record}

			if errs := validateAPIKey(e.App, key); len(errs) > 0 {
				return errs
			}

			return e.Next()
		},
		Priority: 99,
	})

	// sync the original model state after each successful persist so that
	// the immutable fields of an already saved (but not refetched) key are properly validated
	syncOriginal := &hook.Handler[*RecordEvent]{
		Func: func(e *RecordEvent) error {
			if err := e.Next(); err != nil {
				return err
			}

			return e.Record.PostScan()
		},
		Priority: 98,
	}
	app.OnRecordCreateExecute(CollectionNameAPIKeys).Bind(syncOriginal)
	app.OnRecordUpdateExecute(CollectionNameAPIKeys).Bind(syncOriginal)
}

func validateAPIKey(app App, key *APIKey) validation.Errors {
	errs := validation.Errors{}

	original := key.Original()

	// immutable after create
	if !key.IsNew() {
		if key.ClientRef() != original.GetString("clientRef") {
			errs["clientRef"] = validation.NewError("validation_api_key_immutable", "The API key client cannot be changed.")
		}
		if key.Kind() != original.GetString("kind") {
			errs["kind"] = validation.NewError("validation_api_key_immutable", "The API key kind cannot be changed.")
		}
	}

	// only the regular (aka. not managed and not the dashboard) enabled clients
	if errs["clientRef"] == nil && key.ClientRef() != "" {
		client, err := app.FindOAuth2ClientById(key.ClientRef())
		switch {
		case err != nil:
			errs["clientRef"] = validation.NewError("validation_invalid_client", "Missing or invalid OAuth2 client.")
		case client.IsManaged() || client.IsDashboard():
			errs["clientRef"] = validation.NewError(
				"validation_api_key_client_not_allowed",
				"API keys are available only for the regular OAuth2 clients (not for the dashboard and the application installations clients).",
			)
		case client.Disabled() && key.IsNew():
			errs["clientRef"] = validation.NewError("validation_api_key_client_disabled", "The OAuth2 client is disabled.")
		}
	}

	switch key.Kind() {
	case APIKeyKindPublic:
		if key.BuyerContext() != "" {
			errs["buyerContext"] = validation.NewError("validation_api_key_public_buyer_context", "The public keys don't have a buyer context.")
		}

		origins := key.AllowedOrigins()
		normalized := make([]string, 0, len(origins))
		for _, o := range origins {
			n, err := NormalizeAPIKeyOrigin(o)
			if err != nil {
				errs["allowedOrigins"] = validation.NewError(
					"validation_invalid_origin",
					"Invalid origin {{.origin}} - must be in the format scheme://host[:port].",
				).SetParams(map[string]any{"origin": o})
				break
			}
			if !slices.Contains(normalized, n) {
				normalized = append(normalized, n)
			}
		}
		if errs["allowedOrigins"] == nil && len(origins) > 0 {
			key.SetAllowedOrigins(normalized)
		}

		if !strings.HasPrefix(key.Token(), APIKeyPublicTokenPrefix) || security.SHA256(key.Token()) != key.TokenHash() {
			errs["tokenHash"] = validation.NewError("validation_api_key_token", "Invalid public API key token.")
		}
	case APIKeyKindPrivate:
		if key.BuyerContext() != APIKeyBuyerContextRequired && key.BuyerContext() != APIKeyBuyerContextNone {
			errs["buyerContext"] = validation.NewError(
				"validation_api_key_buyer_context",
				"The private keys buyer context must be required or none.",
			)
		}

		if len(key.AllowedOrigins()) > 0 {
			errs["allowedOrigins"] = validation.NewError(
				"validation_api_key_private_origins",
				"The private keys can't be used from a browser and therefore they don't have allowed origins.",
			)
		}

		if key.Token() != "" || !strings.HasPrefix(key.TokenPrefix(), APIKeyPrivateTokenPrefix) {
			errs["tokenHash"] = validation.NewError("validation_api_key_token", "Invalid private API key token.")
		}
	}

	// only the regular collections actions (no system resources)
	permissions := key.Permissions()
	if len(permissions.System) > 0 {
		errs["permissions"] = validation.NewError(
			"validation_api_key_system_permissions",
			"The API keys can have only collections permissions.",
		)
	} else if err := permissions.Validate(app); err != nil {
		errs["permissions"] = err
	}

	return errs
}
