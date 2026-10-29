package core

import (
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/lumm2509/pocketbomb/tools/inflector"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/security"
)

// Common request store keys used by the middlewares and api handlers.
const (
	RequestEventKeyInfoContext = "infoContext"

	// RequestEventKeyOAuth2 is the store key of the [*RequestInfoOAuth2]
	// data extracted from the loaded OAuth2 server access token (if any).
	RequestEventKeyOAuth2 = "oauth2"

	// RequestEventKeyAPIKey is the store key of the [*RequestInfoAPIKey]
	// data of the verified request API key (if any).
	RequestEventKeyAPIKey = "apiKey"
)

// RequestEvent defines the PocketBase router handler event.
type RequestEvent struct {
	App App

	cachedRequestInfo *RequestInfo
	cachedActorInfo   *RequestInfo

	Auth *Record

	router.Event

	mu sync.Mutex
}

// RequestScheme returns the scheme ("http" or "https") of the current request.
//
// It is "https" for TLS connections. Otherwise, only when a trusted proxy is
// configured (Settings.TrustedProxy.Headers is not empty, aka. the same trust
// requirement as for [RequestEvent.RealIP]), the last X-Forwarded-Proto or
// RFC 7239 Forwarded "proto" value set by the proxy is used.
// Defaults to "http".
func (e *RequestEvent) RequestScheme() string {
	if e.IsTLS() {
		return "https"
	}

	if len(e.App.Settings().TrustedProxy.Headers) == 0 {
		return "http"
	}

	// note: the last value is expected to be the one controlled by the proxy
	if values := e.Request.Header.Values("X-Forwarded-Proto"); len(values) > 0 {
		parts := strings.Split(values[len(values)-1], ",")
		if proto := strings.ToLower(strings.TrimSpace(parts[len(parts)-1])); proto == "https" || proto == "http" {
			return proto
		}
	}

	if values := e.Request.Header.Values("Forwarded"); len(values) > 0 {
		elements := strings.Split(values[len(values)-1], ",")
		for _, pair := range strings.Split(elements[len(elements)-1], ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if ok && strings.EqualFold(k, "proto") {
				if proto := strings.ToLower(strings.Trim(v, `"`)); proto == "https" || proto == "http" {
					return proto
				}
			}
		}
	}

	return "http"
}

// RequestOrigin returns the "{scheme}://{host}" origin of the current request
// (see [RequestEvent.RequestScheme]).
func (e *RequestEvent) RequestOrigin() string {
	if e.Request.Host == "" {
		return ""
	}

	return e.RequestScheme() + "://" + strings.ToLower(e.Request.Host)
}

// RealIP returns the "real" IP address from the configured trusted proxy headers.
//
// If Settings.TrustedProxy is not configured or the found IP is empty,
// it fallbacks to e.RemoteIP().
//
// NB!
// Be careful when used in a security critical context as it relies on
// the trusted proxy to be properly configured and your app to be accessible only through it.
// If you are not sure, use e.RemoteIP().
func (e *RequestEvent) RealIP() string {
	settings := e.App.Settings()

	for _, h := range settings.TrustedProxy.Headers {
		headerValues := e.Request.Header.Values(h)
		if len(headerValues) == 0 {
			continue
		}

		// extract the last header value as it is expected to be the one controlled by the proxy
		ipsList := headerValues[len(headerValues)-1]
		if ipsList == "" {
			continue
		}

		ips := strings.Split(ipsList, ",")

		if settings.TrustedProxy.UseLeftmostIP {
			for _, ip := range ips {
				parsed, err := netip.ParseAddr(strings.TrimSpace(ip))
				if err == nil {
					return parsed.StringExpanded()
				}
			}
		} else {
			for i := len(ips) - 1; i >= 0; i-- {
				parsed, err := netip.ParseAddr(strings.TrimSpace(ips[i]))
				if err == nil {
					return parsed.StringExpanded()
				}
			}
		}
	}

	return e.RemoteIP()
}

// RequestInfo parses the current request into RequestInfo instance.
//
// Note that the returned result is cached to avoid copying the request data multiple times
// but the auth state and other common store items are always refreshed in case they were changed by another handler.
func (e *RequestEvent) RequestInfo() (*RequestInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.cachedRequestInfo != nil {
		e.cachedRequestInfo.Auth = e.Auth
		e.cachedRequestInfo.OAuth2 = e.requestInfoOAuth2()
		e.cachedRequestInfo.APIKey = e.requestInfoAPIKey()

		infoCtx, _ := e.Get(RequestEventKeyInfoContext).(string)
		if infoCtx != "" {
			e.cachedRequestInfo.Context = infoCtx
		} else {
			e.cachedRequestInfo.Context = RequestInfoContextDefault
		}
	} else {
		// (re)init e.cachedRequestInfo based on the current request event
		if err := e.initRequestInfo(); err != nil {
			return nil, err
		}
	}

	return e.cachedRequestInfo, nil
}

func (e *RequestEvent) initRequestInfo() error {
	infoCtx, _ := e.Get(RequestEventKeyInfoContext).(string)
	if infoCtx == "" {
		infoCtx = RequestInfoContextDefault
	}

	info := &RequestInfo{
		Context:          infoCtx,
		Method:           e.Request.Method,
		Query:            map[string]string{},
		Headers:          map[string]string{},
		Body:             map[string]any{},
		permissionsCache: &requestInfoPermissionsCache{},
	}

	if err := e.BindBody(&info.Body); err != nil {
		return err
	}

	// extract the first value of all query params
	query := e.Request.URL.Query()
	for k, v := range query {
		if len(v) > 0 {
			info.Query[k] = v[0]
		}
	}

	// extract the first value of all headers and normalizes the keys
	// ("X-Token" is converted to "x_token")
	for k, v := range e.Request.Header {
		if len(v) > 0 {
			info.Headers[inflector.Snakecase(k)] = v[0]
		}
	}

	info.Auth = e.Auth
	info.OAuth2 = e.requestInfoOAuth2()
	info.APIKey = e.requestInfoAPIKey()

	e.cachedRequestInfo = info

	return nil
}

// requestInfoOAuth2 returns the stored OAuth2 access token data
// but only if it is related to the current e.Auth record.
func (e *RequestEvent) requestInfoOAuth2() RequestInfoOAuth2 {
	data, _ := e.Get(RequestEventKeyOAuth2).(*RequestInfoOAuth2)
	if data == nil ||
		e.Auth == nil ||
		data.authRecordId != e.Auth.Id ||
		data.authCollectionId != e.Auth.Collection().Id {
		return RequestInfoOAuth2{Scopes: []string{}}
	}

	return RequestInfoOAuth2{
		ClientId:                  data.ClientId,
		Scopes:                    slices.Clone(data.Scopes),
		FirstParty:                data.FirstParty,
		ApplicationInstallationId: data.ApplicationInstallationId,
		SessionId:                 data.SessionId,
		Impersonated:              data.Impersonated,
	}
}

// requestInfoAPIKey returns a copy of the stored request API key data (nil if the request doesn't have a key).
func (e *RequestEvent) requestInfoAPIKey() *RequestInfoAPIKey {
	data, _ := e.Get(RequestEventKeyAPIKey).(*RequestInfoAPIKey)

	return data.Clone()
}

// -------------------------------------------------------------------

const (
	RequestInfoContextDefault       = "default"
	RequestInfoContextExpand        = "expand"
	RequestInfoContextRealtime      = "realtime"
	RequestInfoContextProtectedFile = "protectedFile"
	RequestInfoContextBatch         = "batch"
	RequestInfoContextOAuth2        = "oauth2"
	RequestInfoContextOTP           = "otp"
	RequestInfoContextPasswordAuth  = "password"
)

// RequestInfo defines a HTTP request data struct, usually used
// as part of the `@request.*` filter resolver.
//
// The Query and Headers fields contains only the first value for each found entry.
type RequestInfo struct {
	Query   map[string]string `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    map[string]any    `json:"body"`
	Auth    *Record           `json:"auth"`
	Method  string            `json:"method"`
	Context string            `json:"context"`

	// OAuth2 holds the client and scopes of the request OAuth2 server
	// access token (it is empty for the regular auth tokens).
	OAuth2 RequestInfoOAuth2 `json:"oauth2"`

	// APIKey holds the OAuth2 client API key data of the request (nil if the request doesn't have a key).
	//
	// The key identifies the client (aka. the channel), never a person
	// and its permissions are a ceiling of the regular collections actions (see [Authorize]).
	APIKey *RequestInfoAPIKey `json:"apiKey"`

	// permissionsCache caches the resolved RBAC actor permissions (see [RequestInfo.Permissions]).
	permissionsCache *requestInfoPermissionsCache
}

// RequestInfoOAuth2 defines the OAuth2 server access token related request data.
type RequestInfoOAuth2 struct {
	// ClientId is the public client_id of the OAuth2 client the access token was issued to.
	ClientId string `json:"clientId"`

	// Scopes is the list of the access token granted scopes.
	Scopes []string `json:"scopes"`

	// FirstParty indicates whether the access token client is a trusted first-party client.
	FirstParty bool `json:"firstParty"`

	// ApplicationInstallationId is the id of the application installation that manages
	// the access token client (empty for the regular clients).
	//
	// For a staff actor it marks an application extension online token (the staff member
	// on behalf of the installation, see [ActorPermissions.OnBehalfOf]).
	ApplicationInstallationId string `json:"applicationInstallationId,omitempty"`

	// SessionId is the access token auth session id ("sid" claim).
	SessionId string `json:"sessionId,omitzero"`

	// Impersonated indicates whether the access token is an impersonation token ("act" claim).
	Impersonated bool `json:"impersonated,omitzero"`

	authRecordId     string
	authCollectionId string
}

// NewRequestInfoOAuth2 extracts the OAuth2 server data from an already
// verified auth token of the provided auth record (see [App.FindAuthRecordByToken]).
//
// Returns nil if the token is not an OAuth2 server access token.
//
// The result is usually stored in the request event store under the
// [RequestEventKeyOAuth2] key so that it can be used with [RequestEvent.RequestInfo].
func NewRequestInfoOAuth2(authRecord *Record, token string) *RequestInfoOAuth2 {
	if authRecord == nil {
		return nil
	}

	claims, err := security.ParseUnverifiedJWT(token)
	if err != nil {
		return nil
	}

	clientId, _ := claims[TokenClaimOAuth2ClientId].(string)
	if clientId == "" {
		return nil
	}

	scope, _ := claims[TokenClaimOAuth2Scope].(string)

	sessionId, _ := claims[TokenClaimOAuth2SessionId].(string)

	return &RequestInfoOAuth2{
		ClientId:         clientId,
		Scopes:           strings.Fields(scope),
		SessionId:        sessionId,
		Impersonated:     claims[TokenClaimOAuth2Actor] != nil,
		authRecordId:     authRecord.Id,
		authCollectionId: authRecord.Collection().Id,
	}
}

// RequestInfoAPIKey defines the verified request API key data (see [APIKey]).
type RequestInfoAPIKey struct {
	// ClientId is the public client_id of the OAuth2 client of the key.
	ClientId string `json:"clientId"`

	// KeyId is the API key record id.
	KeyId string `json:"keyId"`

	// KeyKind is the API key kind (public or private).
	KeyKind string `json:"keyKind"`

	// BuyerIP is the end-user IP forwarded with a private key (X-PB-Buyer-IP; empty for the public keys).
	BuyerIP string `json:"buyerIP"`

	// Permissions is the key regular collections actions ceiling.
	Permissions Permissions `json:"permissions"`

	tokenHash string
}

// NewRequestInfoAPIKey returns the request data of a verified API key of the provided client
// (the key, the client and the buyer IP are expected to be already checked).
func NewRequestInfoAPIKey(client *OAuth2Client, key *APIKey, buyerIP string) *RequestInfoAPIKey {
	return &RequestInfoAPIKey{
		ClientId:    client.ClientId(),
		KeyId:       key.Id,
		KeyKind:     key.Kind(),
		BuyerIP:     buyerIP,
		Permissions: key.Permissions(),
		tokenHash:   key.TokenHash(),
	}
}

// IsSameToken reports whether the client data was created for the current token of the provided key
// (false after the key rotation).
func (c *RequestInfoAPIKey) IsSameToken(key *APIKey) bool {
	return c != nil && key != nil && c.KeyId == key.Id && c.tokenHash != "" && c.tokenHash == key.TokenHash()
}

// Clone returns a deep copy of the client data (nil for nil).
func (c *RequestInfoAPIKey) Clone() *RequestInfoAPIKey {
	if c == nil {
		return nil
	}

	clone := *c
	clone.Permissions = c.Permissions.Clone()

	return &clone
}

// HasScope reports whether the specified scope is one of the granted OAuth2 scopes.
func (info RequestInfoOAuth2) HasScope(scope string) bool {
	return slices.Contains(info.Scopes, scope)
}

// Clone creates a new shallow copy of the current RequestInfo and its Auth record (if any).
func (info *RequestInfo) Clone() *RequestInfo {
	clone := &RequestInfo{
		Method:  info.Method,
		Context: info.Context,
		Query:   maps.Clone(info.Query),
		Body:    maps.Clone(info.Body),
		Headers: maps.Clone(info.Headers),
		OAuth2: RequestInfoOAuth2{
			ClientId:                  info.OAuth2.ClientId,
			Scopes:                    slices.Clone(info.OAuth2.Scopes),
			FirstParty:                info.OAuth2.FirstParty,
			ApplicationInstallationId: info.OAuth2.ApplicationInstallationId,
			SessionId:                 info.OAuth2.SessionId,
			Impersonated:              info.OAuth2.Impersonated,
			authRecordId:              info.OAuth2.authRecordId,
			authCollectionId:          info.OAuth2.authCollectionId,
		},
		APIKey:           info.APIKey.Clone(),
		permissionsCache: &requestInfoPermissionsCache{},
	}

	if info.Auth != nil {
		clone.Auth = info.Auth.Fresh()
	}

	return clone
}
