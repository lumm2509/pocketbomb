package apis

import (
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

const (
	DefaultLoadAPIKeyMiddlewareId               = "pbLoadAPIKey"
	DefaultRequireClientCredentialsMiddlewareId = "pbRequireClientCredentials"

	// note: after the auth token loader (the bearer client is cross-checked)
	// and before the rate limiter (the API key buckets)
	DefaultLoadAPIKeyMiddlewarePriority = DefaultLoadAuthTokenMiddlewarePriority + 2
)

// API key request headers and query parameter.
const (
	// APIKeyPublicHeader is the public (browser-safe) API key header.
	APIKeyPublicHeader = "X-PB-Public-Key"

	// APIKeyPrivateHeader is the private (server-only) API key header.
	APIKeyPrivateHeader = "X-PB-Private-Key"

	// APIKeyBuyerIPHeader is the end-user IP forwarded by the server with a private key.
	APIKeyBuyerIPHeader = "X-PB-Buyer-IP"

	// APIKeyPublicQueryParam is the public API key query parameter (e.g. for EventSource; public keys only).
	APIKeyPublicQueryParam = "pk"
)

// apiKeyLastUsedThrottle is the min interval between two lastUsedAt writes of the same key.
const apiKeyLastUsedThrottle = time.Minute

const apiKeysLastUsedStoreKey = "__pbAPIKeysLastUsed__"

// loadAPIKey resolves the request OAuth2 client API key (if any) and stores it
// as [core.RequestInfoAPIKey] under the [core.RequestEventKeyAPIKey] request store key.
//
// A request with an invalid, unknown, disabled or expired key (or a key of a disabled client)
// is rejected with 401 (it never falls back to a guest request). Also rejected with 401:
//   - a private key in the query string or from a browser (the fetch metadata headers, see [hasBrowserFetchMetadata])
//   - a private key with required buyer context without a valid X-PB-Buyer-IP header
//   - a public key with allowed origins and a not allowed Origin header
//   - an OAuth2 access token of another client than the key client
//
// This middleware is registered by default for all routes.
func loadAPIKey() *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Id:       DefaultLoadAPIKeyMiddlewareId,
		Priority: DefaultLoadAPIKeyMiddlewarePriority,
		Func: func(e *core.RequestEvent) error {
			client, err := resolveAPIKey(e)
			if err != nil {
				return err
			}

			if client != nil {
				e.Set(core.RequestEventKeyAPIKey, client)
			}

			return e.Next()
		},
	}
}

// resolveAPIKey resolves and checks the request API key (nil if the request doesn't have one).
func resolveAPIKey(e *core.RequestEvent) (*core.RequestInfoAPIKey, error) {
	publicToken := e.Request.Header.Get(APIKeyPublicHeader)
	fromQuery := false
	if publicToken == "" {
		publicToken = e.Request.URL.Query().Get(APIKeyPublicQueryParam)
		fromQuery = publicToken != ""
	}

	privateToken := e.Request.Header.Get(APIKeyPrivateHeader)

	if publicToken == "" && privateToken == "" {
		return nil, nil
	}

	if publicToken != "" && privateToken != "" {
		return nil, e.UnauthorizedError("Send either a public or a private API key, not both.", nil)
	}

	token := publicToken
	kind := core.APIKeyKindPublic
	if privateToken != "" {
		token = privateToken
		kind = core.APIKeyKindPrivate
	}

	if strings.HasPrefix(publicToken, core.APIKeyPrivateTokenPrefix) {
		if fromQuery {
			return nil, e.UnauthorizedError("The private API keys can't be sent in the query string (send them only from a server with the "+APIKeyPrivateHeader+" header).", nil)
		}
		return nil, e.UnauthorizedError("The private API keys must be sent with the "+APIKeyPrivateHeader+" header.", nil)
	}

	// the private keys are server-only
	if kind == core.APIKeyKindPrivate && hasBrowserFetchMetadata(e.Request.Header) {
		return nil, e.UnauthorizedError("The private API keys can't be used from a browser.", nil)
	}

	key, err := e.App.FindAPIKeyByToken(token)
	if err != nil || key.Kind() != kind {
		return nil, e.UnauthorizedError("Invalid API key.", err)
	}

	if !key.IsUsable() {
		return nil, e.UnauthorizedError("The API key is disabled or expired.", nil)
	}

	client, err := e.App.FindOAuth2ClientById(key.ClientRef())
	if err != nil || client.Disabled() || client.IsManaged() || client.IsDashboard() {
		return nil, e.UnauthorizedError("The API key client is missing or disabled.", err)
	}

	var buyerIP string

	switch kind {
	case core.APIKeyKindPrivate:
		if rawIP := e.Request.Header.Get(APIKeyBuyerIPHeader); rawIP != "" {
			ip, err := netip.ParseAddr(strings.TrimSpace(rawIP))
			if err != nil {
				return nil, e.UnauthorizedError("Invalid "+APIKeyBuyerIPHeader+" header value.", err)
			}
			buyerIP = ip.StringExpanded()
		} else if key.BuyerContext() == core.APIKeyBuyerContextRequired {
			return nil, e.UnauthorizedError("The API key requires the "+APIKeyBuyerIPHeader+" header (the end-user IP).", nil)
		}
	case core.APIKeyKindPublic:
		if origin := e.Request.Header.Get("Origin"); origin != "" && !key.AllowsOrigin(origin) {
			return nil, e.UnauthorizedError("The API key is not allowed for this origin.", nil)
		}
	}

	// the access token (if any) must be issued to the same client
	if e.Auth != nil {
		oauth2, _ := e.Get(core.RequestEventKeyOAuth2).(*core.RequestInfoOAuth2)
		if oauth2 == nil || oauth2.ClientId != client.ClientId() {
			return nil, e.UnauthorizedError("The access token and the API key must belong to the same OAuth2 client.", nil)
		}
	}

	touchAPIKeyLastUsed(e.App, key.Id)

	return core.NewRequestInfoAPIKey(client, key, buyerIP), nil
}

// hasBrowserFetchMetadata reports whether the request headers have the browser fetch metadata.
//
// The browsers always send Sec-Fetch-Site and Sec-Fetch-Dest together with Sec-Fetch-Mode.
// Note that Sec-Fetch-Mode alone is not a browser indicator because the Node.js fetch (undici)
// always sends "sec-fetch-mode: cors" from the servers too.
func hasBrowserFetchMetadata(header http.Header) bool {
	return header.Get("Sec-Fetch-Site") != "" || header.Get("Sec-Fetch-Dest") != ""
}

// touchAPIKeyLastUsed updates the key lastUsedAt at most once per [apiKeyLastUsedThrottle]
// (a direct column update, aka. no model hooks and no write per request).
func touchAPIKeyLastUsed(app core.App, keyId string) {
	state := app.Store().GetOrSet(apiKeysLastUsedStoreKey, func() any {
		return &apiKeysLastUsed{times: map[string]time.Time{}}
	}).(*apiKeysLastUsed)

	now := time.Now()

	state.mu.Lock()
	last, ok := state.times[keyId]
	if ok && now.Sub(last) < apiKeyLastUsedThrottle {
		state.mu.Unlock()
		return
	}
	state.times[keyId] = now
	state.mu.Unlock()

	_, err := app.NonconcurrentDB().Update(
		core.CollectionNameAPIKeys,
		dbx.Params{"lastUsedAt": types.NowDateTime().String()},
		dbx.HashExp{"id": keyId},
	).Execute()
	if err != nil {
		app.Logger().Warn("Failed to update the API key lastUsedAt", "keyId", keyId, "error", err)
	}
}

type apiKeysLastUsed struct {
	mu    sync.Mutex
	times map[string]time.Time
}

// requireClientCredentials is a middleware that rejects (401 "missing_client_credentials")
// the requests without an API key and without an auth token (deny by default).
func requireClientCredentials() *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Id: DefaultRequireClientCredentialsMiddlewareId,
		Func: func(e *core.RequestEvent) error {
			if err := checkClientCredentials(e); err != nil {
				return err
			}

			return e.Next()
		},
	}
}

// checkClientCredentials returns a 401 error if the request has neither an API key nor an auth token.
func checkClientCredentials(e *core.RequestEvent) error {
	if e.Auth != nil || e.Get(core.RequestEventKeyAPIKey) != nil {
		return nil
	}

	return e.UnauthorizedError(
		"Missing client credentials - send an API key ("+APIKeyPublicHeader+" or "+APIKeyPrivateHeader+") or an OAuth2 access token.",
		validation.Errors{"client": validation.NewError(
			"missing_client_credentials",
			"The request must identify its client with an API key or an OAuth2 access token.",
		)},
	)
}
