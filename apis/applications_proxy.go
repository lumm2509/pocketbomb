package apis

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/security"
)

// applicationProxyResponseCSP keeps the proxied documents in an opaque origin
// (the proxy shares the origin of the dashboard whose tokens are in localStorage).
const applicationProxyResponseCSP = "sandbox allow-scripts allow-forms allow-popups"

// applicationProxyReservedParams are the query params set by the proxy (the client values are dropped).
var applicationProxyReservedParams = []string{
	"issuer",
	"logged_in_customer_id",
	"path_prefix",
	"timestamp",
	"body_sha256",
	"signature",
}

var applicationProxyHopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// applicationProxyStrippedResponseHeaders are never copied from the application response: the
// listed Shopify ones + the headers that act on the whole (dashboard) origin regardless of the sandbox.
var applicationProxyStrippedResponseHeaders = []string{
	"Set-Cookie",
	"Server",
	"Date",
	"Pragma",
	"X-Powered-By",
	"Clear-Site-Data",
	"Strict-Transport-Security",
	"Alt-Svc",
	"Service-Worker-Allowed",
}

// bindApplicationProxyRoutes registers the public app proxy routes.
//
// note: the methods are explicit since a method-less pattern
// would conflict with the "GET /{path...}" static catch-all.
//
// NB! A custom route that overlaps with them without being more specific or more
// general (e.g. "/{a}/foo/bar") makes the mux panic at startup (intentionally loud).
func bindApplicationProxyRoutes(app core.App, r *router.Router[*core.RequestEvent]) {
	for _, prefix := range core.ApplicationProxyPrefixes {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
			for _, suffix := range []string{"", "/{rest...}"} {
				r.Route(method, "/"+prefix+"/{subpath}"+suffix, applicationProxy(r, prefix)).
					Bind(BodyLimit(core.ApplicationProxyMaxBodySize))
			}
		}
	}
}

func applicationProxy(r *router.Router[*core.RequestEvent], prefix string) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		subpath := e.Request.PathValue("subpath")

		installation, application, manifest, err := e.App.FindActiveApplicationProxy(prefix, subpath)
		if err != nil {
			return applicationProxyFallthrough(r, e, err)
		}

		// public route, but a sent (and not loaded) token never falls back to a guest request
		// (the invalid API keys are rejected by their middleware)
		if e.Auth == nil && getAuthTokenFromRequest(e) != "" {
			return e.UnauthorizedError("Invalid or expired authorization token.", nil)
		}

		event := new(core.ApplicationProxyRequestEvent)
		event.RequestEvent = e
		event.Application = application
		event.Installation = installation

		return e.App.OnApplicationProxyRequest().Trigger(event, func(e *core.ApplicationProxyRequestEvent) error {
			return forwardApplicationProxyRequest(e.RequestEvent, e.Installation, manifest, prefix, subpath)
		})
	}
}

// applicationProxyFallthrough runs the "GET /{path...}" static
// catch-all route (if any) for a path that isn't served by an installation.
func applicationProxyFallthrough(r *router.Router[*core.RequestEvent], e *core.RequestEvent, notFoundErr error) error {
	static := r.FindRoute(http.MethodGet, "/{"+StaticWildcardParam+"...}")
	if static == nil || (e.Request.Method != http.MethodGet && e.Request.Method != http.MethodHead) {
		return e.NotFoundError("", notFoundErr)
	}

	e.Request.SetPathValue(StaticWildcardParam, strings.TrimPrefix(e.Request.URL.Path, "/"))

	chain := &hook.Hook[*core.RequestEvent]{}
	for _, middleware := range static.Middlewares {
		chain.Bind(middleware)
	}

	return chain.Trigger(e, static.Action)
}

func forwardApplicationProxyRequest(e *core.RequestEvent, installation *core.ApplicationInstallation, manifest *core.ApplicationManifest, prefix string, subpath string) error {
	rest, ok := applicationProxyRestPath(e.Request.URL.EscapedPath())
	if !ok {
		return e.NotFoundError("", nil)
	}

	params, err := url.ParseQuery(e.Request.URL.RawQuery)
	if err != nil {
		return e.BadRequestError("Invalid query string.", err)
	}

	body, err := io.ReadAll(e.Request.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) || errors.Is(err, ErrRequestEntityTooLarge) {
			return ErrRequestEntityTooLarge
		}
		return e.BadRequestError("Failed to read the request body.", err)
	}

	customerId := ""
	if e.Auth != nil && e.ActorInfo().Permissions(e.App).Kind == core.ActorKindCustomer {
		customerId = e.Auth.Id
	}

	for _, reserved := range applicationProxyReservedParams {
		params.Del(reserved)
	}

	params.Set("issuer", core.OAuth2Issuer(e.App, installation.Collection()))
	params.Set("logged_in_customer_id", customerId)
	params.Set("path_prefix", "/"+prefix+"/"+subpath)
	params.Set("timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	params.Set("body_sha256", security.SHA256(string(body)))
	params.Set("signature", core.ApplicationProxySignature(params, installation.WebhookSecret()))

	target := strings.TrimRight(manifest.AppProxy.URL, "/") + rest + "?" + params.Encode()

	res, err := e.App.ApplicationCatalogs().SendProxyRequest(e.Request.Context(), e.Request.Method, target, applicationProxyRequestHeaders(e), body)
	if err != nil {
		// note: a transport error message includes the request url (and therefore the signature)
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}

		if errors.Is(err, context.DeadlineExceeded) {
			return e.Error(http.StatusGatewayTimeout, "The application didn't respond in time.", err)
		}

		return e.Error(http.StatusBadGateway, "Failed to reach the application.", err)
	}

	header := e.Response.Header()
	for k, values := range res.Header {
		if slices.Contains(applicationProxyHopByHopHeaders, k) ||
			slices.Contains(applicationProxyStrippedResponseHeaders, k) ||
			strings.HasPrefix(k, "Access-Control-") {
			continue
		}
		header[k] = values
	}
	header.Set("Content-Security-Policy", applicationProxyResponseCSP)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")

	e.Response.WriteHeader(res.StatusCode)
	if e.Request.Method != http.MethodHead {
		if _, err := e.Response.Write(res.Body); err != nil {
			return err
		}
	}

	return nil
}

// applicationProxyRestPath returns the still escaped path after "/{prefix}/{subpath}"
// (false if it has a dot segment, also when it is encoded).
func applicationProxyRestPath(escapedPath string) (string, bool) {
	parts := strings.SplitN(escapedPath, "/", 4)
	if len(parts) < 4 {
		return "", true
	}

	decoded, err := url.PathUnescape(parts[3])
	if err != nil {
		return "", false
	}

	for _, segment := range strings.FieldsFunc(decoded, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == "." || segment == ".." {
			return "", false
		}
	}

	return "/" + parts[3], true
}

func applicationProxyRequestHeaders(e *core.RequestEvent) http.Header {
	result := e.Request.Header.Clone()

	for _, name := range strings.Split(result.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			result.Del(name)
		}
	}
	for _, name := range applicationProxyHopByHopHeaders {
		result.Del(name)
	}

	result.Del("Cookie")
	result.Del("Authorization")
	result.Del(APIKeyBuyerIPHeader)
	for name := range result {
		if strings.HasPrefix(name, "X-Pb-") && strings.HasSuffix(name, "-Key") {
			result.Del(name)
		}
	}

	// the client values of the trusted proxy headers can't reach the application
	for _, name := range e.App.Settings().TrustedProxy.Headers {
		result.Del(name)
	}
	result.Del("Forwarded")

	// let the transport handle (and limit) the compression
	result.Del("Accept-Encoding")

	buyerIP := e.RealIP()
	if apiKey, _ := e.Get(core.RequestEventKeyAPIKey).(*core.RequestInfoAPIKey); apiKey != nil && apiKey.BuyerIP != "" {
		buyerIP = apiKey.BuyerIP
	}

	result.Set("X-Forwarded-For", buyerIP)
	result.Set("X-Forwarded-Host", e.Request.Host)
	result.Set("X-Forwarded-Proto", e.RequestScheme())

	return result
}

// applicationInstallationProxyUpdate handles the app proxy path customization of
// PATCH /api/applications/installations/{id} (see [applicationInstallationUpdate]).
func applicationInstallationProxyUpdate(e *core.RequestEvent, installation *core.ApplicationInstallation, form *applicationInstallationUpdateForm) error {
	if form.Permissions != nil || form.VersionRef != nil {
		return e.BadRequestError("The proxy path must be changed on its own (without permissions or versionRef).", nil)
	}

	if err := core.CheckApplicationInstallationChange(e.App, e.ActorInfo(), installation.Record); err != nil {
		return e.ForbiddenError("You are not allowed to perform this installation change (you must hold every permission of the grant).", err)
	}

	prefix := installation.ProxyPrefix()
	if form.ProxyPrefix != nil {
		prefix = *form.ProxyPrefix
	}

	subpath := installation.ProxySubpath()
	if form.ProxySubpath != nil {
		subpath = *form.ProxySubpath
	}

	if err := e.App.UpdateApplicationInstallationProxyPath(installation, prefix, subpath); err != nil {
		return firstApiError(err, e.BadRequestError("Failed to save the proxy path.", err))
	}

	return e.JSON(http.StatusOK, newApplicationInstallationResponse(e, installation))
}
