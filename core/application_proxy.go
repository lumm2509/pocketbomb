package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/tools/safehttp"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// Application proxy (the Shopify App Proxy equivalent)
// -------------------------------------------------------------------
//
// An installation with the app_proxy permission receives the public "/{prefix}/{subpath}/{rest...}"
// requests at its installed version manifest app_proxy.url + "/{rest...}" (a url change therefore applies
// as soon as the installation is on the new version, while the path is fixed on install and only the
// staff can change it). See apis/applications_proxy.go for the request handling.

// ApplicationProxyManifestScope is the manifest spelling of the system scope of [PermissionResourceAppProxy]
// (normalized to its system: form so that it can't collide with a collection named "app_proxy").
const ApplicationProxyManifestScope = "write_app_proxy"

// Application proxy limits.
const (
	ApplicationProxyMaxBodySize  int64 = 10 << 20
	ApplicationProxyTimeout            = 30 * time.Second
	applicationProxyMaxRedirects       = 3
)

// ApplicationProxyPrefixes is the list of the supported public app proxy path prefixes.
var ApplicationProxyPrefixes = []string{"a", "apps", "community", "tools"}

var (
	applicationProxySubpathRegex    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,30}$`)
	applicationProxyReservedSubpath = []string{"admin", "services", "password", "login"}
)

func checkApplicationProxyPrefix(value any) error {
	v, _ := value.(string)
	if v != "" && !slices.Contains(ApplicationProxyPrefixes, v) {
		return validation.NewError("validation_invalid_app_proxy_prefix", "Must be one of "+strings.Join(ApplicationProxyPrefixes, ", ")+".")
	}

	return nil
}

func checkApplicationProxySubpath(value any) error {
	v, _ := value.(string)
	if v == "" {
		return nil
	}

	if !applicationProxySubpathRegex.MatchString(v) {
		return validation.NewError("validation_invalid_app_proxy_subpath", "Must be 1-30 letters, numbers, underscores or dashes.")
	}

	if slices.Contains(applicationProxyReservedSubpath, strings.ToLower(v)) {
		return validation.NewError("validation_reserved_app_proxy_subpath", "The subpath can't be "+strings.Join(applicationProxyReservedSubpath, ", ")+".")
	}

	return nil
}

func checkApplicationProxyURLShape(value any) error {
	v, _ := value.(string)

	u, err := url.Parse(v)
	if err != nil {
		return nil // reported by the url format check
	}

	if u.RawQuery != "" || u.ForceQuery {
		return validation.NewError("validation_app_proxy_url_query", "The url can't have a query string.")
	}

	return nil
}

// checkApplicationInstallationProxyPath checks the installation proxy path format and that it isn't taken.
func checkApplicationInstallationProxyPath(app App, record *Record) error {
	prefix := record.GetString("proxyPrefix")
	subpath := record.GetString("proxySubpath")

	if prefix == "" && subpath == "" {
		return nil
	}

	if prefix == "" || subpath == "" {
		return validation.NewError("validation_app_proxy_path_incomplete", "Both the proxy prefix and subpath are required.")
	}

	if err := checkApplicationProxyPrefix(prefix); err != nil {
		return err
	}

	if err := checkApplicationProxySubpath(subpath); err != nil {
		return err
	}

	var total int
	err := app.RecordQuery(CollectionNameApplicationInstallations).
		Select("count(*)").
		AndWhere(dbx.HashExp{"proxyPrefix": prefix, "proxySubpath": subpath}).
		AndWhere(dbx.Not(dbx.HashExp{"id": record.Id})).
		Row(&total)
	if err != nil {
		return err
	}

	if total > 0 {
		return validation.NewError("validation_app_proxy_path_conflict", fmt.Sprintf("The proxy path /%s/%s is used by another installation.", prefix, subpath))
	}

	return nil
}

// assignApplicationInstallationProxyPath sets the installation proxy path from the provided manifest if
// it doesn't have one yet and it is granted the app proxy (reports whether it was set).
func assignApplicationInstallationProxyPath(installation *ApplicationInstallation, manifest *ApplicationManifest) bool {
	if manifest.AppProxy == nil || installation.ProxySubpath() != "" ||
		!installation.Permissions().HasSystem(PermissionResourceAppProxy, PermissionLevelWrite) {
		return false
	}

	installation.Set("proxyPrefix", manifest.AppProxy.Prefix)
	installation.Set("proxySubpath", manifest.AppProxy.Subpath)

	return true
}

// UpdateApplicationInstallationProxyPath changes the installation public proxy path
// (the application is notified, best-effort, since the path is part of the signed requests).
func (app *BaseApp) UpdateApplicationInstallationProxyPath(installation *ApplicationInstallation, prefix string, subpath string) error {
	if installation == nil || installation.Id == "" {
		return errors.New("missing application installation")
	}

	fresh, err := app.FindApplicationInstallationById(installation.Id)
	if err != nil {
		return err
	}

	fresh.Set("proxyPrefix", prefix)
	fresh.Set("proxySubpath", subpath)

	if err := app.Save(fresh); err != nil {
		return err
	}

	installation.SetProxyRecord(fresh.Record)

	if installation.IsActive() {
		if application, version, manifest, err := findApplicationInstallationManifest(app, installation); err == nil {
			app.notifyApplicationProxyUpdated(installation, application, version, manifest)
		}
	}

	return nil
}

func (app *BaseApp) notifyApplicationProxyUpdated(installation *ApplicationInstallation, application *Application, version *ApplicationVersion, manifest *ApplicationManifest) {
	if manifest.InstallURL == "" {
		return
	}

	client, err := app.FindApplicationInstallationClient(installation.Id)
	if err != nil {
		return
	}

	err = app.sendApplicationNotification(context.Background(), &applicationNotification{
		event:          ApplicationEventAppProxyUpdated,
		url:            manifest.InstallURL,
		handle:         application.Handle(),
		version:        version.Version(),
		installationId: installation.Id,
		clientId:       client.ClientId(),
		scopes:         ApplicationGrantScopes(app, installation.Permissions()),
		proxyPath:      installation.ProxyPathPrefix(),
	})
	if err != nil {
		app.Logger().Warn(
			"Failed to send the application proxy path notification",
			slog.String("installation", installation.Id),
			slog.String("error", err.Error()),
		)
	}
}

// FindActiveApplicationProxy returns the active installation (with its application and manifest)
// served at the provided proxy path; the installation must still be granted the app proxy
// and its installed version must have an app_proxy table.
func (app *BaseApp) FindActiveApplicationProxy(prefix string, subpath string) (*ApplicationInstallation, *Application, *ApplicationManifest, error) {
	installation := &ApplicationInstallation{}

	err := app.RecordQuery(CollectionNameApplicationInstallations).
		AndWhere(dbx.HashExp{"proxyPrefix": prefix, "proxySubpath": subpath}).
		Limit(1).
		One(installation)
	if err != nil {
		return nil, nil, nil, err
	}

	if !installation.IsActive() || !ApplicationGrantPermissions(installation.Permissions()).HasSystem(PermissionResourceAppProxy, PermissionLevelWrite) {
		return nil, nil, nil, errors.New("the application proxy is not active")
	}

	application, _, manifest, err := findApplicationInstallationManifest(app, installation)
	if err != nil {
		return nil, nil, nil, err
	}

	if manifest.AppProxy == nil {
		return nil, nil, nil, errors.New("the installed version has no application proxy")
	}

	return installation, application, manifest, nil
}

// ApplicationProxySignature returns the hex HMAC-SHA256 of the provided query parameters (Shopify's
// App Proxy algorithm): the params except "signature" sorted by name, "k=v" concatenated
// without separators and the multiple values of a param joined with ",".
func ApplicationProxySignature(params url.Values, secret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k != "signature" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	h := hmac.New(sha256.New, []byte(secret))
	for _, k := range keys {
		h.Write([]byte(k + "=" + strings.Join(params[k], ",")))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// ErrApplicationProxyResponseTooLarge is returned by [ApplicationCatalogs.SendProxyRequest].
var ErrApplicationProxyResponseTooLarge = errors.New("the application proxy response exceeds the max allowed size")

// SendProxyRequest sends the provided app proxy request with the SSRF protected client and follows up
// to 3 redirects, only on the same scheme and host (a 301/302/303 of a non GET/HEAD request continues
// as a bodyless GET, like in the browsers). Any other redirect is an error.
func (c *ApplicationCatalogs) SendProxyRequest(ctx context.Context, method string, target string, header http.Header, body []byte) (*safehttp.Response, error) {
	c.proxyClient.SetOptions(safehttp.Options{
		Timeout:             ApplicationProxyTimeout,
		MaxResponseBodySize: ApplicationProxyMaxBodySize + 1,
		UserAgent:           applicationCatalogUserAgent,
		AllowPrivateTargets: c.app.Settings().webhooksConfig().AllowPrivateTargets || c.app.IsDev(),
	})

	ctx, cancel := context.WithTimeout(ctx, ApplicationProxyTimeout)
	defer cancel()

	origin, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	current := origin

	for redirects := 0; ; redirects++ {
		if err := checkApplicationRemoteURL(c.app, current.String()); err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, method, current.String(), strings.NewReader(string(body)))
		if err != nil {
			return nil, err
		}
		req.Header = header.Clone()
		if len(body) == 0 {
			req.Body = http.NoBody
		}

		res, err := c.proxyClient.Send(req)
		if err != nil {
			return nil, err
		}

		if int64(len(res.Body)) > ApplicationProxyMaxBodySize {
			return nil, ErrApplicationProxyResponseTooLarge
		}

		location := res.Header.Get("Location")
		if res.StatusCode < 300 || res.StatusCode > 399 || res.StatusCode == http.StatusNotModified || location == "" {
			return res, nil
		}

		if redirects >= applicationProxyMaxRedirects {
			return nil, fmt.Errorf("too many redirects (max %d)", applicationProxyMaxRedirects)
		}

		next, err := current.Parse(location)
		if err != nil {
			return nil, fmt.Errorf("invalid redirect location: %w", err)
		}

		if next.Scheme != origin.Scheme || !strings.EqualFold(next.Host, origin.Host) {
			return nil, fmt.Errorf("cross-host redirects are not allowed (%s)", next.Redacted())
		}

		if res.StatusCode != http.StatusTemporaryRedirect && res.StatusCode != http.StatusPermanentRedirect &&
			method != http.MethodGet && method != http.MethodHead {
			method = http.MethodGet
			body = nil
			header = header.Clone()
			header.Del("Content-Type")
			header.Del("Content-Length")
		}

		current = next
	}
}

// FrameOrigins returns the sorted origins of the active installations
// with extensions (the dashboard frame-src; it is cached until an installation change).
func (c *ApplicationCatalogs) FrameOrigins() []string {
	if cached := c.frameOrigins.Load(); cached != nil {
		return *cached
	}

	generation := c.frameOriginsGeneration.Load()

	origins := []string{}

	installations := []*ApplicationInstallation{}
	err := c.app.RecordQuery(CollectionNameApplicationInstallations).
		AndWhere(dbx.HashExp{"status": ApplicationInstallationStatusActive}).
		All(&installations)
	if err != nil {
		// not cached (e.g. not migrated yet)
		return origins
	}

	for _, installation := range installations {
		_, _, manifest, err := findApplicationInstallationManifest(c.app, installation)
		if err != nil || len(manifest.Extensions) == 0 {
			continue
		}

		if origin := ApplicationOrigin(manifest.ApplicationURL); origin != "" {
			origins = append(origins, origin)
		}
	}

	slices.Sort(origins)
	origins = slices.Compact(origins)

	// note: not cached if an installation has changed in the meantime
	if generation == c.frameOriginsGeneration.Load() {
		c.frameOrigins.Store(&origins)
	}

	return origins
}

func (c *ApplicationCatalogs) resetFrameOrigins() {
	c.frameOriginsGeneration.Add(1)
	c.frameOrigins.Store(nil)
}

var applicationOriginRegex = regexp.MustCompile(`^https?://[A-Za-z0-9.\-\[\]:]+$`)

// ApplicationOrigin returns the normalized origin of the provided
// http(s) url (empty string if it is invalid or it can't be used in a CSP).
func ApplicationOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}

	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	origin = strings.TrimSuffix(origin, map[string]string{"http": ":80", "https": ":443"}[strings.ToLower(u.Scheme)])

	if !applicationOriginRegex.MatchString(origin) {
		return ""
	}

	return origin
}
