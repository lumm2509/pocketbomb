package core

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lumm2509/pocketbomb/tools/safehttp"
	"github.com/lumm2509/pocketbomb/tools/security"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// Applications catalog
// -------------------------------------------------------------------
//
// The dashboard discovers the installable applications from the catalog sources
// configured in the settings (settings.applications.catalogs; e.g. pocketbase.com
// or an organization own provider built with "pocketbase applications catalog build").
//
// Catalog index document (JSON), either unsigned:
//
//	{"applications": [entry, ...]}
//
// or signed (required when the source has a public key):
//
//	{"payload": "<base64url of the index JSON bytes>", "signature": "<base64url Ed25519 signature of the index JSON bytes>"}
//
// Entry:
//
//	{"handle", "name", "description", "iconURL", "developer": {"name", "url"}, "version", "manifestURL", "manifestDigest"}
//
// The manifests are not separately signed: the sha256 (hex) of the raw manifest bytes fetched
// from manifestURL must be equal to the (signed) index manifestDigest and the manifest is
// parsed with the same parser as the custom applications manifests ([ParseApplicationManifest]).
//
// The entries and manifests icons are fetched server-side too and inlined as data: URIs
// (png, jpeg, webp or gif sniffed from the bytes, max 64KB; never svg) so that the dashboard
// renders only data: icons and its CSP stays strict. An icon failure only drops the icon.
//
// Everything is fetched server-side with the SSRF protected webhooks HTTP client
// (the private targets are allowed only with the webhooks AllowPrivateTargets setting or in dev mode)
// and https is required (http is allowed only for the loopback hosts in dev mode).

// Applications catalog limits.
const (
	ApplicationCatalogIndexMaxSize = 1 << 20

	applicationCatalogTimeout      = 10 * time.Second
	applicationCatalogMaxRedirects = 3
	applicationCatalogCacheTTL     = 5 * time.Minute
	applicationCatalogUserAgent    = "PocketBase-Applications"

	// ApplicationIconMaxSize is the max size of an inlined application icon (in bytes).
	ApplicationIconMaxSize = 64 << 10

	applicationIconsConcurrency = 8
)

// applicationIconTypes are the accepted (sniffed) application icon content types.
var applicationIconTypes = []string{"image/png", "image/jpeg", "image/webp", "image/gif"}

var applicationManifestDigestRegex = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ApplicationCatalogEntry defines a single catalog index application entry.
type ApplicationCatalogEntry struct {
	Handle         string                       `json:"handle"`
	Name           string                       `json:"name"`
	Description    string                       `json:"description"`
	IconURL        string                       `json:"iconURL"`
	Developer      ApplicationManifestDeveloper `json:"developer"`
	Version        string                       `json:"version"`
	ManifestURL    string                       `json:"manifestURL"`
	ManifestDigest string                       `json:"manifestDigest"`
}

// Validate makes ApplicationCatalogEntry validatable by implementing [validation.Validatable] interface.
func (e ApplicationCatalogEntry) Validate() error {
	return validation.ValidateStruct(&e,
		validation.Field(&e.Handle, validation.Required, validation.Match(applicationHandleRegex)),
		validation.Field(&e.Name, validation.Required, validation.Length(1, 100)),
		validation.Field(&e.Description, validation.Length(0, 1000)),
		validation.Field(&e.IconURL, validation.Length(0, 100000)),
		validation.Field(&e.Version, validation.Required, validation.Length(1, 50), validation.Match(applicationVersionRegex)),
		validation.Field(&e.ManifestURL, validation.Required, validation.Length(1, 2000), validation.By(checkApplicationHTTPURL)),
		validation.Field(&e.ManifestDigest, validation.Required, validation.Match(applicationManifestDigestRegex)),
	)
}

// SafeIconURL returns the entry icon if it is an inlined data: icon (otherwise empty string).
func (e ApplicationCatalogEntry) SafeIconURL() string {
	return SafeApplicationIconURL(e.IconURL)
}

// SafeApplicationIconURL returns the provided icon if it is an inlined png, jpeg, webp or gif
// base64 data: URI (otherwise empty string).
func SafeApplicationIconURL(v string) string {
	for _, t := range applicationIconTypes {
		if strings.HasPrefix(v, "data:"+t+";base64,") {
			return v
		}
	}

	return ""
}

// ApplicationCatalogIndex defines the catalog index document.
type ApplicationCatalogIndex struct {
	Applications []ApplicationCatalogEntry `json:"applications"`
}

// ApplicationCatalogEnvelope defines the signed catalog index envelope.
type ApplicationCatalogEnvelope struct {
	// Payload is the base64url encoded index JSON bytes.
	Payload string `json:"payload"`

	// Signature is the base64url encoded Ed25519 signature of the (decoded) payload bytes.
	Signature string `json:"signature"`
}

// ParseApplicationCatalogIndex parses and validates a raw catalog index document.
//
// If publicKey (base64 Ed25519) is set, the document must be a signed envelope with a valid signature.
// Without publicKey both the signed envelope and the unsigned form are accepted but the
// result is reported as unsigned (there is nothing to verify the signature with).
//
// It returns the index and whether its signature was verified.
func ParseApplicationCatalogIndex(raw []byte, publicKey string) (*ApplicationCatalogIndex, bool, error) {
	if len(raw) > ApplicationCatalogIndexMaxSize {
		return nil, false, fmt.Errorf("the catalog index must be less than %d bytes", ApplicationCatalogIndexMaxSize)
	}

	doc := map[string]jsontext.Value{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false, fmt.Errorf("invalid catalog index JSON: %w", err)
	}

	_, isEnvelope := doc["payload"]

	var key ed25519.PublicKey
	if publicKey != "" {
		var err error
		key, err = ParseApplicationCatalogPublicKey(publicKey)
		if err != nil {
			return nil, false, errors.New("invalid catalog public key")
		}

		if !isEnvelope {
			return nil, false, errors.New("the catalog index is not signed (a signed envelope is required by the configured public key)")
		}
	}

	indexRaw := raw
	signed := false

	if isEnvelope {
		envelope := ApplicationCatalogEnvelope{}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return nil, false, fmt.Errorf("invalid catalog index envelope: %w", err)
		}

		payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(envelope.Payload, "="))
		if err != nil {
			return nil, false, errors.New("invalid catalog index envelope payload encoding")
		}

		if key != nil {
			signature, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(envelope.Signature, "="))
			if err != nil || !ed25519.Verify(key, payload, signature) {
				return nil, false, errors.New("invalid catalog index signature")
			}
			signed = true
		}

		indexRaw = payload
	}

	index := &ApplicationCatalogIndex{}
	if err := json.Unmarshal(indexRaw, index); err != nil {
		return nil, false, fmt.Errorf("invalid catalog index: %w", err)
	}

	handles := map[string]struct{}{}
	for i, entry := range index.Applications {
		if err := entry.Validate(); err != nil {
			return nil, false, fmt.Errorf("invalid catalog index entry %d (%s): %w", i, entry.Handle, err)
		}

		if _, ok := handles[entry.Handle]; ok {
			return nil, false, fmt.Errorf("duplicated catalog index entry handle %q", entry.Handle)
		}
		handles[entry.Handle] = struct{}{}
	}

	if index.Applications == nil {
		index.Applications = []ApplicationCatalogEntry{}
	}

	return index, signed, nil
}

// SignApplicationCatalogIndex returns the signed envelope JSON of the provided raw index JSON bytes.
func SignApplicationCatalogIndex(indexRaw []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}

	envelope := ApplicationCatalogEnvelope{
		Payload:   base64.RawURLEncoding.EncodeToString(indexRaw),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, indexRaw)),
	}

	return json.Marshal(envelope, json.Deterministic(true))
}

// ApplicationManifestRawDigest returns the hex encoded sha256 digest of the raw manifest bytes
// (aka. the catalog index manifestDigest).
func ApplicationManifestRawDigest(raw []byte) string {
	return security.SHA256(string(raw))
}

// -------------------------------------------------------------------
// Remote urls
// -------------------------------------------------------------------

func isLoopbackIPString(host string) bool {
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && addr.Unmap().IsLoopback()
}

// checkApplicationRemoteURL checks whether the provided url could be used for a server-side
// applications request (catalog index, manifest, install/uninstall notifications):
// https is required and http is allowed only for the loopback hosts in dev mode.
//
// The resolved target address is further checked by the SSRF protected client on dial.
func checkApplicationRemoteURL(app App, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("invalid url %q", rawURL)
	}

	if u.Scheme == "https" {
		return nil
	}

	if u.Scheme == "http" && app.IsDev() && isLoopbackURLHost(u) {
		return nil
	}

	return fmt.Errorf("https is required (http is allowed only for the loopback hosts in dev mode): %s", u.Redacted())
}

// -------------------------------------------------------------------
// Catalogs service
// -------------------------------------------------------------------

// ApplicationCatalogResult defines the fetch result of a single catalog source.
type ApplicationCatalogResult struct {
	Name string `json:"name"`
	URL  string `json:"url"`

	// Signed indicates whether the index signature was verified with the source public key.
	Signed bool `json:"signed"`

	Entries []ApplicationCatalogEntry `json:"entries"`

	// Error is the (non-fatal) source fetch or verification error.
	Error string `json:"error"`

	FetchedAt time.Time `json:"fetchedAt"`
}

type applicationCatalogCacheItem struct {
	result    *ApplicationCatalogResult
	expiresAt time.Time
}

// ApplicationCatalogs is the app applications catalogs service.
//
// It is accessible via [App.ApplicationCatalogs].
type ApplicationCatalogs struct {
	app *BaseApp

	// client is the SSRF protected client used for all applications remote requests
	// (catalog indexes, manifests, icons and install/uninstall notifications)
	client *safehttp.Client

	// proxyClient is the client of the app proxy requests (other timeout and limits)
	proxyClient *safehttp.Client

	// frameOrigins is the cached result of [ApplicationCatalogs.FrameOrigins]
	frameOrigins           atomic.Pointer[[]string]
	frameOriginsGeneration atomic.Uint64

	cacheMu sync.Mutex
	cache   map[string]*applicationCatalogCacheItem

	// pendingUninstalls holds the uninstall notifications of the installations that
	// are being deleted (sent after the delete is committed, see registerApplicationHooks)
	pendingUninstalls sync.Map
}

func newApplicationCatalogs(app *BaseApp) *ApplicationCatalogs {
	return &ApplicationCatalogs{
		app:         app,
		client:      safehttp.NewClient(safehttp.Options{Timeout: applicationCatalogTimeout, UserAgent: applicationCatalogUserAgent}),
		proxyClient: safehttp.NewClient(safehttp.Options{Timeout: ApplicationProxyTimeout, UserAgent: applicationCatalogUserAgent}),
		cache:       map[string]*applicationCatalogCacheItem{},
	}
}

// ApplicationCatalogs returns the app applications catalogs service.
func (app *BaseApp) ApplicationCatalogs() *ApplicationCatalogs {
	return app.applicationCatalogs
}

// httpClient returns the SSRF protected client synced with the current settings
// (the private targets are allowed only with the webhooks AllowPrivateTargets setting or in dev mode).
func (c *ApplicationCatalogs) httpClient() *safehttp.Client {
	c.client.SetOptions(safehttp.Options{
		Timeout:             applicationCatalogTimeout,
		UserAgent:           applicationCatalogUserAgent,
		AllowPrivateTargets: c.app.Settings().webhooksConfig().AllowPrivateTargets || c.app.IsDev(),
	})

	return c.client
}

// fetch fetches the provided url with the applications remote url checks and limits.
func (c *ApplicationCatalogs) fetch(ctx context.Context, rawURL string, maxSize int64) (*safehttp.FetchResult, error) {
	if err := checkApplicationRemoteURL(c.app, rawURL); err != nil {
		return nil, err
	}

	result, err := c.httpClient().Fetch(ctx, rawURL, safehttp.FetchOptions{
		MaxBodySize:  maxSize,
		MaxRedirects: applicationCatalogMaxRedirects,
		Accept:       "application/json, application/toml;q=0.9, */*;q=0.1",
	})
	if err != nil {
		return nil, err
	}

	if result.StatusCode < 200 || result.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected response status %d", result.StatusCode)
	}

	return result, nil
}

// List returns the fetch results of all configured catalog sources (in the settings order).
//
// The successful results are cached for 5 minutes per source (refresh bypasses the cache).
// The per-source errors are reported in [ApplicationCatalogResult.Error].
func (c *ApplicationCatalogs) List(ctx context.Context, refresh bool) []*ApplicationCatalogResult {
	sources := c.app.Settings().applicationsConfig().Catalogs

	results := make([]*ApplicationCatalogResult, len(sources))

	var wg sync.WaitGroup
	for i, source := range sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = c.Fetch(ctx, source, refresh)
		}()
	}
	wg.Wait()

	return results
}

// Fetch fetches, verifies and parses the index of the provided catalog source
// (see [ApplicationCatalogs.List] for the cache).
func (c *ApplicationCatalogs) Fetch(ctx context.Context, source ApplicationCatalogSource, refresh bool) *ApplicationCatalogResult {
	cacheKey := source.URL + "|" + source.PublicKey

	if !refresh {
		c.cacheMu.Lock()
		item, ok := c.cache[cacheKey]
		c.cacheMu.Unlock()
		if ok && time.Now().Before(item.expiresAt) {
			result := *item.result
			result.Name = source.Name
			return &result
		}
	}

	result := &ApplicationCatalogResult{
		Name:      source.Name,
		URL:       source.URL,
		Entries:   []ApplicationCatalogEntry{},
		FetchedAt: time.Now(),
	}

	res, err := c.fetch(ctx, source.URL, ApplicationCatalogIndexMaxSize)
	if err != nil {
		result.Error = "Failed to fetch the catalog index: " + err.Error()
		return result
	}

	index, signed, err := ParseApplicationCatalogIndex(res.Body, source.PublicKey)
	if err != nil {
		result.Error = "Invalid catalog index: " + err.Error()
		return result
	}

	result.Signed = signed
	result.Entries = index.Applications

	// the remote icons are inlined (and cached together with the index)
	c.inlineEntriesIcons(ctx, result.Entries)

	c.cacheMu.Lock()
	c.cache[cacheKey] = &applicationCatalogCacheItem{result: result, expiresAt: time.Now().Add(applicationCatalogCacheTTL)}
	c.cacheMu.Unlock()

	return result
}

// inlineEntriesIcons replaces the entries icon urls with their inlined data: URIs (empty on failure).
func (c *ApplicationCatalogs) inlineEntriesIcons(ctx context.Context, entries []ApplicationCatalogEntry) {
	sem := make(chan struct{}, applicationIconsConcurrency)

	var wg sync.WaitGroup
	for i := range entries {
		if entries[i].IconURL == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			entries[i].IconURL = c.InlineIcon(ctx, entries[i].IconURL)
		}()
	}
	wg.Wait()
}

// InlineIcon fetches the provided icon url (with the same https/dev mode and SSRF rules as the catalogs)
// and returns it as a base64 data: URI.
//
// Only the png, jpeg, webp and gif icons (sniffed from the bytes, the response content type is ignored)
// up to [ApplicationIconMaxSize] are accepted. Any failure returns an empty string (the icon is dropped).
func (c *ApplicationCatalogs) InlineIcon(ctx context.Context, rawURL string) string {
	if rawURL == "" {
		return ""
	}

	// already inlined
	if strings.HasPrefix(rawURL, "data:") {
		return SafeApplicationIconURL(rawURL)
	}

	res, err := c.fetch(ctx, rawURL, ApplicationIconMaxSize)
	if err != nil {
		c.app.Logger().Debug("Failed to fetch the application icon", slog.String("url", rawURL), slog.String("error", err.Error()))
		return ""
	}

	contentType := http.DetectContentType(res.Body)
	if !slices.Contains(applicationIconTypes, contentType) {
		c.app.Logger().Debug("Unsupported application icon type", slog.String("url", rawURL), slog.String("type", contentType))
		return ""
	}

	return "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(res.Body)
}

// FindEntry returns the (freshly fetched and verified) catalog entry with the
// specified handle of the catalog source with the specified name.
func (c *ApplicationCatalogs) FindEntry(ctx context.Context, sourceName string, handle string) (ApplicationCatalogSource, ApplicationCatalogEntry, error) {
	source, ok := c.app.Settings().applicationsConfig().FindCatalog(sourceName)
	if !ok {
		return source, ApplicationCatalogEntry{}, validation.Errors{"source": validation.NewError("validation_unknown_catalog", "Unknown catalog source.")}
	}

	result := c.Fetch(ctx, source, true)
	if result.Error != "" {
		return source, ApplicationCatalogEntry{}, errors.New(result.Error)
	}

	for _, entry := range result.Entries {
		if entry.Handle == handle {
			return source, entry, nil
		}
	}

	return source, ApplicationCatalogEntry{}, validation.Errors{"handle": validation.NewError("validation_unknown_catalog_application", "The application is not in the catalog.")}
}

// FetchManifest fetches the manifest of the provided catalog entry, verifies its raw
// bytes digest and parses it with the same parser as the custom applications manifests
// (the format is decided by the response content type or by the url extension).
//
// The manifest handle and version must match the entry and the install_url is required.
func (c *ApplicationCatalogs) FetchManifest(ctx context.Context, entry ApplicationCatalogEntry) (*ApplicationManifest, string, error) {
	res, err := c.fetch(ctx, entry.ManifestURL, ApplicationManifestMaxSize)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch the application manifest: %w", err)
	}

	if digest := ApplicationManifestRawDigest(res.Body); digest != entry.ManifestDigest {
		return nil, "", fmt.Errorf("the application manifest digest %s doesn't match the catalog digest %s", digest, entry.ManifestDigest)
	}

	format := applicationManifestFormatOf(res.Header.Get("Content-Type"), res.URL)
	if format == "" {
		return nil, "", errors.New("unsupported application manifest format (expected TOML or JSON content type or url extension)")
	}

	manifest, err := ParseApplicationManifest(res.Body, format)
	if err != nil {
		return nil, "", fmt.Errorf("invalid application manifest: %w", err)
	}

	if manifest.Handle != entry.Handle || manifest.Version != entry.Version {
		return nil, "", errors.New("the application manifest handle or version doesn't match the catalog entry")
	}

	if manifest.InstallURL == "" {
		return nil, "", validation.Errors{"install_url": validation.NewError("validation_catalog_install_url_required", "The catalog applications must have an install_url.")}
	}

	return manifest, format, nil
}

// applicationManifestFormatOf returns the manifest format based on the content type
// or on the url extension (empty string if unknown).
func applicationManifestFormatOf(contentType string, rawURL string) string {
	mediaType, _, _ := mime.ParseMediaType(contentType)

	switch {
	case strings.HasSuffix(mediaType, "/toml") || strings.HasSuffix(mediaType, "/x-toml"):
		return ApplicationManifestFormatTOML
	case strings.HasSuffix(mediaType, "/json") || strings.HasSuffix(mediaType, "+json"):
		return ApplicationManifestFormatJSON
	}

	if u, err := url.Parse(rawURL); err == nil {
		switch strings.ToLower(path.Ext(u.Path)) {
		case ".toml":
			return ApplicationManifestFormatTOML
		case ".json":
			return ApplicationManifestFormatJSON
		}
	}

	return ""
}

// ImportApplicationCatalogEntry fetches the current catalog entry with the specified handle,
// verifies and imports its manifest as a catalog application (or as a new version of
// the existing catalog application with the same handle).
//
// A handle of an existing custom application is rejected.
func (app *BaseApp) ImportApplicationCatalogEntry(ctx context.Context, sourceName string, handle string, createdBy string) (*ApplicationManifestImportResult, error) {
	source, entry, err := app.applicationCatalogs.FindEntry(ctx, sourceName, handle)
	if err != nil {
		return nil, err
	}

	manifest, format, err := app.applicationCatalogs.FetchManifest(ctx, entry)
	if err != nil {
		return nil, err
	}

	// the manifest icon has precedence over the (already inlined) catalog entry icon
	iconURL := entry.SafeIconURL()
	if manifest.IconURL != "" {
		if icon := app.applicationCatalogs.InlineIcon(ctx, manifest.IconURL); icon != "" {
			iconURL = icon
		}
	}

	return app.importApplicationManifest(manifest, format, createdBy, applicationOrigin{
		source:      ApplicationSourceCatalog,
		catalogURL:  source.URL,
		manifestURL: entry.ManifestURL,
		iconURL:     iconURL,
	})
}
