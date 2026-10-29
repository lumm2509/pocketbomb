package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/lumm2509/pocketbomb/core"
)

// ApplicationVendorNotification defines a single notification received by an [ApplicationVendor].
type ApplicationVendorNotification struct {
	// Path is the notification url path (/install or /uninstall).
	Path string

	ContentType string

	// Token is the raw notification JWT.
	Token string
}

// ApplicationVendor is a mock applications catalog provider (and application backend)
// for the applications catalog tests:
//   - GET /catalog/index.json and /catalog/{handle}-{version}.json serve the published catalog
//   - GET /icon.png serves a tiny png icon (the published entries icon, see [ApplicationVendorIcon])
//   - POST /install and /uninstall record the notifications and respond with InstallStatus/200
//
// Use [ApplicationVendor.URL] in the manifests (http loopback urls require an app in dev mode).
type ApplicationVendor struct {
	Server     *httptest.Server
	PrivateKey ed25519.PrivateKey

	// PublicKey is the base64 encoded Ed25519 public key of the catalog signing key.
	PublicKey string

	mu            sync.Mutex
	files         map[string][]byte
	installStatus int
	installFunc   func(token string) int
	notifications []ApplicationVendorNotification
}

// NewApplicationVendor starts a new mock applications vendor server
// (the caller should call [ApplicationVendor.Close] when done).
func NewApplicationVendor() *ApplicationVendor {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	v := &ApplicationVendor{
		PrivateKey:    privateKey,
		PublicKey:     base64.StdEncoding.EncodeToString(publicKey),
		files:         map[string][]byte{},
		installStatus: http.StatusOK,
	}

	v.Server = httptest.NewServer(http.HandlerFunc(v.handle))

	return v
}

// URL returns the vendor server base url.
func (v *ApplicationVendor) URL() string {
	return v.Server.URL
}

// IndexURL returns the catalog index url.
func (v *ApplicationVendor) IndexURL() string {
	return v.Server.URL + "/catalog/index.json"
}

// Close stops the vendor server.
func (v *ApplicationVendor) Close() {
	v.Server.Close()
}

// SetInstallStatus changes the response status of the /install notifications.
func (v *ApplicationVendor) SetInstallStatus(status int) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.installStatus = status
}

// SetInstallHandler sets an optional /install notifications handler that returns the
// response status (e.g. to exchange the delivered credentials during the notification).
//
// It is called without holding the vendor lock.
func (v *ApplicationVendor) SetInstallHandler(fn func(token string) int) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.installFunc = fn
}

// SetFile sets (or replaces) a raw served file (e.g. a tampered index).
func (v *ApplicationVendor) SetFile(path string, content []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.files[path] = content
}

// Notifications returns the received notifications.
func (v *ApplicationVendor) Notifications() []ApplicationVendorNotification {
	v.mu.Lock()
	defer v.mu.Unlock()

	result := make([]ApplicationVendorNotification, len(v.notifications))
	copy(result, v.notifications)

	return result
}

// Publish validates the provided JSON manifests with the server parser and publishes them as
// "/catalog/{handle}-{version}.json" together with the (signed or unsigned) catalog index.
func (v *ApplicationVendor) Publish(signed bool, manifests ...string) {
	index := core.ApplicationCatalogIndex{Applications: []core.ApplicationCatalogEntry{}}

	for _, raw := range manifests {
		manifest, err := core.ParseApplicationManifest([]byte(raw), core.ApplicationManifestFormatJSON)
		if err != nil {
			panic(err)
		}

		path := "/catalog/" + manifest.Handle + "-" + manifest.Version + ".json"
		v.SetFile(path, []byte(raw))

		index.Applications = append(index.Applications, core.ApplicationCatalogEntry{
			Handle:         manifest.Handle,
			Name:           manifest.Name,
			Description:    manifest.Description,
			Developer:      manifest.Developer,
			Version:        manifest.Version,
			IconURL:        v.Server.URL + "/icon.png",
			ManifestURL:    v.Server.URL + path,
			ManifestDigest: core.ApplicationManifestRawDigest([]byte(raw)),
		})
	}

	indexRaw, err := json.Marshal(index)
	if err != nil {
		panic(err)
	}

	if signed {
		indexRaw, err = core.SignApplicationCatalogIndex(indexRaw, v.PrivateKey)
		if err != nil {
			panic(err)
		}
	}

	v.SetFile("/catalog/index.json", indexRaw)
}

func (v *ApplicationVendor) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/icon.png" {
		w.Header().Set("Content-Type", "image/png")
		w.Write(ApplicationVendorIcon())
		return
	}

	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/catalog/") {
		v.mu.Lock()
		content, ok := v.files[r.URL.Path]
		v.mu.Unlock()

		if !ok {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(content)
		return
	}

	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	v.mu.Lock()
	installFunc := v.installFunc
	v.mu.Unlock()

	status := v.installStatusFor(r.URL.Path)
	if installFunc != nil && r.URL.Path == "/install" {
		status = installFunc(string(body))
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	switch r.URL.Path {
	case "/install", "/uninstall":
		v.notifications = append(v.notifications, ApplicationVendorNotification{
			Path:        r.URL.Path,
			ContentType: r.Header.Get("Content-Type"),
			Token:       string(body),
		})

		if status != http.StatusOK {
			w.WriteHeader(status)
			w.Write([]byte("vendor install failure"))
			return
		}

		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func (v *ApplicationVendor) installStatusFor(path string) int {
	v.mu.Lock()
	defer v.mu.Unlock()

	if path == "/install" {
		return v.installStatus
	}

	return http.StatusOK
}

// ApplicationVendorIcon returns the bytes of a tiny (1x1) png icon.
func ApplicationVendorIcon() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 16, G: 85, B: 201, A: 255})

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}

	return buf.Bytes()
}
