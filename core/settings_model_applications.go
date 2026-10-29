package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"

	validation "github.com/pocketbase/ozzo-validation/v4"
)

// ApplicationsConfig defines the app applications settings.
type ApplicationsConfig struct {
	// Catalogs is the list of the applications catalog sources the dashboard discovers
	// the installable applications from (see [ApplicationCatalogs]).
	Catalogs []ApplicationCatalogSource `form:"catalogs" json:"catalogs"`
}

// Validate makes ApplicationsConfig validatable by implementing [validation.Validatable] interface.
func (c ApplicationsConfig) Validate() error {
	errs := validation.Errors{}

	names := map[string]struct{}{}
	for i, source := range c.Catalogs {
		if err := source.Validate(); err != nil {
			errs[strconv.Itoa(i)] = err
			continue
		}

		key := strings.ToLower(source.Name)
		if _, ok := names[key]; ok {
			errs[strconv.Itoa(i)] = validation.Errors{"name": validation.NewError("validation_duplicated_catalog_name", "The catalog name must be unique.")}
			continue
		}
		names[key] = struct{}{}
	}

	if len(errs) > 0 {
		return validation.Errors{"catalogs": errs}
	}

	return nil
}

// FindCatalog returns the catalog source with the specified name (case-insensitive).
func (c ApplicationsConfig) FindCatalog(name string) (ApplicationCatalogSource, bool) {
	for _, source := range c.Catalogs {
		if strings.EqualFold(source.Name, name) {
			return source, true
		}
	}

	return ApplicationCatalogSource{}, false
}

// ApplicationCatalogSource defines a single applications catalog source.
type ApplicationCatalogSource struct {
	// Name is the unique catalog source display name (e.g. "PocketBase" or "ACME internal").
	Name string `form:"name" json:"name"`

	// URL is the catalog index document url.
	URL string `form:"url" json:"url"`

	// PublicKey is an optional base64 encoded Ed25519 public key.
	//
	// If set, the catalog index must be a signed envelope with a valid signature of this key
	// (otherwise both the signed and the unsigned index forms are accepted).
	PublicKey string `form:"publicKey" json:"publicKey"`
}

// Validate makes ApplicationCatalogSource validatable by implementing [validation.Validatable] interface.
func (s ApplicationCatalogSource) Validate() error {
	return validation.ValidateStruct(&s,
		validation.Field(&s.Name, validation.Required, validation.Length(1, 100)),
		validation.Field(&s.URL, validation.Required, validation.Length(1, 2000), validation.By(checkApplicationHTTPURL)),
		validation.Field(&s.PublicKey, validation.By(func(value any) error {
			v, _ := value.(string)
			if v == "" {
				return nil
			}

			if _, err := ParseApplicationCatalogPublicKey(v); err != nil {
				return validation.NewError("validation_invalid_catalog_public_key", "Must be a base64 encoded Ed25519 public key.")
			}

			return nil
		})),
	)
}

// ParseApplicationCatalogPublicKey decodes a base64 (std or url, with or without padding)
// encoded Ed25519 public key.
func ParseApplicationCatalogPublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := decodeApplicationCatalogBase64(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}

	if len(raw) != ed25519.PublicKeySize {
		return nil, validation.NewError("validation_invalid_key_size", "Invalid Ed25519 public key size.")
	}

	return ed25519.PublicKey(raw), nil
}

// decodeApplicationCatalogBase64 decodes a std or url base64 string (with or without padding).
func decodeApplicationCatalogBase64(v string) ([]byte, error) {
	v = strings.TrimRight(v, "=")

	if strings.ContainsAny(v, "-_") {
		return base64.RawURLEncoding.DecodeString(v)
	}

	return base64.RawStdEncoding.DecodeString(v)
}

// isLoopbackURLHost reports whether the provided url host is a loopback host
// (localhost or a loopback IP).
func isLoopbackURLHost(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())

	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}

	return isLoopbackIPString(host)
}
