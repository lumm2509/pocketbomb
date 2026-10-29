package applicationscmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fatih/color"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/spf13/cobra"
)

func applicationsCatalogCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "catalog",
		Short: "Applications catalog provider tools (signing keys and signed catalog builds)",
	}

	command.AddCommand(applicationsCatalogKeygenCommand())
	command.AddCommand(applicationsCatalogBuildCommand())

	return command
}

func applicationsCatalogKeygenCommand() *cobra.Command {
	var out string

	command := &cobra.Command{
		Use:          "keygen",
		Example:      "applications catalog keygen --out ./catalog.key",
		Short:        "Generates an Ed25519 catalog signing key pair (the public key is for the catalog source settings)",
		SilenceUsage: true,
		RunE: func(command *cobra.Command, args []string) error {
			privatePEM, publicKey, err := generateApplicationCatalogKey()
			if err != nil {
				return err
			}

			if out != "" {
				if err := os.WriteFile(out, privatePEM, 0600); err != nil {
					return fmt.Errorf("failed to write the private key: %w", err)
				}
				fmt.Fprintf(command.OutOrStdout(), "Private key saved to %s (keep it secret).\n", out)
			} else {
				fmt.Fprintf(command.OutOrStdout(), "Private key (keep it secret):\n%s\n", privatePEM)
			}

			fmt.Fprintf(command.OutOrStdout(), "Public key (catalog source publicKey setting):\n%s\n", publicKey)

			return nil
		},
	}

	command.Flags().StringVar(&out, "out", "", "the file path to save the PEM private key to (default to stdout)")

	return command
}

// generateApplicationCatalogKey generates a new Ed25519 key pair and returns
// the PEM (PKCS #8) encoded private key and the base64 encoded public key.
func generateApplicationCatalogKey() ([]byte, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, "", err
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	return privatePEM, base64.StdEncoding.EncodeToString(publicKey), nil
}

// parseApplicationCatalogPrivateKey parses a PEM (PKCS #8) or a base64 encoded
// (32 bytes seed or 64 bytes private key) Ed25519 private key.
func parseApplicationCatalogPrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	if block, _ := pem.Decode(raw); block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid PEM private key: %w", err)
		}

		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("the PEM private key is not an Ed25519 key")
		}

		return privateKey, nil
	}

	encoded := strings.TrimRight(strings.TrimSpace(string(raw)), "=")
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("the private key must be PEM or base64 encoded")
		}
	}

	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	}

	return nil, errors.New("invalid Ed25519 private key size")
}

func applicationsCatalogBuildCommand() *cobra.Command {
	var keyPath string
	var baseURL string
	var outDir string

	command := &cobra.Command{
		Use:          "build [manifests dir]",
		Example:      "applications catalog build ./manifests --key ./catalog.key --base-url https://apps.example.com/catalog --out ./public/catalog",
		Short:        "Validates the *.toml and *.json manifests of a directory and writes the normalized manifests and the signed index.json",
		SilenceUsage: true,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("missing manifests directory argument")
			}

			if baseURL == "" {
				return errors.New("missing --base-url flag (the public url of the --out directory)")
			}

			if outDir == "" {
				return errors.New("missing --out flag")
			}

			var privateKey ed25519.PrivateKey
			if keyPath != "" {
				raw, err := os.ReadFile(keyPath)
				if err != nil {
					return fmt.Errorf("failed to read the private key: %w", err)
				}

				privateKey, err = parseApplicationCatalogPrivateKey(raw)
				if err != nil {
					return err
				}
			}

			index, err := buildApplicationCatalog(args[0], outDir, baseURL, privateKey)
			if err != nil {
				return err
			}

			signed := "unsigned"
			if privateKey != nil {
				signed = "signed"
			}

			color.Green("Successfully built the %s catalog index with %d application(s) in %s.", signed, len(index.Applications), outDir)

			return nil
		},
	}

	command.Flags().StringVar(&keyPath, "key", "", "the Ed25519 private key file (PEM or base64; without it the index is not signed)")
	command.Flags().StringVar(&baseURL, "base-url", "", "the public base url of the output directory (used for the manifest urls)")
	command.Flags().StringVar(&outDir, "out", "", "the output directory")

	return command
}

// buildApplicationCatalog parses and validates every *.toml|*.json manifest of the provided directory
// (one manifest per handle), writes the normalized manifests as "{handle}-{version}.json" and
// the (signed if privateKey is set) index.json into outDir.
func buildApplicationCatalog(dir string, outDir string, baseURL string, privateKey ed25519.PrivateKey) (*core.ApplicationCatalogIndex, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read the manifests directory: %w", err)
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, err
	}

	baseURL = strings.TrimRight(baseURL, "/")

	index := &core.ApplicationCatalogIndex{Applications: []core.ApplicationCatalogEntry{}}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		var format string
		switch strings.ToLower(filepath.Ext(f.Name())) {
		case ".toml":
			format = core.ApplicationManifestFormatTOML
		case ".json":
			format = core.ApplicationManifestFormatJSON
		default:
			continue
		}

		raw, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			return nil, err
		}

		manifest, err := core.ParseApplicationManifest(raw, format)
		if err != nil {
			return nil, fmt.Errorf("invalid manifest %s: %w", f.Name(), err)
		}

		if manifest.InstallURL == "" {
			return nil, fmt.Errorf("invalid manifest %s: the catalog applications must have an install_url", f.Name())
		}

		if slices.ContainsFunc(index.Applications, func(e core.ApplicationCatalogEntry) bool { return e.Handle == manifest.Handle }) {
			return nil, fmt.Errorf("duplicated manifest handle %q (%s)", manifest.Handle, f.Name())
		}

		normalized, err := manifest.JSON()
		if err != nil {
			return nil, err
		}

		name := manifest.Handle + "-" + manifest.Version + ".json"
		if err := os.WriteFile(filepath.Join(outDir, name), normalized, 0644); err != nil {
			return nil, err
		}

		index.Applications = append(index.Applications, core.ApplicationCatalogEntry{
			Handle:         manifest.Handle,
			Name:           manifest.Name,
			Description:    manifest.Description,
			IconURL:        manifest.IconURL,
			Developer:      manifest.Developer,
			Version:        manifest.Version,
			ManifestURL:    baseURL + "/" + name,
			ManifestDigest: core.ApplicationManifestRawDigest(normalized),
		})
	}

	slices.SortFunc(index.Applications, func(a, b core.ApplicationCatalogEntry) int {
		return strings.Compare(a.Handle, b.Handle)
	})

	indexRaw, err := json.Marshal(index, json.Deterministic(true))
	if err != nil {
		return nil, err
	}

	if privateKey != nil {
		indexRaw, err = core.SignApplicationCatalogIndex(indexRaw, privateKey)
		if err != nil {
			return nil, err
		}
	}

	if err := os.WriteFile(filepath.Join(outDir, "index.json"), indexRaw, 0644); err != nil {
		return nil, err
	}

	return index, nil
}
