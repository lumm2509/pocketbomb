// Package applicationscmd adds the "applications" command to a PocketBase instance.
//
// The deploy subcommand is a thin HTTP client of a (local or remote) PocketBase instance
// (it posts the manifest to POST /api/applications/manifests with a staff access token)
// and it doesn't access the app data directly.
//
// The catalog subcommands are offline tools for the catalog providers (e.g. an organization
// own applications catalog): "catalog keygen" generates the Ed25519 signing key pair and
// "catalog build" validates the manifests with the same parser as the server and writes the
// normalized manifests and the signed index.json.
//
// Example usage:
//
//	applicationscmd.MustRegister(app, app.RootCmd)
package applicationscmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/spf13/cobra"
)

// MustRegister registers the applicationscmd plugin to the provided app instance
// and panic if it fails.
func MustRegister(app core.App, rootCmd *cobra.Command) {
	if err := Register(app, rootCmd); err != nil {
		panic(err)
	}
}

// Register registers the applicationscmd plugin to the provided app instance.
func Register(app core.App, rootCmd *cobra.Command) error {
	if rootCmd == nil {
		return errors.New("missing root command")
	}

	rootCmd.AddCommand(newCommand())

	return nil
}

func newCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "applications",
		Short: "Manage the applications (extensions)",
	}

	command.AddCommand(applicationsDeployCommand())
	command.AddCommand(applicationsCatalogCommand())

	return command
}

func applicationsDeployCommand() *cobra.Command {
	var baseURL string
	var token string

	command := &cobra.Command{
		Use:          "deploy [manifest]",
		Example:      "applications deploy ./pocketbase.app.toml --url https://example.com --token STAFF_ACCESS_TOKEN",
		Short:        "Deploys an application manifest (pocketbase.app.toml or .json) as a new custom application version",
		SilenceUsage: true,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("missing manifest file path argument")
			}

			if token == "" {
				token = os.Getenv("PB_TOKEN")
			}
			if token == "" {
				return errors.New("missing --token flag or PB_TOKEN env variable (an access token of a staff member with the applications write permission)")
			}

			result, err := deployApplicationManifest(command.Context(), baseURL, token, args[0])
			if err != nil {
				return err
			}

			status := "new version"
			switch {
			case result.Unchanged:
				status = "unchanged"
			case result.Created:
				status = "created"
			}

			color.Green("Successfully deployed %s %s (%s).", result.Application.Handle, result.Version.Version, status)

			return nil
		},
	}

	command.Flags().StringVar(&baseURL, "url", "http://127.0.0.1:8090", "the PocketBase instance base URL")
	command.Flags().StringVar(&token, "token", "", "the staff access token (default to the PB_TOKEN env variable)")

	return command
}

type applicationDeployResult struct {
	Application struct {
		Handle string `json:"handle"`
	} `json:"application"`
	Version struct {
		Version string `json:"version"`
	} `json:"version"`
	Created   bool `json:"created"`
	Unchanged bool `json:"unchanged"`
}

// deployApplicationManifest posts the manifest file to POST {baseURL}/api/applications/manifests.
func deployApplicationManifest(ctx context.Context, baseURL string, token string, manifestPath string) (*applicationDeployResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var contentType string
	switch strings.ToLower(filepath.Ext(manifestPath)) {
	case ".toml":
		contentType = "application/toml"
	case ".json":
		contentType = "application/json"
	default:
		return nil, errors.New("the manifest must be a .toml or .json file")
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read the manifest: %w", err)
	}

	endpoint := strings.TrimRight(baseURL, "/") + "/api/applications/manifests"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", token)

	client := &http.Client{Timeout: 30 * time.Second}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to deploy the manifest: %w", err)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to deploy the manifest (%d): %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	result := &applicationDeployResult{}
	if err := json.Unmarshal(body, result); err != nil {
		return nil, fmt.Errorf("invalid deploy response: %w", err)
	}

	return result, nil
}
