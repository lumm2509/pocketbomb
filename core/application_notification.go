package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/tools/security"
)

// Application notification events (the "event" claim of the notification JWTs).
const (
	ApplicationEventInstalled          = "application.installed"
	ApplicationEventUninstalled        = "application.uninstalled"
	ApplicationEventCredentialsRotated = "application.credentials_rotated"
	ApplicationEventScopesUpdate       = "application.scopes_update"
)

// applicationNotificationDuration is the notification JWT expiration duration.
const applicationNotificationDuration = 5 * time.Minute

// ApplicationNotificationError is returned when an application install (or credentials rotated)
// notification was not acknowledged with a 2xx response (or couldn't be sent at all).
type ApplicationNotificationError struct {
	Event      string
	URL        string
	StatusCode int
	Reason     string
}

// Error implements the [error] interface.
func (e *ApplicationNotificationError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("the application %s notification was rejected by %s (status %d): %s", e.Event, e.URL, e.StatusCode, e.Reason)
	}

	return fmt.Sprintf("the application %s notification to %s failed: %s", e.Event, e.URL, e.Reason)
}

// applicationNotification defines the data of a single application notification.
type applicationNotification struct {
	event          string
	url            string
	handle         string
	version        string
	installationId string
	clientId       string
	scopes         []string

	// secrets (installed and credentials rotated only)
	clientSecret  string
	webhookSecret string
}

// newApplicationNotificationJWT returns the notification JWT signed with the active signing key
// of the _applicationInstallations issuer (verifiable at the issuer JWKS).
func newApplicationNotificationJWT(app App, n *applicationNotification) (string, error) {
	signer, issuer, err := applicationIssuerSigner(app)
	if err != nil {
		return "", err
	}

	now := time.Now()

	claims := map[string]any{
		"iss":             issuer,
		"aud":             n.handle,
		"iat":             now.Unix(),
		"exp":             now.Add(applicationNotificationDuration).Unix(),
		"jti":             security.RandomString(32),
		"event":           n.event,
		"installation_id": n.installationId,
		"client_id":       n.clientId,
		"token_endpoint":  issuer + "/token",
		"scopes":          n.scopes,
		"version":         n.version,
	}

	if n.clientSecret != "" {
		claims["client_secret"] = n.clientSecret
	}
	if n.webhookSecret != "" {
		claims["webhook_secret"] = n.webhookSecret
	}

	return security.NewSignedJWT(claims, signer, applicationNotificationDuration)
}

// applicationIssuerSigner returns the active signing key of the _applicationInstallations issuer
// (verifiable at the issuer JWKS) and the issuer identifier.
func applicationIssuerSigner(app App) (*security.JWTSigner, string, error) {
	collection, err := app.FindCachedCollectionByNameOrId(CollectionNameApplicationInstallations)
	if err != nil {
		return nil, "", err
	}

	signingKey, ok := collection.OAuth2Server.ActiveSigningKey()
	if !ok {
		return nil, "", ErrMissingSigningKey
	}

	signer, err := signingKey.Signer()
	if err != nil {
		return nil, "", err
	}

	return signer, OAuth2Issuer(app, collection), nil
}

// sendApplicationNotification POSTs the signed notification JWT ("application/jwt")
// to the notification url (the secrets travel only over https or loopback in dev mode).
func (app *BaseApp) sendApplicationNotification(ctx context.Context, n *applicationNotification) error {
	notificationErr := func(statusCode int, reason string) error {
		return &ApplicationNotificationError{Event: n.event, URL: n.url, StatusCode: statusCode, Reason: reason}
	}

	if err := checkApplicationRemoteURL(app, n.url); err != nil {
		return notificationErr(0, err.Error())
	}

	token, err := newApplicationNotificationJWT(app, n)
	if err != nil {
		return notificationErr(0, "failed to sign the notification: "+err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, strings.NewReader(token))
	if err != nil {
		return notificationErr(0, err.Error())
	}
	req.Header.Set("Content-Type", "application/jwt")

	res, err := app.applicationCatalogs.httpClient().Send(req)
	if res == nil {
		return notificationErr(0, err.Error())
	}

	succeeded := res.StatusCode >= 200 && res.StatusCode < 300

	if err != nil && !succeeded {
		return notificationErr(res.StatusCode, "failed to read the response body: "+err.Error())
	}

	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return notificationErr(res.StatusCode, "redirects are not followed ("+res.Header.Get("Location")+")")
	}

	if !succeeded {
		reason := strings.TrimSpace(strings.ToValidUTF8(string(res.Body), ""))
		if len(reason) > 500 {
			reason = reason[:500]
		}
		if reason == "" {
			reason = http.StatusText(res.StatusCode)
		}
		return notificationErr(res.StatusCode, reason)
	}

	return nil
}
