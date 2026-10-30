// Package webhooks implements a standalone, Shopify-style outgoing
// webhooks delivery toolkit:
//   - HMAC-SHA256 request signing and receiver verification ([Sign], [Verify])
//   - HTTP sender with timeout, no redirects, capped response capture
//     and optional SSRF protection ([Client])
//   - exponential backoff retry policy ([RetryPolicy])
//   - persistent queue abstraction with leases ([Store])
//   - bounded worker pool dispatcher ([Dispatcher])
//
// The package doesn't depend on the PocketBase core and could be used standalone.
//
// Each HTTP request body is the raw event payload and the event metadata is sent as headers:
//
//	X-PB-Topic:        the event topic (e.g. "posts.create")
//	X-PB-Hmac-Sha256:  base64(HMAC-SHA256(secret, rawBody))
//	X-PB-Webhook-Id:   the delivery id (same across the retries of a single delivery)
//	X-PB-Event-Id:     the event id (same across retries and redeliveries; use it for deduplication)
//	X-PB-Triggered-At: the event time (RFC3339 with milliseconds, UTC)
//	X-PB-Api-Version:  the payload api version
//	X-PB-Application-Installation, X-PB-Issuer: the application installation id and the issuer
//	                   of the managed (application installation) webhooks only (not signed)
//	User-Agent:        PocketBase-Webhooks
//
// Receiver example (Go):
//
//	http.HandleFunc("/webhooks", func(w http.ResponseWriter, r *http.Request) {
//		body, err := webhooks.Verify(r, os.Getenv("WEBHOOK_SECRET"))
//		if err != nil {
//			w.WriteHeader(http.StatusUnauthorized)
//			return
//		}
//		eventId := r.Header.Get(webhooks.HeaderEventId)
//		// ... skip if eventId was already processed, otherwise handle body ...
//		w.WriteHeader(http.StatusOK)
//	})
//
// Receiver example (Node.js, raw body is required):
//
//	const digest = crypto.createHmac("sha256", secret).update(rawBody).digest("base64");
//	const valid = crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(req.headers["x-pb-hmac-sha256"] || ""));
package webhooks

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Webhook request headers.
const (
	HeaderTopic       = "X-PB-Topic"
	HeaderHmac        = "X-PB-Hmac-Sha256"
	HeaderWebhookId   = "X-PB-Webhook-Id"
	HeaderEventId     = "X-PB-Event-Id"
	HeaderTriggeredAt = "X-PB-Triggered-At"
	HeaderApiVersion  = "X-PB-Api-Version"
	HeaderTest        = "X-PB-Test"

	// HeaderApplicationInstallation and HeaderIssuer identify the application installation of a
	// managed (application installation) webhook delivery: the installation id and the
	// _applicationInstallations issuer identifier of the instance (they are not part of the signed
	// content; the receiver verifies the body signature with the secret of that installation).
	HeaderApplicationInstallation = "X-PB-Application-Installation"
	HeaderIssuer                  = "X-PB-Issuer"

	DefaultUserAgent = "PocketBase-Webhooks"
)

// TriggeredAtLayout is the [HeaderTriggeredAt] time format.
const TriggeredAtLayout = "2006-01-02T15:04:05.000Z07:00"

// Delivery statuses.
const (
	// StatusPending is a new delivery waiting for its first attempt.
	StatusPending = "pending"

	// StatusRetrying is a delivery with at least one failed attempt that is scheduled for retry.
	StatusRetrying = "retrying"

	// StatusSuccess is a delivery whose last attempt was successful (2xx).
	StatusSuccess = "success"

	// StatusFailed is a delivery that has exhausted all of its attempts.
	StatusFailed = "failed"

	// StatusDisabled is a delivery that was discarded without being sent
	// (e.g. because its subscription was deleted or deactivated).
	StatusDisabled = "disabled"
)

// ErrDisabled could be returned (or wrapped) by a [SendFunc] to mark
// a delivery as [StatusDisabled] without counting it as failed attempt.
var ErrDisabled = errors.New("webhooks: delivery disabled")

// ErrLeaseLost is returned by the [Store] Mark* methods when the delivery
// lease token doesn't match (aka. the lease has expired and the delivery
// was claimed by another worker).
var ErrLeaseLost = errors.New("webhooks: delivery lease lost")

// Event defines a single webhook event.
type Event struct {
	// Id is the event unique identifier (it is used as receivers dedupe key
	// and it is the same across all retries and redeliveries).
	Id string `json:"id"`

	// Topic is the event topic, e.g. "posts.create".
	Topic string `json:"topic"`

	// ApiVersion is the payload api version.
	ApiVersion string `json:"apiVersion"`

	// TriggeredAt is the time when the event occurred.
	TriggeredAt time.Time `json:"triggeredAt"`

	// Payload is the raw JSON payload that is sent as request body.
	Payload json.RawMessage `json:"payload"`
}

// Delivery defines a single event delivery to a single subscription (aka. endpoint).
type Delivery struct {
	// Id is the delivery unique identifier (sent as [HeaderWebhookId]).
	Id string `json:"id"`

	// SubscriptionId is the id of the related subscription.
	SubscriptionId string `json:"subscriptionId"`

	Event Event `json:"event"`

	Status   string `json:"status"`
	Attempts int    `json:"attempts"`

	// NextAttemptAt is the time of the next scheduled attempt
	// (zero for the completed deliveries).
	NextAttemptAt time.Time `json:"nextAttemptAt"`

	// LeaseUntil and LeaseToken are set by [Store.ClaimDue] and
	// prevent the delivery from being claimed by another worker.
	LeaseUntil time.Time `json:"leaseUntil"`
	LeaseToken string    `json:"-"`

	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

// IsDone reports whether the delivery is in a final state (success, failed or disabled).
func (d *Delivery) IsDone() bool {
	return d.Status == StatusSuccess || d.Status == StatusFailed || d.Status == StatusDisabled
}

// Request defines a single webhook HTTP request.
//
// Header and Body could be modified before sending (the signature
// is calculated by [Client.Send] from the final Body).
type Request struct {
	URL string

	// Secret is the HMAC signing secret (if empty, the request is sent without the
	// signature header, e.g. a request with an already self-signed body like a JWT).
	Secret string

	// Header contains the request headers (the standard webhook headers are
	// set by [NewRequest] and the signature header is always (re)set by [Client.Send]).
	Header http.Header

	Body []byte
}

// NewRequest creates a new webhook request for the specified delivery
// with the delivery event payload as body and the standard webhook headers.
//
// topic is the value of the [HeaderTopic] (if empty, fallbacks to d.Event.Topic).
func NewRequest(d *Delivery, url string, secret string, topic string) *Request {
	if topic == "" {
		topic = d.Event.Topic
	}

	body := []byte(d.Event.Payload)
	if len(body) == 0 {
		body = []byte("{}")
	}

	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set(HeaderTopic, topic)
	h.Set(HeaderWebhookId, d.Id)
	h.Set(HeaderEventId, d.Event.Id)
	h.Set(HeaderTriggeredAt, d.Event.TriggeredAt.UTC().Format(TriggeredAtLayout))
	h.Set(HeaderApiVersion, d.Event.ApiVersion)

	return &Request{
		URL:    url,
		Secret: secret,
		Header: h,
		Body:   body,
	}
}

// Attempt defines the result of a single delivery HTTP request.
type Attempt struct {
	URL string `json:"url"`

	RequestHeaders http.Header `json:"requestHeaders"`
	RequestBody    []byte      `json:"requestBody"`

	// StatusCode is the response status code (0 if no response was received).
	StatusCode      int         `json:"statusCode"`
	ResponseHeaders http.Header `json:"responseHeaders"`

	// ResponseBody is the response body (capped to [ClientOptions.MaxResponseBodySize]).
	ResponseBody []byte `json:"responseBody"`

	// Error is the transport (or other) error message (if any).
	Error string `json:"error"`

	StartedAt time.Time     `json:"startedAt"`
	Duration  time.Duration `json:"duration"`
}

// Succeeded reports whether the attempt is successful (aka. no error and 2xx response status).
func (a *Attempt) Succeeded() bool {
	return a != nil && a.Error == "" && a.StatusCode >= 200 && a.StatusCode < 300
}
