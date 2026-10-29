package webhooks

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/lumm2509/pocketbomb/tools/safehttp"
)

// Default client options.
const (
	DefaultTimeout             = 5 * time.Second
	DefaultMaxResponseBodySize = 4 << 10 // 4KB
)

// ErrBlockedTarget is returned (wrapped) when the target address is
// not allowed by the client SSRF protection (see [ClientOptions.AllowPrivateTargets]).
var ErrBlockedTarget = safehttp.ErrBlockedTarget

// ClientOptions defines the [Client] options.
type ClientOptions struct {
	// Timeout is the per-request timeout (default to [DefaultTimeout]).
	Timeout time.Duration

	// MaxResponseBodySize is the max number of captured response body bytes
	// (default to [DefaultMaxResponseBodySize]).
	MaxResponseBodySize int

	// AllowPrivateTargets disables the SSRF protection and allows sending
	// requests to private, loopback, link-local and other reserved IP addresses.
	//
	// It is false by default (aka. the protection is enabled) and it is
	// expected to be enabled only in development or tests.
	AllowPrivateTargets bool

	// UserAgent is the request User-Agent header value (default to [DefaultUserAgent]).
	UserAgent string
}

func (o ClientOptions) normalize() ClientOptions {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.MaxResponseBodySize <= 0 {
		o.MaxResponseBodySize = DefaultMaxResponseBodySize
	}
	if o.UserAgent == "" {
		o.UserAgent = DefaultUserAgent
	}
	return o
}

// Client is a webhooks HTTP sender (see [safehttp.Client]).
//
// Redirect policy: redirects are never followed and any 3xx response is
// treated as failure. This keeps the signature bound to the configured
// endpoint and avoids redirect based SSRF bypasses (receivers are expected
// to update their endpoint url instead).
//
// Client is safe for concurrent use.
type Client struct {
	mu      sync.RWMutex
	options ClientOptions
	http    *safehttp.Client
}

// NewClient creates a new webhooks client.
func NewClient(options ClientOptions) *Client {
	c := &Client{http: safehttp.NewClient(safehttp.Options{})}
	c.SetOptions(options)
	return c
}

// Options returns the current (normalized) client options.
func (c *Client) Options() ClientOptions {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.options
}

// SetOptions replaces the client options.
func (c *Client) SetOptions(options ClientOptions) {
	options = options.normalize()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.options = options
	c.http.SetOptions(safehttp.Options{
		Timeout:             options.Timeout,
		MaxResponseBodySize: int64(options.MaxResponseBodySize),
		AllowPrivateTargets: options.AllowPrivateTargets,
		UserAgent:           options.UserAgent,
	})
}

// Send signs and sends the provided webhook request.
//
// It never returns nil and any transport error is reported in [Attempt.Error].
func (c *Client) Send(ctx context.Context, req *Request) *Attempt {
	options := c.Options()

	attempt := &Attempt{
		URL:       req.URL,
		StartedAt: time.Now(),
	}

	header := req.Header.Clone()
	if header == nil {
		header = http.Header{}
	}
	header.Set("User-Agent", options.UserAgent)
	if header.Get("Content-Type") == "" {
		header.Set("Content-Type", "application/json")
	}
	if req.Secret != "" {
		header.Set(HeaderHmac, Sign(req.Body, req.Secret))
	} else {
		header.Del(HeaderHmac)
	}

	attempt.RequestHeaders = header
	attempt.RequestBody = req.Body

	defer func() {
		attempt.Duration = time.Since(attempt.StartedAt)
	}()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		attempt.Error = err.Error()
		return attempt
	}
	httpReq.Header = header.Clone()

	resp, err := c.http.Send(httpReq)
	if resp == nil {
		attempt.Error = err.Error()
		return attempt
	}

	attempt.StatusCode = resp.StatusCode
	attempt.ResponseHeaders = resp.Header
	attempt.ResponseBody = resp.Body
	if err != nil && !attempt.Succeeded() {
		attempt.Error = "failed to read the response body: " + err.Error()
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 && attempt.Error == "" {
		attempt.Error = "redirects are not followed (" + resp.Header.Get("Location") + ")"
	}

	return attempt
}

// Close releases the idle client connections.
func (c *Client) Close() {
	c.http.Close()
}
