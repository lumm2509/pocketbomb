// Package safehttp implements a SSRF protected HTTP client for requests
// to user configured urls (webhooks, applications catalogs, avatars, etc.).
//
// The connections to private, loopback, link-local and otherwise reserved
// IP addresses are rejected after the DNS resolution (aka. also on DNS rebinding)
// unless [Options.AllowPrivateTargets] is set.
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"
)

// Default client options.
const (
	DefaultTimeout             = 10 * time.Second
	DefaultMaxResponseBodySize = 4 << 10 // 4KB
	DefaultUserAgent           = "PocketBase"
)

var (
	// ErrBlockedTarget is returned (wrapped) when the target address is not allowed
	// by the client SSRF protection (see [Options.AllowPrivateTargets]).
	ErrBlockedTarget = errors.New("safehttp: the target address is not allowed (private, loopback or otherwise reserved IP)")

	// ErrResponseTooLarge is returned (wrapped) by [Client.Fetch] when the
	// response body exceeds [FetchOptions.MaxBodySize].
	ErrResponseTooLarge = errors.New("safehttp: the response body exceeds the max allowed size")
)

// Options defines the [Client] options.
type Options struct {
	// Timeout is the per-request timeout (default to [DefaultTimeout]).
	Timeout time.Duration

	// MaxResponseBodySize is the max number of the [Client.Send] response body
	// bytes that are read (default to [DefaultMaxResponseBodySize]).
	MaxResponseBodySize int64

	// AllowPrivateTargets disables the SSRF protection and allows sending
	// requests to private, loopback, link-local and other reserved IP addresses.
	//
	// It is false by default and it is expected to be enabled only in development or tests.
	AllowPrivateTargets bool

	// UserAgent is the default request User-Agent header value (default to [DefaultUserAgent]).
	UserAgent string
}

func (o Options) normalize() Options {
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

// Client is a SSRF protected HTTP client.
//
// The environment HTTP proxy settings are intentionally ignored so
// that the dial check is always applied to the actual target address.
//
// Client is safe for concurrent use.
type Client struct {
	mu         sync.RWMutex
	options    Options
	httpClient *http.Client
}

// NewClient creates a new SSRF protected client.
func NewClient(options Options) *Client {
	c := &Client{}
	c.SetOptions(options)
	return c
}

// Options returns the current (normalized) client options.
func (c *Client) Options() Options {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.options
}

// SetOptions replaces the client options.
//
// The underlying HTTP transport is recreated only if the options have changed.
func (c *Client) SetOptions(options Options) {
	options = options.normalize()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.httpClient != nil && c.options == options {
		return
	}

	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}

	c.options = options
	c.httpClient = newHTTPClient(options)
}

// Close releases the idle client connections.
func (c *Client) Close() {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
}

func (c *Client) state() (Options, *http.Client) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.options, c.httpClient
}

func newHTTPClient(options Options) *http.Client {
	dialer := &net.Dialer{
		Timeout:   options.Timeout,
		KeepAlive: 30 * time.Second,
	}

	if !options.AllowPrivateTargets {
		dialer.Control = dialControl
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   options.Timeout,
		ResponseHeaderTimeout: options.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// dialControl is a [net.Dialer.Control] function that blocks the connections
// to non-public IP addresses (it is invoked with the already resolved IP address).
func dialControl(network string, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBlockedTarget, host)
	}

	if IsBlockedIP(addr) {
		return fmt.Errorf("%w: %s", ErrBlockedTarget, addr.String())
	}

	return nil
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this" network
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved (incl. broadcast)
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 (could map to private IPv4)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

// IsBlockedIP reports whether the provided IP is not a public unicast address
// (loopback, private, link-local, multicast, unspecified or otherwise reserved).
func IsBlockedIP(addr netip.Addr) bool {
	addr = addr.Unmap()

	if !addr.IsValid() ||
		addr.IsUnspecified() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() {
		return true
	}

	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}

	return false
}

// checkURL checks whether the target url is a valid absolute http(s) url.
func checkURL(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("safehttp: invalid target url - must be an absolute http(s) url")
	}

	return nil
}

// Response defines a [Client.Send] response.
type Response struct {
	StatusCode int
	Header     http.Header

	// Body is the response body limited to [Options.MaxResponseBodySize] bytes.
	Body []byte
}

// Send sends the provided request without following the redirects
// (the 3xx responses are returned as any other response).
//
// The User-Agent header is set to [Options.UserAgent] if missing.
//
// A transport error is returned with a nil response. A body read error
// is returned together with the (partially read) response.
func (c *Client) Send(req *http.Request) (*Response, error) {
	options, httpClient := c.state()

	if err := checkURL(req.URL); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(req.Context(), options.Timeout)
	defer cancel()

	req = req.WithContext(ctx)
	if req.Header == nil {
		req.Header = http.Header{}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", options.UserAgent)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result := &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
	}

	result.Body, err = io.ReadAll(io.LimitReader(resp.Body, options.MaxResponseBodySize))

	// drain a limited amount of the remaining body to allow connection reuse
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	return result, err
}

// FetchOptions defines the [Client.Fetch] options.
type FetchOptions struct {
	// MaxBodySize is the max allowed response body size (default to [DefaultMaxResponseBodySize]).
	MaxBodySize int64

	// MaxRedirects is the max number of followed redirects (0 = none).
	MaxRedirects int

	// AllowCrossHostRedirects allows following the redirects to another scheme or host
	// (by default only the same scheme and host redirects are followed).
	AllowCrossHostRedirects bool

	// Accept is an optional Accept request header value.
	Accept string
}

// FetchResult defines the [Client.Fetch] result.
type FetchResult struct {
	// URL is the final (after the redirects) request url.
	URL        string
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Fetch sends a GET request to the provided url (e.g. for fetching a remote document).
//
// Up to opts.MaxRedirects redirects are followed (by default only to the same scheme and host).
// The full response body must fit in opts.MaxBodySize (otherwise [ErrResponseTooLarge] is returned).
//
// The final response is returned regardless of its status code.
func (c *Client) Fetch(ctx context.Context, rawURL string, opts FetchOptions) (*FetchResult, error) {
	options, httpClient := c.state()

	if opts.MaxBodySize <= 0 {
		opts.MaxBodySize = DefaultMaxResponseBodySize
	}

	current, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	if err := checkURL(current); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	origin := current

	for redirects := 0; ; redirects++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", options.UserAgent)
		if opts.Accept != "" {
			req.Header.Set("Accept", opts.Accept)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "" {
			location := resp.Header.Get("Location")
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()

			if redirects >= opts.MaxRedirects {
				return nil, fmt.Errorf("safehttp: too many redirects (max %d)", opts.MaxRedirects)
			}

			next, err := current.Parse(location)
			if err != nil {
				return nil, fmt.Errorf("safehttp: invalid redirect location: %w", err)
			}

			if err := checkURL(next); err != nil {
				return nil, err
			}

			if !opts.AllowCrossHostRedirects && (next.Scheme != origin.Scheme || next.Host != origin.Host) {
				return nil, fmt.Errorf("safehttp: cross-host redirects are not allowed (%s)", next.Redacted())
			}

			current = next
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodySize+1))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("safehttp: failed to read the response body: %w", err)
		}

		if int64(len(body)) > opts.MaxBodySize {
			return nil, fmt.Errorf("%w (%d bytes)", ErrResponseTooLarge, opts.MaxBodySize)
		}

		return &FetchResult{
			URL:        current.String(),
			StatusCode: resp.StatusCode,
			Header:     resp.Header.Clone(),
			Body:       body,
		}, nil
	}
}
