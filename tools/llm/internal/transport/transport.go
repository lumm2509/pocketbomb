// Package transport contains the HTTP helpers shared by the provider drivers.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lumm2509/pocketbomb/tools/llm/driver"
)

// maxErrorBodySize is the max number of bytes read from an error response body.
const maxErrorBodySize = 1 << 20

var errTimeout = fmt.Errorf("llm: request timeout: %w", context.DeadlineExceeded)

// Client is a thin JSON-over-HTTP client shared by the drivers.
type Client struct {
	Provider string
	BaseURL  string
	Headers  map[string]string
	Timeout  time.Duration
	HTTP     *http.Client
}

// NewClient creates a new Client from the driver config
// (defaultBaseURL is used if config.BaseURL is empty).
func NewClient(provider string, config driver.Config, defaultBaseURL string) *Client {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	headers := make(map[string]string, len(config.Headers))
	for k, v := range config.Headers {
		headers[k] = v
	}

	return &Client{
		Provider: provider,
		BaseURL:  strings.TrimRight(baseURL, "/"),
		Headers:  headers,
		Timeout:  config.Timeout,
		HTTP:     httpClient,
	}
}

// Post sends a POST JSON request to the specified path and returns the raw response.
//
// body is serialized as JSON and the extra fields (if any) are shallow merged into it.
//
// Non-2xx responses are returned as *driver.APIError.
//
// If stream is true, the Client.Timeout is applied only until the response headers are received.
//
// The caller must close the returned response body.
func (c *Client) Post(
	ctx context.Context,
	path string,
	headers map[string]string,
	body any,
	extra map[string]any,
	stream bool,
) (*http.Response, error) {
	rawBody, err := MergeJSON(body, extra)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancelCause(ctx)

	var timer *time.Timer
	if c.Timeout > 0 {
		timer = time.AfterFunc(c.Timeout, func() { cancel(errTimeout) })
	}

	cleanup := func() {
		if timer != nil {
			timer.Stop()
		}
		cancel(nil)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(rawBody))
	if err != nil {
		cleanup()
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			err = cause
		}
		cleanup()
		return nil, err
	}

	if stream && timer != nil {
		timer.Stop()
	}

	resp.Body = &cleanupBody{ReadCloser: resp.Body, cleanup: cleanup}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return nil, ParseError(c.Provider, resp.StatusCode, raw)
	}

	return resp, nil
}

// PostJSON sends a non-streaming POST JSON request and decodes the response into result.
//
// It returns the raw response body.
func (c *Client) PostJSON(
	ctx context.Context,
	path string,
	headers map[string]string,
	body any,
	extra map[string]any,
	result any,
) (json.RawMessage, error) {
	resp, err := c.Post(ctx, path, headers, body, extra, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(raw, result); err != nil {
		return nil, fmt.Errorf("llm: failed to decode %s response: %w", c.Provider, err)
	}

	return raw, nil
}

type cleanupBody struct {
	io.ReadCloser
	cleanup func()
	once    sync.Once
}

func (b *cleanupBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.cleanup)
	return err
}

// MergeJSON serializes v as JSON object and shallow merges the extra fields into it.
//
// An extra field with nil value removes the related key.
func MergeJSON(v any, extra map[string]any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	if len(extra) == 0 {
		return raw, nil
	}

	obj := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}

	for k, val := range extra {
		if val == nil {
			delete(obj, k)
			continue
		}

		encoded, err := json.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("llm: failed to encode extra field %q: %w", k, err)
		}
		obj[k] = encoded
	}

	return json.Marshal(obj)
}

// ParseError tries to normalize the most common provider error bodies into *driver.APIError:
//
//	OpenAI:    {"error": {"message": "...", "type": "...", "code": "..."}}
//	Anthropic: {"type": "error", "error": {"type": "...", "message": "..."}}
//	Gemini:    {"error": {"code": 400, "message": "...", "status": "..."}}
func ParseError(provider string, status int, raw []byte) *driver.APIError {
	apiErr := &driver.APIError{
		Provider: provider,
		Status:   status,
		Raw:      raw,
	}

	var body struct {
		Error json.RawMessage `json:"error"`
	}

	if err := json.Unmarshal(raw, &body); err != nil || len(body.Error) == 0 {
		apiErr.Message = strings.TrimSpace(string(raw))
		return apiErr
	}

	// some providers return the error as plain string
	var str string
	if json.Unmarshal(body.Error, &str) == nil {
		apiErr.Message = str
		return apiErr
	}

	var details struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Status  string `json:"status"`
		Code    any    `json:"code"`
	}
	_ = json.Unmarshal(body.Error, &details)

	apiErr.Message = details.Message

	switch {
	case details.Status != "":
		apiErr.Code = details.Status
	case details.Code != nil && fmt.Sprint(details.Code) != "":
		if s, ok := details.Code.(string); ok {
			apiErr.Code = s
		} else if details.Type != "" {
			apiErr.Code = details.Type
		} else {
			apiErr.Code = fmt.Sprint(details.Code)
		}
	default:
		apiErr.Code = details.Type
	}

	return apiErr
}
