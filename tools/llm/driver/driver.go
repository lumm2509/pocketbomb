// Package driver defines the normalized types and the minimal interfaces
// that every LLM provider implementation must satisfy.
//
// It is kept as a separate package (similar to filesystem/blob) so that
// the provider implementations could depend on it without import cycles.
package driver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var (
	// ErrUnsupported is returned when the driver doesn't support the requested operation.
	ErrUnsupported = errors.New("llm: operation is not supported by the provider")

	// ErrMissingModel is returned when neither the request nor the config specify a model.
	ErrMissingModel = errors.New("llm: missing model (set Request.Model or Config.DefaultModel)")

	// ErrClosed is returned when operating on an already closed driver or stream.
	ErrClosed = errors.New("llm: closed")
)

// Config defines the common provider driver configuration options.
type Config struct {
	// Provider is the name of the registered provider driver (e.g. "openai", "anthropic", "gemini").
	Provider string

	// APIKey is the provider API key (could be empty for local providers like Ollama).
	APIKey string

	// BaseURL overrides the default provider API base url
	// (e.g. "https://api.x.ai/v1").
	BaseURL string

	// DefaultModel is the model used when Request.Model is not set.
	DefaultModel string

	// Headers specifies optional extra HTTP headers sent with every request.
	Headers map[string]string

	// Timeout is an optional per-request timeout.
	//
	// For streaming requests it is applied only until the response
	// headers are received (use the ctx to limit the entire stream).
	Timeout time.Duration

	// HTTPClient is an optional custom HTTP client (default to http.DefaultClient).
	HTTPClient *http.Client

	// Options specifies optional provider specific settings
	// (see the related provider constructor for the supported keys).
	Options map[string]any
}

// Driver defines the minimal interface that every LLM provider must implement.
type Driver interface {
	// Generate sends a single non-streaming request and returns the normalized response.
	Generate(ctx context.Context, req *Request) (*Response, error)

	// Stream sends a streaming request and returns an iterator over the normalized events.
	//
	// The caller must call Close on the returned Stream when done.
	Stream(ctx context.Context, req *Request) (Stream, error)

	// Close releases any resources used by the driver.
	Close() error
}

// Embedder is an optional interface that drivers with embeddings support could implement.
type Embedder interface {
	Embed(ctx context.Context, req *EmbedRequest) (*EmbedResponse, error)
}

// Stream defines an iterator-like streaming response.
//
// Example:
//
//	defer s.Close()
//	for s.Next() {
//		e := s.Event()
//		// ...
//	}
//	if err := s.Err(); err != nil { ... }
type Stream interface {
	// Next advances the stream to the next event.
	// It returns false when the stream ends or an error occurs.
	Next() bool

	// Event returns the current event (valid after a Next() call that returned true).
	Event() StreamEvent

	// Err returns the first non-EOF error that was encountered by the stream (if any).
	Err() error

	// Close releases the stream resources (it is safe to be called multiple times).
	Close() error
}

// APIError defines a normalized provider API error.
type APIError struct {
	// Provider is the name of the provider that returned the error.
	Provider string `json:"provider"`

	// Status is the HTTP response status code (0 for errors received mid-stream).
	Status int `json:"status"`

	// Code is the provider specific error type/code (e.g. "invalid_request_error").
	Code string `json:"code"`

	// Message is the human readable error message.
	Message string `json:"message"`

	// Raw is the raw error response body.
	Raw []byte `json:"-"`
}

// Error implements the [error] interface.
func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}

	if e.Code != "" {
		return fmt.Sprintf("llm: %s API error (status %d, %s): %s", e.Provider, e.Status, e.Code, msg)
	}

	return fmt.Sprintf("llm: %s API error (status %d): %s", e.Provider, e.Status, msg)
}

// ResolveModel returns the request model or the config default one.
//
// Returns ErrMissingModel if both are empty.
func ResolveModel(reqModel string, config Config) (string, error) {
	if reqModel != "" {
		return reqModel, nil
	}

	if config.DefaultModel != "" {
		return config.DefaultModel, nil
	}

	return "", ErrMissingModel
}
