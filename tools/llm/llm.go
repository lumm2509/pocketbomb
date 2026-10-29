// Package llm implements a lightweight provider-agnostic LLM client
// (OpenAI, OpenAI-compatible, Anthropic, Gemini, etc.).
//
// Example:
//
//	client, err := llm.NewAnthropic(apiKey, "claude-opus-5-5")
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//
//	resp, err := client.Generate(ctx, &llm.Request{
//		Messages: []llm.Message{llm.UserText("Hello!")},
//	})
//	if err != nil {
//		return err
//	}
//
//	fmt.Println(resp.Text())
package llm

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/llm/driver"
)

// BeforeRequestEvent is triggered before every Generate and Stream driver call.
//
// Handlers could modify the Request or return an error to abort it.
type BeforeRequestEvent struct {
	hook.Event
	Client   *Client
	Context  context.Context
	Request  *Request
	IsStream bool
}

// AfterResponseEvent is triggered after every Generate and Stream driver call.
//
// For streams it is triggered once the stream ends (or it is closed)
// with the accumulated (possibly partial) Response.
//
// e.Next() returns e.Error, so handlers could modify the Response
// or replace/clear the Error by returning a different value.
type AfterResponseEvent struct {
	hook.Event
	Client   *Client
	Context  context.Context
	Request  *Request
	IsStream bool
	Response *Response // could be nil on error
	Error    error

	// Duration is the elapsed time since the start of the request
	// (for streams - until the stream end or close).
	Duration time.Duration
}

// Client is a provider-agnostic LLM client that wraps a provider [Driver].
type Client struct {
	drv Driver

	onBeforeRequest *hook.Hook[*BeforeRequestEvent]
	onAfterResponse *hook.Hook[*AfterResponseEvent]
}

// NewWithDriver initializes a new LLM client with a custom driver.
//
// NB! Make sure to call `Close()` after you are done working with it.
func NewWithDriver(drv Driver) *Client {
	return &Client{drv: drv}
}

// Driver returns the underlying client driver.
func (c *Client) Driver() Driver {
	return c.drv
}

// Close releases any resources used by the client and its driver.
func (c *Client) Close() error {
	if c.onBeforeRequest != nil {
		c.onBeforeRequest.UnbindAll()
		c.onBeforeRequest = nil
	}

	if c.onAfterResponse != nil {
		c.onAfterResponse.UnbindAll()
		c.onAfterResponse = nil
	}

	return c.drv.Close()
}

// OnBeforeRequest is a low level hook that is triggered before every
// [Client.Generate] and [Client.Stream] call.
//
// It could be used for example to redact the request messages or to enforce budgets.
func (c *Client) OnBeforeRequest() *hook.Hook[*BeforeRequestEvent] {
	if c.onBeforeRequest == nil {
		c.onBeforeRequest = &hook.Hook[*BeforeRequestEvent]{}
	}

	return c.onBeforeRequest
}

// OnAfterResponse is a low level hook that is triggered after every
// [Client.Generate] and [Client.Stream] call (including failed ones).
//
// It could be used for example to log the tokens usage.
func (c *Client) OnAfterResponse() *hook.Hook[*AfterResponseEvent] {
	if c.onAfterResponse == nil {
		c.onAfterResponse = &hook.Hook[*AfterResponseEvent]{}
	}

	return c.onAfterResponse
}

// Generate sends a single non-streaming request to the LLM provider.
//
// Provider HTTP errors are returned as [*APIError].
func (c *Client) Generate(ctx context.Context, req *Request) (*Response, error) {
	if err := c.beforeRequest(ctx, req, false); err != nil {
		return nil, err
	}

	start := time.Now()

	resp, err := c.drv.Generate(ctx, req)

	return c.afterResponse(ctx, req, false, resp, err, start)
}

// Stream sends a streaming request to the LLM provider.
//
// NB! Make sure to call `Close()` on the returned stream after you are done working with it.
//
// Use [Accumulate] if you want to collect the stream events into a final [Response].
func (c *Client) Stream(ctx context.Context, req *Request) (Stream, error) {
	if err := c.beforeRequest(ctx, req, true); err != nil {
		return nil, err
	}

	start := time.Now()

	s, err := c.drv.Stream(ctx, req)
	if err != nil {
		_, hookErr := c.afterResponse(ctx, req, true, nil, err, start)
		if hookErr == nil {
			hookErr = err // a stream can't be returned without a driver stream
		}
		return nil, hookErr
	}

	if c.onAfterResponse == nil || c.onAfterResponse.Length() == 0 {
		return s, nil
	}

	return &hookedStream{Stream: s, client: c, ctx: ctx, req: req, start: start}, nil
}

// Embed creates embedding vectors for the specified inputs.
//
// Returns [ErrUnsupported] if the provider driver doesn't support embeddings.
func (c *Client) Embed(ctx context.Context, req *EmbedRequest) (*EmbedResponse, error) {
	if req == nil {
		return nil, errors.New("llm: nil embed request")
	}

	embedder, ok := c.drv.(Embedder)
	if !ok {
		return nil, ErrUnsupported
	}

	return embedder.Embed(ctx, req)
}

func (c *Client) beforeRequest(ctx context.Context, req *Request, isStream bool) error {
	if req == nil {
		return errors.New("llm: nil request")
	}

	if c.onBeforeRequest == nil {
		return nil
	}

	return c.onBeforeRequest.Trigger(&BeforeRequestEvent{
		Client:   c,
		Context:  ctx,
		Request:  req,
		IsStream: isStream,
	})
}

func (c *Client) afterResponse(ctx context.Context, req *Request, isStream bool, resp *Response, err error, start time.Time) (*Response, error) {
	if c.onAfterResponse == nil {
		return resp, err
	}

	event := &AfterResponseEvent{
		Client:   c,
		Context:  ctx,
		Request:  req,
		IsStream: isStream,
		Response: resp,
		Error:    err,
		Duration: time.Since(start),
	}

	hookErr := c.onAfterResponse.Trigger(event, func(e *AfterResponseEvent) error {
		return e.Error
	})

	return event.Response, hookErr
}

// hookedStream wraps a driver stream and triggers OnAfterResponse when it ends.
type hookedStream struct {
	driver.Stream

	client *Client
	ctx    context.Context
	req    *Request
	start  time.Time
	acc    driver.Accumulator
	once   sync.Once
	err    error
}

func (s *hookedStream) Next() bool {
	if s.Stream.Next() {
		s.acc.Add(s.Stream.Event())
		return true
	}

	s.finish()

	return false
}

func (s *hookedStream) Err() error {
	if s.err != nil {
		return s.err
	}
	return s.Stream.Err()
}

func (s *hookedStream) Close() error {
	s.finish()
	return s.Stream.Close()
}

func (s *hookedStream) finish() {
	s.once.Do(func() {
		streamErr := s.Stream.Err()

		// note: on error the Response contains the partially accumulated data
		_, hookErr := s.client.afterResponse(s.ctx, s.req, true, s.acc.Response(), streamErr, s.start)
		if hookErr != streamErr {
			s.err = hookErr
		}
	})
}
