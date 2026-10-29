package llm_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/tools/llm"
)

// fakeDriver is a minimal Driver implementation (without Embedder support).
type fakeDriver struct {
	lastModel string
	resp      *llm.Response
	err       error
	events    []llm.StreamEvent
	streamErr error
	closed    bool
}

func (d *fakeDriver) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	d.lastModel = req.Model
	return d.resp, d.err
}

func (d *fakeDriver) Stream(ctx context.Context, req *llm.Request) (llm.Stream, error) {
	d.lastModel = req.Model
	if d.err != nil {
		return nil, d.err
	}
	return &fakeStream{events: d.events, err: d.streamErr, idx: -1}, nil
}

func (d *fakeDriver) Close() error {
	d.closed = true
	return nil
}

type fakeStream struct {
	events []llm.StreamEvent
	err    error
	idx    int
}

func (s *fakeStream) Next() bool {
	s.idx++
	return s.idx < len(s.events)
}

func (s *fakeStream) Event() llm.StreamEvent { return s.events[s.idx] }

func (s *fakeStream) Err() error {
	if s.idx >= len(s.events) {
		return s.err
	}
	return nil
}

func (s *fakeStream) Close() error { return nil }

func TestRegistry(t *testing.T) {
	providers := llm.Providers()
	for _, name := range []string{"openai", "openai-compatible", "xai", "grok", "ollama", "anthropic", "gemini"} {
		if !slices.Contains(providers, name) {
			t.Fatalf("Expected built-in provider %q to be registered, got %v", name, providers)
		}
	}

	t.Run("unknown provider", func(t *testing.T) {
		if _, err := llm.New(llm.Config{Provider: "missing"}); err == nil {
			t.Fatal("Expected error")
		}
	})

	t.Run("openai-compatible without BaseURL", func(t *testing.T) {
		if _, err := llm.New(llm.Config{Provider: "openai-compatible"}); err == nil {
			t.Fatal("Expected error")
		}
		if _, err := llm.NewOpenAICompatible("", "", ""); err == nil {
			t.Fatal("Expected error")
		}
	})

	t.Run("convenience constructors", func(t *testing.T) {
		constructors := []func() (*llm.Client, error){
			func() (*llm.Client, error) { return llm.NewOpenAI("k", "m") },
			func() (*llm.Client, error) { return llm.NewOpenAICompatible("http://localhost:1234/v1", "", "m") },
			func() (*llm.Client, error) { return llm.NewAnthropic("k", "m") },
			func() (*llm.Client, error) { return llm.NewGemini("k", "m") },
		}
		for i, fn := range constructors {
			c, err := fn()
			if err != nil {
				t.Fatalf("[%d] %v", i, err)
			}
			c.Close()
		}
	})

	t.Run("custom provider", func(t *testing.T) {
		drv := &fakeDriver{resp: &llm.Response{Model: "custom"}}

		llm.Register("test_custom", func(config llm.Config) (llm.Driver, error) {
			return drv, nil
		})

		client, err := llm.New(llm.Config{Provider: "test_custom"})
		if err != nil {
			t.Fatal(err)
		}

		if client.Driver() != drv {
			t.Fatal("Expected the custom driver")
		}

		if err := client.Close(); err != nil || !drv.closed {
			t.Fatalf("Expected the driver to be closed (err: %v)", err)
		}
	})

	t.Run("duplicated registration", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("Expected panic")
			}
		}()
		llm.Register("openai", func(config llm.Config) (llm.Driver, error) { return nil, nil })
	})

	t.Run("nil factory", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("Expected panic")
			}
		}()
		llm.Register("test_nil", nil)
	})
}

func TestClientEmbedUnsupported(t *testing.T) {
	client := llm.NewWithDriver(&fakeDriver{})
	defer client.Close()

	_, err := client.Embed(context.Background(), &llm.EmbedRequest{Model: "m"})
	if !errors.Is(err, llm.ErrUnsupported) {
		t.Fatalf("Expected ErrUnsupported, got %v", err)
	}

	if _, err := client.Embed(context.Background(), nil); err == nil {
		t.Fatal("Expected nil request error")
	}
}

func TestClientNilRequest(t *testing.T) {
	client := llm.NewWithDriver(&fakeDriver{})
	defer client.Close()

	if _, err := client.Generate(context.Background(), nil); err == nil {
		t.Fatal("Expected Generate error")
	}

	if _, err := client.Stream(context.Background(), nil); err == nil {
		t.Fatal("Expected Stream error")
	}
}

func TestClientGenerateHooks(t *testing.T) {
	driverErr := errors.New("driver_err")
	hookErr := errors.New("hook_err")

	scenarios := []struct {
		name          string
		driver        *fakeDriver
		before        func(e *llm.BeforeRequestEvent) error
		after         func(e *llm.AfterResponseEvent) error
		expectedModel string // the model received by the driver
		expectedResp  string // response model
		expectedErr   error
		expectedAfter int
	}{
		{
			"modify request and inspect response",
			&fakeDriver{resp: &llm.Response{Model: "resp", Usage: llm.Usage{InputTokens: 1}}},
			func(e *llm.BeforeRequestEvent) error {
				e.Request.Model = "changed"
				return e.Next()
			},
			func(e *llm.AfterResponseEvent) error {
				if e.Response.Usage.InputTokens != 1 || e.IsStream {
					return errors.New("unexpected after event")
				}
				return e.Next()
			},
			"changed",
			"resp",
			nil,
			1,
		},
		{
			"abort in before",
			&fakeDriver{resp: &llm.Response{Model: "resp"}},
			func(e *llm.BeforeRequestEvent) error {
				return hookErr
			},
			func(e *llm.AfterResponseEvent) error {
				return e.Next()
			},
			"",
			"",
			hookErr,
			0,
		},
		{
			"driver error propagated through after",
			&fakeDriver{err: driverErr},
			nil,
			func(e *llm.AfterResponseEvent) error {
				if e.Error != driverErr {
					return errors.New("expected driver error in event")
				}
				return e.Next()
			},
			"orig",
			"",
			driverErr,
			1,
		},
		{
			"after replaces error and response",
			&fakeDriver{err: driverErr},
			nil,
			func(e *llm.AfterResponseEvent) error {
				e.Response = &llm.Response{Model: "fallback"}
				return nil
			},
			"orig",
			"fallback",
			nil,
			1,
		},
		{
			"after returns error on success",
			&fakeDriver{resp: &llm.Response{Model: "resp"}},
			nil,
			func(e *llm.AfterResponseEvent) error {
				return hookErr
			},
			"orig",
			"resp",
			hookErr,
			1,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			client := llm.NewWithDriver(s.driver)
			defer client.Close()

			var afterCalls int

			if s.before != nil {
				client.OnBeforeRequest().BindFunc(s.before)
			}

			client.OnAfterResponse().BindFunc(func(e *llm.AfterResponseEvent) error {
				afterCalls++
				return s.after(e)
			})

			resp, err := client.Generate(context.Background(), &llm.Request{Model: "orig"})

			if !errors.Is(err, s.expectedErr) {
				t.Fatalf("Expected error %v, got %v", s.expectedErr, err)
			}

			if s.driver.lastModel != s.expectedModel {
				t.Fatalf("Expected driver model %q, got %q", s.expectedModel, s.driver.lastModel)
			}

			var respModel string
			if resp != nil {
				respModel = resp.Model
			}
			if respModel != s.expectedResp {
				t.Fatalf("Expected response model %q, got %q", s.expectedResp, respModel)
			}

			if afterCalls != s.expectedAfter {
				t.Fatalf("Expected %d after calls, got %d", s.expectedAfter, afterCalls)
			}
		})
	}
}

func TestClientStreamHooks(t *testing.T) {
	events := []llm.StreamEvent{
		{Type: llm.StreamEventTextDelta, Text: "a", Model: "m"},
		{Type: llm.StreamEventTextDelta, Text: "b"},
		{Type: llm.StreamEventUsage, Usage: &llm.Usage{InputTokens: 2, OutputTokens: 3}},
		{Type: llm.StreamEventStop, StopReason: llm.StopReasonEndTurn},
	}

	t.Run("after fired once with accumulated response", func(t *testing.T) {
		client := llm.NewWithDriver(&fakeDriver{events: events})
		defer client.Close()

		var calls int
		var got *llm.Response
		client.OnAfterResponse().BindFunc(func(e *llm.AfterResponseEvent) error {
			calls++
			got = e.Response
			if !e.IsStream {
				t.Error("Expected IsStream to be true")
			}
			return e.Next()
		})

		s, err := client.Stream(context.Background(), &llm.Request{})
		if err != nil {
			t.Fatal(err)
		}

		resp, err := llm.Accumulate(s)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
		s.Close()

		if calls != 1 {
			t.Fatalf("Expected 1 after call, got %d", calls)
		}

		if got == nil || got.Text() != "ab" || got.Usage.OutputTokens != 3 || got.StopReason != llm.StopReasonEndTurn || got.Model != "m" {
			t.Fatalf("Unexpected hook response %#v", got)
		}

		if resp.Text() != "ab" {
			t.Fatalf("Unexpected accumulated text %q", resp.Text())
		}
	})

	t.Run("after error is returned by Err", func(t *testing.T) {
		client := llm.NewWithDriver(&fakeDriver{events: events})
		defer client.Close()

		hookErr := errors.New("budget exceeded")
		client.OnAfterResponse().BindFunc(func(e *llm.AfterResponseEvent) error {
			return hookErr
		})

		s, err := client.Stream(context.Background(), &llm.Request{})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		if _, err := llm.Accumulate(s); !errors.Is(err, hookErr) {
			t.Fatalf("Expected hook error, got %v", err)
		}
	})

	t.Run("stream error with partial response", func(t *testing.T) {
		streamErr := errors.New("stream_err")
		client := llm.NewWithDriver(&fakeDriver{events: events[:1], streamErr: streamErr})
		defer client.Close()

		var gotErr error
		var gotText string
		client.OnAfterResponse().BindFunc(func(e *llm.AfterResponseEvent) error {
			gotErr = e.Error
			gotText = e.Response.Text()
			return e.Next()
		})

		s, err := client.Stream(context.Background(), &llm.Request{})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		if _, err := llm.Accumulate(s); !errors.Is(err, streamErr) {
			t.Fatalf("Expected stream error, got %v", err)
		}

		if gotErr != streamErr || gotText != "a" {
			t.Fatalf("Unexpected hook event data: %v, %q", gotErr, gotText)
		}
	})

	t.Run("driver stream init error", func(t *testing.T) {
		driverErr := errors.New("driver_err")
		client := llm.NewWithDriver(&fakeDriver{err: driverErr})
		defer client.Close()

		var calls int
		client.OnAfterResponse().BindFunc(func(e *llm.AfterResponseEvent) error {
			calls++
			return nil // try to suppress the error
		})

		if _, err := client.Stream(context.Background(), &llm.Request{}); !errors.Is(err, driverErr) {
			t.Fatalf("Expected driver error, got %v", err)
		}

		if calls != 1 {
			t.Fatalf("Expected 1 after call, got %d", calls)
		}
	})

	t.Run("before abort", func(t *testing.T) {
		client := llm.NewWithDriver(&fakeDriver{events: events})
		defer client.Close()

		hookErr := errors.New("hook_err")
		client.OnBeforeRequest().BindFunc(func(e *llm.BeforeRequestEvent) error {
			if !e.IsStream {
				t.Error("Expected IsStream to be true")
			}
			return hookErr
		})

		if _, err := client.Stream(context.Background(), &llm.Request{}); !errors.Is(err, hookErr) {
			t.Fatalf("Expected hook error, got %v", err)
		}
	})
}

func TestClientTimeoutAndCancellation(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	t.Run("config timeout", func(t *testing.T) {
		client := newTestClient(t, llm.Config{Provider: "openai", BaseURL: srv.URL, DefaultModel: "m", Timeout: 50 * time.Millisecond})

		_, err := client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Expected DeadlineExceeded, got %v", err)
		}
	})

	t.Run("ctx cancellation", func(t *testing.T) {
		client := newTestClient(t, llm.Config{Provider: "anthropic", BaseURL: srv.URL, DefaultModel: "m"})

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := client.Stream(ctx, &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Expected DeadlineExceeded, got %v", err)
		}
	})
}

func TestClientStreamTimeoutAppliesOnlyToHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(100 * time.Millisecond) // longer than the timeout
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"))
	}))
	defer srv.Close()

	client := newTestClient(t, llm.Config{Provider: "openai", BaseURL: srv.URL, DefaultModel: "m", Timeout: 30 * time.Millisecond})

	s, err := client.Stream(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	resp, err := llm.Accumulate(s)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Text() != "ok" || resp.StopReason != llm.StopReasonEndTurn {
		t.Fatalf("Unexpected response %#v", resp)
	}
}

type slowDriver struct {
	fakeDriver
	delay time.Duration
}

func (d *slowDriver) Generate(ctx context.Context, req *llm.Request) (*llm.Response, error) {
	time.Sleep(d.delay)
	return d.fakeDriver.Generate(ctx, req)
}

func (d *slowDriver) Stream(ctx context.Context, req *llm.Request) (llm.Stream, error) {
	time.Sleep(d.delay)
	return d.fakeDriver.Stream(ctx, req)
}

func TestClientAfterResponseDuration(t *testing.T) {
	delay := 15 * time.Millisecond

	for _, isStream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream_%v", isStream), func(t *testing.T) {
			client := llm.NewWithDriver(&slowDriver{
				fakeDriver: fakeDriver{
					resp:   &llm.Response{Model: "m"},
					events: []llm.StreamEvent{{Type: llm.StreamEventTextDelta, Text: "a"}},
				},
				delay: delay,
			})
			defer client.Close()

			var duration time.Duration
			client.OnAfterResponse().BindFunc(func(e *llm.AfterResponseEvent) error {
				duration = e.Duration
				return e.Next()
			})

			if isStream {
				s, err := client.Stream(context.Background(), &llm.Request{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := llm.Accumulate(s); err != nil {
					t.Fatal(err)
				}
				s.Close()
			} else {
				if _, err := client.Generate(context.Background(), &llm.Request{}); err != nil {
					t.Fatal(err)
				}
			}

			if duration < delay {
				t.Fatalf("Expected duration >= %v, got %v", delay, duration)
			}
		})
	}
}
