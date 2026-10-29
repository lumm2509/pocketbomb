package llm_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/tools/llm"
)

func TestOpenAIGenerateRequest(t *testing.T) {
	scenarios := []struct {
		name         string
		config       llm.Config
		request      *llm.Request
		expectedAuth string
		expectedBody string
	}{
		{
			"openai full request",
			llm.Config{Provider: "openai", APIKey: "test_key", DefaultModel: "default-model"},
			sampleRequest(),
			"Bearer test_key",
			`{
				"model": "default-model",
				"messages": [
					{"role": "system", "content": "be nice"},
					{"role": "user", "content": [
						{"type": "text", "text": "what is in the image?"},
						{"type": "image_url", "image_url": {"url": "data:image/png;base64,aGVsbG8="}},
						{"type": "image_url", "image_url": {"url": "https://example.com/a.jpg"}}
					]},
					{"role": "assistant", "content": "let me check", "tool_calls": [
						{"id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": "{\"q\":\"cat\"}"}}
					]},
					{"role": "tool", "tool_call_id": "call_1", "content": "{\"found\":true}"},
					{"role": "user", "content": "thanks"}
				],
				"tools": [{"type": "function", "function": {
					"name": "lookup",
					"description": "lookup something",
					"parameters": {"type":"object","properties":{"q":{"type":"string"}}}
				}}],
				"tool_choice": {"type": "function", "function": {"name": "lookup"}},
				"max_completion_tokens": 100,
				"temperature": 0.5,
				"top_p": 0.9,
				"stop": ["END"],
				"response_format": {"type": "json_schema", "json_schema": {"name": "answer", "schema": {"type":"object"}}},
				"custom": 123
			}`,
		},
		{
			"compatible minimal request (no api key, max_tokens field, json mode, extra removal)",
			llm.Config{Provider: "openai-compatible"},
			&llm.Request{
				Model:          "local-model",
				Messages:       []llm.Message{llm.UserText("hi")},
				MaxTokens:      10,
				ToolChoice:     &llm.ToolChoice{Mode: llm.ToolChoiceRequired},
				ResponseFormat: &llm.ResponseFormat{Type: llm.ResponseFormatJSON},
				Extra:          map[string]any{"max_tokens": nil, "num_ctx": 2048},
			},
			"",
			`{
				"model": "local-model",
				"messages": [{"role": "user", "content": "hi"}],
				"tool_choice": "required",
				"response_format": {"type": "json_object"},
				"num_ctx": 2048
			}`,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			srv := newFakeServer(t, 200, "application/json", `{"model":"m","choices":[]}`)

			s.config.BaseURL = srv.URL + "/v1"
			client := newTestClient(t, s.config)

			if _, err := client.Generate(context.Background(), s.request); err != nil {
				t.Fatal(err)
			}

			req := srv.last(t)

			if req.Method != http.MethodPost || req.Path != "/v1/chat/completions" {
				t.Fatalf("Expected POST /v1/chat/completions, got %s %s", req.Method, req.Path)
			}

			if auth := req.Header.Get("Authorization"); auth != s.expectedAuth {
				t.Fatalf("Expected Authorization %q, got %q", s.expectedAuth, auth)
			}

			assertJSON(t, s.expectedBody, req.Body)
		})
	}
}

func TestOpenAIGenerateResponse(t *testing.T) {
	scenarios := []struct {
		name     string
		body     string
		expected string
	}{
		{
			"text response",
			`{"model":"gpt-x","choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`,
			`{"message":{"role":"assistant","parts":[{"type":"text","text":"hello"}]},"stopReason":"end_turn","usage":{"inputTokens":3,"outputTokens":2},"model":"gpt-x"}`,
		},
		{
			"tool calls response",
			`{"model":"gpt-x","choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"lookup","arguments":"{\"q\":1}"}}]},"finish_reason":"tool_calls"}]}`,
			`{"message":{"role":"assistant","parts":[{"type":"tool_call","toolCall":{"id":"c1","name":"lookup","arguments":{"q":1}}}]},"stopReason":"tool_use","usage":{"inputTokens":0,"outputTokens":0},"model":"gpt-x"}`,
		},
		{
			"max tokens",
			`{"model":"gpt-x","choices":[{"message":{"content":"he"},"finish_reason":"length"}]}`,
			`{"message":{"role":"assistant","parts":[{"type":"text","text":"he"}]},"stopReason":"max_tokens","usage":{"inputTokens":0,"outputTokens":0},"model":"gpt-x"}`,
		},
		{
			"content filter",
			`{"model":"gpt-x","choices":[{"message":{"content":""},"finish_reason":"content_filter"}]}`,
			`{"message":{"role":"assistant","parts":null},"stopReason":"other","usage":{"inputTokens":0,"outputTokens":0},"model":"gpt-x"}`,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			srv := newFakeServer(t, 200, "application/json", s.body)
			client := newTestClient(t, llm.Config{Provider: "openai", BaseURL: srv.URL, DefaultModel: "m"})

			resp, err := client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
			if err != nil {
				t.Fatal(err)
			}

			if string(resp.Raw) != s.body {
				t.Fatalf("Expected Raw %s, got %s", s.body, resp.Raw)
			}

			assertResponseJSON(t, s.expected, resp)
		})
	}
}

func TestOpenAIErrors(t *testing.T) {
	t.Run("missing model", func(t *testing.T) {
		srv := newFakeServer(t, 200, "application/json", `{}`)
		client := newTestClient(t, llm.Config{Provider: "openai", BaseURL: srv.URL})

		_, err := client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
		if !errors.Is(err, llm.ErrMissingModel) {
			t.Fatalf("Expected ErrMissingModel, got %v", err)
		}
	})

	t.Run("api error", func(t *testing.T) {
		body := `{"error":{"message":"bad model","type":"invalid_request_error","code":"model_not_found"}}`
		srv := newFakeServer(t, 404, "application/json", body)
		client := newTestClient(t, llm.Config{Provider: "xai", BaseURL: srv.URL, DefaultModel: "m"})

		_, err := client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})

		var apiErr *llm.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("Expected APIError, got %v", err)
		}

		if apiErr.Provider != "xai" || apiErr.Status != 404 || apiErr.Code != "model_not_found" || apiErr.Message != "bad model" || string(apiErr.Raw) != body {
			t.Fatalf("Unexpected APIError %#v", apiErr)
		}
	})

	t.Run("non-json api error", func(t *testing.T) {
		srv := newFakeServer(t, 502, "text/plain", "bad gateway")
		client := newTestClient(t, llm.Config{Provider: "openai", BaseURL: srv.URL, DefaultModel: "m"})

		_, err := client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})

		var apiErr *llm.APIError
		if !errors.As(err, &apiErr) || apiErr.Status != 502 || apiErr.Message != "bad gateway" {
			t.Fatalf("Unexpected error %v", err)
		}
	})

	t.Run("stream error chunk", func(t *testing.T) {
		srv := newFakeServer(t, 200, "text/event-stream", sseBody(
			`data: {"choices":[{"delta":{"content":"a"}}]}`,
			`data: {"error":{"message":"overloaded","type":"server_error"}}`,
		))
		client := newTestClient(t, llm.Config{Provider: "openai", BaseURL: srv.URL, DefaultModel: "m"})

		s, err := client.Stream(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		_, err = llm.Accumulate(s)

		var apiErr *llm.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != "server_error" || apiErr.Message != "overloaded" {
			t.Fatalf("Unexpected error %v", err)
		}
	})
}

func TestOpenAIStream(t *testing.T) {
	srv := newFakeServer(t, 200, "text/event-stream", sseBody(
		`: keep-alive comment`,
		`data: {"model":"gpt-x","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}`,
		`data: {"model":"gpt-x","choices":[{"index":0,"delta":{"content":"lo"}}]}`,
		`data: {"model":"gpt-x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"lookup","arguments":""}}]}}]}`,
		`data: {"model":"gpt-x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"q\":"}}]}}]}`,
		`data: {"model":"gpt-x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}},{"index":1,"id":"c2","function":{"name":"other","arguments":"{}"}}]}}]}`,
		`data: {"model":"gpt-x","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: {"model":"gpt-x","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":7}}`,
		`data: [DONE]`,
		`data: {"choices":[{"delta":{"content":"ignored after done"}}]}`,
	))

	client := newTestClient(t, llm.Config{Provider: "openai", BaseURL: srv.URL, DefaultModel: "m"})

	s, err := client.Stream(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	resp, err := llm.Accumulate(s)
	if err != nil {
		t.Fatal(err)
	}

	req := srv.last(t)
	assertJSON(t, `{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"include_usage":true}}`, req.Body)
	if accept := req.Header.Get("Accept"); accept != "text/event-stream" {
		t.Fatalf("Expected text/event-stream Accept header, got %q", accept)
	}

	assertResponseJSON(t, `{
		"message": {"role":"assistant","parts":[
			{"type":"text","text":"Hello"},
			{"type":"tool_call","toolCall":{"id":"c1","name":"lookup","arguments":{"q":1}}},
			{"type":"tool_call","toolCall":{"id":"c2","name":"other","arguments":{}}}
		]},
		"stopReason":"tool_use",
		"usage":{"inputTokens":5,"outputTokens":7},
		"model":"gpt-x"
	}`, resp)
}

func TestOpenAIEmbed(t *testing.T) {
	srv := newFakeServer(t, 200, "application/json", `{"model":"emb","data":[{"index":1,"embedding":[0.3,0.4]},{"index":0,"embedding":[0.1,0.2]}],"usage":{"prompt_tokens":4}}`)
	client := newTestClient(t, llm.Config{Provider: "openai", BaseURL: srv.URL, APIKey: "k"})

	if _, err := client.Embed(context.Background(), &llm.EmbedRequest{Input: []string{"a"}}); !errors.Is(err, llm.ErrMissingModel) {
		t.Fatalf("Expected ErrMissingModel, got %v", err)
	}

	resp, err := client.Embed(context.Background(), &llm.EmbedRequest{Model: "emb", Input: []string{"a", "b"}, Dimensions: 2})
	if err != nil {
		t.Fatal(err)
	}

	req := srv.last(t)
	if req.Path != "/embeddings" {
		t.Fatalf("Expected /embeddings path, got %q", req.Path)
	}
	assertJSON(t, `{"model":"emb","input":["a","b"],"dimensions":2}`, req.Body)

	if len(resp.Embeddings) != 2 || resp.Embeddings[0][0] != 0.1 || resp.Embeddings[1][0] != 0.3 || resp.Usage.InputTokens != 4 || resp.Model != "emb" {
		t.Fatalf("Unexpected embed response %#v", resp)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestOpenAICompatibleAliasesBaseURL(t *testing.T) {
	scenarios := []struct {
		provider    string
		baseURL     string
		expectedURL string
	}{
		{"xai", "", "https://api.x.ai/v1/chat/completions"},
		{"grok", "", "https://api.x.ai/v1/chat/completions"},
		{"ollama", "", "http://localhost:11434/v1/chat/completions"},
		{"openai", "", "https://api.openai.com/v1/chat/completions"},
		{"ollama", "http://example.com/v1/", "http://example.com/v1/chat/completions"},
	}

	for _, s := range scenarios {
		t.Run(s.provider+"_"+s.baseURL, func(t *testing.T) {
			var calledURL string

			httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calledURL = r.URL.String()
				return &http.Response{
					StatusCode: 200,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"choices":[]}`)),
				}, nil
			})}

			client := newTestClient(t, llm.Config{Provider: s.provider, BaseURL: s.baseURL, DefaultModel: "m", HTTPClient: httpClient})

			if _, err := client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}}); err != nil {
				t.Fatal(err)
			}

			if calledURL != s.expectedURL {
				t.Fatalf("Expected url %q, got %q", s.expectedURL, calledURL)
			}
		})
	}
}
