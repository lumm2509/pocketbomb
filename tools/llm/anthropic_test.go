package llm_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lumm2509/pocketbomb/tools/llm"
)

func TestAnthropicGenerateRequest(t *testing.T) {
	scenarios := []struct {
		name            string
		config          llm.Config
		request         *llm.Request
		expectedVersion string
		expectedBody    string
	}{
		{
			"full request",
			llm.Config{Provider: "anthropic", APIKey: "test_key", DefaultModel: "default-model"},
			sampleRequest(),
			"2023-06-01",
			`{
				"model": "default-model",
				"max_tokens": 100,
				"system": "be nice",
				"messages": [
					{"role": "user", "content": [
						{"type": "text", "text": "what is in the image?"},
						{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "aGVsbG8="}},
						{"type": "image", "source": {"type": "url", "url": "https://example.com/a.jpg"}}
					]},
					{"role": "assistant", "content": [
						{"type": "text", "text": "let me check"},
						{"type": "tool_use", "id": "call_1", "name": "lookup", "input": {"q":"cat"}}
					]},
					{"role": "user", "content": [
						{"type": "tool_result", "tool_use_id": "call_1", "content": "{\"found\":true}"},
						{"type": "text", "text": "thanks"}
					]}
				],
				"tools": [{
					"name": "lookup",
					"description": "lookup something",
					"input_schema": {"type":"object","properties":{"q":{"type":"string"}}}
				}],
				"tool_choice": {"type": "tool", "name": "lookup"},
				"temperature": 0.5,
				"top_p": 0.9,
				"stop_sequences": ["END"],
				"output_config": {"format": {"type": "json_schema", "schema": {"type":"object"}}},
				"custom": 123
			}`,
		},
		{
			"minimal request with options and error tool result",
			llm.Config{Provider: "anthropic", APIKey: "test_key", Options: map[string]any{"version": "2026-10-21", "defaultMaxTokens": 64}},
			&llm.Request{
				Model: "claude-x",
				Messages: []llm.Message{
					llm.UserMessage(llm.ToolResultPart("c1", "boom", true)),
				},
				Tools:      []llm.Tool{{Name: "noargs"}},
				ToolChoice: &llm.ToolChoice{Mode: llm.ToolChoiceRequired},
			},
			"2026-10-21",
			`{
				"model": "claude-x",
				"max_tokens": 64,
				"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": "boom", "is_error": true}]}],
				"tools": [{"name": "noargs", "input_schema": {"type":"object","properties":{}}}],
				"tool_choice": {"type": "any"}
			}`,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			srv := newFakeServer(t, 200, "application/json", `{"model":"m","content":[],"stop_reason":"end_turn"}`)

			s.config.BaseURL = srv.URL
			client := newTestClient(t, s.config)

			if _, err := client.Generate(context.Background(), s.request); err != nil {
				t.Fatal(err)
			}

			req := srv.last(t)

			if req.Path != "/messages" {
				t.Fatalf("Expected /messages path, got %q", req.Path)
			}

			if v := req.Header.Get("x-api-key"); v != "test_key" {
				t.Fatalf("Expected x-api-key header, got %q", v)
			}

			if v := req.Header.Get("anthropic-version"); v != s.expectedVersion {
				t.Fatalf("Expected anthropic-version %q, got %q", s.expectedVersion, v)
			}

			if v := req.Header.Get("Authorization"); v != "" {
				t.Fatalf("Expected no Authorization header, got %q", v)
			}

			assertJSON(t, s.expectedBody, req.Body)
		})
	}
}

func TestAnthropicGenerateResponse(t *testing.T) {
	scenarios := []struct {
		name     string
		body     string
		expected string
	}{
		{
			"text and tool use",
			`{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","content":[{"type":"thinking","thinking":""},{"type":"text","text":"checking"},{"type":"tool_use","id":"tu_1","name":"lookup","input":{"q":"cat"}}],"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":20}}`,
			`{"message":{"role":"assistant","parts":[{"type":"text","text":"checking"},{"type":"tool_call","toolCall":{"id":"tu_1","name":"lookup","arguments":{"q":"cat"}}}]},"stopReason":"tool_use","usage":{"inputTokens":10,"outputTokens":20},"model":"claude-x"}`,
		},
		{
			"stop sequence",
			`{"model":"claude-x","content":[{"type":"text","text":"a"}],"stop_reason":"stop_sequence","usage":{"input_tokens":1,"output_tokens":1}}`,
			`{"message":{"role":"assistant","parts":[{"type":"text","text":"a"}]},"stopReason":"stop_sequence","usage":{"inputTokens":1,"outputTokens":1},"model":"claude-x"}`,
		},
		{
			"refusal",
			`{"model":"claude-x","content":[],"stop_reason":"refusal","usage":{"input_tokens":1,"output_tokens":0}}`,
			`{"message":{"role":"assistant","parts":null},"stopReason":"other","usage":{"inputTokens":1,"outputTokens":0},"model":"claude-x"}`,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			srv := newFakeServer(t, 200, "application/json", s.body)
			client := newTestClient(t, llm.Config{Provider: "anthropic", BaseURL: srv.URL, DefaultModel: "m"})

			resp, err := client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
			if err != nil {
				t.Fatal(err)
			}

			assertResponseJSON(t, s.expected, resp)
		})
	}
}

func TestAnthropicStream(t *testing.T) {
	srv := newFakeServer(t, 200, "text/event-stream", sseBody(
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-x\",\"content\":[],\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}",
		"event: ping\ndata: {\"type\":\"ping\"}",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" there\"}}",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu_1\",\"name\":\"lookup\",\"input\":{}}}",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\"}}",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"q\\\": \"}}",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"cat\\\"}\"}}",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":15}}",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}",
	))

	client := newTestClient(t, llm.Config{Provider: "anthropic", BaseURL: srv.URL, APIKey: "k"})

	s, err := client.Stream(context.Background(), &llm.Request{Model: "claude-x", Messages: []llm.Message{llm.UserText("hi")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var textDeltas int
	var acc llm.Accumulator
	for s.Next() {
		e := s.Event()
		if e.Type == llm.StreamEventTextDelta {
			textDeltas++
		}
		acc.Add(e)
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}

	if textDeltas != 2 {
		t.Fatalf("Expected 2 text deltas, got %d", textDeltas)
	}

	assertJSON(t, `{"model":"claude-x","max_tokens":4096,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],"stream":true}`, srv.last(t).Body)

	assertResponseJSON(t, `{
		"message": {"role":"assistant","parts":[
			{"type":"text","text":"Hello there"},
			{"type":"tool_call","toolCall":{"id":"tu_1","name":"lookup","arguments":{"q":"cat"}}}
		]},
		"stopReason":"tool_use",
		"usage":{"inputTokens":25,"outputTokens":15},
		"model":"claude-x"
	}`, acc.Response())
}

func TestAnthropicErrors(t *testing.T) {
	t.Run("http error", func(t *testing.T) {
		srv := newFakeServer(t, 401, "application/json", `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
		client := newTestClient(t, llm.Config{Provider: "anthropic", BaseURL: srv.URL, DefaultModel: "m"})

		_, err := client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})

		var apiErr *llm.APIError
		if !errors.As(err, &apiErr) || apiErr.Provider != "anthropic" || apiErr.Status != 401 || apiErr.Code != "authentication_error" || apiErr.Message != "invalid x-api-key" {
			t.Fatalf("Unexpected error %v", err)
		}
	})

	t.Run("stream error event", func(t *testing.T) {
		srv := newFakeServer(t, 200, "text/event-stream", sseBody(
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-x\",\"usage\":{\"input_tokens\":1}}}",
			"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}",
		))
		client := newTestClient(t, llm.Config{Provider: "anthropic", BaseURL: srv.URL, DefaultModel: "m"})

		s, err := client.Stream(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		_, err = llm.Accumulate(s)

		var apiErr *llm.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != "overloaded_error" || apiErr.Status != 0 {
			t.Fatalf("Unexpected error %v", err)
		}
	})

	t.Run("embed unsupported", func(t *testing.T) {
		client := newTestClient(t, llm.Config{Provider: "anthropic"})

		_, err := client.Embed(context.Background(), &llm.EmbedRequest{Model: "m", Input: []string{"a"}})
		if !errors.Is(err, llm.ErrUnsupported) {
			t.Fatalf("Expected ErrUnsupported, got %v", err)
		}
	})
}
