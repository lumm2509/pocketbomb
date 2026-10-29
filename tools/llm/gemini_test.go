package llm_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lumm2509/pocketbomb/tools/llm"
)

func TestGeminiGenerateRequest(t *testing.T) {
	srv := newFakeServer(t, 200, "application/json", `{"candidates":[]}`)
	client := newTestClient(t, llm.Config{Provider: "gemini", BaseURL: srv.URL + "/v1beta", APIKey: "test_key", DefaultModel: "gemini-x"})

	if _, err := client.Generate(context.Background(), sampleRequest()); err != nil {
		t.Fatal(err)
	}

	req := srv.last(t)

	if req.Path != "/v1beta/models/gemini-x:generateContent" {
		t.Fatalf("Unexpected path %q", req.Path)
	}

	if v := req.Header.Get("x-goog-api-key"); v != "test_key" {
		t.Fatalf("Expected x-goog-api-key header, got %q", v)
	}

	assertJSON(t, `{
		"systemInstruction": {"parts": [{"text": "be nice"}]},
		"contents": [
			{"role": "user", "parts": [
				{"text": "what is in the image?"},
				{"inlineData": {"mimeType": "image/png", "data": "aGVsbG8="}},
				{"fileData": {"mimeType": "image/jpeg", "fileUri": "https://example.com/a.jpg"}}
			]},
			{"role": "model", "parts": [
				{"text": "let me check"},
				{"functionCall": {"id": "call_1", "name": "lookup", "args": {"q":"cat"}}}
			]},
			{"role": "user", "parts": [
				{"functionResponse": {"id": "call_1", "name": "lookup", "response": {"found": true}}},
				{"text": "thanks"}
			]}
		],
		"tools": [{"functionDeclarations": [{
			"name": "lookup",
			"description": "lookup something",
			"parametersJsonSchema": {"type":"object","properties":{"q":{"type":"string"}}}
		}]}],
		"toolConfig": {"functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": ["lookup"]}},
		"generationConfig": {
			"maxOutputTokens": 100,
			"temperature": 0.5,
			"topP": 0.9,
			"stopSequences": ["END"],
			"responseMimeType": "application/json",
			"responseJsonSchema": {"type":"object"}
		},
		"custom": 123
	}`, req.Body)
}

func TestGeminiToolResultConversion(t *testing.T) {
	scenarios := []struct {
		name          string
		messages      []llm.Message
		expectError   bool
		expectedParts string
	}{
		{
			"plain text error result with generated id",
			[]llm.Message{
				llm.AssistantMessage(llm.ToolCallPart("gemini_call_0", "lookup", nil)),
				llm.UserMessage(llm.ToolResultPart("gemini_call_0", "boom", true)),
			},
			false,
			`[{"role":"model","parts":[{"functionCall":{"name":"lookup","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"name":"lookup","response":{"error":"boom"}}}]}]`,
		},
		{
			"plain text result with explicit name",
			[]llm.Message{
				llm.UserMessage(llm.Part{Type: "tool_result", ToolResult: &llm.ToolResult{ToolCallID: "x", Name: "lookup", Content: "ok"}}),
			},
			false,
			`[{"role":"user","parts":[{"functionResponse":{"id":"x","name":"lookup","response":{"content":"ok"}}}]}]`,
		},
		{
			"unresolvable tool name",
			[]llm.Message{llm.UserMessage(llm.ToolResultPart("missing", "ok", false))},
			true,
			``,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			srv := newFakeServer(t, 200, "application/json", `{"candidates":[]}`)
			client := newTestClient(t, llm.Config{Provider: "gemini", BaseURL: srv.URL, DefaultModel: "gemini-x"})

			_, err := client.Generate(context.Background(), &llm.Request{Messages: s.messages})

			hasErr := err != nil
			if hasErr != s.expectError {
				t.Fatalf("Expected hasErr %v, got %v (%v)", s.expectError, hasErr, err)
			}

			if hasErr {
				return
			}

			var body struct {
				Contents json.RawMessage `json:"contents"`
			}
			if err := json.Unmarshal(srv.last(t).Body, &body); err != nil {
				t.Fatal(err)
			}

			assertJSON(t, s.expectedParts, body.Contents)
		})
	}
}

func TestGeminiGenerateResponse(t *testing.T) {
	scenarios := []struct {
		name     string
		body     string
		expected string
	}{
		{
			"text response",
			`{"candidates":[{"content":{"role":"model","parts":[{"text":"thinking...","thought":true},{"text":"Hel"},{"text":"lo"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":2,"thoughtsTokenCount":3},"modelVersion":"gemini-x-001"}`,
			`{"message":{"role":"assistant","parts":[{"type":"text","text":"Hello"}]},"stopReason":"end_turn","usage":{"inputTokens":4,"outputTokens":5},"model":"gemini-x-001"}`,
		},
		{
			"function calls (with and without id)",
			`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"a","args":{"x":1}}},{"functionCall":{"id":"fc_2","name":"b"}}]},"finishReason":"STOP"}]}`,
			`{"message":{"role":"assistant","parts":[{"type":"tool_call","toolCall":{"id":"gemini_call_0","name":"a","arguments":{"x":1}}},{"type":"tool_call","toolCall":{"id":"fc_2","name":"b","arguments":{}}}]},"stopReason":"tool_use","usage":{"inputTokens":0,"outputTokens":0},"model":"gemini-x"}`,
		},
		{
			"max tokens",
			`{"candidates":[{"content":{"parts":[{"text":"a"}]},"finishReason":"MAX_TOKENS"}]}`,
			`{"message":{"role":"assistant","parts":[{"type":"text","text":"a"}]},"stopReason":"max_tokens","usage":{"inputTokens":0,"outputTokens":0},"model":"gemini-x"}`,
		},
		{
			"safety",
			`{"candidates":[{"content":{"parts":[]},"finishReason":"SAFETY"}]}`,
			`{"message":{"role":"assistant","parts":null},"stopReason":"other","usage":{"inputTokens":0,"outputTokens":0},"model":"gemini-x"}`,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			srv := newFakeServer(t, 200, "application/json", s.body)
			client := newTestClient(t, llm.Config{Provider: "gemini", BaseURL: srv.URL, DefaultModel: "gemini-x"})

			resp, err := client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
			if err != nil {
				t.Fatal(err)
			}

			assertResponseJSON(t, s.expected, resp)
		})
	}
}

func TestGeminiStream(t *testing.T) {
	srv := newFakeServer(t, 200, "text/event-stream", sseBody(
		`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Hel"}]}}],"usageMetadata":{"promptTokenCount":3},"modelVersion":"gemini-x-001"}`,
		`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"lo"},{"functionCall":{"name":"lookup","args":{"q":"cat"}}}]}}],"modelVersion":"gemini-x-001"}`,
		`data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"id":"f2","name":"other","args":{}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":9},"modelVersion":"gemini-x-001"}`,
	))

	client := newTestClient(t, llm.Config{Provider: "gemini", BaseURL: srv.URL, APIKey: "k"})

	s, err := client.Stream(context.Background(), &llm.Request{Model: "models/gemini-x", Messages: []llm.Message{llm.UserText("hi")}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	resp, err := llm.Accumulate(s)
	if err != nil {
		t.Fatal(err)
	}

	req := srv.last(t)
	if req.Path != "/models/gemini-x:streamGenerateContent" || req.Query != "alt=sse" {
		t.Fatalf("Unexpected stream url %s?%s", req.Path, req.Query)
	}

	assertResponseJSON(t, `{
		"message": {"role":"assistant","parts":[
			{"type":"text","text":"Hello"},
			{"type":"tool_call","toolCall":{"id":"gemini_call_0","name":"lookup","arguments":{"q":"cat"}}},
			{"type":"tool_call","toolCall":{"id":"f2","name":"other","arguments":{}}}
		]},
		"stopReason":"tool_use",
		"usage":{"inputTokens":3,"outputTokens":9},
		"model":"gemini-x-001"
	}`, resp)
}

func TestGeminiErrors(t *testing.T) {
	srv := newFakeServer(t, 400, "application/json", `{"error":{"code":400,"message":"API key not valid","status":"INVALID_ARGUMENT"}}`)
	client := newTestClient(t, llm.Config{Provider: "gemini", BaseURL: srv.URL, DefaultModel: "gemini-x"})

	_, err := client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})

	var apiErr *llm.APIError
	if !errors.As(err, &apiErr) || apiErr.Provider != "gemini" || apiErr.Status != 400 || apiErr.Code != "INVALID_ARGUMENT" || apiErr.Message != "API key not valid" {
		t.Fatalf("Unexpected error %v", err)
	}
}

func TestGeminiEmbed(t *testing.T) {
	srv := newFakeServer(t, 200, "application/json", `{"embeddings":[{"values":[0.1,0.2]},{"values":[0.3,0.4]}]}`)
	client := newTestClient(t, llm.Config{Provider: "gemini", BaseURL: srv.URL, APIKey: "k"})

	resp, err := client.Embed(context.Background(), &llm.EmbedRequest{Model: "emb", Input: []string{"a", "b"}, Dimensions: 2})
	if err != nil {
		t.Fatal(err)
	}

	req := srv.last(t)
	if req.Path != "/models/emb:batchEmbedContents" {
		t.Fatalf("Unexpected path %q", req.Path)
	}

	assertJSON(t, `{"requests":[
		{"model":"models/emb","content":{"parts":[{"text":"a"}]},"outputDimensionality":2},
		{"model":"models/emb","content":{"parts":[{"text":"b"}]},"outputDimensionality":2}
	]}`, req.Body)

	if len(resp.Embeddings) != 2 || resp.Embeddings[1][1] != 0.4 {
		t.Fatalf("Unexpected embeddings %v", resp.Embeddings)
	}
}
