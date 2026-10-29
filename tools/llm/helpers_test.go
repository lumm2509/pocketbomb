package llm_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/lumm2509/pocketbomb/tools/llm"
)

type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte
}

type fakeServer struct {
	*httptest.Server

	mu       sync.Mutex
	requests []*recordedRequest
}

func (s *fakeServer) last(t *testing.T) *recordedRequest {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.requests) == 0 {
		t.Fatal("Expected at least one request")
	}

	return s.requests[len(s.requests)-1]
}

// newFakeServer creates a new test server that records the requests
// and always responds with the specified status, content type and body.
func newFakeServer(t *testing.T, status int, contentType string, body string) *fakeServer {
	t.Helper()

	s := &fakeServer{}

	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)

		s.mu.Lock()
		s.requests = append(s.requests, &recordedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.RawQuery,
			Header: r.Header.Clone(),
			Body:   raw,
		})
		s.mu.Unlock()

		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))

	t.Cleanup(s.Close)

	return s
}

func newTestClient(t *testing.T, config llm.Config) *llm.Client {
	t.Helper()

	client, err := llm.New(config)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { client.Close() })

	return client
}

func assertJSON(t *testing.T, expected string, actual []byte) {
	t.Helper()

	var e, a any

	if err := json.Unmarshal([]byte(expected), &e); err != nil {
		t.Fatalf("Invalid expected JSON: %v\n%s", err, expected)
	}

	if err := json.Unmarshal(actual, &a); err != nil {
		t.Fatalf("Invalid actual JSON: %v\n%s", err, actual)
	}

	if !reflect.DeepEqual(e, a) {
		ePretty, _ := json.Marshal(e)
		aPretty, _ := json.Marshal(a)
		t.Fatalf("JSON mismatch\nExpected: %s\nGot:      %s", ePretty, aPretty)
	}
}

func assertResponseJSON(t *testing.T, expected string, resp *llm.Response) {
	t.Helper()

	clone := *resp
	clone.Raw = nil

	raw, err := json.Marshal(clone)
	if err != nil {
		t.Fatal(err)
	}

	assertJSON(t, expected, raw)
}

func sseBody(events ...string) string {
	return strings.Join(events, "\n\n") + "\n\n"
}

func ptr[T any](v T) *T {
	return &v
}

// sampleRequest returns a request that covers most of the normalized fields.
func sampleRequest() *llm.Request {
	return &llm.Request{
		System: "be nice",
		Messages: []llm.Message{
			llm.UserMessage(
				llm.TextPart("what is in the image?"),
				llm.ImageDataPart("aGVsbG8=", "image/png"),
				llm.ImageURLPart("https://example.com/a.jpg", "image/jpeg"),
			),
			llm.AssistantMessage(
				llm.TextPart("let me check"),
				llm.ToolCallPart("call_1", "lookup", json.RawMessage(`{"q":"cat"}`)),
			),
			llm.UserMessage(
				llm.ToolResultPart("call_1", `{"found":true}`, false),
				llm.TextPart("thanks"),
			),
		},
		Tools: []llm.Tool{{
			Name:        "lookup",
			Description: "lookup something",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`),
		}},
		ToolChoice:    &llm.ToolChoice{Mode: llm.ToolChoiceTool, Name: "lookup"},
		MaxTokens:     100,
		Temperature:   ptr(0.5),
		TopP:          ptr(0.9),
		StopSequences: []string{"END"},
		ResponseFormat: &llm.ResponseFormat{
			Type:   llm.ResponseFormatJSON,
			Name:   "answer",
			Schema: json.RawMessage(`{"type":"object"}`),
		},
		Extra: map[string]any{"custom": 123},
	}
}
