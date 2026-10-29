package tests

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
)

// LLMFakeServerRequest defines a single recorded fake LLM server request.
type LLMFakeServerRequest struct {
	Path   string
	Header http.Header
	Body   string
}

// LLMFakeServer defines a fake OpenAI-compatible Chat Completions server
// that could be used in tests without network access.
type LLMFakeServer struct {
	*httptest.Server

	mu       sync.Mutex
	requests []*LLMFakeServerRequest

	// Status is the response status code (default to 200).
	Status int

	// Body is the non-stream response body.
	Body string

	// StreamBody is the "text/event-stream" response body
	// (used for requests with "stream":true).
	StreamBody string
}

// Requests returns a copy of all recorded requests.
func (s *LLMFakeServer) Requests() []*LLMFakeServerRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]*LLMFakeServerRequest{}, s.requests...)
}

// LLMFakeServerDefaultBody is the default fake server non-stream response.
const LLMFakeServerDefaultBody = `{
	"id": "chatcmpl-test",
	"model": "fake-model",
	"choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello from fake"}, "finish_reason": "stop"}],
	"usage": {"prompt_tokens": 11, "completion_tokens": 7}
}`

// LLMFakeServerDefaultStreamBody is the default fake server stream response.
const LLMFakeServerDefaultStreamBody = "" +
	"data: {\"model\":\"fake-model\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hel\"}}]}\n\n" +
	"data: {\"model\":\"fake-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n" +
	"data: {\"model\":\"fake-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
	"data: {\"model\":\"fake-model\",\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2}}\n\n" +
	"data: [DONE]\n\n"

// NewLLMFakeServer creates and starts a new fake OpenAI-compatible LLM server
// (it is automatically closed on test cleanup).
//
// Use the returned server URL as "openai-compatible" provider BaseURL.
func NewLLMFakeServer(t testing.TB) *LLMFakeServer {
	s := &LLMFakeServer{
		Status:     http.StatusOK,
		Body:       LLMFakeServerDefaultBody,
		StreamBody: LLMFakeServerDefaultStreamBody,
	}

	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)

		s.mu.Lock()
		s.requests = append(s.requests, &LLMFakeServerRequest{
			Path:   r.URL.Path,
			Header: r.Header.Clone(),
			Body:   string(raw),
		})
		status := s.Status
		body := s.Body
		streamBody := s.StreamBody
		s.mu.Unlock()

		if status == http.StatusOK && strings.Contains(string(raw), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, streamBody)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))

	t.Cleanup(s.Close)

	return s
}

// StubLLMLogsData replaces the existing _llmLogs entries with the following test stubs:
//
//	| id          | provider | model | profile | status  | in | out | durationMs | auth                      | ip      | created                  |
//	|-------------|----------|-------|---------|---------|----|-----|------------|---------------------------|---------|--------------------------|
//	| llmlog00001 | p1       | gpt-a | support | success | 10 | 20  | 100        | _pb_users_auth_/4q1xlclmfloku33 | 1.1.1.1 | 2022-05-01 10:00:00.123Z |
//	| llmlog00002 | p1       | gpt-a | support | success | 5  | 5   | 300        | _pb_users_auth_/4q1xlclmfloku33 | 1.1.1.1 | 2022-05-01 10:30:00.000Z |
//	| llmlog00003 | p1       | gpt-b | support | error   | 0  | 0   | 50         | -                         | 2.2.2.2 | 2022-05-01 11:00:00.000Z |
//	| llmlog00004 | p1       | gpt-b | other   | denied  | 0  | 0   | 0          | -                         | 2.2.2.2 | 2022-05-02 10:00:00.000Z |
func StubLLMLogsData(app core.App) error {
	_, err := app.AuxDB().NewQuery(`
		delete from {{_llmLogs}};

		insert into {{_llmLogs}} (
			[[id]], [[provider]], [[model]], [[profile]], [[stream]], [[status]], [[error]],
			[[inputTokens]], [[outputTokens]], [[durationMs]], [[request]], [[response]],
			[[authCollection]], [[authRecord]], [[ip]], [[meta]], [[created]]
		)
		values
		(
			"llmlog00001", "p1", "gpt-a", "support", false, "success", "",
			10, 20, 100, '{"messages":[{"role":"user","parts":[{"type":"text","text":"hi"}]}]}', '{"message":{"role":"assistant","parts":[{"type":"text","text":"hello"}]}}',
			"_pb_users_auth_", "4q1xlclmfloku33", "1.1.1.1", '{"source":"test"}', "2022-05-01 10:00:00.123Z"
		),
		(
			"llmlog00002", "p1", "gpt-a", "support", true, "success", "",
			5, 5, 300, null, null,
			"_pb_users_auth_", "4q1xlclmfloku33", "1.1.1.1", '{}', "2022-05-01 10:30:00.000Z"
		),
		(
			"llmlog00003", "p1", "gpt-b", "support", false, "error", "boom",
			0, 0, 50, null, null,
			"", "", "2.2.2.2", '{}', "2022-05-01 11:00:00.000Z"
		),
		(
			"llmlog00004", "p1", "gpt-b", "other", false, "denied", "only superusers can access the profile",
			0, 0, 0, null, null,
			"", "", "2.2.2.2", '{}', "2022-05-02 10:00:00.000Z"
		);
	`).Execute()

	return err
}
