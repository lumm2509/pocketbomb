package driver_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/lumm2509/pocketbomb/tools/llm/driver"
)

func TestAccumulator(t *testing.T) {
	var a driver.Accumulator

	events := []driver.StreamEvent{
		{Type: driver.StreamEventUsage, Usage: &driver.Usage{InputTokens: 10}, Model: "m1"},
		{Type: driver.StreamEventTextDelta, Text: "Hel"},
		{Type: driver.StreamEventTextDelta, Text: "lo"},
		{Type: driver.StreamEventToolCallDelta, ToolCall: &driver.ToolCallDelta{Index: 5, ID: "a", Name: "first"}},
		{Type: driver.StreamEventToolCallDelta, ToolCall: &driver.ToolCallDelta{Index: 7, ID: "b", Name: "second"}},
		{Type: driver.StreamEventToolCallDelta, ToolCall: &driver.ToolCallDelta{Index: 5, ArgumentsDelta: `{"x":`}},
		{Type: driver.StreamEventToolCallDelta, ToolCall: &driver.ToolCallDelta{Index: 5, ArgumentsDelta: `1}`}},
		{Type: driver.StreamEventToolCallDelta}, // nil ToolCall is ignored
		{Type: driver.StreamEventTextDelta, Text: "after"},
		{Type: driver.StreamEventUsage, Usage: &driver.Usage{OutputTokens: 4}, Model: "m2"},
		{Type: driver.StreamEventStop, StopReason: driver.StopReasonToolUse},
	}

	for _, e := range events {
		a.Add(e)
	}

	resp := a.Response()

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"message":{"role":"assistant","parts":[{"type":"text","text":"Hello"},{"type":"tool_call","toolCall":{"id":"a","name":"first","arguments":{"x":1}}},{"type":"tool_call","toolCall":{"id":"b","name":"second","arguments":{}}},{"type":"text","text":"after"}]},"stopReason":"tool_use","usage":{"inputTokens":10,"outputTokens":4},"model":"m2"}`
	if string(raw) != expected {
		t.Fatalf("Expected\n%s\ngot\n%s", expected, raw)
	}

	if resp.Text() != "Helloafter" {
		t.Fatalf("Unexpected Text() %q", resp.Text())
	}

	if calls := resp.ToolCalls(); len(calls) != 2 || calls[0].Name != "first" {
		t.Fatalf("Unexpected ToolCalls() %v", calls)
	}

	// calling Response() again must not be affected by the previous result
	resp.Message.Parts[1].ToolCall.Name = "changed"
	if a.Response().Message.Parts[1].ToolCall.Name != "first" {
		t.Fatal("Expected Response() to return a copy")
	}
}

func TestResolveModel(t *testing.T) {
	scenarios := []struct {
		reqModel     string
		defaultModel string
		expected     string
		expectErr    bool
	}{
		{"", "", "", true},
		{"a", "", "a", false},
		{"", "b", "b", false},
		{"a", "b", "a", false},
	}

	for _, s := range scenarios {
		model, err := driver.ResolveModel(s.reqModel, driver.Config{DefaultModel: s.defaultModel})
		if (err != nil) != s.expectErr || model != s.expected {
			t.Fatalf("[%q, %q] Expected %q (err %v), got %q (%v)", s.reqModel, s.defaultModel, s.expected, s.expectErr, model, err)
		}
		if s.expectErr && !errors.Is(err, driver.ErrMissingModel) {
			t.Fatalf("Expected ErrMissingModel, got %v", err)
		}
	}
}

func TestAPIErrorString(t *testing.T) {
	scenarios := []struct {
		err      *driver.APIError
		expected string
	}{
		{&driver.APIError{Provider: "p", Status: 400, Code: "c", Message: "m"}, "llm: p API error (status 400, c): m"},
		{&driver.APIError{Provider: "p", Status: 503}, "llm: p API error (status 503): Service Unavailable"},
	}

	for _, s := range scenarios {
		if s.err.Error() != s.expected {
			t.Fatalf("Expected %q, got %q", s.expected, s.err.Error())
		}
	}
}
