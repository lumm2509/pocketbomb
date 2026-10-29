package transport_test

import (
	"testing"

	"github.com/lumm2509/pocketbomb/tools/llm/internal/transport"
)

func TestMergeJSON(t *testing.T) {
	scenarios := []struct {
		name     string
		value    any
		extra    map[string]any
		expected string
	}{
		{"no extra", map[string]any{"a": 1}, nil, `{"a":1}`},
		{"add, replace and delete", map[string]any{"a": 1, "b": 2}, map[string]any{"b": "x", "c": []int{1}, "a": nil}, `{"b":"x","c":[1]}`},
		{"large numbers are preserved", map[string]any{"n": int64(9007199254740993)}, map[string]any{"x": true}, `{"n":9007199254740993,"x":true}`},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			raw, err := transport.MergeJSON(s.value, s.extra)
			if err != nil {
				t.Fatal(err)
			}

			if string(raw) != s.expected {
				t.Fatalf("Expected %s, got %s", s.expected, raw)
			}
		})
	}
}

func TestParseError(t *testing.T) {
	scenarios := []struct {
		name            string
		raw             string
		expectedCode    string
		expectedMessage string
	}{
		{"plain text", "oops", "", "oops"},
		{"string error", `{"error":"not found"}`, "", "not found"},
		{"openai with code", `{"error":{"message":"m","type":"t","code":"c"}}`, "c", "m"},
		{"openai with null code", `{"error":{"message":"m","type":"t","code":null}}`, "t", "m"},
		{"openai with numeric code", `{"error":{"message":"m","type":"t","code":429}}`, "t", "m"},
		{"anthropic", `{"type":"error","error":{"type":"rate_limit_error","message":"m"}}`, "rate_limit_error", "m"},
		{"gemini", `{"error":{"code":403,"message":"m","status":"PERMISSION_DENIED"}}`, "PERMISSION_DENIED", "m"},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			err := transport.ParseError("p", 400, []byte(s.raw))

			if err.Provider != "p" || err.Status != 400 || string(err.Raw) != s.raw {
				t.Fatalf("Unexpected base fields %#v", err)
			}

			if err.Code != s.expectedCode {
				t.Fatalf("Expected code %q, got %q", s.expectedCode, err.Code)
			}

			if err.Message != s.expectedMessage {
				t.Fatalf("Expected message %q, got %q", s.expectedMessage, err.Message)
			}

			if err.Error() == "" {
				t.Fatal("Expected non-empty error string")
			}
		})
	}
}
