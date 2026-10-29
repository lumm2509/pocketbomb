package sse_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/tools/llm/driver"
	"github.com/lumm2509/pocketbomb/tools/llm/internal/sse"
)

func TestReader(t *testing.T) {
	scenarios := []struct {
		name     string
		input    string
		expected []sse.Event
	}{
		{"empty", "", nil},
		{"only comments", ": a\n: b\n\n", nil},
		{
			"single event without trailing blank line",
			"data: hello",
			[]sse.Event{{Data: "hello"}},
		},
		{
			"multiple events with CRLF and fields",
			"event: a\r\nid: 1\r\ndata: x\r\n\r\n:comment\r\ndata:y\r\n\r\n",
			[]sse.Event{{Event: "a", ID: "1", Data: "x"}, {Data: "y"}},
		},
		{
			"multi-line data and extra blank lines",
			"\n\ndata: line1\ndata: line2\n\n\n\nevent: only\n\n",
			[]sse.Event{{Data: "line1\nline2"}, {Event: "only"}},
		},
		{
			"data with colons and only the first space trimmed",
			"data:  {\"a\":\"b:c\"}\n\n",
			[]sse.Event{{Data: " {\"a\":\"b:c\"}"}},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			r := sse.NewReader(strings.NewReader(s.input))

			var events []sse.Event
			for r.Next() {
				events = append(events, r.Event())
			}

			if err := r.Err(); err != nil {
				t.Fatal(err)
			}

			if len(events) != len(s.expected) {
				t.Fatalf("Expected %d events, got %d: %#v", len(s.expected), len(events), events)
			}

			for i, e := range s.expected {
				if events[i] != e {
					t.Fatalf("[%d] Expected %#v, got %#v", i, e, events[i])
				}
			}
		})
	}
}

type errReader struct {
	data string
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.data == "" {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func (r *errReader) Close() error { return nil }

func TestStream(t *testing.T) {
	readErr := errors.New("read_err")
	handlerErr := errors.New("handler_err")

	handler := func(ev sse.Event) ([]driver.StreamEvent, bool, error) {
		switch ev.Data {
		case "[DONE]":
			return nil, true, nil
		case "fail":
			return []driver.StreamEvent{{Type: driver.StreamEventTextDelta, Text: "before_fail"}}, false, handlerErr
		case "skip":
			return nil, false, nil
		}
		return []driver.StreamEvent{
			{Type: driver.StreamEventTextDelta, Text: ev.Data},
			{Type: driver.StreamEventTextDelta, Text: ev.Data},
		}, false, nil
	}

	scenarios := []struct {
		name          string
		body          io.ReadCloser
		expectedTexts string
		expectedErr   error
	}{
		{"done", io.NopCloser(strings.NewReader("data: a\n\ndata: skip\n\ndata: b\n\ndata: [DONE]\n\ndata: c\n\n")), "aabb", nil},
		{"eof without done", io.NopCloser(strings.NewReader("data: a\n\n")), "aa", nil},
		{"handler error", io.NopCloser(strings.NewReader("data: a\n\ndata: fail\n\ndata: b\n\n")), "aabefore_fail", handlerErr},
		{"read error", &errReader{data: "data: a\n\n", err: readErr}, "aa", readErr},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			stream := sse.NewStream(s.body, handler)
			defer stream.Close()

			var texts string
			for stream.Next() {
				texts += stream.Event().Text
			}

			if texts != s.expectedTexts {
				t.Fatalf("Expected texts %q, got %q", s.expectedTexts, texts)
			}

			if !errors.Is(stream.Err(), s.expectedErr) {
				t.Fatalf("Expected error %v, got %v", s.expectedErr, stream.Err())
			}

			if stream.Next() {
				t.Fatal("Expected Next to remain false")
			}
		})
	}
}
