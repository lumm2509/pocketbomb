package driver

import (
	"encoding/json"
)

// StreamEventType defines the type of a single stream event.
type StreamEventType string

const (
	StreamEventTextDelta     StreamEventType = "text_delta"
	StreamEventToolCallDelta StreamEventType = "tool_call_delta"
	StreamEventUsage         StreamEventType = "usage"
	StreamEventStop          StreamEventType = "stop"
)

// ToolCallDelta defines a partial tool call stream chunk.
type ToolCallDelta struct {
	// Index identifies the tool call within the stream
	// (all chunks of the same tool call share the same Index).
	Index int `json:"index"`

	// ID and Name are usually sent only with the first tool call chunk.
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`

	// ArgumentsDelta is a partial JSON arguments string.
	ArgumentsDelta string `json:"argumentsDelta,omitempty"`
}

// StreamEvent defines a single normalized stream event.
type StreamEvent struct {
	Type StreamEventType `json:"type"`

	// Text is set for StreamEventTextDelta.
	Text string `json:"text,omitempty"`

	// ToolCall is set for StreamEventToolCallDelta.
	ToolCall *ToolCallDelta `json:"toolCall,omitempty"`

	// Usage is set for StreamEventUsage (zero fields are not known yet).
	Usage *Usage `json:"usage,omitempty"`

	// StopReason is set for StreamEventStop.
	StopReason StopReason `json:"stopReason,omitempty"`

	// Model is the provider reported model (if known).
	Model string `json:"model,omitempty"`
}

// Accumulator collects stream events into a final Response.
//
// The zero value is ready to use.
type Accumulator struct {
	parts      []Part
	toolCalls  map[int]int    // ToolCallDelta.Index -> parts index
	args       map[int][]byte // parts index -> collected arguments
	usage      Usage
	stopReason StopReason
	model      string
}

// Add adds a single stream event to the accumulator.
func (a *Accumulator) Add(e StreamEvent) {
	if e.Model != "" {
		a.model = e.Model
	}

	switch e.Type {
	case StreamEventTextDelta:
		if n := len(a.parts); n > 0 && a.parts[n-1].Type == PartTypeText {
			a.parts[n-1].Text += e.Text
		} else {
			a.parts = append(a.parts, TextPart(e.Text))
		}
	case StreamEventToolCallDelta:
		if e.ToolCall == nil {
			return
		}
		if a.toolCalls == nil {
			a.toolCalls = map[int]int{}
			a.args = map[int][]byte{}
		}
		idx, ok := a.toolCalls[e.ToolCall.Index]
		if !ok {
			idx = len(a.parts)
			a.toolCalls[e.ToolCall.Index] = idx
			a.parts = append(a.parts, ToolCallPart("", "", nil))
		}
		tc := a.parts[idx].ToolCall
		if e.ToolCall.ID != "" {
			tc.ID = e.ToolCall.ID
		}
		if e.ToolCall.Name != "" {
			tc.Name = e.ToolCall.Name
		}
		a.args[idx] = append(a.args[idx], e.ToolCall.ArgumentsDelta...)
	case StreamEventUsage:
		if e.Usage != nil {
			if e.Usage.InputTokens > 0 {
				a.usage.InputTokens = e.Usage.InputTokens
			}
			if e.Usage.OutputTokens > 0 {
				a.usage.OutputTokens = e.Usage.OutputTokens
			}
		}
	case StreamEventStop:
		a.stopReason = e.StopReason
	}
}

// Response returns the accumulated Response.
func (a *Accumulator) Response() *Response {
	parts := make([]Part, len(a.parts))
	for i, p := range a.parts {
		if p.ToolCall != nil {
			tc := *p.ToolCall
			tc.Arguments = json.RawMessage(a.args[i])
			if len(tc.Arguments) == 0 {
				tc.Arguments = json.RawMessage("{}")
			}
			p.ToolCall = &tc
		}
		parts[i] = p
	}

	return &Response{
		Message:    Message{Role: RoleAssistant, Parts: parts},
		StopReason: a.stopReason,
		Usage:      a.usage,
		Model:      a.model,
	}
}

// Accumulate reads the entire stream and returns the accumulated Response.
//
// Note that Accumulate doesn't close the stream.
func Accumulate(s Stream) (*Response, error) {
	var a Accumulator

	for s.Next() {
		a.Add(s.Event())
	}

	if err := s.Err(); err != nil {
		return nil, err
	}

	return a.Response(), nil
}
