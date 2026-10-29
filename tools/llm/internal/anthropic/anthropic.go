// Package anthropic implements an LLM driver for the Anthropic Messages API.
package anthropic

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lumm2509/pocketbomb/tools/llm/driver"
	"github.com/lumm2509/pocketbomb/tools/llm/internal/sse"
	"github.com/lumm2509/pocketbomb/tools/llm/internal/transport"
)

// DefaultBaseURL is the default Anthropic API base url.
const DefaultBaseURL = "https://api.anthropic.com/v1"

// DefaultVersion is the default "anthropic-version" header value.
const DefaultVersion = "2023-06-01"

// DefaultMaxTokens is the max_tokens value used when Request.MaxTokens is not set
// (the field is required by the Messages API).
const DefaultMaxTokens = 4096

// Supported config.Options keys:
const (
	// OptionVersion overrides the "anthropic-version" header (default to [DefaultVersion]).
	//
	// Note that with version "2026-10-21" and newer the API rejects
	// Request.Temperature and Request.TopP.
	OptionVersion = "version"

	// OptionDefaultMaxTokens overrides [DefaultMaxTokens].
	OptionDefaultMaxTokens = "defaultMaxTokens"
)

var _ driver.Driver = (*Driver)(nil)

// Driver is an Anthropic Messages API driver.
type Driver struct {
	config           driver.Config
	client           *transport.Client
	version          string
	defaultMaxTokens int
}

// New creates a new Anthropic driver.
func New(config driver.Config) (*Driver, error) {
	d := &Driver{
		config:           config,
		client:           transport.NewClient("anthropic", config, DefaultBaseURL),
		version:          DefaultVersion,
		defaultMaxTokens: DefaultMaxTokens,
	}

	if v, ok := config.Options[OptionVersion].(string); ok && v != "" {
		d.version = v
	}

	switch v := config.Options[OptionDefaultMaxTokens].(type) {
	case int:
		d.defaultMaxTokens = v
	case float64:
		d.defaultMaxTokens = int(v)
	}

	return d, nil
}

// Close implements [driver.Driver.Close].
func (d *Driver) Close() error {
	return nil
}

// Generate implements [driver.Driver.Generate].
func (d *Driver) Generate(ctx context.Context, req *driver.Request) (*driver.Response, error) {
	body, err := d.buildBody(req, false)
	if err != nil {
		return nil, err
	}

	var result struct {
		Model      string         `json:"model"`
		StopReason string         `json:"stop_reason"`
		Content    []contentBlock `json:"content"`
		Usage      usage          `json:"usage"`
	}

	raw, err := d.client.PostJSON(ctx, "/messages", d.headers(), body, req.Extra, &result)
	if err != nil {
		return nil, err
	}

	resp := &driver.Response{
		Model:      result.Model,
		Raw:        raw,
		StopReason: mapStopReason(result.StopReason),
		Usage:      driver.Usage{InputTokens: result.Usage.InputTokens, OutputTokens: result.Usage.OutputTokens},
		Message:    driver.Message{Role: driver.RoleAssistant},
	}

	for _, block := range result.Content {
		switch block.Type {
		case "text":
			resp.Message.Parts = append(resp.Message.Parts, driver.TextPart(block.Text))
		case "tool_use":
			args := block.Input
			if len(args) == 0 {
				args = json.RawMessage("{}")
			}
			resp.Message.Parts = append(resp.Message.Parts, driver.ToolCallPart(block.ID, block.Name, args))
		}
	}

	return resp, nil
}

// Stream implements [driver.Driver.Stream].
func (d *Driver) Stream(ctx context.Context, req *driver.Request) (driver.Stream, error) {
	body, err := d.buildBody(req, true)
	if err != nil {
		return nil, err
	}

	resp, err := d.client.Post(ctx, "/messages", d.headers(), body, req.Extra, true)
	if err != nil {
		return nil, err
	}

	var model string

	return sse.NewStream(resp.Body, func(ev sse.Event) ([]driver.StreamEvent, bool, error) {
		if ev.Data == "" {
			return nil, false, nil
		}

		var data struct {
			Type         string          `json:"type"`
			Index        int             `json:"index"`
			Message      json.RawMessage `json:"message"`
			ContentBlock contentBlock    `json:"content_block"`
			Delta        struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
			Usage usage `json:"usage"`
		}
		if err := json.Unmarshal([]byte(ev.Data), &data); err != nil {
			return nil, false, fmt.Errorf("llm: failed to decode anthropic stream event: %w", err)
		}

		switch data.Type {
		case "message_start":
			var msg struct {
				Model string `json:"model"`
				Usage usage  `json:"usage"`
			}
			_ = json.Unmarshal(data.Message, &msg)
			model = msg.Model
			return []driver.StreamEvent{{
				Type:  driver.StreamEventUsage,
				Model: model,
				Usage: &driver.Usage{InputTokens: msg.Usage.InputTokens, OutputTokens: msg.Usage.OutputTokens},
			}}, false, nil
		case "content_block_start":
			switch data.ContentBlock.Type {
			case "tool_use":
				return []driver.StreamEvent{{
					Type:  driver.StreamEventToolCallDelta,
					Model: model,
					ToolCall: &driver.ToolCallDelta{
						Index: data.Index,
						ID:    data.ContentBlock.ID,
						Name:  data.ContentBlock.Name,
					},
				}}, false, nil
			case "text":
				if data.ContentBlock.Text != "" {
					return []driver.StreamEvent{{Type: driver.StreamEventTextDelta, Text: data.ContentBlock.Text, Model: model}}, false, nil
				}
			}
		case "content_block_delta":
			switch data.Delta.Type {
			case "text_delta":
				return []driver.StreamEvent{{Type: driver.StreamEventTextDelta, Text: data.Delta.Text, Model: model}}, false, nil
			case "input_json_delta":
				return []driver.StreamEvent{{
					Type:     driver.StreamEventToolCallDelta,
					Model:    model,
					ToolCall: &driver.ToolCallDelta{Index: data.Index, ArgumentsDelta: data.Delta.PartialJSON},
				}}, false, nil
			}
		case "message_delta":
			var events []driver.StreamEvent
			if data.Usage.OutputTokens > 0 || data.Usage.InputTokens > 0 {
				events = append(events, driver.StreamEvent{
					Type:  driver.StreamEventUsage,
					Model: model,
					Usage: &driver.Usage{InputTokens: data.Usage.InputTokens, OutputTokens: data.Usage.OutputTokens},
				})
			}
			if data.Delta.StopReason != "" {
				events = append(events, driver.StreamEvent{
					Type:       driver.StreamEventStop,
					Model:      model,
					StopReason: mapStopReason(data.Delta.StopReason),
				})
			}
			return events, false, nil
		case "message_stop":
			return nil, true, nil
		case "error":
			return nil, false, transport.ParseError("anthropic", 0, []byte(ev.Data))
		}

		// ping, content_block_stop, thinking deltas, etc.
		return nil, false, nil
	}), nil
}

func (d *Driver) headers() map[string]string {
	return map[string]string{
		"x-api-key":         d.config.APIKey,
		"anthropic-version": d.version,
	}
}

func (d *Driver) buildBody(req *driver.Request, stream bool) (map[string]any, error) {
	model, err := driver.ResolveModel(req.Model, d.config)
	if err != nil {
		return nil, err
	}

	messages, err := convertMessages(req.Messages)
	if err != nil {
		return nil, err
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = d.defaultMaxTokens
	}

	body := map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"messages":   messages,
	}

	if stream {
		body["stream"] = true
	}

	if req.System != "" {
		body["system"] = req.System
	}

	if req.Temperature != nil {
		body["temperature"] = *req.Temperature
	}

	if req.TopP != nil {
		body["top_p"] = *req.TopP
	}

	if len(req.StopSequences) > 0 {
		body["stop_sequences"] = req.StopSequences
	}

	if len(req.Tools) > 0 {
		tools := make([]map[string]any, len(req.Tools))
		for i, t := range req.Tools {
			schema := t.InputSchema
			if len(schema) == 0 {
				schema = json.RawMessage(`{"type":"object","properties":{}}`)
			}
			tool := map[string]any{"name": t.Name, "input_schema": schema}
			if t.Description != "" {
				tool["description"] = t.Description
			}
			tools[i] = tool
		}
		body["tools"] = tools
	}

	if req.ToolChoice != nil {
		switch req.ToolChoice.Mode {
		case driver.ToolChoiceAuto:
			body["tool_choice"] = map[string]any{"type": "auto"}
		case driver.ToolChoiceNone:
			body["tool_choice"] = map[string]any{"type": "none"}
		case driver.ToolChoiceRequired:
			body["tool_choice"] = map[string]any{"type": "any"}
		case driver.ToolChoiceTool:
			body["tool_choice"] = map[string]any{"type": "tool", "name": req.ToolChoice.Name}
		}
	}

	// note: JSON mode without schema has no direct equivalent and it is ignored
	if rf := req.ResponseFormat; rf != nil && rf.Type == driver.ResponseFormatJSON && len(rf.Schema) > 0 {
		body["output_config"] = map[string]any{
			"format": map[string]any{"type": "json_schema", "schema": rf.Schema},
		}
	}

	return body, nil
}

func convertMessages(messages []driver.Message) ([]map[string]any, error) {
	result := make([]map[string]any, 0, len(messages))

	for _, m := range messages {
		blocks := make([]map[string]any, 0, len(m.Parts))

		for _, p := range m.Parts {
			switch p.Type {
			case driver.PartTypeText:
				blocks = append(blocks, map[string]any{"type": "text", "text": p.Text})
			case driver.PartTypeImage:
				if p.Image == nil {
					continue
				}
				var source map[string]any
				if p.Image.URL != "" {
					source = map[string]any{"type": "url", "url": p.Image.URL}
				} else {
					source = map[string]any{"type": "base64", "media_type": p.Image.MimeType, "data": p.Image.Data}
				}
				blocks = append(blocks, map[string]any{"type": "image", "source": source})
			case driver.PartTypeToolCall:
				if p.ToolCall == nil {
					continue
				}
				input := p.ToolCall.Arguments
				if len(input) == 0 {
					input = json.RawMessage("{}")
				}
				blocks = append(blocks, map[string]any{
					"type":  "tool_use",
					"id":    p.ToolCall.ID,
					"name":  p.ToolCall.Name,
					"input": input,
				})
			case driver.PartTypeToolResult:
				if p.ToolResult == nil {
					continue
				}
				block := map[string]any{
					"type":        "tool_result",
					"tool_use_id": p.ToolResult.ToolCallID,
					"content":     p.ToolResult.Content,
				}
				if p.ToolResult.IsError {
					block["is_error"] = true
				}
				blocks = append(blocks, block)
			default:
				return nil, fmt.Errorf("llm: unsupported message part type %q", p.Type)
			}
		}

		if len(blocks) == 0 {
			continue
		}

		result = append(result, map[string]any{"role": string(m.Role), "content": blocks})
	}

	return result, nil
}

func mapStopReason(reason string) driver.StopReason {
	switch reason {
	case "end_turn":
		return driver.StopReasonEndTurn
	case "max_tokens":
		return driver.StopReasonMaxTokens
	case "tool_use":
		return driver.StopReasonToolUse
	case "stop_sequence":
		return driver.StopReasonStopSequence
	default: // pause_turn, refusal, etc.
		return driver.StopReasonOther
	}
}

type contentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

type usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}
