// Package openai implements an LLM driver for the OpenAI Chat Completions API
// and all OpenAI-compatible APIs (xAI, Ollama, vLLM, LM Studio, OpenRouter, etc.).
package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lumm2509/pocketbomb/tools/llm/driver"
	"github.com/lumm2509/pocketbomb/tools/llm/internal/sse"
	"github.com/lumm2509/pocketbomb/tools/llm/internal/transport"
)

// DefaultBaseURL is the default OpenAI API base url.
const DefaultBaseURL = "https://api.openai.com/v1"

// Supported config.Options keys:
const (
	// OptionMaxTokensField overrides the request body max tokens field name
	// (default to "max_completion_tokens" for the "openai" provider and "max_tokens" otherwise).
	OptionMaxTokensField = "maxTokensField"

	// OptionStreamUsage controls whether to send stream_options.include_usage (default true).
	OptionStreamUsage = "streamUsage"
)

var (
	_ driver.Driver   = (*Driver)(nil)
	_ driver.Embedder = (*Driver)(nil)
)

// Driver is an OpenAI Chat Completions driver.
type Driver struct {
	config         driver.Config
	client         *transport.Client
	maxTokensField string
	streamUsage    bool
}

// New creates a new OpenAI driver.
//
// provider is the name used in the returned errors (e.g. "openai", "xai", "ollama").
func New(provider string, config driver.Config) (*Driver, error) {
	d := &Driver{
		config:         config,
		client:         transport.NewClient(provider, config, DefaultBaseURL),
		maxTokensField: "max_tokens",
		streamUsage:    true,
	}

	if provider == "openai" {
		d.maxTokensField = "max_completion_tokens"
	}

	if v, ok := config.Options[OptionMaxTokensField].(string); ok && v != "" {
		d.maxTokensField = v
	}

	if v, ok := config.Options[OptionStreamUsage].(bool); ok {
		d.streamUsage = v
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

	var result chatResponse

	raw, err := d.client.PostJSON(ctx, "/chat/completions", d.headers(), body, req.Extra, &result)
	if err != nil {
		return nil, err
	}

	resp := &driver.Response{
		Model: result.Model,
		Raw:   raw,
		Usage: driver.Usage{
			InputTokens:  result.Usage.PromptTokens,
			OutputTokens: result.Usage.CompletionTokens,
		},
		Message:    driver.Message{Role: driver.RoleAssistant},
		StopReason: driver.StopReasonOther,
	}

	if len(result.Choices) > 0 {
		choice := result.Choices[0]

		resp.StopReason = mapFinishReason(choice.FinishReason)

		if text := contentText(choice.Message.Content); text != "" {
			resp.Message.Parts = append(resp.Message.Parts, driver.TextPart(text))
		}

		for _, tc := range choice.Message.ToolCalls {
			args := json.RawMessage(tc.Function.Arguments)
			if len(args) == 0 {
				args = json.RawMessage("{}")
			}
			resp.Message.Parts = append(resp.Message.Parts, driver.ToolCallPart(tc.ID, tc.Function.Name, args))
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

	resp, err := d.client.Post(ctx, "/chat/completions", d.headers(), body, req.Extra, true)
	if err != nil {
		return nil, err
	}

	return sse.NewStream(resp.Body, d.handleStreamEvent), nil
}

// Embed implements [driver.Embedder.Embed].
func (d *Driver) Embed(ctx context.Context, req *driver.EmbedRequest) (*driver.EmbedResponse, error) {
	if req.Model == "" {
		return nil, driver.ErrMissingModel
	}

	body := map[string]any{
		"model": req.Model,
		"input": req.Input,
	}
	if req.Dimensions > 0 {
		body["dimensions"] = req.Dimensions
	}

	var result struct {
		Model string `json:"model"`
		Data  []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
		} `json:"usage"`
	}

	raw, err := d.client.PostJSON(ctx, "/embeddings", d.headers(), body, req.Extra, &result)
	if err != nil {
		return nil, err
	}

	embeddings := make([][]float64, len(req.Input))
	for i, item := range result.Data {
		idx := item.Index
		if idx < 0 || idx >= len(embeddings) {
			idx = i
		}
		if idx < len(embeddings) {
			embeddings[idx] = item.Embedding
		}
	}

	return &driver.EmbedResponse{
		Embeddings: embeddings,
		Model:      result.Model,
		Usage:      driver.Usage{InputTokens: result.Usage.PromptTokens},
		Raw:        raw,
	}, nil
}

func (d *Driver) headers() map[string]string {
	if d.config.APIKey == "" {
		return nil
	}
	return map[string]string{"Authorization": "Bearer " + d.config.APIKey}
}

func (d *Driver) handleStreamEvent(ev sse.Event) ([]driver.StreamEvent, bool, error) {
	data := strings.TrimSpace(ev.Data)
	if data == "" {
		return nil, false, nil
	}
	if data == "[DONE]" {
		return nil, true, nil
	}

	var chunk struct {
		chatResponse
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return nil, false, fmt.Errorf("llm: failed to decode %s stream chunk: %w", d.client.Provider, err)
	}

	if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
		return nil, false, transport.ParseError(d.client.Provider, 0, []byte(data))
	}

	var events []driver.StreamEvent

	for _, choice := range chunk.Choices {
		if text := contentText(choice.Delta.Content); text != "" {
			events = append(events, driver.StreamEvent{
				Type:  driver.StreamEventTextDelta,
				Text:  text,
				Model: chunk.Model,
			})
		}

		for _, tc := range choice.Delta.ToolCalls {
			events = append(events, driver.StreamEvent{
				Type:  driver.StreamEventToolCallDelta,
				Model: chunk.Model,
				ToolCall: &driver.ToolCallDelta{
					Index:          tc.Index,
					ID:             tc.ID,
					Name:           tc.Function.Name,
					ArgumentsDelta: tc.Function.Arguments,
				},
			})
		}

		if choice.FinishReason != "" {
			events = append(events, driver.StreamEvent{
				Type:       driver.StreamEventStop,
				StopReason: mapFinishReason(choice.FinishReason),
				Model:      chunk.Model,
			})
		}
	}

	if chunk.Usage.PromptTokens > 0 || chunk.Usage.CompletionTokens > 0 {
		events = append(events, driver.StreamEvent{
			Type:  driver.StreamEventUsage,
			Model: chunk.Model,
			Usage: &driver.Usage{
				InputTokens:  chunk.Usage.PromptTokens,
				OutputTokens: chunk.Usage.CompletionTokens,
			},
		})
	}

	return events, false, nil
}

func (d *Driver) buildBody(req *driver.Request, stream bool) (map[string]any, error) {
	model, err := driver.ResolveModel(req.Model, d.config)
	if err != nil {
		return nil, err
	}

	messages, err := convertMessages(req)
	if err != nil {
		return nil, err
	}

	body := map[string]any{
		"model":    model,
		"messages": messages,
	}

	if stream {
		body["stream"] = true
		if d.streamUsage {
			body["stream_options"] = map[string]any{"include_usage": true}
		}
	}

	if req.MaxTokens > 0 {
		body[d.maxTokensField] = req.MaxTokens
	}

	if req.Temperature != nil {
		body["temperature"] = *req.Temperature
	}

	if req.TopP != nil {
		body["top_p"] = *req.TopP
	}

	if len(req.StopSequences) > 0 {
		body["stop"] = req.StopSequences
	}

	if len(req.Tools) > 0 {
		tools := make([]map[string]any, len(req.Tools))
		for i, t := range req.Tools {
			fn := map[string]any{"name": t.Name}
			if t.Description != "" {
				fn["description"] = t.Description
			}
			if len(t.InputSchema) > 0 {
				fn["parameters"] = t.InputSchema
			}
			tools[i] = map[string]any{"type": "function", "function": fn}
		}
		body["tools"] = tools
	}

	if req.ToolChoice != nil {
		switch req.ToolChoice.Mode {
		case driver.ToolChoiceAuto, driver.ToolChoiceNone, driver.ToolChoiceRequired:
			body["tool_choice"] = string(req.ToolChoice.Mode)
		case driver.ToolChoiceTool:
			body["tool_choice"] = map[string]any{
				"type":     "function",
				"function": map[string]any{"name": req.ToolChoice.Name},
			}
		}
	}

	if rf := req.ResponseFormat; rf != nil && rf.Type == driver.ResponseFormatJSON {
		if len(rf.Schema) > 0 {
			name := rf.Name
			if name == "" {
				name = "response"
			}
			body["response_format"] = map[string]any{
				"type": "json_schema",
				"json_schema": map[string]any{
					"name":   name,
					"schema": rf.Schema,
				},
			}
		} else {
			body["response_format"] = map[string]any{"type": "json_object"}
		}
	}

	return body, nil
}

func convertMessages(req *driver.Request) ([]map[string]any, error) {
	result := make([]map[string]any, 0, len(req.Messages)+1)

	if req.System != "" {
		result = append(result, map[string]any{"role": "system", "content": req.System})
	}

	for _, m := range req.Messages {
		var (
			content   []map[string]any
			toolCalls []map[string]any
		)

		for _, p := range m.Parts {
			switch p.Type {
			case driver.PartTypeText:
				content = append(content, map[string]any{"type": "text", "text": p.Text})
			case driver.PartTypeImage:
				if p.Image == nil {
					continue
				}
				url := p.Image.URL
				if url == "" {
					url = "data:" + p.Image.MimeType + ";base64," + p.Image.Data
				}
				content = append(content, map[string]any{"type": "image_url", "image_url": map[string]any{"url": url}})
			case driver.PartTypeToolCall:
				if p.ToolCall == nil {
					continue
				}
				args := string(p.ToolCall.Arguments)
				if args == "" {
					args = "{}"
				}
				toolCalls = append(toolCalls, map[string]any{
					"id":   p.ToolCall.ID,
					"type": "function",
					"function": map[string]any{
						"name":      p.ToolCall.Name,
						"arguments": args,
					},
				})
			case driver.PartTypeToolResult:
				if p.ToolResult == nil {
					continue
				}
				// note: tool results are sent as separate "tool" role messages
				result = append(result, map[string]any{
					"role":         "tool",
					"tool_call_id": p.ToolResult.ToolCallID,
					"content":      p.ToolResult.Content,
				})
			default:
				return nil, fmt.Errorf("llm: unsupported message part type %q", p.Type)
			}
		}

		if len(content) == 0 && len(toolCalls) == 0 {
			continue
		}

		msg := map[string]any{"role": string(m.Role)}

		switch {
		case len(content) == 0:
			msg["content"] = nil
		case len(content) == 1 && content[0]["type"] == "text":
			// plain string for better compatibility with the more limited OpenAI-compatible servers
			msg["content"] = content[0]["text"]
		case m.Role == driver.RoleAssistant:
			// assistant messages support only text parts
			var sb strings.Builder
			for _, c := range content {
				if text, ok := c["text"].(string); ok {
					sb.WriteString(text)
				}
			}
			msg["content"] = sb.String()
		default:
			msg["content"] = content
		}

		if len(toolCalls) > 0 {
			msg["tool_calls"] = toolCalls
		}

		result = append(result, msg)
	}

	return result, nil
}

func mapFinishReason(reason string) driver.StopReason {
	switch reason {
	case "stop":
		return driver.StopReasonEndTurn
	case "length":
		return driver.StopReasonMaxTokens
	case "tool_calls", "function_call":
		return driver.StopReasonToolUse
	default:
		return driver.StopReasonOther
	}
}

// contentText extracts the text from either a plain string or an array of text parts content.
func contentText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}

	var str string
	if json.Unmarshal(raw, &str) == nil {
		return str
	}

	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	_ = json.Unmarshal(raw, &parts)

	var sb strings.Builder
	for _, p := range parts {
		if p.Type == "text" {
			sb.WriteString(p.Text)
		}
	}

	return sb.String()
}

type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message      chatMessage `json:"message"`
		Delta        chatMessage `json:"delta"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

type chatMessage struct {
	Content   json.RawMessage `json:"content"`
	ToolCalls []struct {
		Index    int    `json:"index"`
		ID       string `json:"id"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls"`
}
