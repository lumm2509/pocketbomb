// Package gemini implements an LLM driver for the Google Generative Language (Gemini) API.
package gemini

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/lumm2509/pocketbomb/tools/llm/driver"
	"github.com/lumm2509/pocketbomb/tools/llm/internal/sse"
	"github.com/lumm2509/pocketbomb/tools/llm/internal/transport"
)

// DefaultBaseURL is the default Gemini API base url.
const DefaultBaseURL = "https://generativelanguage.googleapis.com/v1beta"

var (
	_ driver.Driver   = (*Driver)(nil)
	_ driver.Embedder = (*Driver)(nil)
)

// Driver is a Gemini generateContent API driver.
type Driver struct {
	config driver.Config
	client *transport.Client
}

// New creates a new Gemini driver.
func New(config driver.Config) (*Driver, error) {
	return &Driver{
		config: config,
		client: transport.NewClient("gemini", config, DefaultBaseURL),
	}, nil
}

// Close implements [driver.Driver.Close].
func (d *Driver) Close() error {
	return nil
}

// Generate implements [driver.Driver.Generate].
func (d *Driver) Generate(ctx context.Context, req *driver.Request) (*driver.Response, error) {
	model, body, err := d.buildBody(req)
	if err != nil {
		return nil, err
	}

	var result generateResponse

	raw, err := d.client.PostJSON(ctx, "/"+modelPath(model)+":generateContent", d.headers(), body, req.Extra, &result)
	if err != nil {
		return nil, err
	}

	resp := &driver.Response{
		Model:      result.ModelVersion,
		Raw:        raw,
		StopReason: driver.StopReasonOther,
		Usage:      result.UsageMetadata.toUsage(),
		Message:    driver.Message{Role: driver.RoleAssistant},
	}
	if resp.Model == "" {
		resp.Model = model
	}

	var hasToolCalls bool

	if len(result.Candidates) > 0 {
		candidate := result.Candidates[0]

		for i, p := range candidate.Content.Parts {
			switch {
			case p.FunctionCall != nil:
				hasToolCalls = true
				resp.Message.Parts = append(resp.Message.Parts, driver.ToolCallPart(
					p.FunctionCall.callID(i),
					p.FunctionCall.Name,
					p.FunctionCall.args(),
				))
			case p.Text != "" && !p.Thought:
				if n := len(resp.Message.Parts); n > 0 && resp.Message.Parts[n-1].Type == driver.PartTypeText {
					resp.Message.Parts[n-1].Text += p.Text
				} else {
					resp.Message.Parts = append(resp.Message.Parts, driver.TextPart(p.Text))
				}
			}
		}

		resp.StopReason = mapFinishReason(candidate.FinishReason, hasToolCalls)
	}

	return resp, nil
}

// Stream implements [driver.Driver.Stream].
func (d *Driver) Stream(ctx context.Context, req *driver.Request) (driver.Stream, error) {
	model, body, err := d.buildBody(req)
	if err != nil {
		return nil, err
	}

	resp, err := d.client.Post(ctx, "/"+modelPath(model)+":streamGenerateContent?alt=sse", d.headers(), body, req.Extra, true)
	if err != nil {
		return nil, err
	}

	var (
		toolCallIndex int
		hasToolCalls  bool
	)

	return sse.NewStream(resp.Body, func(ev sse.Event) ([]driver.StreamEvent, bool, error) {
		if strings.TrimSpace(ev.Data) == "" {
			return nil, false, nil
		}

		var chunk struct {
			generateResponse
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal([]byte(ev.Data), &chunk); err != nil {
			return nil, false, fmt.Errorf("llm: failed to decode gemini stream chunk: %w", err)
		}

		if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
			return nil, false, transport.ParseError("gemini", 0, []byte(ev.Data))
		}

		var events []driver.StreamEvent

		for _, candidate := range chunk.Candidates {
			for _, p := range candidate.Content.Parts {
				switch {
				case p.FunctionCall != nil:
					// note: Gemini streams function calls as whole (not partial) parts
					hasToolCalls = true
					events = append(events, driver.StreamEvent{
						Type:  driver.StreamEventToolCallDelta,
						Model: chunk.ModelVersion,
						ToolCall: &driver.ToolCallDelta{
							Index:          toolCallIndex,
							ID:             p.FunctionCall.callID(toolCallIndex),
							Name:           p.FunctionCall.Name,
							ArgumentsDelta: string(p.FunctionCall.args()),
						},
					})
					toolCallIndex++
				case p.Text != "" && !p.Thought:
					events = append(events, driver.StreamEvent{
						Type:  driver.StreamEventTextDelta,
						Text:  p.Text,
						Model: chunk.ModelVersion,
					})
				}
			}

			if candidate.FinishReason != "" {
				events = append(events, driver.StreamEvent{
					Type:       driver.StreamEventStop,
					Model:      chunk.ModelVersion,
					StopReason: mapFinishReason(candidate.FinishReason, hasToolCalls),
				})
			}

			break // only the first candidate is supported
		}

		if u := chunk.UsageMetadata.toUsage(); u.InputTokens > 0 || u.OutputTokens > 0 {
			events = append(events, driver.StreamEvent{
				Type:  driver.StreamEventUsage,
				Model: chunk.ModelVersion,
				Usage: &u,
			})
		}

		return events, false, nil
	}), nil
}

// Embed implements [driver.Embedder.Embed].
func (d *Driver) Embed(ctx context.Context, req *driver.EmbedRequest) (*driver.EmbedResponse, error) {
	if req.Model == "" {
		return nil, driver.ErrMissingModel
	}

	model := modelPath(req.Model)

	requests := make([]map[string]any, len(req.Input))
	for i, input := range req.Input {
		r := map[string]any{
			"model":   model,
			"content": map[string]any{"parts": []map[string]any{{"text": input}}},
		}
		if req.Dimensions > 0 {
			r["outputDimensionality"] = req.Dimensions
		}
		requests[i] = r
	}

	var result struct {
		Embeddings []struct {
			Values []float64 `json:"values"`
		} `json:"embeddings"`
	}

	raw, err := d.client.PostJSON(ctx, "/"+model+":batchEmbedContents", d.headers(), map[string]any{"requests": requests}, req.Extra, &result)
	if err != nil {
		return nil, err
	}

	embeddings := make([][]float64, len(result.Embeddings))
	for i, e := range result.Embeddings {
		embeddings[i] = e.Values
	}

	return &driver.EmbedResponse{
		Embeddings: embeddings,
		Model:      req.Model,
		Raw:        raw,
	}, nil
}

func (d *Driver) headers() map[string]string {
	return map[string]string{"x-goog-api-key": d.config.APIKey}
}

func (d *Driver) buildBody(req *driver.Request) (string, map[string]any, error) {
	model, err := driver.ResolveModel(req.Model, d.config)
	if err != nil {
		return "", nil, err
	}

	contents, err := convertMessages(req.Messages)
	if err != nil {
		return "", nil, err
	}

	body := map[string]any{"contents": contents}

	if req.System != "" {
		body["systemInstruction"] = map[string]any{"parts": []map[string]any{{"text": req.System}}}
	}

	genConfig := map[string]any{}
	if req.MaxTokens > 0 {
		genConfig["maxOutputTokens"] = req.MaxTokens
	}
	if req.Temperature != nil {
		genConfig["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		genConfig["topP"] = *req.TopP
	}
	if len(req.StopSequences) > 0 {
		genConfig["stopSequences"] = req.StopSequences
	}
	if rf := req.ResponseFormat; rf != nil && rf.Type == driver.ResponseFormatJSON {
		genConfig["responseMimeType"] = "application/json"
		if len(rf.Schema) > 0 {
			genConfig["responseJsonSchema"] = rf.Schema
		}
	}
	if len(genConfig) > 0 {
		body["generationConfig"] = genConfig
	}

	if len(req.Tools) > 0 {
		decls := make([]map[string]any, len(req.Tools))
		for i, t := range req.Tools {
			decl := map[string]any{"name": t.Name}
			if t.Description != "" {
				decl["description"] = t.Description
			}
			if len(t.InputSchema) > 0 {
				decl["parametersJsonSchema"] = t.InputSchema
			}
			decls[i] = decl
		}
		body["tools"] = []map[string]any{{"functionDeclarations": decls}}
	}

	if req.ToolChoice != nil {
		fcConfig := map[string]any{}
		switch req.ToolChoice.Mode {
		case driver.ToolChoiceAuto:
			fcConfig["mode"] = "AUTO"
		case driver.ToolChoiceNone:
			fcConfig["mode"] = "NONE"
		case driver.ToolChoiceRequired:
			fcConfig["mode"] = "ANY"
		case driver.ToolChoiceTool:
			fcConfig["mode"] = "ANY"
			fcConfig["allowedFunctionNames"] = []string{req.ToolChoice.Name}
		}
		if len(fcConfig) > 0 {
			body["toolConfig"] = map[string]any{"functionCallingConfig": fcConfig}
		}
	}

	return model, body, nil
}

func convertMessages(messages []driver.Message) ([]map[string]any, error) {
	result := make([]map[string]any, 0, len(messages))

	// tool call id -> name (Gemini function responses require the function name)
	toolNames := map[string]string{}

	for _, m := range messages {
		parts := make([]map[string]any, 0, len(m.Parts))

		for _, p := range m.Parts {
			switch p.Type {
			case driver.PartTypeText:
				parts = append(parts, map[string]any{"text": p.Text})
			case driver.PartTypeImage:
				if p.Image == nil {
					continue
				}
				if p.Image.URL != "" {
					parts = append(parts, map[string]any{"fileData": map[string]any{"mimeType": p.Image.MimeType, "fileUri": p.Image.URL}})
				} else {
					parts = append(parts, map[string]any{"inlineData": map[string]any{"mimeType": p.Image.MimeType, "data": p.Image.Data}})
				}
			case driver.PartTypeToolCall:
				if p.ToolCall == nil {
					continue
				}
				toolNames[p.ToolCall.ID] = p.ToolCall.Name
				args := p.ToolCall.Arguments
				if len(args) == 0 {
					args = json.RawMessage("{}")
				}
				fc := map[string]any{"name": p.ToolCall.Name, "args": args}
				if p.ToolCall.ID != "" && !isGeneratedID(p.ToolCall.ID) {
					fc["id"] = p.ToolCall.ID
				}
				parts = append(parts, map[string]any{"functionCall": fc})
			case driver.PartTypeToolResult:
				if p.ToolResult == nil {
					continue
				}
				name := p.ToolResult.Name
				if name == "" {
					name = toolNames[p.ToolResult.ToolCallID]
				}
				if name == "" {
					return nil, fmt.Errorf("llm: gemini requires the tool name for tool result %q", p.ToolResult.ToolCallID)
				}
				fr := map[string]any{"name": name, "response": toolResponse(p.ToolResult)}
				if p.ToolResult.ToolCallID != "" && !isGeneratedID(p.ToolResult.ToolCallID) {
					fr["id"] = p.ToolResult.ToolCallID
				}
				parts = append(parts, map[string]any{"functionResponse": fr})
			default:
				return nil, fmt.Errorf("llm: unsupported message part type %q", p.Type)
			}
		}

		if len(parts) == 0 {
			continue
		}

		role := "user"
		if m.Role == driver.RoleAssistant {
			role = "model"
		}

		result = append(result, map[string]any{"role": role, "parts": parts})
	}

	return result, nil
}

// toolResponse wraps the tool result content into the JSON object required by Gemini.
func toolResponse(r *driver.ToolResult) any {
	key := "content"
	if r.IsError {
		key = "error"
	}

	var obj map[string]any
	if !r.IsError && json.Unmarshal([]byte(r.Content), &obj) == nil && obj != nil {
		return obj
	}

	return map[string]any{key: r.Content}
}

// note: Gemini may not return function call ids so we generate
// a local one which must not be sent back to the API.
const generatedIDPrefix = "gemini_call_"

func isGeneratedID(id string) bool {
	return strings.HasPrefix(id, generatedIDPrefix)
}

func modelPath(model string) string {
	if strings.HasPrefix(model, "models/") || strings.HasPrefix(model, "tunedModels/") {
		return model
	}
	return "models/" + url.PathEscape(model)
}

func mapFinishReason(reason string, hasToolCalls bool) driver.StopReason {
	if hasToolCalls {
		return driver.StopReasonToolUse
	}

	switch reason {
	case "STOP":
		return driver.StopReasonEndTurn
	case "MAX_TOKENS":
		return driver.StopReasonMaxTokens
	default: // SAFETY, RECITATION, MALFORMED_FUNCTION_CALL, etc.
		return driver.StopReasonOther
	}
}

type functionCall struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

func (fc *functionCall) callID(index int) string {
	if fc.ID != "" {
		return fc.ID
	}
	return generatedIDPrefix + strconv.Itoa(index)
}

func (fc *functionCall) args() json.RawMessage {
	if len(fc.Args) == 0 || string(fc.Args) == "null" {
		return json.RawMessage("{}")
	}
	return fc.Args
}

type usageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	ThoughtsTokenCount   int `json:"thoughtsTokenCount"`
}

func (u usageMetadata) toUsage() driver.Usage {
	return driver.Usage{
		InputTokens:  u.PromptTokenCount,
		OutputTokens: u.CandidatesTokenCount + u.ThoughtsTokenCount,
	}
}

type generateResponse struct {
	ModelVersion string `json:"modelVersion"`
	Candidates   []struct {
		FinishReason string `json:"finishReason"`
		Content      struct {
			Parts []struct {
				Text         string        `json:"text"`
				Thought      bool          `json:"thought"`
				FunctionCall *functionCall `json:"functionCall"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	UsageMetadata usageMetadata `json:"usageMetadata"`
}
