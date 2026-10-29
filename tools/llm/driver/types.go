package driver

import (
	"encoding/json"
	"strings"
)

// Role defines a message author role.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// PartType defines a message part type.
type PartType string

const (
	PartTypeText       PartType = "text"
	PartTypeImage      PartType = "image"
	PartTypeToolCall   PartType = "tool_call"
	PartTypeToolResult PartType = "tool_result"
)

// StopReason defines a normalized response stop reason.
type StopReason string

const (
	StopReasonEndTurn      StopReason = "end_turn"
	StopReasonMaxTokens    StopReason = "max_tokens"
	StopReasonToolUse      StopReason = "tool_use"
	StopReasonStopSequence StopReason = "stop_sequence"
	StopReasonOther        StopReason = "other"
)

// ToolChoiceMode defines how the model should use the provided tools.
type ToolChoiceMode string

const (
	ToolChoiceAuto     ToolChoiceMode = "auto"
	ToolChoiceNone     ToolChoiceMode = "none"
	ToolChoiceRequired ToolChoiceMode = "required" // at least one tool call
	ToolChoiceTool     ToolChoiceMode = "tool"     // call the specific ToolChoice.Name tool
)

// ResponseFormatType defines the expected response output format.
type ResponseFormatType string

const (
	ResponseFormatText ResponseFormatType = "text"
	ResponseFormatJSON ResponseFormatType = "json"
)

// Message defines a single normalized conversation message.
//
// Tool results must be sent as parts of a [RoleUser] message
// (drivers take care to convert them to the provider specific format).
type Message struct {
	Role  Role   `json:"role"`
	Parts []Part `json:"parts"`
}

// Text returns the concatenated text of all message text parts.
func (m Message) Text() string {
	var sb strings.Builder
	for _, p := range m.Parts {
		if p.Type == PartTypeText {
			sb.WriteString(p.Text)
		}
	}
	return sb.String()
}

// ToolCalls returns all message tool calls.
func (m Message) ToolCalls() []*ToolCall {
	var result []*ToolCall
	for _, p := range m.Parts {
		if p.Type == PartTypeToolCall && p.ToolCall != nil {
			result = append(result, p.ToolCall)
		}
	}
	return result
}

// Part defines a single message content part.
//
// Only the field related to Type is expected to be set.
type Part struct {
	Type       PartType    `json:"type"`
	Text       string      `json:"text,omitempty"`
	Image      *Image      `json:"image,omitempty"`
	ToolCall   *ToolCall   `json:"toolCall,omitempty"`
	ToolResult *ToolResult `json:"toolResult,omitempty"`
}

// Image defines an image part (either URL or base64 Data should be set).
type Image struct {
	URL      string `json:"url,omitempty"`
	Data     string `json:"data,omitempty"` // base64 encoded
	MimeType string `json:"mimeType,omitempty"`
}

// ToolCall defines a single model tool call request.
type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"` // JSON object
}

// ToolResult defines the result of a single tool call execution.
type ToolResult struct {
	ToolCallID string `json:"toolCallId"`

	// Name is the name of the called tool.
	//
	// It is optional and it is used only by providers that identify
	// results by the tool name (e.g. Gemini). If empty, drivers will try
	// to resolve it from the previous messages tool calls.
	Name string `json:"name,omitempty"`

	Content string `json:"content"`
	IsError bool   `json:"isError,omitempty"`
}

// TextPart creates a new text Part.
func TextPart(text string) Part {
	return Part{Type: PartTypeText, Text: text}
}

// ImageURLPart creates a new image Part from a URL.
func ImageURLPart(url string, mimeType string) Part {
	return Part{Type: PartTypeImage, Image: &Image{URL: url, MimeType: mimeType}}
}

// ImageDataPart creates a new image Part from base64 encoded data.
func ImageDataPart(base64Data string, mimeType string) Part {
	return Part{Type: PartTypeImage, Image: &Image{Data: base64Data, MimeType: mimeType}}
}

// ToolCallPart creates a new tool call Part.
func ToolCallPart(id string, name string, args json.RawMessage) Part {
	return Part{Type: PartTypeToolCall, ToolCall: &ToolCall{ID: id, Name: name, Arguments: args}}
}

// ToolResultPart creates a new tool result Part.
func ToolResultPart(toolCallID string, content string, isError bool) Part {
	return Part{Type: PartTypeToolResult, ToolResult: &ToolResult{ToolCallID: toolCallID, Content: content, IsError: isError}}
}

// UserMessage creates a new user Message with the specified parts.
func UserMessage(parts ...Part) Message {
	return Message{Role: RoleUser, Parts: parts}
}

// UserText creates a new single text part user Message.
func UserText(text string) Message {
	return UserMessage(TextPart(text))
}

// AssistantMessage creates a new assistant Message with the specified parts.
func AssistantMessage(parts ...Part) Message {
	return Message{Role: RoleAssistant, Parts: parts}
}

// Tool defines a single tool (aka. function) declaration.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"` // JSON Schema object
}

// ToolChoice defines the tools usage strategy.
type ToolChoice struct {
	Mode ToolChoiceMode `json:"mode"`
	Name string         `json:"name,omitempty"` // required for ToolChoiceTool
}

// ResponseFormat defines the expected response format.
type ResponseFormat struct {
	Type ResponseFormatType `json:"type"`

	// Name is an optional schema name (used only by some providers).
	Name string `json:"name,omitempty"`

	// Schema is an optional JSON Schema the response must conform to.
	Schema json.RawMessage `json:"schema,omitempty"`
}

// Request defines a normalized LLM generation request.
type Request struct {
	// Model is the provider model id (fallbacks to Config.DefaultModel).
	Model string `json:"model,omitempty"`

	// System is an optional system prompt (aka. instructions).
	System string `json:"system,omitempty"`

	Messages       []Message       `json:"messages"`
	Tools          []Tool          `json:"tools,omitempty"`
	ToolChoice     *ToolChoice     `json:"toolChoice,omitempty"`
	MaxTokens      int             `json:"maxTokens,omitempty"`
	Temperature    *float64        `json:"temperature,omitempty"`
	TopP           *float64        `json:"topP,omitempty"`
	StopSequences  []string        `json:"stopSequences,omitempty"`
	ResponseFormat *ResponseFormat `json:"responseFormat,omitempty"`

	// Extra specifies raw provider specific top-level body fields that
	// are shallow merged into the final provider request body
	// (a nil value removes the related key).
	Extra map[string]any `json:"extra,omitempty"`
}

// Usage defines the request tokens usage.
type Usage struct {
	InputTokens  int `json:"inputTokens"`
	OutputTokens int `json:"outputTokens"`
}

// Response defines a normalized LLM generation response.
type Response struct {
	Message    Message    `json:"message"`
	StopReason StopReason `json:"stopReason"`
	Usage      Usage      `json:"usage"`
	Model      string     `json:"model"`

	// Raw is the raw provider response body (nil for accumulated streams).
	Raw json.RawMessage `json:"raw,omitempty"`
}

// Text returns the concatenated text of the response message.
func (r *Response) Text() string {
	return r.Message.Text()
}

// ToolCalls returns the response message tool calls (if any).
func (r *Response) ToolCalls() []*ToolCall {
	return r.Message.ToolCalls()
}

// EmbedRequest defines a normalized embeddings request.
type EmbedRequest struct {
	// Model is the embeddings model id (required).
	Model string `json:"model"`

	Input []string `json:"input"`

	// Dimensions is the optional output vectors size (if supported by the model).
	Dimensions int `json:"dimensions,omitempty"`

	// Extra specifies raw provider specific body fields (see [Request.Extra]).
	Extra map[string]any `json:"extra,omitempty"`
}

// EmbedResponse defines a normalized embeddings response.
type EmbedResponse struct {
	// Embeddings are in the same order as the EmbedRequest.Input.
	Embeddings [][]float64     `json:"embeddings"`
	Usage      Usage           `json:"usage"`
	Model      string          `json:"model"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}
