package llm

import "github.com/lumm2509/pocketbomb/tools/llm/driver"

// note: the most commonly used driver types are aliased for convenience
// so that in most cases users will need to import only the llm package.

type (
	Config         = driver.Config
	Driver         = driver.Driver
	Embedder       = driver.Embedder
	Stream         = driver.Stream
	StreamEvent    = driver.StreamEvent
	ToolCallDelta  = driver.ToolCallDelta
	Accumulator    = driver.Accumulator
	Request        = driver.Request
	Response       = driver.Response
	Role           = driver.Role
	PartType       = driver.PartType
	Message        = driver.Message
	Part           = driver.Part
	Image          = driver.Image
	ToolCall       = driver.ToolCall
	ToolResult     = driver.ToolResult
	Tool           = driver.Tool
	ToolChoice     = driver.ToolChoice
	ResponseFormat = driver.ResponseFormat
	Usage          = driver.Usage
	StopReason     = driver.StopReason
	EmbedRequest   = driver.EmbedRequest
	EmbedResponse  = driver.EmbedResponse
	APIError       = driver.APIError
)

var (
	ErrUnsupported  = driver.ErrUnsupported
	ErrMissingModel = driver.ErrMissingModel
	ErrClosed       = driver.ErrClosed
)

const (
	RoleUser      = driver.RoleUser
	RoleAssistant = driver.RoleAssistant

	PartTypeText       = driver.PartTypeText
	PartTypeImage      = driver.PartTypeImage
	PartTypeToolCall   = driver.PartTypeToolCall
	PartTypeToolResult = driver.PartTypeToolResult

	StopReasonEndTurn      = driver.StopReasonEndTurn
	StopReasonMaxTokens    = driver.StopReasonMaxTokens
	StopReasonToolUse      = driver.StopReasonToolUse
	StopReasonStopSequence = driver.StopReasonStopSequence
	StopReasonOther        = driver.StopReasonOther

	ToolChoiceAuto     = driver.ToolChoiceAuto
	ToolChoiceNone     = driver.ToolChoiceNone
	ToolChoiceRequired = driver.ToolChoiceRequired
	ToolChoiceTool     = driver.ToolChoiceTool

	ResponseFormatText = driver.ResponseFormatText
	ResponseFormatJSON = driver.ResponseFormatJSON

	StreamEventTextDelta     = driver.StreamEventTextDelta
	StreamEventToolCallDelta = driver.StreamEventToolCallDelta
	StreamEventUsage         = driver.StreamEventUsage
	StreamEventStop          = driver.StreamEventStop
)

var (
	TextPart         = driver.TextPart
	ImageURLPart     = driver.ImageURLPart
	ImageDataPart    = driver.ImageDataPart
	ToolCallPart     = driver.ToolCallPart
	ToolResultPart   = driver.ToolResultPart
	UserMessage      = driver.UserMessage
	UserText         = driver.UserText
	AssistantMessage = driver.AssistantMessage
	Accumulate       = driver.Accumulate
)
