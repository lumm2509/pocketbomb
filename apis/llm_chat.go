package apis

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/llm"
	"github.com/lumm2509/pocketbomb/tools/router"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// llmChatMessage defines a single chat API message.
//
// For convenience the message could be specified either with
// the plain text Content or with the normalized llm Parts.
type llmChatMessage struct {
	Role    string     `json:"role"`
	Content string     `json:"content"`
	Parts   []llm.Part `json:"parts"`
}

func (m llmChatMessage) Validate() error {
	return validation.ValidateStruct(&m,
		validation.Field(&m.Role, validation.Required, validation.In(string(llm.RoleUser), string(llm.RoleAssistant))),
		validation.Field(&m.Content, validation.When(len(m.Parts) == 0, validation.Required)),
	)
}

func (m llmChatMessage) toLLM() llm.Message {
	parts := m.Parts
	if m.Content != "" {
		parts = append([]llm.Part{llm.TextPart(m.Content)}, parts...)
	}

	return llm.Message{Role: llm.Role(m.Role), Parts: parts}
}

// llmChatRequest defines the chat API request body.
type llmChatRequest struct {
	Messages    []llmChatMessage `json:"messages"`
	Model       string           `json:"model"`
	Temperature *float64         `json:"temperature"`
	MaxTokens   int              `json:"maxTokens"`
	Tools       []llm.Tool       `json:"tools"`
	ToolChoice  *llm.ToolChoice  `json:"toolChoice"`
	Stream      bool             `json:"stream"`
}

// validate validates the chat request body against the profile options.
func (r *llmChatRequest) validate(profile *core.LLMProfile, isSuperuser bool) error {
	allowOverrides := profile.AllowClientOverrides || isSuperuser

	overrideErr := validation.NewError("validation_llm_override_not_allowed", "The profile doesn't allow client overrides.")

	return validation.ValidateStruct(r,
		validation.Field(&r.Messages, validation.Required, validation.Length(1, 0)),
		validation.Field(
			&r.Model,
			validation.When(!allowOverrides && r.Model != profile.Model, validation.Empty.ErrorObject(overrideErr)),
			validation.By(func(value any) error {
				if !profile.IsModelAllowed(r.Model) {
					return validation.NewError("validation_llm_model_not_allowed", "The model is not allowed for the profile.")
				}
				return nil
			}),
		),
		validation.Field(&r.Temperature, validation.When(!allowOverrides, validation.Nil.ErrorObject(overrideErr)), validation.Min(0.0), validation.Max(2.0)),
		validation.Field(&r.MaxTokens, validation.When(!allowOverrides, validation.Empty.ErrorObject(overrideErr)), validation.Min(0)),
		validation.Field(&r.Tools, validation.When(!allowOverrides, validation.Empty.ErrorObject(overrideErr))),
		validation.Field(&r.ToolChoice, validation.When(!allowOverrides, validation.Nil.ErrorObject(overrideErr))),
	)
}

func (r *llmChatRequest) toLLM() *llm.Request {
	messages := make([]llm.Message, len(r.Messages))
	for i, m := range r.Messages {
		messages[i] = m.toLLM()
	}

	return &llm.Request{
		Model:       r.Model,
		Messages:    messages,
		Temperature: r.Temperature,
		MaxTokens:   r.MaxTokens,
		Tools:       r.Tools,
		ToolChoice:  r.ToolChoice,
	}
}

// llmChatResponse defines the chat API response
// (also used as data of the final "done" stream event).
type llmChatResponse struct {
	Model      string         `json:"model"`
	Message    llm.Message    `json:"message"`
	Text       string         `json:"text"`
	StopReason llm.StopReason `json:"stopReason"`
	Usage      llm.Usage      `json:"usage"`
}

func newLLMChatResponse(resp *llm.Response) *llmChatResponse {
	if resp == nil {
		resp = &llm.Response{}
	}

	if resp.Message.Parts == nil {
		resp.Message.Parts = []llm.Part{}
	}

	if resp.Message.Role == "" {
		resp.Message.Role = llm.RoleAssistant
	}

	return &llmChatResponse{
		Model:      resp.Model,
		Message:    resp.Message,
		Text:       resp.Text(),
		StopReason: resp.StopReason,
		Usage:      resp.Usage,
	}
}

// llmChat handles the "POST /api/llm/{profile}/chat" requests.
//
// The request flow is: profile rule check -> body validation -> quota check -> provider call -> log.
func llmChat(e *core.RequestEvent) error {
	profile, ok := e.App.Settings().LLM.FindProfile(e.Request.PathValue("profile"))
	if !ok {
		return e.NotFoundError("Missing or invalid LLM profile.", nil)
	}

	requestInfo, err := e.RequestInfo()
	if err != nil {
		return e.BadRequestError("", err)
	}

	// the staff with llm write permission (aka. the playground) bypass the profile rule
	isSuperuser := e.Can(core.PermissionResourceLLM, core.PermissionLevelWrite)

	// load the body (it is loaded even before the rule check because it is
	// needed for the denied requests log, the rule itself uses the requestInfo.Body)
	body := &llmChatRequest{}
	if err := e.BindBody(body); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	// rule check
	canAccess := isSuperuser
	if !canAccess {
		canAccess, err = core.CanAccessRequestRule(e.App, requestInfo, profile.Rule)
	}
	if err != nil || !canAccess {
		reason := "the request doesn't satisfy the profile rule"
		if profile.Rule == nil {
			reason = "only superusers can access the profile"
		}
		if err != nil {
			e.App.Logger().Debug("Failed to evaluate the LLM profile rule", "profile", profile.Name, "error", err.Error())
		}

		writeLLMDeniedLog(e, &profile, body.Model, body.Stream, core.LLMLogStatusDenied, reason)

		if profile.Rule == nil {
			return e.ForbiddenError("Only superusers can access this LLM profile.", nil)
		}

		return e.ForbiddenError("You are not allowed to access this LLM profile.", nil)
	}

	if err := body.validate(&profile, isSuperuser); err != nil {
		return e.BadRequestError("Invalid LLM chat request.", err)
	}

	// quota check
	release, err := reserveLLMQuota(e, &profile)
	if err != nil {
		if quotaErr, ok := isLLMQuotaExceeded(err); ok {
			writeLLMDeniedLog(e, &profile, body.Model, body.Stream, core.LLMLogStatusLimited, quotaErr.Reason)
			return llmQuotaExceededResponse(e, quotaErr)
		}
		return e.InternalServerError("Failed to check the LLM profile quotas.", err)
	}
	defer release()

	client, err := e.App.NewLLMClient(profile.Name)
	if err != nil {
		if errors.Is(err, core.ErrLLMNotConfigured) {
			return e.BadRequestError("The LLM profile provider is missing or disabled.", nil)
		}
		return e.BadRequestError("Failed to initialize the LLM client.", err)
	}
	defer client.Close()

	ctx := core.WithLLMCallInfo(e.Request.Context(), &core.LLMCallInfo{
		Auth: e.Auth,
		IP:   e.RealIP(),
	})

	req := body.toLLM()

	if body.Stream {
		return llmChatStream(e, ctx, client, req)
	}

	resp, err := client.Generate(ctx, req)
	if err != nil {
		return llmCallError(e, err)
	}

	return e.JSON(http.StatusOK, newLLMChatResponse(resp))
}

// llmChatStream sends the LLM response as Server-Sent Events stream:
//   - "delta" - for each normalized llm.StreamEvent
//   - "done"  - the final accumulated response (same format as the non-stream response)
//   - "error" - in case of a mid-stream error ({"message": "..."})
func llmChatStream(e *core.RequestEvent, ctx context.Context, client *llm.Client, req *llm.Request) error {
	s, err := client.Stream(ctx, req)
	if err != nil {
		return llmCallError(e, err)
	}
	defer s.Close()

	// disable the global write deadline for the SSE connection
	rc := http.NewResponseController(e.Response)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return e.InternalServerError("Failed to initialize the LLM SSE stream.", err)
	}

	e.Response.Header().Set("Content-Type", "text/event-stream")
	e.Response.Header().Set("Cache-Control", "no-store")
	e.Response.Header().Set("X-Accel-Buffering", "no")
	e.Response.WriteHeader(http.StatusOK)

	var acc llm.Accumulator

	for s.Next() {
		event := s.Event()
		acc.Add(event)

		if err := writeLLMSSE(e, "delta", event); err != nil {
			return nil // the client has disconnected
		}
	}

	if err := s.Err(); err != nil {
		_ = writeLLMSSE(e, "error", map[string]string{"message": llmCallErrorMessage(e, err)})
		return nil
	}

	_ = writeLLMSSE(e, "done", newLLMChatResponse(acc.Response()))

	return nil
}

func writeLLMSSE(e *core.RequestEvent, name string, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if _, err := e.Response.Write([]byte("event: " + name + "\ndata: ")); err != nil {
		return err
	}

	if _, err := e.Response.Write(raw); err != nil {
		return err
	}

	if _, err := e.Response.Write([]byte("\n\n")); err != nil {
		return err
	}

	return e.Flush()
}

// llmCallErrorMessage returns a public LLM call error message
// (the raw error is included only for superusers).
func llmCallErrorMessage(e *core.RequestEvent, err error) string {
	msg := "Failed to process the LLM request."

	if e.Can(core.PermissionResourceLLM, core.PermissionLevelWrite) {
		msg += " Raw error: " + err.Error()
	}

	return msg
}

// llmCallError normalizes an LLM client call error.
func llmCallError(e *core.RequestEvent, err error) error {
	// e.g. returned by an OnLLMRequest hook
	var apiErr *router.ApiError
	if errors.As(err, &apiErr) {
		return apiErr
	}

	status := http.StatusBadRequest

	var providerErr *llm.APIError
	if errors.As(err, &providerErr) || errors.Is(err, context.DeadlineExceeded) {
		status = http.StatusBadGateway
	}

	apiErr = e.Error(status, "", nil)
	apiErr.Message = llmCallErrorMessage(e, err) // set manually to avoid the default message normalization

	return apiErr
}
