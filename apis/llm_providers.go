package apis

import (
	"context"
	"net/http"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/list"
	"github.com/lumm2509/pocketbomb/tools/llm"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// llmProvidersList returns the supported provider drivers and the resolved enabled providers.
func llmProvidersList(e *core.RequestEvent) error {
	return e.JSON(http.StatusOK, map[string]any{
		"drivers":   llm.Providers(),
		"providers": e.App.LLMProviders(),
	})
}

// llmTestProviderForm defines the LLM provider test request body.
type llmTestProviderForm struct {
	// Name is an optional existing provider name.
	//
	// If set and APIKey is empty, the existing provider api key is used
	// (if Provider is also empty - the entire existing provider config is used).
	Name string `json:"name"`

	Provider     string `json:"provider"`
	BaseURL      string `json:"baseURL"`
	APIKey       string `json:"apiKey"`
	DefaultModel string `json:"defaultModel"`
	Timeout      int    `json:"timeout"`

	// Model is an optional model to test (fallbacks to DefaultModel).
	Model string `json:"model"`

	// Prompt is an optional test prompt.
	Prompt string `json:"prompt"`
}

const llmTestDefaultPrompt = `Reply only with "OK".`

// findExistingLLMProvider looks for a settings or env provider config with the specified name.
func findExistingLLMProvider(app core.App, name string) (core.LLMProviderConfig, bool) {
	if p, ok := app.Settings().LLM.FindProvider(name); ok {
		return p, true
	}

	return core.FindLLMEnvProvider(name)
}

// llmTestProvider sends a test prompt to the submitted provider config
// (the call is not logged and doesn't trigger the app LLM hooks).
func llmTestProvider(e *core.RequestEvent) error {
	form := &llmTestProviderForm{}
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	if form.Name != "" {
		if existing, ok := findExistingLLMProvider(e.App, form.Name); ok {
			if form.Provider == "" {
				form.Provider = existing.Provider
				form.BaseURL = existing.BaseURL
				form.DefaultModel = existing.DefaultModel
				form.Timeout = existing.Timeout
			}
			// note: the stored api key is reused only for the same driver and endpoint
			// (otherwise it could be sent to an arbitrary BaseURL by a non-Owner)
			if form.APIKey == "" && form.Provider == existing.Provider && form.BaseURL == existing.BaseURL {
				form.APIKey = existing.APIKey
			}
		}
	}

	err := validation.ValidateStruct(form,
		validation.Field(&form.Provider, validation.Required, validation.In(list.ToInterfaceSlice(llm.Providers())...)),
		validation.Field(&form.Model, validation.When(form.DefaultModel == "", validation.Required)),
		validation.Field(&form.Timeout, validation.Min(0)),
	)
	if err != nil {
		return e.BadRequestError("Invalid LLM provider test data.", err)
	}

	client, err := llm.New(llm.Config{
		Provider:     form.Provider,
		BaseURL:      form.BaseURL,
		APIKey:       form.APIKey,
		DefaultModel: form.DefaultModel,
		Timeout:      time.Duration(form.Timeout) * time.Second,
	})
	if err != nil {
		return e.BadRequestError("Failed to initialize the LLM client. Raw error: \n"+err.Error(), nil)
	}
	defer client.Close()

	prompt := form.Prompt
	if prompt == "" {
		prompt = llmTestDefaultPrompt
	}

	ctx, cancel := context.WithTimeout(e.Request.Context(), 60*time.Second)
	defer cancel()

	start := time.Now()

	resp, err := client.Generate(ctx, &llm.Request{
		Model:     form.Model,
		Messages:  []llm.Message{llm.UserText(prompt)},
		MaxTokens: 256,
	})
	if err != nil {
		return e.BadRequestError("Failed to test the LLM provider. Raw error: \n"+err.Error(), nil)
	}

	return e.JSON(http.StatusOK, map[string]any{
		"model":      resp.Model,
		"text":       resp.Text(),
		"stopReason": resp.StopReason,
		"usage":      resp.Usage,
		"durationMs": time.Since(start).Milliseconds(),
	})
}
