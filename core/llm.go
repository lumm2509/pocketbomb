package core

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/llm"
	"github.com/lumm2509/pocketbomb/tools/routine"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

// ErrLLMNotConfigured is returned by [App.NewLLMClient] when there is
// no enabled LLM provider configured (neither in the settings nor via env variables).
var ErrLLMNotConfigured = errors.New("llm: no LLM provider is configured")

// LLM env variables used as fallback when no settings providers are configured.
const (
	LLMEnvOpenAIAPIKey    = "OPENAI_API_KEY"
	LLMEnvAnthropicAPIKey = "ANTHROPIC_API_KEY"
	LLMEnvGeminiAPIKey    = "GEMINI_API_KEY"
	LLMEnvXAIAPIKey       = "XAI_API_KEY"
	LLMEnvOllamaHost      = "OLLAMA_HOST"
	LLMEnvDefaultProvider = "PB_LLM_DEFAULT_PROVIDER"
	LLMEnvDefaultModel    = "PB_LLM_DEFAULT_MODEL"
)

const (
	// maxLLMLogContentSize is the max size of a single stored log request/response content.
	maxLLMLogContentSize = 256 << 10 // ~256kb

	llmLogContentTruncated = "__pb_truncated__"
)

// llmEnvLookup is the env variables lookup function (could be replaced in tests).
var llmEnvLookup = os.Getenv

// llmEnvProviders returns the LLM providers configured via env variables
// (in a predefined order: openai, anthropic, gemini, xai, ollama).
func llmEnvProviders() []LLMProviderConfig {
	result := []LLMProviderConfig{}

	keys := []struct {
		env      string
		provider string
	}{
		{LLMEnvOpenAIAPIKey, llm.ProviderOpenAI},
		{LLMEnvAnthropicAPIKey, llm.ProviderAnthropic},
		{LLMEnvGeminiAPIKey, llm.ProviderGemini},
		{LLMEnvXAIAPIKey, llm.ProviderXAI},
	}
	for _, k := range keys {
		if v := strings.TrimSpace(llmEnvLookup(k.env)); v != "" {
			result = append(result, LLMProviderConfig{
				Name:     k.provider,
				Provider: k.provider,
				APIKey:   v,
				Enabled:  true,
			})
		}
	}

	if host := strings.TrimSpace(llmEnvLookup(LLMEnvOllamaHost)); host != "" {
		result = append(result, LLMProviderConfig{
			Name:     llm.ProviderOllama,
			Provider: llm.ProviderOllama,
			BaseURL:  normalizeOllamaHost(host),
			Enabled:  true,
		})
	}

	// apply the env default model to the env default provider
	if model := strings.TrimSpace(llmEnvLookup(LLMEnvDefaultModel)); model != "" && len(result) > 0 {
		idx := 0
		if name := strings.TrimSpace(llmEnvLookup(LLMEnvDefaultProvider)); name != "" {
			idx = -1
			for i, p := range result {
				if p.Name == name {
					idx = i
					break
				}
			}
		}
		if idx >= 0 {
			result[idx].DefaultModel = model
		}
	}

	return result
}

// FindLLMEnvProvider returns the env variables LLM provider config
// with the specified name (if any).
func FindLLMEnvProvider(name string) (LLMProviderConfig, bool) {
	for _, p := range llmEnvProviders() {
		if p.Name == name {
			return p, true
		}
	}

	return LLMProviderConfig{}, false
}

// normalizeOllamaHost converts the OLLAMA_HOST env value
// (e.g. "127.0.0.1:11434") to an OpenAI-compatible base url.
func normalizeOllamaHost(host string) string {
	if !strings.Contains(host, "://") {
		host = "http://" + host
	}

	host = strings.TrimRight(host, "/")

	if u, err := url.Parse(host); err == nil && (u.Path == "" || u.Path == "/") {
		host += "/v1"
	}

	return host
}

// LLMProviderInfo defines the public (aka. without secrets) information
// for a single resolved LLM provider.
type LLMProviderInfo struct {
	Name         string   `json:"name"`
	Provider     string   `json:"provider"`
	BaseURL      string   `json:"baseURL"`
	DefaultModel string   `json:"defaultModel"`
	Models       []string `json:"models"`
	Source       string   `json:"source"` // settings | env
	IsDefault    bool     `json:"isDefault"`
}

type resolvedLLMProvider struct {
	LLMProviderConfig
	source string
}

// resolveLLMProviders returns all enabled settings and env providers
// with the default one as first element.
func (app *BaseApp) resolveLLMProviders() []resolvedLLMProvider {
	settings := app.Settings().LLM

	result := make([]resolvedLLMProvider, 0, len(settings.Providers)+5)

	for _, p := range settings.Providers {
		if p.Enabled {
			result = append(result, resolvedLLMProvider{p, LLMProviderSourceSettings})
		}
	}

	for _, p := range llmEnvProviders() {
		// settings providers take precedence (even if disabled)
		if _, exists := settings.FindProvider(p.Name); exists {
			continue
		}
		result = append(result, resolvedLLMProvider{p, LLMProviderSourceEnv})
	}

	defaultName := settings.DefaultProvider
	if defaultName == "" {
		defaultName = strings.TrimSpace(llmEnvLookup(LLMEnvDefaultProvider))
	}

	// move the default provider at the beginning
	if defaultName != "" {
		for i, p := range result {
			if p.Name == defaultName {
				if i > 0 {
					result = append([]resolvedLLMProvider{p}, append(result[:i:i], result[i+1:]...)...)
				}
				break
			}
		}
	}

	return result
}

// LLMProviders returns the list with the enabled LLM providers
// (from the app settings and the env variables) without their secrets.
//
// The default provider (if any) is always the first list element.
func (app *BaseApp) LLMProviders() []*LLMProviderInfo {
	providers := app.resolveLLMProviders()

	result := make([]*LLMProviderInfo, len(providers))
	for i, p := range providers {
		result[i] = &LLMProviderInfo{
			Name:         p.Name,
			Provider:     p.Provider,
			BaseURL:      p.BaseURL,
			DefaultModel: p.DefaultModel,
			Models:       append([]string{}, p.Models...),
			Source:       p.source,
			IsDefault:    i == 0,
		}
	}

	return result
}

// NewLLMClient creates a new LLM client for the specified profile or
// provider name based on the current app settings (and env variables).
//
// If profileOrProvider is not set, the default provider is used.
// If both a profile and a provider with the same name exist, the profile has precedence.
//
// When a profile is used its defaults and limits (model, system prompt,
// temperature, max tokens cap and allowed models) are applied to every
// client request. The profile access rule and quotas are NOT applied
// since they are request specific (they are enforced by the
// "/api/llm/{profile}/chat" endpoint).
//
// Every client call triggers the [App.OnLLMRequest] and [App.OnLLMResponse]
// hooks and it is logged in the auxiliary db _llmLogs table (if enabled).
// Use [WithLLMCallInfo] to attach an auth record, ip and extra meta to the logs.
//
// Returns [ErrLLMNotConfigured] if there are no enabled LLM providers.
//
// NB! Make sure to call Close() on the returned result
// after you are done working with it.
func (app *BaseApp) NewLLMClient(profileOrProvider ...string) (*llm.Client, error) {
	providers := app.resolveLLMProviders()
	if len(providers) == 0 {
		return nil, ErrLLMNotConfigured
	}

	var name string
	if len(profileOrProvider) > 0 {
		name = profileOrProvider[0]
	}

	var profile *LLMProfile
	var provider *resolvedLLMProvider

	findProvider := func(providerName string) *resolvedLLMProvider {
		if providerName == "" {
			return &providers[0]
		}
		for i := range providers {
			if providers[i].Name == providerName {
				return &providers[i]
			}
		}
		return nil
	}

	if name == "" {
		provider = &providers[0]
	} else if p, ok := app.Settings().LLM.FindProfile(name); ok {
		profile = &p
		provider = findProvider(p.Provider)
		if provider == nil {
			return nil, fmt.Errorf("%w (profile %q provider %q is missing or disabled)", ErrLLMNotConfigured, p.Name, p.Provider)
		}
	} else {
		provider = findProvider(name)
		if provider == nil {
			return nil, fmt.Errorf("%w (missing or disabled profile or provider %q)", ErrLLMNotConfigured, name)
		}
	}

	config := llm.Config{
		Provider:     provider.Provider,
		APIKey:       provider.APIKey,
		BaseURL:      provider.BaseURL,
		DefaultModel: provider.DefaultModel,
		Timeout:      time.Duration(provider.Timeout) * time.Second,
	}
	if profile != nil && profile.Model != "" {
		config.DefaultModel = profile.Model
	}

	client, err := llm.New(config)
	if err != nil {
		return nil, err
	}

	app.bindLLMClientHooks(client, provider.Name, profile, config.DefaultModel)

	return client, nil
}

// -------------------------------------------------------------------

type llmCallInfoKey struct{}

// LLMCallInfo defines the optional caller information
// that is attached to the LLM requests context and logs.
type LLMCallInfo struct {
	// Auth is the optional authenticated record that initiated the call.
	Auth *Record

	// IP is the optional client IP address.
	IP string

	// Meta is an optional map with extra data that will be stored in the log meta field.
	Meta map[string]any
}

// WithLLMCallInfo returns a new context with the attached LLM caller information.
//
// Example:
//
//	ctx := core.WithLLMCallInfo(e.Request.Context(), &core.LLMCallInfo{Auth: e.Auth, IP: e.RealIP()})
//	resp, err := client.Generate(ctx, req)
func WithLLMCallInfo(ctx context.Context, info *LLMCallInfo) context.Context {
	return context.WithValue(ctx, llmCallInfoKey{}, info)
}

// LLMCallInfoFromContext returns the LLM caller information attached to the context
// (or an empty non-nil one if missing).
func LLMCallInfoFromContext(ctx context.Context) *LLMCallInfo {
	if ctx != nil {
		if info, ok := ctx.Value(llmCallInfoKey{}).(*LLMCallInfo); ok && info != nil {
			return info
		}
	}

	return &LLMCallInfo{}
}

// -------------------------------------------------------------------

// bindLLMClientHooks attaches the profile defaults, the app hooks and the logs writer to the client.
func (app *BaseApp) bindLLMClientHooks(client *llm.Client, providerName string, profile *LLMProfile, defaultModel string) {
	var profileName string
	if profile != nil {
		profileName = profile.Name
	}

	client.OnBeforeRequest().BindFunc(func(originalEvent *llm.BeforeRequestEvent) error {
		if profile != nil {
			applyLLMProfileDefaults(profile, originalEvent.Request)
		}

		appEvent := new(LLMRequestEvent)
		appEvent.App = app
		appEvent.BeforeRequestEvent = originalEvent
		appEvent.Profile = profileName
		appEvent.ProviderName = providerName
		appEvent.CallInfo = LLMCallInfoFromContext(originalEvent.Context)

		err := app.onLLMRequest.Trigger(appEvent, func(e *LLMRequestEvent) error {
			if profile != nil && !profile.IsModelAllowed(e.Request.Model) {
				return fmt.Errorf("llm: model %q is not allowed for profile %q", e.Request.Model, profile.Name)
			}

			return originalEvent.Next()
		})
		if err != nil {
			// log the aborted request
			log := app.newLLMLog(providerName, profile, defaultModel, originalEvent.Request, originalEvent.IsStream, appEvent.CallInfo)
			log.Status = LLMLogStatusDenied
			log.Error = err.Error()
			app.WriteLLMLog(log)
		}

		return err
	})

	client.OnAfterResponse().BindFunc(func(originalEvent *llm.AfterResponseEvent) error {
		appEvent := new(LLMResponseEvent)
		appEvent.App = app
		appEvent.AfterResponseEvent = originalEvent
		appEvent.Profile = profileName
		appEvent.ProviderName = providerName
		appEvent.CallInfo = LLMCallInfoFromContext(originalEvent.Context)

		err := app.onLLMResponse.Trigger(appEvent, func(e *LLMResponseEvent) error {
			return originalEvent.Next()
		})

		log := app.newLLMLog(providerName, profile, defaultModel, originalEvent.Request, originalEvent.IsStream, appEvent.CallInfo)
		log.DurationMs = int(originalEvent.Duration.Milliseconds())
		if originalEvent.Response != nil {
			if originalEvent.Response.Model != "" {
				log.Model = originalEvent.Response.Model
			}
			log.InputTokens = originalEvent.Response.Usage.InputTokens
			log.OutputTokens = originalEvent.Response.Usage.OutputTokens
		}
		if err != nil {
			log.Status = LLMLogStatusError
			log.Error = err.Error()
		} else {
			log.Status = LLMLogStatusSuccess
		}
		if log.Request != nil && originalEvent.Response != nil {
			resp := *originalEvent.Response
			resp.Raw = nil
			log.Response = marshalLLMLogContent(resp)
		}
		app.WriteLLMLog(log)

		return err
	})
}

// applyLLMProfileDefaults applies the profile defaults and limits to the request.
func applyLLMProfileDefaults(profile *LLMProfile, req *llm.Request) {
	if req.Model == "" {
		req.Model = profile.Model
	}

	if profile.SystemPrompt != "" {
		if req.System == "" {
			req.System = profile.SystemPrompt
		} else if !strings.HasPrefix(req.System, profile.SystemPrompt) {
			req.System = profile.SystemPrompt + "\n\n" + req.System
		}
	}

	if req.Temperature == nil && profile.Temperature != nil {
		t := *profile.Temperature
		req.Temperature = &t
	}

	if profile.MaxTokens > 0 && (req.MaxTokens <= 0 || req.MaxTokens > profile.MaxTokens) {
		req.MaxTokens = profile.MaxTokens
	}
}

// newLLMLog initializes a new LLMLog model from the specified call data.
func (app *BaseApp) newLLMLog(
	providerName string,
	profile *LLMProfile,
	defaultModel string,
	req *llm.Request,
	isStream bool,
	info *LLMCallInfo,
) *LLMLog {
	log := &LLMLog{}
	log.Id = GenerateDefaultRandomId()
	log.Created = types.NowDateTime()
	log.Provider = providerName
	log.Stream = isStream
	log.Model = defaultModel
	if req != nil && req.Model != "" {
		log.Model = req.Model
	}

	storeContent := app.Settings().LLM.Logs.StoreContent

	if profile != nil {
		log.Profile = profile.Name
		if profile.StoreContent != nil {
			storeContent = *profile.StoreContent
		}
	}

	if info != nil {
		log.IP = info.IP
		if info.Auth != nil {
			log.AuthCollection = info.Auth.Collection().Id
			log.AuthRecord = info.Auth.Id
		}
		if len(info.Meta) > 0 {
			log.Meta = types.JSONMap[any](info.Meta)
		}
	}

	if storeContent && req != nil {
		log.Request = marshalLLMLogContent(req)
	}

	return log
}

// marshalLLMLogContent serializes the provided LLM content for storage
// (if the serialized content is too large it is replaced with a truncated marker).
func marshalLLMLogContent(v any) types.JSONRaw {
	raw, err := json.Marshal(v)
	if err != nil {
		return types.JSONRaw(`{"` + llmLogContentTruncated + `":true,"error":"failed to serialize the content"}`)
	}

	if len(raw) > maxLLMLogContentSize {
		return types.JSONRaw(fmt.Sprintf(`{"%s":true,"size":%d}`, llmLogContentTruncated, len(raw)))
	}

	return raw
}

func (app *BaseApp) registerLLMHooks() {
	// persist all queued logs before clearing the application bootstrap state
	app.OnBootstrapClear().Bind(&hook.Handler[*BootstrapEvent]{
		Id: "__pbLLMLogsFlushBeforeStop__",
		Func: func(e *BootstrapEvent) error {
			// extra precaution in case the hook was manually triggered while inside aux db transaction
			if _, isTx := e.App.AuxNonconcurrentDB().(*dbx.Tx); isTx {
				routine.FireAndForget(app.FlushLLMLogs)
			} else {
				app.FlushLLMLogs()
			}

			return e.Next()
		},
		Priority: bootstrapClearPriorityLLMLogs,
	})

	// cleanup old logs
	app.Cron().Add("__pbLLMLogsCleanup__", "10 */6 * * *", func() {
		maxDays := app.Settings().LLM.Logs.MaxDays

		err := app.DeleteOldLLMLogs(time.Now().AddDate(0, 0, -1*maxDays))
		if err != nil {
			app.Logger().Warn("Failed to delete old LLM logs", "error", err)
		}
	})
}
