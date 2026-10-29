package core

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"regexp"
	"slices"
	"strconv"

	"github.com/lumm2509/pocketbomb/tools/llm"
	validation "github.com/pocketbase/ozzo-validation/v4"
	"github.com/pocketbase/ozzo-validation/v4/is"
)

// LLM profile quota windows.
const (
	LLMQuotaWindowMinute = "minute"
	LLMQuotaWindowHour   = "hour"
	LLMQuotaWindowDay    = "day"
)

// LLM provider config sources.
const (
	LLMProviderSourceSettings = "settings"
	LLMProviderSourceEnv      = "env"
)

var llmNameRegex = regexp.MustCompile(`^[\w\-]+$`)

// LLMConfig defines the app LLM settings
// (providers, gateway profiles and usage logs).
type LLMConfig struct {
	// @todo similar to SMTPConfig.hidePassword - consider normalizing with the other Settings sensitive fields
	//
	// hideSecrets specifies whether to hide the providers api keys from the struct JSON serialization
	// (and to include the env providers).
	hideSecrets bool

	// DefaultProvider is the name of the provider used when no explicit
	// provider or profile is specified in [App.NewLLMClient].
	//
	// If empty, fallbacks to the PB_LLM_DEFAULT_PROVIDER env variable
	// and then to the first enabled provider.
	DefaultProvider string `form:"defaultProvider" json:"defaultProvider"`

	// Providers is a list with the configured LLM providers.
	//
	// Settings providers take precedence over the env variables ones
	// with the same name (e.g. to disable an env provider you can register
	// a disabled settings provider with the same name).
	Providers []LLMProviderConfig `form:"providers" json:"providers"`

	// Profiles is a list with named gateway profiles
	// (exposed via the "/api/llm/{profile}/chat" endpoint).
	Profiles []LLMProfile `form:"profiles" json:"profiles"`

	// Logs specifies the LLM usage logs options.
	Logs LLMLogsConfig `form:"logs" json:"logs"`
}

// FindProvider returns the settings provider with the specified name (if any).
func (c LLMConfig) FindProvider(name string) (LLMProviderConfig, bool) {
	for _, p := range c.Providers {
		if p.Name == name {
			return p, true
		}
	}

	return LLMProviderConfig{}, false
}

// FindProfile returns the profile with the specified name (if any).
func (c LLMConfig) FindProfile(name string) (LLMProfile, bool) {
	for _, p := range c.Profiles {
		if p.Name == name {
			return p, true
		}
	}

	return LLMProfile{}, false
}

// Validate makes LLMConfig validatable by implementing [validation.Validatable] interface.
//
// Note that the profiles rule syntax is validated separately
// in [Settings.PostValidate] since it requires an app instance.
func (c LLMConfig) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.DefaultProvider, validation.By(c.checkProviderRef)),
		validation.Field(&c.Providers, validation.By(func(any) error {
			return checkUniqueLLMNames(func(i int) string { return c.Providers[i].Name }, len(c.Providers))
		})),
		validation.Field(&c.Profiles, validation.By(func(any) error {
			return checkUniqueLLMNames(func(i int) string { return c.Profiles[i].Name }, len(c.Profiles))
		}), validation.By(c.checkProfiles)),
		validation.Field(&c.Logs),
	)
}

// checkProviderRef checks whether the value is an existing settings or env provider name.
func (c LLMConfig) checkProviderRef(value any) error {
	v, _ := value.(string)
	if v == "" {
		return nil
	}

	if _, ok := c.FindProvider(v); ok {
		return nil
	}

	for _, p := range llmEnvProviders() {
		if p.Name == v {
			return nil
		}
	}

	return validation.NewError("validation_invalid_llm_provider", "Missing or invalid LLM provider.")
}

func (c LLMConfig) checkProfiles(value any) error {
	profiles, _ := value.([]LLMProfile)

	errs := validation.Errors{}

	for i, p := range profiles {
		pErrs := validation.Errors{}

		if err := c.checkProviderRef(p.Provider); err != nil {
			pErrs["provider"] = err
		}

		if p.Quotas.IsEnabled() && (!c.Logs.Enabled || c.Logs.MaxDays < 1) {
			pErrs["quotas"] = validation.NewError(
				"validation_llm_quotas_require_logs",
				"The profile quotas require the LLM logs to be enabled (with at least 1 max days retention).",
			)
		}

		if len(pErrs) > 0 {
			errs[strconv.Itoa(i)] = pErrs
		}
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}

func checkUniqueLLMNames(nameAt func(i int) string, total int) error {
	existing := make(map[string]struct{}, total)
	errs := validation.Errors{}

	for i := 0; i < total; i++ {
		name := nameAt(i)
		if _, ok := existing[name]; ok {
			errs[strconv.Itoa(i)] = validation.Errors{
				"name": validation.NewError("validation_duplicated_name", "The name must be unique.").
					SetParams(map[string]any{"name": name}),
			}
			continue
		}
		existing[name] = struct{}{}
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}

// MarshalJSON implements the [json.Marshaler] interface.
func (c LLMConfig) MarshalJSON() ([]byte, error) {
	type alias LLMConfig

	if !c.hideSecrets {
		return json.Marshal(alias(c))
	}

	type hiddenProvider struct {
		LLMProviderConfig
		APIKey    string `json:"apiKey,omitempty"`
		HasAPIKey bool   `json:"hasApiKey"`
	}

	type envProvider struct {
		LLMProviderConfig
		APIKey    string `json:"apiKey,omitempty"`
		HasAPIKey bool   `json:"hasApiKey"`
		Source    string `json:"source"`
	}

	providers := make([]hiddenProvider, len(c.Providers))
	for i, p := range c.Providers {
		providers[i] = hiddenProvider{LLMProviderConfig: p, HasAPIKey: p.APIKey != ""}
	}

	envProviders := []envProvider{}
	for _, p := range llmEnvProviders() {
		envProviders = append(envProviders, envProvider{
			LLMProviderConfig: p,
			HasAPIKey:         p.APIKey != "",
			Source:            LLMProviderSourceEnv,
		})
	}

	v := struct {
		alias
		Providers    []hiddenProvider `json:"providers"`
		EnvProviders []envProvider    `json:"envProviders"`
	}{alias(c), providers, envProviders}

	return json.Marshal(v)
}

// UnmarshalJSON implements the [json.Unmarshaler] interface.
//
// Providers without an explicit "apiKey" key preserve the previously
// loaded api key of the provider with the same name (if any) so that
// the masked settings could be safely submitted back without the secrets.
func (c *LLMConfig) UnmarshalJSON(data []byte) error {
	type alias LLMConfig

	raw := map[string]jsontext.Value{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	oldKeys := make(map[string]string, len(c.Providers))
	for _, p := range c.Providers {
		oldKeys[p.Name] = p.APIKey
	}

	// replace the old slices (if submitted) instead of merging them by index
	if _, ok := raw["providers"]; ok {
		c.Providers = nil
	}
	if _, ok := raw["profiles"]; ok {
		c.Profiles = nil
	}

	if err := json.Unmarshal(data, (*alias)(c)); err != nil {
		return err
	}

	if rawProviders, ok := raw["providers"]; ok {
		var keys []struct {
			APIKey *string `json:"apiKey"`
		}
		if err := json.Unmarshal(rawProviders, &keys); err != nil {
			return err
		}

		for i := range c.Providers {
			if i < len(keys) && keys[i].APIKey == nil {
				c.Providers[i].APIKey = oldKeys[c.Providers[i].Name]
			}
		}
	}

	return nil
}

// -------------------------------------------------------------------

// LLMProviderConfig defines a single LLM provider configuration.
type LLMProviderConfig struct {
	// Name is the unique provider identifier (e.g. "openai", "local-ollama").
	Name string `form:"name" json:"name"`

	// Provider is the registered tools/llm provider driver
	// (openai, openai-compatible, xai, ollama, anthropic, gemini, etc.).
	Provider string `form:"provider" json:"provider"`

	// BaseURL is an optional provider API base url
	// (required for "openai-compatible").
	BaseURL string `form:"baseURL" json:"baseURL"`

	// APIKey is the provider API key (it is never returned in the API responses).
	APIKey string `form:"apiKey" json:"apiKey"`

	// DefaultModel is the model used when neither the request nor the profile specify one.
	DefaultModel string `form:"defaultModel" json:"defaultModel"`

	// Models is an optional list with the provider models
	// (used only as hint/autocomplete in the dashboard).
	Models []string `form:"models" json:"models"`

	// Timeout is an optional per request timeout in seconds
	// (for streams it is applied only until the response headers are received).
	Timeout int `form:"timeout" json:"timeout"`

	// Enabled specifies whether the provider is active.
	Enabled bool `form:"enabled" json:"enabled"`
}

// Validate makes LLMProviderConfig validatable by implementing [validation.Validatable] interface.
func (c LLMProviderConfig) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.Name, validation.Required, validation.Length(1, 100), validation.Match(llmNameRegex)),
		validation.Field(&c.Provider, validation.Required, validation.By(checkLLMProviderDriver)),
		validation.Field(
			&c.BaseURL,
			validation.When(c.Provider == llm.ProviderOpenAICompatible, validation.Required),
			is.URL,
		),
		validation.Field(&c.DefaultModel, validation.Length(0, 255)),
		validation.Field(&c.Models, validation.Each(validation.Required, validation.Length(1, 255))),
		validation.Field(&c.Timeout, validation.Min(0)),
	)
}

func checkLLMProviderDriver(value any) error {
	v, _ := value.(string)
	if v == "" {
		return nil
	}

	if !slices.Contains(llm.Providers(), v) {
		return validation.NewError("validation_invalid_llm_provider_driver", "Unknown LLM provider driver.").
			SetParams(map[string]any{"supported": llm.Providers()})
	}

	return nil
}

// -------------------------------------------------------------------

// LLMProfile defines a named LLM gateway profile (aka. route)
// with its own access rule, defaults, limits and quotas.
type LLMProfile struct {
	// Name is the unique profile identifier used in the "/api/llm/{profile}/chat" endpoint.
	Name string `form:"name" json:"name"`

	// Provider is the name of the profile provider
	// (if empty - fallbacks to the default one).
	Provider string `form:"provider" json:"provider"`

	// Model is the default profile model
	// (if empty - fallbacks to the provider default model).
	Model string `form:"model" json:"model"`

	// AllowedModels is an optional list with the models that the
	// clients are allowed to request (in addition to Model).
	//
	// If empty and AllowClientOverrides is enabled, any model is allowed.
	AllowedModels []string `form:"allowedModels" json:"allowedModels"`

	// SystemPrompt is an optional system prompt that is always
	// prepended to the request system instructions.
	SystemPrompt string `form:"systemPrompt" json:"systemPrompt"`

	// MaxTokens is an optional max output tokens cap (0 means no cap).
	MaxTokens int `form:"maxTokens" json:"maxTokens"`

	// Temperature is the optional default request temperature.
	Temperature *float64 `form:"temperature" json:"temperature"`

	// AllowClientOverrides specifies whether the API clients are allowed to
	// change the model, temperature, max tokens (still capped) and tools.
	AllowClientOverrides bool `form:"allowClientOverrides" json:"allowClientOverrides"`

	// Rule is the profile access rule with the same semantics as the collection API rules:
	//  - nil: only superusers can access the profile
	//  - "":  everyone can access the profile
	//  - "...": only requests satisfying the "@request.*" (or "@collection.*") filter expression
	Rule *string `form:"rule" json:"rule"`

	// Quotas specifies optional per user and per guest IP usage quotas.
	Quotas LLMProfileQuotas `form:"quotas" json:"quotas"`

	// StoreContent overrides the [LLMLogsConfig.StoreContent] option for the current profile.
	StoreContent *bool `form:"storeContent" json:"storeContent"`
}

// Validate makes LLMProfile validatable by implementing [validation.Validatable] interface.
func (p LLMProfile) Validate() error {
	return validation.ValidateStruct(&p,
		validation.Field(&p.Name, validation.Required, validation.Length(1, 100), validation.Match(llmNameRegex)),
		validation.Field(&p.Model, validation.Length(0, 255)),
		validation.Field(&p.AllowedModels, validation.Each(validation.Required, validation.Length(1, 255))),
		validation.Field(&p.MaxTokens, validation.Min(0)),
		validation.Field(&p.Temperature, validation.Min(0.0), validation.Max(2.0)),
		validation.Field(&p.Quotas),
	)
}

// IsModelAllowed reports whether the specified request model is allowed for the profile.
//
// An empty model (aka. the profile/provider default one) is always allowed.
func (p LLMProfile) IsModelAllowed(model string) bool {
	if model == "" || model == p.Model {
		return true
	}

	if len(p.AllowedModels) == 0 {
		return p.AllowClientOverrides
	}

	return slices.Contains(p.AllowedModels, model)
}

// LLMProfileQuotas defines the LLM profile quotas.
type LLMProfileQuotas struct {
	// PerUser is applied to the authenticated non-superuser requests.
	PerUser LLMQuota `form:"perUser" json:"perUser"`

	// PerGuestIP is applied to the guest requests (grouped by the client IP).
	PerGuestIP LLMQuota `form:"perGuestIP" json:"perGuestIP"`
}

// IsEnabled reports whether at least one of the quotas is enabled.
func (q LLMProfileQuotas) IsEnabled() bool {
	return q.PerUser.IsEnabled() || q.PerGuestIP.IsEnabled()
}

// Validate makes LLMProfileQuotas validatable by implementing [validation.Validatable] interface.
func (q LLMProfileQuotas) Validate() error {
	return validation.ValidateStruct(&q,
		validation.Field(&q.PerUser),
		validation.Field(&q.PerGuestIP),
	)
}

// LLMQuota defines a single sliding window LLM usage quota.
type LLMQuota struct {
	// Requests is the max allowed number of requests in the Window (0 means no limit).
	Requests int `form:"requests" json:"requests"`

	// Tokens is the max allowed input+output tokens in the Window (0 means no limit).
	Tokens int `form:"tokens" json:"tokens"`

	// Window is the quota sliding window (minute, hour, day).
	Window string `form:"window" json:"window"`
}

// IsEnabled reports whether the quota has at least one limit.
func (q LLMQuota) IsEnabled() bool {
	return q.Requests > 0 || q.Tokens > 0
}

// Validate makes LLMQuota validatable by implementing [validation.Validatable] interface.
func (q LLMQuota) Validate() error {
	return validation.ValidateStruct(&q,
		validation.Field(&q.Requests, validation.Min(0)),
		validation.Field(&q.Tokens, validation.Min(0)),
		validation.Field(
			&q.Window,
			validation.When(q.IsEnabled(), validation.Required),
			validation.In(LLMQuotaWindowMinute, LLMQuotaWindowHour, LLMQuotaWindowDay),
		),
	)
}

// -------------------------------------------------------------------

// LLMLogsConfig defines the LLM usage logs options.
type LLMLogsConfig struct {
	// Enabled specifies whether to store the LLM calls in the auxiliary db _llmLogs table.
	//
	// Note that the profile quotas require the logs to be enabled.
	Enabled bool `form:"enabled" json:"enabled"`

	// StoreContent specifies whether to store also the requests and responses content
	// (messages, tools, etc.). Disabled by default for privacy reasons.
	StoreContent bool `form:"storeContent" json:"storeContent"`

	// MaxDays is the LLM logs retention period in days.
	MaxDays int `form:"maxDays" json:"maxDays"`
}

// Validate makes LLMLogsConfig validatable by implementing [validation.Validatable] interface.
func (c LLMLogsConfig) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.MaxDays, validation.When(c.Enabled, validation.Required), validation.Min(0)),
	)
}
