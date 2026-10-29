package llm

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/lumm2509/pocketbomb/tools/llm/internal/anthropic"
	"github.com/lumm2509/pocketbomb/tools/llm/internal/gemini"
	"github.com/lumm2509/pocketbomb/tools/llm/internal/openai"
)

// Built-in provider names.
const (
	ProviderOpenAI           = "openai"
	ProviderOpenAICompatible = "openai-compatible"
	ProviderXAI              = "xai"
	ProviderGrok             = "grok" // alias of ProviderXAI
	ProviderOllama           = "ollama"
	ProviderAnthropic        = "anthropic"
	ProviderGemini           = "gemini"
)

// Default base urls of the OpenAI-compatible built-in aliases.
const (
	XAIBaseURL    = "https://api.x.ai/v1"
	OllamaBaseURL = "http://localhost:11434/v1"
)

// Factory defines a provider driver factory function.
type Factory func(config Config) (Driver, error)

var (
	factoriesMu sync.RWMutex
	factories   = map[string]Factory{}
)

func init() {
	Register(ProviderOpenAI, func(config Config) (Driver, error) {
		return openai.New(ProviderOpenAI, config)
	})

	Register(ProviderOpenAICompatible, func(config Config) (Driver, error) {
		if config.BaseURL == "" {
			return nil, errors.New("llm: openai-compatible provider requires BaseURL")
		}
		return openai.New(providerName(config, ProviderOpenAICompatible), config)
	})

	xai := openAICompatibleAlias(ProviderXAI, XAIBaseURL)
	Register(ProviderXAI, xai)
	Register(ProviderGrok, xai)

	Register(ProviderOllama, openAICompatibleAlias(ProviderOllama, OllamaBaseURL))

	Register(ProviderAnthropic, func(config Config) (Driver, error) {
		return anthropic.New(config)
	})

	Register(ProviderGemini, func(config Config) (Driver, error) {
		return gemini.New(config)
	})
}

// Register makes an LLM provider driver available by the provided name.
//
// Similar to database/sql.Register, it panics if called twice
// with the same name or if factory is nil.
func Register(name string, factory Factory) {
	factoriesMu.Lock()
	defer factoriesMu.Unlock()

	if factory == nil {
		panic("llm: Register factory is nil")
	}

	if _, exists := factories[name]; exists {
		panic("llm: Register called twice for provider " + name)
	}

	factories[name] = factory
}

// Providers returns a sorted list of the names of the registered providers.
func Providers() []string {
	factoriesMu.RLock()
	defer factoriesMu.RUnlock()

	names := make([]string, 0, len(factories))
	for name := range factories {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

// New initializes a new LLM client for the registered config.Provider driver.
//
// NB! Make sure to call `Close()` after you are done working with it.
func New(config Config) (*Client, error) {
	factoriesMu.RLock()
	factory, ok := factories[config.Provider]
	factoriesMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("llm: unknown provider %q (forgotten Register?)", config.Provider)
	}

	drv, err := factory(config)
	if err != nil {
		return nil, err
	}

	return NewWithDriver(drv), nil
}

// NewOpenAI initializes a new OpenAI Chat Completions LLM client.
//
// NB! Make sure to call `Close()` after you are done working with it.
func NewOpenAI(apiKey string, defaultModel string) (*Client, error) {
	return New(Config{Provider: ProviderOpenAI, APIKey: apiKey, DefaultModel: defaultModel})
}

// NewOpenAICompatible initializes a new LLM client for an OpenAI-compatible
// Chat Completions API (xAI, Ollama, vLLM, LM Studio, OpenRouter, etc.).
//
// NB! Make sure to call `Close()` after you are done working with it.
func NewOpenAICompatible(baseURL string, apiKey string, defaultModel string) (*Client, error) {
	return New(Config{Provider: ProviderOpenAICompatible, BaseURL: baseURL, APIKey: apiKey, DefaultModel: defaultModel})
}

// NewAnthropic initializes a new Anthropic Messages API LLM client.
//
// NB! Make sure to call `Close()` after you are done working with it.
func NewAnthropic(apiKey string, defaultModel string) (*Client, error) {
	return New(Config{Provider: ProviderAnthropic, APIKey: apiKey, DefaultModel: defaultModel})
}

// NewGemini initializes a new Google Gemini LLM client.
//
// NB! Make sure to call `Close()` after you are done working with it.
func NewGemini(apiKey string, defaultModel string) (*Client, error) {
	return New(Config{Provider: ProviderGemini, APIKey: apiKey, DefaultModel: defaultModel})
}

func openAICompatibleAlias(name string, defaultBaseURL string) Factory {
	return func(config Config) (Driver, error) {
		if config.BaseURL == "" {
			config.BaseURL = defaultBaseURL
		}
		return openai.New(providerName(config, name), config)
	}
}

func providerName(config Config, fallback string) string {
	if config.Provider != "" {
		return config.Provider
	}
	return fallback
}
