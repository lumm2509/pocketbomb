package jsvm

import (
	"testing"

	"github.com/dop251/goja"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/llm"
)

func TestAppNewLLMClientBind(t *testing.T) {
	for _, key := range []string{
		core.LLMEnvOpenAIAPIKey,
		core.LLMEnvAnthropicAPIKey,
		core.LLMEnvGeminiAPIKey,
		core.LLMEnvXAIAPIKey,
		core.LLMEnvOllamaHost,
	} {
		t.Setenv(key, "")
	}

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	server := tests.NewLLMFakeServer(t)

	app.Settings().LLM.Providers = []core.LLMProviderConfig{
		{Name: "fake", Provider: llm.ProviderOpenAICompatible, BaseURL: server.URL, DefaultModel: "m", Enabled: true},
	}

	vm := goja.New()
	BindCore(vm)
	vm.Set("$app", app)

	_, err := vm.RunString(`
		const providers = $app.llmProviders()
		if (providers.length != 1 || providers[0].name != "fake") {
			throw new Error("Unexpected providers: " + JSON.stringify(providers))
		}

		const client = $app.newLLMClient()
		try {
			const resp = client.generate(new Context(), {
				messages: [{ role: "user", parts: [{ type: "text", text: "hi" }] }],
			})

			if (resp.text() != "Hello from fake") {
				throw new Error("Unexpected response text: " + resp.text())
			}
		} finally {
			client.close()
		}
	`)
	if err != nil {
		t.Fatal(err)
	}

	reqs := server.Requests()
	if len(reqs) != 1 {
		t.Fatalf("Expected 1 fake server request, got %d", len(reqs))
	}
}
