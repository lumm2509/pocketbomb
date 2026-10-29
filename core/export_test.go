package core

import "github.com/lumm2509/pocketbomb/tools/webhooks"

// Dispatcher returns the underlying webhooks dispatcher (tests only).
func (w *Webhooks) Dispatcher() *webhooks.Dispatcher {
	return w.dispatcher
}

// Unexported helpers exposed for the core_test package.
var (
	ApplicationManifestFromJSON    = applicationManifestFromJSON
	NormalizeWebhookTopic          = normalizeWebhookTopic
	IsDashboardRedirectURI         = isDashboardRedirectURI
	SendSystemAlertToAllSuperusers = sendSystemAlertToAllSuperusers
)

// SetTestLLMEnvLookup replaces the LLM env variables lookup with
// the provided static values and returns a restore function.
//
// NB! It must be used only in non-parallel tests.
func SetTestLLMEnvLookup(values map[string]string) func() {
	old := llmEnvLookup

	llmEnvLookup = func(key string) string {
		return values[key]
	}

	return func() {
		llmEnvLookup = old
	}
}
