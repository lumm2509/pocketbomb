package core_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/llm"
	"github.com/lumm2509/pocketbomb/tools/types"
	"github.com/pocketbase/dbx"
)

func TestNewLLMClientNotConfigured(t *testing.T) {
	restore := core.SetTestLLMEnvLookup(nil)
	defer restore()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	if providers := app.LLMProviders(); len(providers) != 0 {
		t.Fatalf("Expected no providers, got %v", providers)
	}

	for _, name := range []string{"", "missing"} {
		client, err := app.NewLLMClient(name)
		if !errors.Is(err, core.ErrLLMNotConfigured) {
			t.Fatalf("[%q] Expected ErrLLMNotConfigured, got %v", name, err)
		}
		if client != nil {
			t.Fatalf("[%q] Expected nil client", name)
		}
	}

	// disabled settings provider
	app.Settings().LLM.Providers = []core.LLMProviderConfig{{Name: "test", Provider: llm.ProviderOpenAI, APIKey: "abc"}}
	if _, err := app.NewLLMClient(); !errors.Is(err, core.ErrLLMNotConfigured) {
		t.Fatalf("Expected ErrLLMNotConfigured for disabled provider, got %v", err)
	}
}

func TestLLMProvidersResolution(t *testing.T) {
	restore := core.SetTestLLMEnvLookup(map[string]string{
		core.LLMEnvOpenAIAPIKey:    "env_openai",
		core.LLMEnvAnthropicAPIKey: "env_anthropic",
		core.LLMEnvGeminiAPIKey:    "env_gemini",
		core.LLMEnvXAIAPIKey:       "env_xai",
		core.LLMEnvOllamaHost:      "127.0.0.1:11434",
		core.LLMEnvDefaultProvider: "gemini",
		core.LLMEnvDefaultModel:    "gemini-test",
	})
	defer restore()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	app.Settings().LLM.Providers = []core.LLMProviderConfig{
		{Name: "custom", Provider: llm.ProviderOpenAICompatible, BaseURL: "http://example.com", APIKey: "custom_key", DefaultModel: "m1", Enabled: true},
		{Name: "anthropic", Provider: llm.ProviderAnthropic, APIKey: "settings_key", Enabled: false}, // shadows the env one
	}

	names := func() []string {
		result := []string{}
		for _, p := range app.LLMProviders() {
			result = append(result, p.Name+":"+p.Source)
		}
		return result
	}

	// env default provider
	expected := []string{"gemini:env", "custom:settings", "openai:env", "xai:env", "ollama:env"}
	if v := names(); !slices.Equal(v, expected) {
		t.Fatalf("Expected providers\n%v\ngot\n%v", expected, v)
	}

	providers := app.LLMProviders()
	if !providers[0].IsDefault || providers[0].DefaultModel != "gemini-test" {
		t.Fatalf("Expected gemini to be the default provider with the env default model, got %#v", providers[0])
	}
	if providers[4].BaseURL != "http://127.0.0.1:11434/v1" {
		t.Fatalf("Expected normalized ollama base url, got %q", providers[4].BaseURL)
	}

	// settings default provider has precedence
	app.Settings().LLM.DefaultProvider = "custom"
	expected = []string{"custom:settings", "openai:env", "gemini:env", "xai:env", "ollama:env"}
	if v := names(); !slices.Equal(v, expected) {
		t.Fatalf("Expected providers\n%v\ngot\n%v", expected, v)
	}

	// no secrets
	raw, err := json.Marshal(app.LLMProviders())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"env_openai", "env_gemini", "custom_key", "settings_key"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("Didn't expect secret %q in\n%s", secret, raw)
		}
	}

	// the masked settings JSON should list the env providers too
	rawSettings, err := json.Marshal(app.Settings())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"env_openai", "custom_key", "settings_key"} {
		if strings.Contains(string(rawSettings), secret) {
			t.Fatalf("Didn't expect secret %q in\n%s", secret, rawSettings)
		}
	}
	for _, part := range []string{`"envProviders":[{"name":"openai"`, `"hasApiKey":true`, `"source":"env"`} {
		if !strings.Contains(string(rawSettings), part) {
			t.Fatalf("Expected %q in\n%s", part, rawSettings)
		}
	}
}

func newLLMTestApp(t *testing.T, server *tests.LLMFakeServer) *tests.TestApp {
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}

	temperature := 0.3
	storeContent := true

	app.Settings().LLM = core.LLMConfig{
		Providers: []core.LLMProviderConfig{
			{Name: "fake", Provider: llm.ProviderOpenAICompatible, BaseURL: server.URL, APIKey: "fake_key", DefaultModel: "provider-model", Enabled: true},
		},
		Profiles: []core.LLMProfile{
			{
				Name:          "support",
				Provider:      "fake",
				Model:         "profile-model",
				AllowedModels: []string{"allowed-model"},
				SystemPrompt:  "You are a support bot.",
				MaxTokens:     100,
				Temperature:   &temperature,
				StoreContent:  &storeContent,
			},
		},
		Logs: core.LLMLogsConfig{Enabled: true, MaxDays: 7},
	}

	return app
}

func TestNewLLMClientWithProfile(t *testing.T) {
	restore := core.SetTestLLMEnvLookup(nil)
	defer restore()

	server := tests.NewLLMFakeServer(t)

	app := newLLMTestApp(t, server)
	defer app.Cleanup()

	user, err := app.FindAuthRecordByEmail("users", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	var requestCalls, responseCalls, otherTagCalls int

	app.OnLLMRequest("support").BindFunc(func(e *core.LLMRequestEvent) error {
		requestCalls++
		if requestCalls > 1 {
			return e.Next() // the "not allowed" model call
		}

		if e.Profile != "support" || e.ProviderName != "fake" {
			t.Errorf("Unexpected request event profile/provider: %q/%q", e.Profile, e.ProviderName)
		}
		if e.CallInfo == nil || e.CallInfo.Auth == nil || e.CallInfo.Auth.Id != user.Id {
			t.Errorf("Expected the call info auth record, got %#v", e.CallInfo)
		}
		if e.Request.System != "You are a support bot.\n\nBe nice." {
			t.Errorf("Unexpected system prompt %q", e.Request.System)
		}
		if e.Request.MaxTokens != 100 {
			t.Errorf("Expected max tokens to be capped to 100, got %d", e.Request.MaxTokens)
		}
		if e.Request.Temperature == nil || *e.Request.Temperature != 0.3 {
			t.Errorf("Expected the profile default temperature, got %v", e.Request.Temperature)
		}
		if e.Request.Model != "profile-model" {
			t.Errorf("Expected the profile model, got %q", e.Request.Model)
		}

		e.CallInfo.Meta = map[string]any{"hook": "request"}

		return e.Next()
	})

	app.OnLLMRequest("other").BindFunc(func(e *core.LLMRequestEvent) error {
		otherTagCalls++
		return e.Next()
	})

	app.OnLLMResponse().BindFunc(func(e *core.LLMResponseEvent) error {
		responseCalls++
		if e.Response == nil || e.Response.Text() != "Hello from fake" {
			t.Errorf("Unexpected response %#v", e.Response)
		}
		return e.Next()
	})

	client, err := app.NewLLMClient("support")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx := core.WithLLMCallInfo(context.Background(), &core.LLMCallInfo{Auth: user, IP: "1.2.3.4"})

	resp, err := client.Generate(ctx, &llm.Request{
		System:    "Be nice.",
		MaxTokens: 500,
		Messages:  []llm.Message{llm.UserText("hi")},
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Text() != "Hello from fake" {
		t.Fatalf("Unexpected response text %q", resp.Text())
	}

	if requestCalls != 1 || responseCalls != 1 || otherTagCalls != 0 {
		t.Fatalf("Expected 1 request, 1 response and 0 other hook calls, got %d, %d, %d", requestCalls, responseCalls, otherTagCalls)
	}

	reqs := server.Requests()
	if len(reqs) != 1 {
		t.Fatalf("Expected 1 server request, got %d", len(reqs))
	}
	if reqs[0].Header.Get("Authorization") != "Bearer fake_key" {
		t.Fatalf("Expected the provider api key, got %q", reqs[0].Header.Get("Authorization"))
	}

	// not allowed model
	_, err = client.Generate(ctx, &llm.Request{Model: "unknown", Messages: []llm.Message{llm.UserText("hi")}})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("Expected not allowed model error, got %v", err)
	}
	if len(server.Requests()) != 1 {
		t.Fatal("Expected the not allowed model request to not reach the provider")
	}

	app.FlushLLMLogs()

	logs := []*core.LLMLog{}
	if err := app.LLMLogQuery().OrderBy("status DESC").All(&logs); err != nil {
		t.Fatal(err)
	}

	if len(logs) != 2 {
		t.Fatalf("Expected 2 logs, got %d", len(logs))
	}

	success := logs[0]
	if success.Status != core.LLMLogStatusSuccess ||
		success.Profile != "support" ||
		success.Provider != "fake" ||
		success.Model != "fake-model" ||
		success.InputTokens != 11 ||
		success.OutputTokens != 7 ||
		success.AuthRecord != user.Id ||
		success.AuthCollection != user.Collection().Id ||
		success.IP != "1.2.3.4" ||
		success.Meta["hook"] != "request" {
		t.Fatalf("Unexpected success log %#v", success)
	}
	if !strings.Contains(success.Request.String(), "You are a support bot.") || !strings.Contains(success.Response.String(), "Hello from fake") {
		t.Fatalf("Expected stored content, got\n%s\n%s", success.Request, success.Response)
	}

	denied := logs[1]
	if denied.Status != core.LLMLogStatusDenied || denied.Model != "unknown" || !strings.Contains(denied.Error, "not allowed") {
		t.Fatalf("Unexpected denied log %#v", denied)
	}
}

func TestNewLLMClientStreamAndErrors(t *testing.T) {
	restore := core.SetTestLLMEnvLookup(nil)
	defer restore()

	server := tests.NewLLMFakeServer(t)

	app := newLLMTestApp(t, server)
	defer app.Cleanup()

	// provider name (default model + no content storage)
	client, err := app.NewLLMClient("fake")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	s, err := client.Stream(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := llm.Accumulate(s)
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text() != "Hello" {
		t.Fatalf("Unexpected stream text %q", resp.Text())
	}

	// provider error
	server.Status = 500
	server.Body = `{"error":{"message":"overloaded","type":"server_error"}}`

	_, err = client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
	if err == nil {
		t.Fatal("Expected provider error")
	}

	// hook abort
	app.OnLLMRequest().BindFunc(func(e *core.LLMRequestEvent) error {
		return errors.New("aborted by hook")
	})
	_, err = client.Generate(context.Background(), &llm.Request{Messages: []llm.Message{llm.UserText("hi")}})
	if err == nil || err.Error() != "aborted by hook" {
		t.Fatalf("Expected hook error, got %v", err)
	}

	app.FlushLLMLogs()

	logs := []*core.LLMLog{}
	if err := app.LLMLogQuery().OrderBy("rowid ASC").All(&logs); err != nil {
		t.Fatal(err)
	}

	if len(logs) != 3 {
		t.Fatalf("Expected 3 logs, got %d", len(logs))
	}

	if logs[0].Status != core.LLMLogStatusSuccess || !logs[0].Stream || logs[0].InputTokens != 5 || logs[0].OutputTokens != 2 || logs[0].Profile != "" || len(logs[0].Request) != 0 {
		t.Fatalf("Unexpected stream log %#v", logs[0])
	}

	if logs[1].Status != core.LLMLogStatusError || !strings.Contains(logs[1].Error, "overloaded") || logs[1].Model != "provider-model" {
		t.Fatalf("Unexpected error log %#v", logs[1])
	}

	if logs[2].Status != core.LLMLogStatusDenied || logs[2].Error != "aborted by hook" {
		t.Fatalf("Unexpected denied log %#v", logs[2])
	}
}

func TestWriteLLMLogDisabled(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	app.Settings().LLM.Logs.Enabled = false

	app.WriteLLMLog(&core.LLMLog{Status: core.LLMLogStatusSuccess})
	app.FlushLLMLogs()

	total, err := countLLMLogs(app)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Fatalf("Expected no logs, got %d", total)
	}
}

func countLLMLogs(app core.App) (int, error) {
	var total int
	err := app.LLMLogQuery().Select("count(*)").Row(&total)
	return total, err
}

func TestLLMUsage(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	now := time.Now()

	newLog := func(id string, status string, authRecord string, ip string, created time.Time, tokens int) *core.LLMLog {
		l := &core.LLMLog{}
		l.Id = id
		l.Profile = "p"
		l.Status = status
		l.AuthCollection = "_pb_users_auth_"
		if authRecord == "" {
			l.AuthCollection = ""
		}
		l.AuthRecord = authRecord
		l.IP = ip
		l.InputTokens = tokens
		l.OutputTokens = tokens
		l.Created, _ = types.ParseDateTime(created)
		return l
	}

	// persisted
	app.WriteLLMLog(newLog("u1", core.LLMLogStatusSuccess, "user1", "1.1.1.1", now.Add(-30*time.Minute), 10))
	app.WriteLLMLog(newLog("u2", core.LLMLogStatusError, "user1", "1.1.1.1", now.Add(-10*time.Minute), 0))
	app.WriteLLMLog(newLog("u3", core.LLMLogStatusDenied, "user1", "1.1.1.1", now.Add(-5*time.Minute), 0))
	app.WriteLLMLog(newLog("u4", core.LLMLogStatusSuccess, "user1", "1.1.1.1", now.Add(-2*time.Hour), 100)) // outside of the window
	app.WriteLLMLog(newLog("g1", core.LLMLogStatusSuccess, "", "1.1.1.1", now.Add(-time.Minute), 3))
	app.FlushLLMLogs()

	// queued
	app.WriteLLMLog(newLog("u5", core.LLMLogStatusSuccess, "user1", "2.2.2.2", now, 1))
	app.WriteLLMLog(newLog("g2", core.LLMLogStatusSuccess, "", "1.1.1.1", now, 2))

	scenarios := []struct {
		name             string
		filter           core.LLMUsageFilter
		expectedRequests int
		expectedTokens   int
	}{
		{
			"user",
			core.LLMUsageFilter{Profile: "p", AuthCollection: "_pb_users_auth_", AuthRecord: "user1", Since: now.Add(-time.Hour)},
			3, // u1, u2, u5
			22,
		},
		{
			"guest ip",
			core.LLMUsageFilter{Profile: "p", IP: "1.1.1.1", Since: now.Add(-time.Hour)},
			2, // g1, g2
			10,
		},
		{
			"different profile",
			core.LLMUsageFilter{Profile: "other", IP: "1.1.1.1", Since: now.Add(-time.Hour)},
			0,
			0,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			usage, err := app.LLMUsage(s.filter)
			if err != nil {
				t.Fatal(err)
			}

			if usage.Requests != s.expectedRequests {
				t.Fatalf("Expected %d requests, got %d", s.expectedRequests, usage.Requests)
			}

			if usage.TotalTokens() != s.expectedTokens {
				t.Fatalf("Expected %d tokens, got %d", s.expectedTokens, usage.TotalTokens())
			}

			if s.expectedRequests > 0 && usage.Oldest.IsZero() {
				t.Fatal("Expected non-zero oldest date")
			}
		})
	}

	// the queued logs shouldn't be counted twice after flush
	app.FlushLLMLogs()
	usage, err := app.LLMUsage(scenarios[0].filter)
	if err != nil {
		t.Fatal(err)
	}
	if usage.Requests != 3 {
		t.Fatalf("Expected 3 requests after flush, got %d", usage.Requests)
	}
}

func TestLLMLogsStats(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	if err := tests.StubLLMLogsData(app); err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name     string
		params   core.LLMLogsStatsParams
		expected string
	}{
		{
			"hour interval",
			core.LLMLogsStatsParams{},
			`[{"date":"2022-05-01 10:00:00.000Z","group":"","requests":2,"errors":0,"denied":0,"inputTokens":15,"outputTokens":25,"avgDurationMs":200,"p50DurationMs":100,"p95DurationMs":300},{"date":"2022-05-01 11:00:00.000Z","group":"","requests":1,"errors":1,"denied":0,"inputTokens":0,"outputTokens":0,"avgDurationMs":50,"p50DurationMs":50,"p95DurationMs":50},{"date":"2022-05-02 10:00:00.000Z","group":"","requests":1,"errors":0,"denied":1,"inputTokens":0,"outputTokens":0,"avgDurationMs":0,"p50DurationMs":0,"p95DurationMs":0}]`,
		},
		{
			"day interval grouped by model with filter",
			core.LLMLogsStatsParams{
				Interval: core.LLMLogsStatsIntervalDay,
				GroupBy:  core.LLMLogsStatsGroupByModel,
				Filter:   dbx.NewExp("[[profile]] = {:p}", dbx.Params{"p": "support"}),
			},
			`[{"date":"2022-05-01 00:00:00.000Z","group":"gpt-a","requests":2,"errors":0,"denied":0,"inputTokens":15,"outputTokens":25,"avgDurationMs":200,"p50DurationMs":100,"p95DurationMs":300},{"date":"2022-05-01 00:00:00.000Z","group":"gpt-b","requests":1,"errors":1,"denied":0,"inputTokens":0,"outputTokens":0,"avgDurationMs":50,"p50DurationMs":50,"p95DurationMs":50}]`,
		},
		{
			"grouped by user",
			core.LLMLogsStatsParams{Interval: core.LLMLogsStatsIntervalDay, GroupBy: core.LLMLogsStatsGroupByUser},
			`[{"date":"2022-05-01 00:00:00.000Z","group":"","requests":1,"errors":1,"denied":0,"inputTokens":0,"outputTokens":0,"avgDurationMs":50,"p50DurationMs":50,"p95DurationMs":50},{"date":"2022-05-01 00:00:00.000Z","group":"_pb_users_auth_/4q1xlclmfloku33","requests":2,"errors":0,"denied":0,"inputTokens":15,"outputTokens":25,"avgDurationMs":200,"p50DurationMs":100,"p95DurationMs":300},{"date":"2022-05-02 00:00:00.000Z","group":"","requests":1,"errors":0,"denied":1,"inputTokens":0,"outputTokens":0,"avgDurationMs":0,"p50DurationMs":0,"p95DurationMs":0}]`,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			result, err := app.LLMLogsStats(s.params)
			if err != nil {
				t.Fatal(err)
			}

			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}

			if string(raw) != s.expected {
				t.Fatalf("Expected\n%s\ngot\n%s", s.expected, raw)
			}
		})
	}
}

func TestLLMLogsTopUsers(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	if err := tests.StubLLMLogsData(app); err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name     string
		params   core.LLMLogsTopUsersParams
		expected string
	}{
		{
			"by user",
			core.LLMLogsTopUsersParams{},
			`[{"authCollection":"_pb_users_auth_","authRecord":"4q1xlclmfloku33","ip":"1.1.1.1","requests":2,"errors":0,"denied":0,"inputTokens":15,"outputTokens":25,"totalTokens":40,"lastCall":"2022-05-01 10:30:00.000Z"}]`,
		},
		{
			"by ip sorted by requests",
			core.LLMLogsTopUsersParams{By: core.LLMLogsTopUsersByIP, Sort: core.LLMLogsTopUsersSortRequests},
			`[{"authCollection":"","authRecord":"","ip":"2.2.2.2","requests":2,"errors":1,"denied":1,"inputTokens":0,"outputTokens":0,"totalTokens":0,"lastCall":"2022-05-02 10:00:00.000Z"}]`,
		},
		{
			"with filter",
			core.LLMLogsTopUsersParams{Filter: dbx.HashExp{"profile": "missing"}},
			`[]`,
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			result, err := app.LLMLogsTopUsers(s.params)
			if err != nil {
				t.Fatal(err)
			}

			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}

			if string(raw) != s.expected {
				t.Fatalf("Expected\n%s\ngot\n%s", s.expected, raw)
			}
		})
	}
}

func TestFindLLMLogByIdAndDeleteOld(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	if err := tests.StubLLMLogsData(app); err != nil {
		t.Fatal(err)
	}

	log, err := app.FindLLMLogById("llmlog00001")
	if err != nil {
		t.Fatal(err)
	}
	if log.Model != "gpt-a" || log.Meta["source"] != "test" || !strings.Contains(log.Request.String(), "hi") {
		t.Fatalf("Unexpected log %#v", log)
	}

	if _, err := app.FindLLMLogById("missing"); err == nil {
		t.Fatal("Expected error for missing log")
	}

	date, _ := time.Parse(time.DateTime, "2022-05-01 10:45:00")
	if err := app.DeleteOldLLMLogs(date); err != nil {
		t.Fatal(err)
	}

	total, err := countLLMLogs(app)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("Expected 2 remaining logs, got %d", total)
	}
}
