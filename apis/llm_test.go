package apis_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/llm"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/types"
)

var (
	llmTestUserToken      = tests.AuthToken("users", "test@example.com")
	llmTestSuperuserToken = tests.AuthToken("_superusers", "test@example.com")
	llmTestUserId         = "4q1xlclmfloku33"
	llmTestRemoteIP       = "192.0.2.1" // the default httptest.NewRequest RemoteAddr
)

// clearLLMEnv clears the LLM env variables for the duration of the test
// (NB! it can't be used with parallel tests).
func clearLLMEnv(t *testing.T) {
	for _, key := range []string{
		core.LLMEnvOpenAIAPIKey,
		core.LLMEnvAnthropicAPIKey,
		core.LLMEnvGeminiAPIKey,
		core.LLMEnvXAIAPIKey,
		core.LLMEnvOllamaHost,
		core.LLMEnvDefaultProvider,
		core.LLMEnvDefaultModel,
	} {
		t.Setenv(key, "")
	}
}

// setupLLMTestSettings configures the test app LLM settings with the provided fake server.
func setupLLMTestSettings(app *tests.TestApp, server *tests.LLMFakeServer) {
	app.Settings().LLM = core.LLMConfig{
		DefaultProvider: "fake",
		Providers: []core.LLMProviderConfig{
			{Name: "fake", Provider: llm.ProviderOpenAICompatible, BaseURL: server.URL, APIKey: "fake_key", DefaultModel: "fake-model", Enabled: true},
			{Name: "disabled", Provider: llm.ProviderOpenAICompatible, BaseURL: server.URL, APIKey: "disabled_key"},
		},
		Profiles: []core.LLMProfile{
			{Name: "admin", Rule: nil},
			{Name: "public", Rule: types.Pointer(""), MaxTokens: 50},
			{
				Name:                 "members",
				Rule:                 types.Pointer("@request.auth.id != ''"),
				Model:                "members-model",
				AllowedModels:        []string{"allowed-model"},
				AllowClientOverrides: true,
			},
			{
				Name:   "guest_quota",
				Rule:   types.Pointer(""),
				Quotas: core.LLMProfileQuotas{PerGuestIP: core.LLMQuota{Requests: 1, Window: core.LLMQuotaWindowHour}},
			},
			{
				Name:   "user_quota",
				Rule:   types.Pointer(""),
				Quotas: core.LLMProfileQuotas{PerUser: core.LLMQuota{Tokens: 10, Window: core.LLMQuotaWindowDay}},
			},
			{Name: "broken", Provider: "disabled", Rule: types.Pointer("")},
		},
		Logs: core.LLMLogsConfig{Enabled: true, StoreContent: true, MaxDays: 7},
	}
}

func findLLMTestLogs(t testing.TB, app *tests.TestApp) []*core.LLMLog {
	app.FlushLLMLogs()

	logs := []*core.LLMLog{}
	if err := app.LLMLogQuery().OrderBy("rowid ASC").All(&logs); err != nil {
		t.Fatal(err)
	}

	return logs
}

func writeLLMTestLog(t testing.TB, app *tests.TestApp, profile string, authRecord string, ip string, tokens int) {
	l := &core.LLMLog{}
	l.Profile = profile
	l.Provider = "fake"
	l.Status = core.LLMLogStatusSuccess
	l.IP = ip
	if authRecord != "" {
		l.AuthCollection = "_pb_users_auth_"
		l.AuthRecord = authRecord
	}
	l.InputTokens = tokens
	l.Created = types.NowDateTime().Add(-10 * time.Minute)

	app.WriteLLMLog(l)
	app.FlushLLMLogs()
}

func TestLLMChat(t *testing.T) {
	clearLLMEnv(t)

	const chatBody = `{"messages":[{"role":"user","content":"hi"}]}`

	scenarios := []tests.ApiScenario{
		{
			Name:            "missing profile",
			Method:          http.MethodPost,
			URL:             "/api/llm/missing/chat",
			Body:            strings.NewReader(chatBody),
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "superusers only profile as guest",
			Method:          http.MethodPost,
			URL:             "/api/llm/admin/chat",
			Body:            strings.NewReader(chatBody),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`, `Only superusers`},
			ExpectedEvents:  map[string]int{"*": 0},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				logs := findLLMTestLogs(t, app)
				if len(logs) != 1 || logs[0].Status != core.LLMLogStatusDenied || logs[0].Profile != "admin" || logs[0].IP != llmTestRemoteIP {
					t.Fatalf("Expected 1 denied log, got %#v", logs)
				}
			},
		},
		{
			Name:            "superusers only profile as regular user",
			Method:          http.MethodPost,
			URL:             "/api/llm/admin/chat",
			Body:            strings.NewReader(chatBody),
			Headers:         map[string]string{"Authorization": llmTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "superusers only profile as superuser",
			Method:         http.MethodPost,
			URL:            "/api/llm/admin/chat",
			Body:           strings.NewReader(`{"messages":[{"role":"user","content":"hi"}],"temperature":0.5}`),
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"model":"fake-model"`,
				`"text":"Hello from fake"`,
				`"stopReason":"end_turn"`,
				`"usage":{"inputTokens":11,"outputTokens":7}`,
				`"message":{"role":"assistant","parts":[{"type":"text","text":"Hello from fake"}]}`,
			},
			ExpectedEvents: map[string]int{"*": 0},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				logs := findLLMTestLogs(t, app)
				if len(logs) != 1 ||
					logs[0].Status != core.LLMLogStatusSuccess ||
					logs[0].AuthRecord != "sywbhecnh46rhm0" ||
					logs[0].InputTokens != 11 ||
					!strings.Contains(logs[0].Request.String(), `"temperature":0.5`) ||
					!strings.Contains(logs[0].Response.String(), "Hello from fake") {
					t.Fatalf("Unexpected logs %#v", logs)
				}
			},
		},
		{
			Name:            "auth rule as guest",
			Method:          http.MethodPost,
			URL:             "/api/llm/members/chat",
			Body:            strings.NewReader(chatBody),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`, `not allowed to access`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "auth rule as user with allowed model override",
			Method:         http.MethodPost,
			URL:            "/api/llm/members/chat",
			Body:           strings.NewReader(`{"messages":[{"role":"user","parts":[{"type":"text","text":"hi"}]}],"model":"allowed-model","maxTokens":20}`),
			Headers:        map[string]string{"Authorization": llmTestUserToken},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"text":"Hello from fake"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				logs := findLLMTestLogs(t, app)
				if len(logs) != 1 || logs[0].AuthRecord != llmTestUserId || logs[0].AuthCollection != "_pb_users_auth_" || logs[0].Profile != "members" {
					t.Fatalf("Unexpected logs %#v", logs)
				}
			},
		},
		{
			Name:            "auth rule as user with not allowed model",
			Method:          http.MethodPost,
			URL:             "/api/llm/members/chat",
			Body:            strings.NewReader(`{"messages":[{"role":"user","content":"hi"}],"model":"other-model"}`),
			Headers:         map[string]string{"Authorization": llmTestUserToken},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"model":{"code":"validation_llm_model_not_allowed"`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "public profile with invalid body",
			Method:         http.MethodPost,
			URL:            "/api/llm/public/chat",
			Body:           strings.NewReader(`{"messages":[{"role":"system","content":"hi"},{"role":"user"}]}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"messages":{"0":{"role":{"code":"validation_in_invalid"`,
				`"1":{"content":{"code":"validation_required"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:           "public profile with empty messages",
			Method:         http.MethodPost,
			URL:            "/api/llm/public/chat",
			Body:           strings.NewReader(`{"messages":[]}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"messages":{"code":"validation_required"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:           "public profile with not allowed overrides",
			Method:         http.MethodPost,
			URL:            "/api/llm/public/chat",
			Body:           strings.NewReader(`{"messages":[{"role":"user","content":"hi"}],"model":"x","temperature":1,"maxTokens":1,"tools":[{"name":"test"}]}`),
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"model":{"code":"validation_llm_override_not_allowed"`,
				`"temperature":{"code":"validation_llm_override_not_allowed"`,
				`"maxTokens":{"code":"validation_llm_override_not_allowed"`,
				`"tools":{"code":"validation_llm_override_not_allowed"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:            "public profile (max tokens cap)",
			Method:          http.MethodPost,
			URL:             "/api/llm/public/chat",
			Body:            strings.NewReader(chatBody),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"text":"Hello from fake"`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "public profile stream",
			Method:         http.MethodPost,
			URL:            "/api/llm/public/chat",
			Body:           strings.NewReader(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`),
			ExpectedStatus: 200,
			ExpectedContent: []string{
				"event: delta\ndata: {\"type\":\"text_delta\",\"text\":\"Hel\",\"model\":\"fake-model\"}\n\n",
				"event: delta\ndata: {\"type\":\"text_delta\",\"text\":\"lo\",\"model\":\"fake-model\"}\n\n",
				"event: done\ndata: {\"model\":\"fake-model\",\"message\":{\"role\":\"assistant\",\"parts\":[{\"type\":\"text\",\"text\":\"Hello\"}]},\"text\":\"Hello\",\"stopReason\":\"end_turn\",\"usage\":{\"inputTokens\":5,\"outputTokens\":2}}\n\n",
			},
			ExpectedEvents: map[string]int{"*": 0},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if ct := res.Header.Get("Content-Type"); ct != "text/event-stream" {
					t.Fatalf("Expected text/event-stream content type, got %q", ct)
				}

				logs := findLLMTestLogs(t, app)
				if len(logs) != 1 || !logs[0].Stream || logs[0].OutputTokens != 2 || logs[0].Profile != "public" {
					t.Fatalf("Unexpected logs %#v", logs)
				}
			},
		},
		{
			Name:            "guest quota (not exceeded)",
			Method:          http.MethodPost,
			URL:             "/api/llm/guest_quota/chat",
			Body:            strings.NewReader(chatBody),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"text":"Hello from fake"`},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				// different ip and user logs
				writeLLMTestLog(t, app, "guest_quota", "", "127.0.0.1", 1)
				writeLLMTestLog(t, app, "guest_quota", llmTestUserId, llmTestRemoteIP, 1)
			},
		},
		{
			Name:            "guest quota (exceeded)",
			Method:          http.MethodPost,
			URL:             "/api/llm/guest_quota/chat",
			Body:            strings.NewReader(chatBody),
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`, `quota exceeded`},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				writeLLMTestLog(t, app, "guest_quota", "", llmTestRemoteIP, 1)
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				retryAfter, _ := strconv.Atoi(res.Header.Get("Retry-After"))
				// the log was created 10 minutes ago
				if retryAfter < 49*60 || retryAfter > 51*60 {
					t.Fatalf("Expected ~50min Retry-After, got %q", res.Header.Get("Retry-After"))
				}

				logs := findLLMTestLogs(t, app)
				last := logs[len(logs)-1]
				if last.Status != core.LLMLogStatusLimited || !strings.Contains(last.Error, "requests quota") {
					t.Fatalf("Expected limited log, got %#v", last)
				}
			},
		},
		{
			Name:            "guest quota (superuser bypass)",
			Method:          http.MethodPost,
			URL:             "/api/llm/guest_quota/chat",
			Body:            strings.NewReader(chatBody),
			Headers:         map[string]string{"Authorization": llmTestSuperuserToken},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"text":"Hello from fake"`},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				writeLLMTestLog(t, app, "guest_quota", "", llmTestRemoteIP, 1)
			},
		},
		{
			Name:            "user tokens quota (exceeded)",
			Method:          http.MethodPost,
			URL:             "/api/llm/user_quota/chat",
			Body:            strings.NewReader(chatBody),
			Headers:         map[string]string{"Authorization": llmTestUserToken},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				writeLLMTestLog(t, app, "user_quota", llmTestUserId, "", 10)
			},
		},
		{
			Name:            "user tokens quota (guest is not affected)",
			Method:          http.MethodPost,
			URL:             "/api/llm/user_quota/chat",
			Body:            strings.NewReader(chatBody),
			ExpectedStatus:  200,
			ExpectedContent: []string{`"text":"Hello from fake"`},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				writeLLMTestLog(t, app, "user_quota", llmTestUserId, "", 10)
			},
		},
		{
			Name:            "disabled profile provider",
			Method:          http.MethodPost,
			URL:             "/api/llm/broken/chat",
			Body:            strings.NewReader(chatBody),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`, `missing or disabled`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "OnLLMRequest hook api error",
			Method:          http.MethodPost,
			URL:             "/api/llm/public/chat",
			Body:            strings.NewReader(chatBody),
			ExpectedStatus:  403,
			ExpectedContent: []string{`"message":"Blocked by hook."`},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnLLMRequest("public").BindFunc(func(e *core.LLMRequestEvent) error {
					return router.NewForbiddenError("Blocked by hook.", nil)
				})
			},
		},
		{
			Name:            "rate limit (llm:chat label)",
			Method:          http.MethodPost,
			URL:             "/api/llm/public/chat",
			Body:            strings.NewReader(chatBody),
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{Label: "llm:chat", MaxRequests: 1, Duration: 100},
				}

				// consume the only allowed request
				mux, err := e.Router.BuildMux()
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodPost, "/api/llm/public/chat", strings.NewReader(chatBody))
				req.Header.Set("content-type", "application/json")
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				if rec.Code != 200 {
					t.Fatalf("Expected the first request to succeed, got %d", rec.Code)
				}
			},
		},
	}

	for _, scenario := range scenarios {
		originalBefore := scenario.BeforeTestFunc
		scenario.BeforeTestFunc = func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			setupLLMTestSettings(app, tests.NewLLMFakeServer(t))
			if originalBefore != nil {
				originalBefore(t, app, e)
			}
		}
		scenario.Test(t)
	}
}

func TestLLMChatProviderError(t *testing.T) {
	clearLLMEnv(t)

	newServer := func(t testing.TB) *tests.LLMFakeServer {
		server := tests.NewLLMFakeServer(t)
		server.Status = 500
		server.Body = `{"error":{"message":"upstream overloaded","type":"server_error"}}`
		return server
	}

	scenarios := []tests.ApiScenario{
		{
			Name:               "as guest (no raw error)",
			Method:             http.MethodPost,
			URL:                "/api/llm/public/chat",
			Body:               strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`),
			ExpectedStatus:     502,
			ExpectedContent:    []string{`"message":"Failed to process the LLM request."`},
			NotExpectedContent: []string{"upstream overloaded"},
			ExpectedEvents:     map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				setupLLMTestSettings(app, newServer(t))
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				logs := findLLMTestLogs(t, app)
				if len(logs) != 1 || logs[0].Status != core.LLMLogStatusError || !strings.Contains(logs[0].Error, "upstream overloaded") {
					t.Fatalf("Unexpected logs %#v", logs)
				}
			},
		},
		{
			Name:            "as superuser (with raw error)",
			Method:          http.MethodPost,
			URL:             "/api/llm/public/chat",
			Body:            strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`),
			Headers:         map[string]string{"Authorization": llmTestSuperuserToken},
			ExpectedStatus:  502,
			ExpectedContent: []string{"upstream overloaded"},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				setupLLMTestSettings(app, newServer(t))
			},
		},
		{
			Name:            "not configured",
			Method:          http.MethodPost,
			URL:             "/api/llm/public/chat",
			Body:            strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`),
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().LLM.Profiles = []core.LLMProfile{{Name: "public", Rule: types.Pointer("")}}
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestLLMLogsList(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodGet,
			URL:             "/api/llm/logs",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "authorized as regular user",
			Method:          http.MethodGet,
			URL:             "/api/llm/logs",
			Headers:         map[string]string{"Authorization": llmTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:    "authorized as superuser",
			Method:  http.MethodGet,
			URL:     "/api/llm/logs?sort=-created",
			Headers: map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				if err := tests.StubLLMLogsData(app); err != nil {
					t.Fatal(err)
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"page":1`,
				`"perPage":30`,
				`"totalItems":4`,
				`"items":[{"id":"llmlog00004"`,
				`"id":"llmlog00001"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:    "authorized as superuser + filter + fields",
			Method:  http.MethodGet,
			URL:     "/api/llm/logs?filter=" + escapeQuery(`status="success" && meta.source="test"`) + "&fields=id,model,inputTokens",
			Headers: map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				if err := tests.StubLLMLogsData(app); err != nil {
					t.Fatal(err)
				}
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"totalItems":1`,
				`"id":"llmlog00001"`,
				`"inputTokens":10`,
				`"model":"gpt-a"`,
			},
			NotExpectedContent: []string{`"provider"`, `"request"`},
			ExpectedEvents:     map[string]int{"*": 0},
		},
		{
			Name:            "authorized as superuser + invalid filter field",
			Method:          http.MethodGet,
			URL:             "/api/llm/logs?filter=request~'hi'",
			Headers:         map[string]string{"Authorization": llmTestSuperuserToken},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestLLMLogsView(t *testing.T) {
	t.Parallel()

	stub := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		if err := tests.StubLLMLogsData(app); err != nil {
			t.Fatal(err)
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodGet,
			URL:             "/api/llm/logs/llmlog00001",
			BeforeTestFunc:  stub,
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "authorized as regular user",
			Method:          http.MethodGet,
			URL:             "/api/llm/logs/llmlog00001",
			Headers:         map[string]string{"Authorization": llmTestUserToken},
			BeforeTestFunc:  stub,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "authorized as superuser (missing)",
			Method:          http.MethodGet,
			URL:             "/api/llm/logs/missing",
			Headers:         map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc:  stub,
			ExpectedStatus:  404,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "authorized as superuser (existing)",
			Method:         http.MethodGet,
			URL:            "/api/llm/logs/llmlog00001",
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: stub,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"id":"llmlog00001"`,
				`"profile":"support"`,
				`"request":{"messages":[{"role":"user","parts":[{"type":"text","text":"hi"}]}]}`,
				`"response":{"message":{`,
				`"authRecord":"4q1xlclmfloku33"`,
				`"meta":{"source":"test"}`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestLLMLogsTruncate(t *testing.T) {
	t.Parallel()

	stub := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		if err := tests.StubLLMLogsData(app); err != nil {
			t.Fatal(err)
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodDelete,
			URL:             "/api/llm/logs",
			BeforeTestFunc:  stub,
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "authorized as regular user",
			Method:          http.MethodDelete,
			URL:             "/api/llm/logs",
			Headers:         map[string]string{"Authorization": llmTestUserToken},
			BeforeTestFunc:  stub,
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "authorized as superuser",
			Method:         http.MethodDelete,
			URL:            "/api/llm/logs",
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: stub,
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				var found []*core.LLMLog

				if err := app.LLMLogQuery().All(&found); err != nil {
					t.Fatal(err)
				}

				if len(found) > 0 {
					t.Fatalf("Expected all LLM logs to be deleted, found %d", len(found))
				}
			},
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestLLMLogsStats(t *testing.T) {
	t.Parallel()

	stub := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		if err := tests.StubLLMLogsData(app); err != nil {
			t.Fatal(err)
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodGet,
			URL:             "/api/llm/logs/stats",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "authorized as regular user",
			Method:          http.MethodGet,
			URL:             "/api/llm/logs/stats",
			Headers:         map[string]string{"Authorization": llmTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "authorized as superuser",
			Method:         http.MethodGet,
			URL:            "/api/llm/logs/stats",
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: stub,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`[{"date":"2022-05-01 10:00:00.000Z","group":"","requests":2,"errors":0,"denied":0,"inputTokens":15,"outputTokens":25,"avgDurationMs":200,"p50DurationMs":100,"p95DurationMs":300},`,
				`{"date":"2022-05-02 10:00:00.000Z","group":"","requests":1,"errors":0,"denied":1,`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:           "authorized as superuser + interval + groupBy + filter",
			Method:         http.MethodGet,
			URL:            "/api/llm/logs/stats?interval=day&groupBy=profile&filter=" + escapeQuery(`created < "2022-05-02"`),
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: stub,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`[{"date":"2022-05-01 00:00:00.000Z","group":"support","requests":3,"errors":1,"denied":0,"inputTokens":15,"outputTokens":25,"avgDurationMs":150,"p50DurationMs":100,"p95DurationMs":300}]`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:           "authorized as superuser + invalid params",
			Method:         http.MethodGet,
			URL:            "/api/llm/logs/stats?interval=week&groupBy=abc",
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"interval":{"code":"validation_in_invalid"`,
				`"groupBy":{"code":"validation_in_invalid"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:            "authorized as superuser + invalid filter",
			Method:          http.MethodGet,
			URL:             "/api/llm/logs/stats?filter=missing=1",
			Headers:         map[string]string{"Authorization": llmTestSuperuserToken},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestLLMLogsTopUsers(t *testing.T) {
	t.Parallel()

	stub := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		if err := tests.StubLLMLogsData(app); err != nil {
			t.Fatal(err)
		}
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodGet,
			URL:             "/api/llm/logs/top-users",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "authorized as regular user",
			Method:          http.MethodGet,
			URL:             "/api/llm/logs/top-users",
			Headers:         map[string]string{"Authorization": llmTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "authorized as superuser",
			Method:         http.MethodGet,
			URL:            "/api/llm/logs/top-users",
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: stub,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"authRecord":"4q1xlclmfloku33"`,
				`"totalTokens":40`,
				`"requests":2`,
				`"record":{`,
				`"email":"test@example.com"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:           "authorized as superuser (by ip)",
			Method:         http.MethodGet,
			URL:            "/api/llm/logs/top-users?by=ip&sort=requests&limit=5",
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: stub,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`[{"authCollection":"","authRecord":"","ip":"2.2.2.2","requests":2,"errors":1,"denied":1,"inputTokens":0,"outputTokens":0,"totalTokens":0,"lastCall":"2022-05-02 10:00:00.000Z","record":null}]`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:           "authorized as superuser (invalid params)",
			Method:         http.MethodGet,
			URL:            "/api/llm/logs/top-users?by=abc&sort=abc&limit=1000",
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"by":{"code":"validation_in_invalid"`,
				`"sort":{"code":"validation_in_invalid"`,
				`"limit":{"code":"validation_max_less_equal_than_required"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestLLMProvidersList(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv(core.LLMEnvAnthropicAPIKey, "env_anthropic_key")

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodGet,
			URL:             "/api/llm/providers",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "authorized as regular user",
			Method:          http.MethodGet,
			URL:             "/api/llm/providers",
			Headers:         map[string]string{"Authorization": llmTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:    "authorized as superuser",
			Method:  http.MethodGet,
			URL:     "/api/llm/providers",
			Headers: map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				setupLLMTestSettings(app, tests.NewLLMFakeServer(t))
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"drivers":["anthropic","gemini","grok","ollama","openai","openai-compatible","xai"]`,
				`"providers":[{"name":"fake","provider":"openai-compatible","baseURL":"http://127.0.0.1:`,
				`"source":"settings","isDefault":true}`,
				`{"name":"anthropic","provider":"anthropic","baseURL":"","defaultModel":"","models":[],"source":"env","isDefault":false}`,
			},
			NotExpectedContent: []string{"fake_key", "env_anthropic_key", `"name":"disabled"`},
			ExpectedEvents:     map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestLLMTestProvider(t *testing.T) {
	clearLLMEnv(t)

	// note: shared between the scenarios because its url is needed in the request body
	server := tests.NewLLMFakeServer(t)
	attacker := tests.NewLLMFakeServer(t)

	lastRequest := func(t testing.TB) *tests.LLMFakeServerRequest {
		reqs := server.Requests()
		if len(reqs) == 0 {
			t.Fatal("Expected at least one fake server request")
		}
		return reqs[len(reqs)-1]
	}

	setup := func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		setupLLMTestSettings(app, server)
	}

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodPost,
			URL:             "/api/llm/test",
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:            "authorized as regular user",
			Method:          http.MethodPost,
			URL:             "/api/llm/test",
			Headers:         map[string]string{"Authorization": llmTestUserToken},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:           "authorized as superuser (invalid data)",
			Method:         http.MethodPost,
			URL:            "/api/llm/test",
			Body:           strings.NewReader(`{"provider":"missing","timeout":-1}`),
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: setup,
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"provider":{"code":"validation_in_invalid"`,
				`"model":{"code":"validation_required"`,
				`"timeout":{"code":"validation_min_greater_equal_than_required"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
		},
		{
			Name:           "authorized as superuser (existing provider by name)",
			Method:         http.MethodPost,
			URL:            "/api/llm/test",
			Body:           strings.NewReader(`{"name":"fake","prompt":"ping"}`),
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"model":"fake-model"`,
				`"text":"Hello from fake"`,
				`"usage":{"inputTokens":11,"outputTokens":7}`,
				`"durationMs":`,
			},
			ExpectedEvents: map[string]int{"*": 0},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				req := lastRequest(t)
				if req.Header.Get("Authorization") != "Bearer fake_key" || !strings.Contains(req.Body, "ping") {
					t.Fatalf("Unexpected fake server request %#v", req)
				}

				// test calls are not logged
				if logs := findLLMTestLogs(t, app); len(logs) != 0 {
					t.Fatalf("Expected no logs, got %d", len(logs))
				}
			},
		},
		{
			Name:           "authorized as superuser (new config with existing name key fallback)",
			Method:         http.MethodPost,
			URL:            "/api/llm/test",
			Body:           strings.NewReader(`{"name":"disabled","provider":"openai-compatible","baseURL":"` + server.URL + `","model":"new-model"}`),
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"text":"Hello from fake"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				req := lastRequest(t)
				if req.Header.Get("Authorization") != "Bearer disabled_key" || !strings.Contains(req.Body, `"model":"new-model"`) {
					t.Fatalf("Unexpected fake server request %#v", req)
				}
			},
		},
		{
			// R1-F2: the stored api key must not be sent to a different endpoint
			Name:           "authorized as superuser (existing name with another baseURL doesn't reuse the stored key)",
			Method:         http.MethodPost,
			URL:            "/api/llm/test",
			Body:           strings.NewReader(`{"name":"fake","provider":"openai-compatible","baseURL":"` + attacker.URL + `","model":"x"}`),
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: setup,
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"text":"Hello from fake"`,
			},
			ExpectedEvents: map[string]int{"*": 0},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				reqs := attacker.Requests()
				if len(reqs) == 0 {
					t.Fatal("Expected an attacker server request")
				}
				if auth := reqs[len(reqs)-1].Header.Get("Authorization"); strings.Contains(auth, "fake_key") {
					t.Fatalf("The stored api key was sent to another endpoint: %q", auth)
				}
			},
		},
		{
			Name:            "authorized as superuser (provider error)",
			Method:          http.MethodPost,
			URL:             "/api/llm/test",
			Body:            strings.NewReader(`{"name":"fake"}`),
			Headers:         map[string]string{"Authorization": llmTestSuperuserToken},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`, `invalid api key`},
			ExpectedEvents:  map[string]int{"*": 0},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				setup(t, app, e)
				server.Status = 401
				server.Body = `{"error":{"message":"invalid api key","type":"auth_error"}}`
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func TestLLMSettingsMasking(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv(core.LLMEnvOpenAIAPIKey, "env_openai_key")

	scenarios := []tests.ApiScenario{
		{
			Name:    "list masked settings",
			Method:  http.MethodGet,
			URL:     "/api/settings",
			Headers: map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				setupLLMTestSettings(app, tests.NewLLMFakeServer(t))
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"llm":{`,
				`"name":"fake"`,
				`"hasApiKey":true`,
				`"envProviders":[{"name":"openai","provider":"openai","baseURL":"","defaultModel":"","models":[],"timeout":0,"enabled":true,"hasApiKey":true,"source":"env"}]`,
			},
			NotExpectedContent: []string{"fake_key", "disabled_key", "env_openai_key"},
			ExpectedEvents: map[string]int{
				"*":                     0,
				"OnSettingsListRequest": 1,
			},
		},
		{
			Name:   "update with masked providers",
			Method: http.MethodPatch,
			URL:    "/api/settings",
			Body: strings.NewReader(`{"llm":{
				"providers":[
					{"name":"disabled","provider":"openai-compatible","baseURL":"http://example.com","hasApiKey":true},
					{"name":"fake","provider":"openai-compatible","baseURL":"http://example.com","enabled":true,"hasApiKey":true}
				],
				"profiles":[{"name":"test","rule":"@request.auth.id != ''","quotas":{"perUser":{"requests":5,"window":"minute"}}}],
				"logs":{"enabled":true,"maxDays":3},
				"envProviders":[{"name":"openai"}]
			}}`),
			Headers: map[string]string{"Authorization": llmTestSuperuserToken},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				setupLLMTestSettings(app, tests.NewLLMFakeServer(t))
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"profiles":[{"name":"test"`,
				`"hasApiKey":true`,
			},
			NotExpectedContent: []string{"fake_key", "disabled_key", "env_openai_key"},
			ExpectedEvents: map[string]int{
				"*":                         0,
				"OnSettingsUpdateRequest":   1,
				"OnModelUpdate":             1,
				"OnModelUpdateExecute":      1,
				"OnModelAfterUpdateSuccess": 1,
				"OnModelValidate":           1,
				"OnSettingsReload":          1,
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				providers := app.Settings().LLM.Providers
				if len(providers) != 2 || providers[0].APIKey != "disabled_key" || providers[1].APIKey != "fake_key" {
					t.Fatalf("Expected the provider keys to be preserved, got %#v", providers)
				}
			},
		},
		{
			Name:   "update with invalid profile rule",
			Method: http.MethodPatch,
			URL:    "/api/settings",
			Body: strings.NewReader(`{"llm":{
				"profiles":[{"name":"test","rule":"id = 1","quotas":{"perUser":{"requests":5}}}],
				"logs":{"enabled":false}
			}}`),
			Headers:        map[string]string{"Authorization": llmTestSuperuserToken},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"llm":{`,
				`"profiles":{"0":{`,
			},
			ExpectedEvents: map[string]int{
				"*":                       0,
				"OnSettingsUpdateRequest": 1,
				"OnModelUpdate":           1,
				"OnModelValidate":         1,
				"OnModelAfterUpdateError": 1,
			},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}

func escapeQuery(s string) string {
	r := strings.NewReplacer(" ", "%20", `"`, "%22", "&", "%26", "=", "%3D", "<", "%3C", "'", "%27")
	return r.Replace(s)
}
