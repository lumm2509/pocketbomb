package apis

import (
	"errors"
	"math"
	"strconv"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/types"
)

// bindLLMApi registers the LLM api endpoints.
func bindLLMApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	sub := rg.Group("/llm")

	// public (governed by the profile rule)
	sub.POST("/{profile}/chat", llmChat).Bind(llmChatRateLimit())

	// staff only
	read := RequirePermission(core.PermissionResourceLLM, core.PermissionLevelRead)
	write := RequirePermission(core.PermissionResourceLLM, core.PermissionLevelWrite)

	sub.GET("/providers", llmProvidersList).Bind(read)
	sub.POST("/test", llmTestProvider).Bind(write)

	logs := sub.Group("/logs").Bind(SkipSuccessActivityLog())
	logs.GET("", llmLogsList).Bind(read)
	logs.DELETE("", llmLogsTruncate).Bind(write)
	logs.GET("/stats", llmLogsStats).Bind(read)
	logs.GET("/top-users", llmLogsTopUsers).Bind(read)
	logs.GET("/{id}", llmLogsView).Bind(read)
}

// llmChatRateLimit defines the rate limit middleware for the LLM chat endpoint.
//
// In addition to the default path labels it also checks for a rule with the "llm:chat" label.
func llmChatRateLimit() *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Id:       DefaultRateLimitMiddlewareId,
		Priority: DefaultRateLimitMiddlewarePriority,
		Func: func(e *core.RequestEvent) error {
			if skipRateLimit(e) {
				return e.Next()
			}

			labels := append([]string{"llm:chat"}, defaultRateLimitLabels(e)...)

			rule, ok := e.App.Settings().RateLimits.FindRateLimitRule(labels, defaultRateLimitAudience(e)...)
			if ok {
				err := checkRateLimit(e, rule.Label+rule.Audience, rule)
				if err != nil {
					return err
				}
			}

			return e.Next()
		},
	}
}

// reserveLLMQuota checks the profile quotas of the current request actor
// (see [core.App.ReserveLLMQuota]).
//
// The quotas are bypassed for the staff with the llm write permission (aka. the playground).
func reserveLLMQuota(e *core.RequestEvent, profile *core.LLMProfile) (func(), error) {
	if e.Can(core.PermissionResourceLLM, core.PermissionLevelWrite) {
		return func() {}, nil
	}

	return e.App.ReserveLLMQuota(profile, e.Auth, e.RealIP())
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

// writeLLMDeniedLog logs a denied or limited LLM chat request
// (aka. a request that never reached the provider).
func writeLLMDeniedLog(e *core.RequestEvent, profile *core.LLMProfile, model string, stream bool, status string, reason string) {
	log := &core.LLMLog{}
	log.Id = core.GenerateDefaultRandomId()
	log.Created = types.NowDateTime()
	log.Profile = profile.Name
	log.Provider = profile.Provider
	if log.Provider == "" {
		if providers := e.App.LLMProviders(); len(providers) > 0 {
			log.Provider = providers[0].Name
		}
	}
	log.Model = model
	if log.Model == "" {
		log.Model = profile.Model
	}
	log.Stream = stream
	log.Status = status
	log.Error = reason
	log.IP = e.RealIP()
	if e.Auth != nil {
		log.AuthCollection = e.Auth.Collection().Id
		log.AuthRecord = e.Auth.Id
	}

	e.App.WriteLLMLog(log)
}

// llmQuotaExceededResponse returns a 429 error with the related Retry-After header.
func llmQuotaExceededResponse(e *core.RequestEvent, err *core.LLMQuotaExceededError) error {
	seconds := int(math.Ceil(err.RetryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}

	e.Response.Header().Set("Retry-After", strconv.Itoa(seconds))

	return e.TooManyRequestsError("LLM profile quota exceeded.", nil)
}

// isLLMQuotaExceeded reports whether the error is *core.LLMQuotaExceededError.
func isLLMQuotaExceeded(err error) (*core.LLMQuotaExceededError, bool) {
	var quotaErr *core.LLMQuotaExceededError
	ok := errors.As(err, &quotaErr)
	return quotaErr, ok
}
