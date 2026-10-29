package apis_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
)

func TestRecordRequestVerification(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:            "unauthorized",
			Method:          http.MethodPost,
			URL:             "/api/collections/users/request-verification",
			Body:            strings.NewReader(`{"email":"test@example.com"}`),
			ExpectedStatus:  401,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "not an auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/demo1/request-verification",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "record authentication but from different auth collection",
			Method: http.MethodPost,
			URL:    "/api/collections/users/request-verification",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("clients", "test@example.com"),
			},
			ExpectedStatus:  403,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "superusers",
			Method: http.MethodPost,
			URL:    "/api/collections/_superusers/request-verification",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("_superusers", "test@example.com"),
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "already verified auth record",
			Method: http.MethodPost,
			URL:    "/api/collections/users/request-verification",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test2@example.com"),
			},
			Delay:          100 * time.Millisecond,
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                                  0,
				"OnRecordRequestVerificationRequest": 1,
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if app.TestMailer.TotalSend() != 0 {
					t.Fatalf("Expected zero emails, got %d", app.TestMailer.TotalSend())
				}
			},
		},
		{
			Name:   "existing unverified auth record",
			Method: http.MethodPost,
			URL:    "/api/collections/users/request-verification",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			Delay:          100 * time.Millisecond,
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{
				"*":                                  0,
				"OnRecordRequestVerificationRequest": 1,
				"OnMailerSend":                       1,
				"OnMailerRecordVerificationSend":     1,
			},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if !strings.Contains(app.TestMailer.LastMessage().HTML, "/oauth2/users/verify-email?token=") {
					t.Fatalf("Expected verification email with the issuer hosted page link, got\n%v", app.TestMailer.LastMessage().HTML)
				}
			},
		},
		{
			Name:   "existing unverified auth record (after already sent)",
			Method: http.MethodPost,
			URL:    "/api/collections/users/request-verification",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			Delay: 100 * time.Millisecond,
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				// simulate recent verification sent
				authRecord, err := app.FindFirstRecordByData("users", "email", "test@example.com")
				if err != nil {
					t.Fatal(err)
				}
				resendKey := "@limitVerificationEmail_" + authRecord.Collection().Id + authRecord.Id
				app.Store().Set(resendKey, struct{}{})
			},
			ExpectedStatus: 204,
			ExpectedEvents: map[string]int{"*": 0},
			AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
				if app.TestMailer.TotalSend() != 0 {
					t.Fatalf("Expected zero emails, got %d", app.TestMailer.TotalSend())
				}
			},
		},
		{
			Name:   "OnRecordRequestVerificationRequest tx body write check",
			Method: http.MethodPost,
			URL:    "/api/collections/users/request-verification",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.OnRecordRequestVerificationRequest().BindFunc(func(e *core.RecordRequestVerificationRequestEvent) error {
					original := e.App
					return e.App.RunInTransaction(func(txApp core.App) error {
						e.App = txApp
						defer func() { e.App = original }()

						if err := e.Next(); err != nil {
							return err
						}

						return e.BadRequestError("TX_ERROR", nil)
					})
				})
			},
			ExpectedStatus:  400,
			ExpectedEvents:  map[string]int{"OnRecordRequestVerificationRequest": 1},
			ExpectedContent: []string{"TX_ERROR"},
		},

		// rate limit checks
		// -----------------------------------------------------------
		{
			Name:   "RateLimit rule - users:requestVerification",
			Method: http.MethodPost,
			URL:    "/api/collections/users/request-verification",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 100, Label: "*:requestVerification"},
					{MaxRequests: 0, Label: "users:requestVerification"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
		{
			Name:   "RateLimit rule - *:requestVerification",
			Method: http.MethodPost,
			URL:    "/api/collections/users/request-verification",
			Headers: map[string]string{
				"Authorization": tests.AuthToken("users", "test@example.com"),
			},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				app.Settings().RateLimits.Enabled = true
				app.Settings().RateLimits.Rules = []core.RateLimitRule{
					{MaxRequests: 100, Label: "abc"},
					{MaxRequests: 0, Label: "*:requestVerification"},
				}
			},
			ExpectedStatus:  429,
			ExpectedContent: []string{`"data":{}`},
			ExpectedEvents:  map[string]int{"*": 0},
		},
	}

	for _, scenario := range scenarios {
		scenario.Test(t)
	}
}
