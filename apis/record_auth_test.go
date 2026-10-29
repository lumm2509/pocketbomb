package apis_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/tests"
)

func TestVanillaAuthRoutesRemoved(t *testing.T) {
	t.Parallel()

	routes := []struct {
		method string
		url    string
		body   string
	}{
		{http.MethodGet, "/api/collections/users/auth-methods", ""},
		{http.MethodPost, "/api/collections/users/auth-refresh", ""},
		{http.MethodPost, "/api/collections/users/auth-with-password", `{"identity":"test@example.com","password":"1234567890"}`},
		{http.MethodPost, "/api/collections/users/auth-with-oauth2", `{"provider":"gitlab","code":"123"}`},
		{http.MethodPost, "/api/collections/users/request-otp", `{"email":"test@example.com"}`},
		{http.MethodPost, "/api/collections/users/auth-with-otp", `{"otpId":"123","password":"456"}`},
		{http.MethodPost, "/api/collections/users/impersonate/4q1xlclmfloku33", `{}`},
		{http.MethodPost, "/api/collections/_superusers/auth-with-password", `{"identity":"test@example.com","password":"1234567890"}`},
		{http.MethodPost, "/api/collections/users/request-password-reset", `{"email":"test@example.com"}`},
		{http.MethodPost, "/api/collections/users/confirm-password-reset", `{"token":"123","password":"1234567890","passwordConfirm":"1234567890"}`},
		{http.MethodPost, "/api/collections/users/confirm-verification", `{"token":"123"}`},
		{http.MethodPost, "/api/collections/users/confirm-email-change", `{"token":"123","password":"1234567890"}`},
	}

	for _, r := range routes {
		for _, auth := range []string{"", tests.AuthToken("_superusers", "test@example.com")} {
			name := r.method + " " + r.url
			if auth != "" {
				name += " (superuser)"
			}

			s := tests.ApiScenario{
				Name:            name,
				Method:          r.method,
				URL:             r.url,
				Body:            strings.NewReader(r.body),
				Headers:         map[string]string{"Authorization": auth},
				ExpectedStatus:  404,
				ExpectedContent: []string{`"data":{}`},
				NotExpectedContent: []string{
					`"token":`,
					`"otpId":`,
					`"mfaId":`,
				},
				ExpectedEvents: map[string]int{"*": 0},
			}
			if auth == "" {
				s.ExpectedEvents = map[string]int{"*": 0}
			} else {
				// the auth token resolution doesn't trigger request hooks
				s.ExpectedEvents = nil
			}
			s.Test(t)
		}
	}
}
