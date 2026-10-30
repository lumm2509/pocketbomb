package apis

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/core"
)

func TestRedactLogURL(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		url        string
		notContain []string
		contain    []string
	}{
		{"/api/collections/users/records", nil, []string{"/api/collections/users/records"}},
		{"/api/files/c/r/f.txt?token=FILE_TOKEN&thumb=100x100", []string{"FILE_TOKEN"}, []string{"thumb=100x100", "token=REDACTED"}},
		{"/apps/reviews/x?signature=PROXY_SIGNATURE&a=1", []string{"PROXY_SIGNATURE"}, []string{"a=1"}},
		{"/oauth2/users/password-reset/confirm?token=RESET_TOKEN", []string{"RESET_TOKEN"}, nil},
		{"/oauth2/users/verify-email?token=VERIFY_TOKEN", []string{"VERIFY_TOKEN"}, nil},
		{"/oauth2/users/email-change/confirm?token=CHANGE_TOKEN", []string{"CHANGE_TOKEN"}, nil},
		{"/_/?code=AUTH_CODE&state=STATE_VALUE&iss=x", []string{"AUTH_CODE", "STATE_VALUE"}, []string{"iss=x"}},
		{"/api/oauth2-redirect?code=UPSTREAM_CODE&state=pbas.HANDLE", []string{"UPSTREAM_CODE", "HANDLE"}, nil},
		{"/oauth2/users/login?auth_state=FLOW_HANDLE", []string{"FLOW_HANDLE"}, nil},
		{"/oauth2/users/logout?id_token_hint=ID_TOKEN&client_id=app", []string{"ID_TOKEN"}, []string{"client_id=app"}},
		{"/x?refresh_token=RT&access_token=AT&client_secret=CS&code_verifier=CV&password=PW&Token=UPPER", []string{"RT", "AT", "CS", "CV", "PW", "UPPER"}, nil},
		{"https://example.com/oauth2/users/password-reset/confirm?token=REFERER_TOKEN", []string{"REFERER_TOKEN"}, []string{"https://example.com/"}},
		{"/api/realtime?pk=pb_pk_PUBLIC_KEY&x=1", []string{"pb_pk_PUBLIC_KEY"}, []string{"x=1", "pk=REDACTED"}},
		{"/api/collections/demo2/records?PK=pb_sk_PRIVATE_KEY", []string{"pb_sk_PRIVATE_KEY"}, nil},
	}

	for _, s := range scenarios {
		result := redactLogURL(s.url)

		for _, v := range s.notContain {
			if strings.Contains(result, v) {
				t.Fatalf("[%s] Expected %q to be redacted, got %q", s.url, v, result)
			}
		}

		for _, v := range s.contain {
			if !strings.Contains(result, v) {
				t.Fatalf("[%s] Expected %q in the result, got %q", s.url, v, result)
			}
		}
	}
}

func TestRequestLogAttrsAPIKey(t *testing.T) {
	t.Parallel()

	// note: the settings are enough (no bootstrap; this package tests can't import the tests package)
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})

	newEvent := func(client *core.RequestInfoAPIKey) *core.RequestEvent {
		req := httptest.NewRequest(http.MethodGet, "/api/collections/demo2/records?pk=pb_pk_SECRET_PUBLIC", nil)
		req.Header.Set(APIKeyPublicHeader, "pb_pk_SECRET_PUBLIC")
		req.Header.Set(APIKeyPrivateHeader, "pb_sk_SECRET_PRIVATE")
		req.Header.Set(APIKeyBuyerIPHeader, "203.0.113.7")

		e := &core.RequestEvent{}
		e.App = app
		e.Request = req
		e.Response = httptest.NewRecorder()
		if client != nil {
			e.Set(core.RequestEventKeyAPIKey, client)
		}
		return e
	}

	scenarios := []struct {
		name       string
		client     *core.RequestInfoAPIKey
		logIP      bool
		contain    []string
		notContain []string
	}{
		{
			"without key",
			nil,
			true,
			nil,
			[]string{"apiKeyId", "buyerIp"},
		},
		{
			"public key",
			&core.RequestInfoAPIKey{KeyId: "key_public", KeyKind: core.APIKeyKindPublic},
			true,
			[]string{"apiKeyId=key_public"},
			[]string{"buyerIp"},
		},
		{
			"private key with buyer IP",
			&core.RequestInfoAPIKey{KeyId: "key_private", KeyKind: core.APIKeyKindPrivate, BuyerIP: "203.0.113.7"},
			true,
			[]string{"apiKeyId=key_private", "buyerIp=203.0.113.7"},
			nil,
		},
		{
			"private key with buyer IP and disabled IP logging",
			&core.RequestInfoAPIKey{KeyId: "key_private", KeyKind: core.APIKeyKindPrivate, BuyerIP: "203.0.113.7"},
			false,
			[]string{"apiKeyId=key_private"},
			[]string{"buyerIp", "203.0.113.7"},
		},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app.Settings().Logs.LogIP = s.logIP

			_, url, attrs := requestLogAttrs(newEvent(s.client), nil)

			raw := url + " " + fmt.Sprint(attrs...)

			// the keys themselves are never logged
			for _, secret := range []string{"pb_pk_SECRET_PUBLIC", "pb_sk_SECRET_PRIVATE"} {
				if strings.Contains(raw, secret) {
					t.Fatalf("Expected %q to be redacted, got %s", secret, raw)
				}
			}

			for _, v := range s.contain {
				if !strings.Contains(raw, v) {
					t.Fatalf("Expected %q in %s", v, raw)
				}
			}

			for _, v := range s.notContain {
				if strings.Contains(raw, v) {
					t.Fatalf("Expected no %q in %s", v, raw)
				}
			}
		})
	}
}
