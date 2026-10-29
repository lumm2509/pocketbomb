package core

import (
	"encoding/json/v2"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// sensitiveFieldNamePattern matches the Go field names that hold secrets.
//
// Any new secret field (e.g. "ClientSecret", "PrivateKey", "APIKey", "Password")
// must be redacted by the JSON serialization of its parent model,
// otherwise the future-proofing tests below fail.
var sensitiveFieldNamePattern = regexp.MustCompile(`(?i)(secret|password|privatekey|apikey)`)

type sentinelField struct {
	path     string
	value    string
	isSecret bool
}

// fillSentinels sets every reachable exported string field to an unique sentinel value
// (slices of structs get a single element) and returns the list of the filled fields.
func fillSentinels(v reflect.Value, path string, result *[]sentinelField) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			if !v.CanSet() {
				return
			}
			v.Set(reflect.New(v.Type().Elem()))
		}
		fillSentinels(v.Elem(), path, result)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fv := v.Field(i)

			// embedded structs are inlined
			if f.Anonymous {
				fillSentinels(fv, path, result)
				continue
			}

			if !f.IsExported() || !fv.CanSet() {
				continue
			}

			fieldPath := path + "." + f.Name

			if fv.Kind() == reflect.String {
				value := fmt.Sprintf("SENTINEL_%d_%s", len(*result), strings.ReplaceAll(fieldPath, ".", "_"))
				fv.SetString(value)
				*result = append(*result, sentinelField{
					path:     fieldPath,
					value:    value,
					isSecret: sensitiveFieldNamePattern.MatchString(f.Name),
				})
				continue
			}

			fillSentinels(fv, fieldPath, result)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() != reflect.Struct || !v.CanSet() {
			return
		}
		slice := reflect.MakeSlice(v.Type(), 1, 1)
		fillSentinels(slice.Index(0), path+"[0]", result)
		v.Set(slice)
	}
}

func assertSecretsRedacted(t *testing.T, name string, fields []sentinelField, raw []byte, minSecrets int) {
	t.Helper()

	totalSecrets := 0

	for _, f := range fields {
		if !f.isSecret {
			continue
		}

		totalSecrets++

		if strings.Contains(string(raw), f.value) {
			t.Errorf("[%s] secret field %s is not redacted in the JSON serialization", name, f.path)
		}
	}

	// ensure that the walker reached the known secret fields
	if totalSecrets < minSecrets {
		t.Fatalf("[%s] expected at least %d secret fields, found %d: %v", name, minSecrets, totalSecrets, fields)
	}
}

func TestSettingsMarshalJSONRedactsAllSecrets(t *testing.T) {
	t.Parallel()

	s := newDefaultSettings()

	fields := []sentinelField{}
	fillSentinels(reflect.ValueOf(&s.settings).Elem(), "settings", &fields)

	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	// SMTP password, S3 secret, backups S3 secret, LLM provider api key
	assertSecretsRedacted(t, "settings", fields, raw, 4)

	if !strings.Contains(string(raw), "SENTINEL_") {
		t.Fatal("Expected the non-secret sentinels to be serialized")
	}
}

// TestSettingsConcurrentAccess runs the settings readers (String, MarshalJSON, DBExport,
// Clone, IsNew, webhooksConfig) concurrently with writers (Merge, self Merge, MarkAsNew)
// and fails on deadlock (it is expected to be run also with -race).
func TestSettingsConcurrentAccess(t *testing.T) {
	t.Parallel()

	app := NewBaseApp(BaseAppConfig{DataDir: t.TempDir()})

	s := newDefaultSettings()
	s.LLM.Providers = []LLMProviderConfig{{Name: "p0", APIKey: "secret_0"}}

	// different settings versions with different slice lengths
	versions := make([]*Settings, 4)
	for i := range versions {
		v := newDefaultSettings()
		for j := 0; j <= i; j++ {
			v.LLM.Providers = append(v.LLM.Providers, LLMProviderConfig{Name: fmt.Sprintf("p%d_%d", i, j), APIKey: "secret"})
			v.RateLimits.Rules = append(v.RateLimits.Rules, RateLimitRule{Label: fmt.Sprintf("/r%d_%d/", i, j), MaxRequests: 1, Duration: 1})
			v.SuperuserIPs = append(v.SuperuserIPs, fmt.Sprintf("10.0.%d.%d", i, j))
		}
		versions[i] = v
	}

	const duration = 500 * time.Millisecond

	stop := make(chan struct{})
	done := make(chan struct{})

	var wg sync.WaitGroup

	worker := func(fn func(i int)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				fn(i)
			}
		}()
	}

	// writers
	worker(func(i int) {
		if err := s.Merge(versions[i%len(versions)]); err != nil {
			t.Errorf("Merge error: %v", err)
		}
	})
	worker(func(i int) {
		// self merge must not deadlock
		if err := s.Merge(s); err != nil {
			t.Errorf("self Merge error: %v", err)
		}
	})
	worker(func(i int) {
		if i%2 == 0 {
			s.MarkAsNew()
		} else {
			s.MarkAsNotNew()
		}
	})
	// opposite direction merges (lock ordering)
	worker(func(i int) {
		_ = versions[0].Merge(s)
	})

	// readers
	worker(func(i int) {
		str := s.String()
		if strings.Contains(str, "secret") {
			t.Errorf("Expected the LLM api keys to be hidden, got %s", str)
		}
	})
	worker(func(i int) {
		if _, err := s.MarshalJSON(); err != nil {
			t.Errorf("MarshalJSON error: %v", err)
		}
	})
	worker(func(i int) {
		if _, err := s.DBExport(app); err != nil {
			t.Errorf("DBExport error: %v", err)
		}
	})
	worker(func(i int) {
		if _, err := s.Clone(); err != nil {
			t.Errorf("Clone error: %v", err)
		}
	})
	worker(func(i int) {
		_ = s.IsNew()
		_ = s.webhooksConfig()
	})

	go func() {
		time.Sleep(duration)
		close(stop)
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(duration + 10*time.Second):
		t.Fatal("Settings concurrent access deadlocked")
	}
}

// TestDefaultRateLimitsCoverOAuth2Server checks that the default rate limit
// rules cover the OAuth2 server hosted and protocol routes.
func TestDefaultRateLimitsCoverOAuth2Server(t *testing.T) {
	t.Parallel()

	defaults := newDefaultSettings().RateLimits

	for _, path := range []string{
		"/oauth2/users/authorize",
		"/oauth2/users/login",
		"/oauth2/users/login/otp",
		"/oauth2/users/signup",
		"/oauth2/users/password-reset",
		"/oauth2/users/verify-email/request",
		"/oauth2/users/token",
		"/oauth2/users/userinfo",
		"/oauth2/users/revoke",
		"/oauth2/users/introspect",
		"/oauth2/users/logout",
		"/oauth2/_superusers/token",
		"/api/oauth2-redirect",
	} {
		for _, method := range []string{"GET", "POST"} {
			if _, ok := defaults.FindRateLimitRule([]string{"users:x", "*:x", method + " " + path, path}); !ok {
				t.Errorf("%s %s is not covered by the default rate limit rules", method, path)
			}
		}
	}
}
