package webhooks_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lumm2509/pocketbomb/tools/webhooks"
)

func TestSign(t *testing.T) {
	t.Parallel()

	// echo -n '{"a":1}' | openssl dgst -sha256 -hmac "secret" -binary | base64
	expected := "qp4uNXX11wmLbKzNeQiIw21f22M0KnO62i1qUXR6hJQ="

	if v := webhooks.Sign([]byte(`{"a":1}`), "secret"); v != expected {
		t.Fatalf("Expected %q, got %q", expected, v)
	}
}

func TestCheckSignature(t *testing.T) {
	t.Parallel()

	body := []byte(`{"a":1}`)
	sig := webhooks.Sign(body, "secret")

	scenarios := []struct {
		name      string
		body      []byte
		secret    string
		signature string
		expected  bool
	}{
		{"valid", body, "secret", sig, true},
		{"valid with spaces", body, "secret", " " + sig + " ", true},
		{"empty secret", body, "", sig, false},
		{"empty signature", body, "secret", "", false},
		{"different secret", body, "secret2", sig, false},
		{"different body", []byte(`{"a":2}`), "secret", sig, false},
		{"non-base64 signature", body, "secret", "!!!", false},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			if v := webhooks.CheckSignature(s.body, s.secret, s.signature); v != s.expected {
				t.Fatalf("Expected %v, got %v", s.expected, v)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	body := `{"hello":"world"}`

	newReq := func(sig string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		if sig != "" {
			r.Header.Set(webhooks.HeaderHmac, sig)
		}
		return r
	}

	t.Run("nil request", func(t *testing.T) {
		if _, err := webhooks.Verify(nil, "secret"); err == nil {
			t.Fatal("Expected error")
		}
	})

	t.Run("empty secret", func(t *testing.T) {
		if _, err := webhooks.Verify(newReq(webhooks.Sign([]byte(body), "")), ""); err == nil {
			t.Fatal("Expected error")
		}
	})

	t.Run("missing signature", func(t *testing.T) {
		_, err := webhooks.Verify(newReq(""), "secret")
		if !errors.Is(err, webhooks.ErrMissingSignature) {
			t.Fatalf("Expected ErrMissingSignature, got %v", err)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		_, err := webhooks.Verify(newReq(webhooks.Sign([]byte(body), "other")), "secret")
		if !errors.Is(err, webhooks.ErrInvalidSignature) {
			t.Fatalf("Expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("valid signature and re-readable body", func(t *testing.T) {
		r := newReq(webhooks.Sign([]byte(body), "secret"))

		raw, err := webhooks.Verify(r, "secret")
		if err != nil {
			t.Fatal(err)
		}

		if string(raw) != body {
			t.Fatalf("Expected body %q, got %q", body, raw)
		}

		again, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, raw) {
			t.Fatalf("Expected the body to be re-readable, got %q", again)
		}
	})
}
