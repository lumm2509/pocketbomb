package webhooks

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DefaultMaxVerifyBodySize is the max request body size read by [Verify].
const DefaultMaxVerifyBodySize = 10 << 20 // 10MB

var (
	// ErrMissingSignature is returned by [Verify] when the request doesn't have a signature header.
	ErrMissingSignature = errors.New("webhooks: missing " + HeaderHmac + " header")

	// ErrInvalidSignature is returned by [Verify] when the request signature doesn't match.
	ErrInvalidSignature = errors.New("webhooks: invalid signature")
)

// Sign returns the base64 encoded HMAC-SHA256 signature of the raw body.
func Sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)

	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// CheckSignature reports whether the provided base64 signature matches
// the raw body HMAC-SHA256 signature (constant-time comparison).
func CheckSignature(body []byte, secret string, signature string) bool {
	if secret == "" || signature == "" {
		return false
	}

	provided, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)

	return hmac.Equal(mac.Sum(nil), provided)
}

// Verify verifies the [HeaderHmac] signature of an incoming webhook request
// and returns its raw body.
//
// The request body is read (up to [DefaultMaxVerifyBodySize]) and
// then restored so that it could be read again by the caller.
//
// Returns [ErrMissingSignature] or [ErrInvalidSignature] on verification failure.
func Verify(r *http.Request, secret string) ([]byte, error) {
	if r == nil {
		return nil, errors.New("webhooks: nil request")
	}

	if secret == "" {
		return nil, errors.New("webhooks: empty secret")
	}

	signature := r.Header.Get(HeaderHmac)
	if signature == "" {
		return nil, ErrMissingSignature
	}

	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, DefaultMaxVerifyBodySize+1))
		r.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("webhooks: failed to read the request body: %w", err)
		}
		if len(body) > DefaultMaxVerifyBodySize {
			return nil, errors.New("webhooks: request body is too large")
		}
	}

	// restore the body so that it could be read again
	r.Body = io.NopCloser(bytes.NewReader(body))

	if !CheckSignature(body, secret, signature) {
		return nil, ErrInvalidSignature
	}

	return body, nil
}
