package webhooks_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/tools/webhooks"
)

func testDelivery() *webhooks.Delivery {
	return &webhooks.Delivery{
		Id:             "d1",
		SubscriptionId: "s1",
		Event: webhooks.Event{
			Id:          "e1",
			Topic:       "posts.create",
			ApiVersion:  "2026-10",
			TriggeredAt: time.Date(2026, 10, 23, 10, 11, 12, 345000000, time.UTC),
			Payload:     json.RawMessage(`{"title":"hello"}`),
		},
	}
}

func TestNewRequest(t *testing.T) {
	t.Parallel()

	req := webhooks.NewRequest(testDelivery(), "https://example.com/hook", "secret", "")

	if req.URL != "https://example.com/hook" || req.Secret != "secret" {
		t.Fatalf("Unexpected url/secret: %q, %q", req.URL, req.Secret)
	}

	if string(req.Body) != `{"title":"hello"}` {
		t.Fatalf("Unexpected body %q", req.Body)
	}

	expectedHeaders := map[string]string{
		webhooks.HeaderTopic:       "posts.create",
		webhooks.HeaderWebhookId:   "d1",
		webhooks.HeaderEventId:     "e1",
		webhooks.HeaderTriggeredAt: "2026-10-23T10:11:12.345Z",
		webhooks.HeaderApiVersion:  "2026-10",
		"Content-Type":             "application/json",
	}
	for k, v := range expectedHeaders {
		if req.Header.Get(k) != v {
			t.Errorf("Expected header %s %q, got %q", k, v, req.Header.Get(k))
		}
	}

	// custom topic and empty payload
	d := testDelivery()
	d.Event.Payload = nil
	req = webhooks.NewRequest(d, "https://example.com", "secret", "custom.topic")
	if req.Header.Get(webhooks.HeaderTopic) != "custom.topic" {
		t.Fatalf("Expected custom topic header, got %q", req.Header.Get(webhooks.HeaderTopic))
	}
	if string(req.Body) != "{}" {
		t.Fatalf("Expected {} body, got %q", req.Body)
	}
}

func TestClientSendSuccess(t *testing.T) {
	t.Parallel()

	var received *http.Request
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := webhooks.Verify(r, "secret")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		received = r
		receivedBody = body
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(strings.Repeat("a", 10000)))
	}))
	defer srv.Close()

	client := webhooks.NewClient(webhooks.ClientOptions{AllowPrivateTargets: true})

	req := webhooks.NewRequest(testDelivery(), srv.URL, "secret", "")
	req.Header.Set("X-Extra", "extra")

	attempt := client.Send(context.Background(), req)

	if !attempt.Succeeded() {
		t.Fatalf("Expected successful attempt, got %#v", attempt)
	}

	if attempt.StatusCode != http.StatusAccepted {
		t.Fatalf("Expected status 202, got %d", attempt.StatusCode)
	}

	if len(attempt.ResponseBody) != webhooks.DefaultMaxResponseBodySize {
		t.Fatalf("Expected the response body to be capped to %d, got %d", webhooks.DefaultMaxResponseBodySize, len(attempt.ResponseBody))
	}

	if attempt.ResponseHeaders.Get("X-Test") != "ok" {
		t.Fatalf("Expected response header X-Test, got %v", attempt.ResponseHeaders)
	}

	if received == nil {
		t.Fatal("The request was not received")
	}

	if received.Header.Get("User-Agent") != webhooks.DefaultUserAgent {
		t.Fatalf("Unexpected user agent %q", received.Header.Get("User-Agent"))
	}

	if received.Header.Get("X-Extra") != "extra" {
		t.Fatal("Missing X-Extra header")
	}

	if received.Header.Get(webhooks.HeaderEventId) != "e1" {
		t.Fatal("Missing event id header")
	}

	if string(receivedBody) != `{"title":"hello"}` {
		t.Fatalf("Unexpected received body %q", receivedBody)
	}

	if attempt.RequestHeaders.Get(webhooks.HeaderHmac) == "" {
		t.Fatal("Expected the attempt request headers to contain the signature")
	}

	if attempt.Duration <= 0 {
		t.Fatal("Expected non-zero duration")
	}
}

func TestClientSendFailures(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/500":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("oops"))
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/slow":
			time.Sleep(500 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	client := webhooks.NewClient(webhooks.ClientOptions{
		AllowPrivateTargets: true,
		Timeout:             100 * time.Millisecond,
	})

	scenarios := []struct {
		name           string
		url            string
		expectedStatus int
		expectedError  string
	}{
		{"5xx", srv.URL + "/500", 500, ""},
		{"redirect is not followed", srv.URL + "/redirect", 302, "redirects are not followed"},
		{"timeout", srv.URL + "/slow", 0, "Post"},
		{"invalid scheme", "ftp://example.com", 0, "invalid target url"},
		{"relative url", "/test", 0, "invalid target url"},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			attempt := client.Send(context.Background(), webhooks.NewRequest(testDelivery(), s.url, "secret", ""))

			if attempt.Succeeded() {
				t.Fatal("Expected failed attempt")
			}

			if attempt.StatusCode != s.expectedStatus {
				t.Fatalf("Expected status %d, got %d", s.expectedStatus, attempt.StatusCode)
			}

			if !strings.Contains(attempt.Error, s.expectedError) {
				t.Fatalf("Expected error containing %q, got %q", s.expectedError, attempt.Error)
			}
		})
	}
}

func TestClientSSRFProtection(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// default (private targets are blocked)
	client := webhooks.NewClient(webhooks.ClientOptions{})

	attempt := client.Send(context.Background(), webhooks.NewRequest(testDelivery(), srv.URL, "secret", ""))
	if attempt.Succeeded() || !strings.Contains(attempt.Error, "not allowed") {
		t.Fatalf("Expected blocked target error, got %#v", attempt)
	}

	// localhost (resolved) should also be blocked
	localhostURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	attempt = client.Send(context.Background(), webhooks.NewRequest(testDelivery(), localhostURL, "secret", ""))
	if attempt.Succeeded() || !strings.Contains(attempt.Error, "not allowed") {
		t.Fatalf("Expected blocked localhost target error, got %#v", attempt)
	}

	if hits.Load() != 0 {
		t.Fatalf("Expected no hits, got %d", hits.Load())
	}

	// allow
	client.SetOptions(webhooks.ClientOptions{AllowPrivateTargets: true})
	if !client.Options().AllowPrivateTargets {
		t.Fatal("Expected AllowPrivateTargets to be updated")
	}

	attempt = client.Send(context.Background(), webhooks.NewRequest(testDelivery(), srv.URL, "secret", ""))
	if !attempt.Succeeded() {
		t.Fatalf("Expected successful attempt, got %#v", attempt)
	}

	if hits.Load() != 1 {
		t.Fatalf("Expected 1 hit, got %d", hits.Load())
	}
}

func TestClientSendFunc(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := webhooks.NewClient(webhooks.ClientOptions{AllowPrivateTargets: true})

	send := client.SendFunc(func(ctx context.Context, d *webhooks.Delivery) (*webhooks.Request, error) {
		if d.SubscriptionId == "disabled" {
			return nil, webhooks.ErrDisabled
		}
		return webhooks.NewRequest(d, srv.URL, "secret", ""), nil
	})

	attempt, err := send(context.Background(), testDelivery())
	if err != nil || !attempt.Succeeded() {
		t.Fatalf("Expected successful attempt, got %v, %#v", err, attempt)
	}

	d := testDelivery()
	d.SubscriptionId = "disabled"
	_, err = send(context.Background(), d)
	if !errors.Is(err, webhooks.ErrDisabled) {
		t.Fatalf("Expected ErrDisabled, got %v", err)
	}
}

func TestClientSendWithoutSecret(t *testing.T) {
	t.Parallel()

	var hmacHeader, contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hmacHeader = r.Header.Get(webhooks.HeaderHmac)
		contentType = r.Header.Get("Content-Type")
	}))
	defer srv.Close()

	client := webhooks.NewClient(webhooks.ClientOptions{AllowPrivateTargets: true})

	header := http.Header{}
	header.Set("Content-Type", "application/jwt")
	header.Set(webhooks.HeaderHmac, "forged")

	attempt := client.Send(context.Background(), &webhooks.Request{URL: srv.URL, Header: header, Body: []byte("a.b.c")})
	if !attempt.Succeeded() {
		t.Fatalf("Expected success, got %v", attempt.Error)
	}

	if hmacHeader != "" || contentType != "application/jwt" {
		t.Fatalf("Expected no signature header and the custom content type, got %q, %q", hmacHeader, contentType)
	}
}
