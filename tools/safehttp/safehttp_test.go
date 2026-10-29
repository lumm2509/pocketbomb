package safehttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/tools/safehttp"
)

func TestIsBlockedIP(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // cloud metadata
		{"0.0.0.0", true},
		{"100.64.0.1", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"::1", true},
		{"::", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"::ffff:127.0.0.1", true},
		{"::ffff:10.0.0.1", true},
		{"64:ff9b::a00:1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false},
		{"::ffff:8.8.8.8", false},
	}

	for _, s := range scenarios {
		t.Run(s.ip, func(t *testing.T) {
			if v := safehttp.IsBlockedIP(netip.MustParseAddr(s.ip)); v != s.expected {
				t.Fatalf("Expected %v, got %v", s.expected, v)
			}
		})
	}
}

func TestClientFetch(t *testing.T) {
	t.Parallel()

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("other"))
	}))
	defer other.Close()

	release := make(chan struct{})

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			if r.Header.Get("User-Agent") != "test-agent" || r.Header.Get("Accept") != "application/json" {
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		case "/large":
			w.Write([]byte(strings.Repeat("a", 101)))
		case "/status":
			w.WriteHeader(404)
			w.Write([]byte("missing"))
		case "/redirect/1":
			http.Redirect(w, r, "/redirect/2", http.StatusFound)
		case "/redirect/2":
			http.Redirect(w, r, srvURL+"/ok", http.StatusMovedPermanently)
		case "/redirect/loop":
			http.Redirect(w, r, "/redirect/loop", http.StatusFound)
		case "/redirect/cross":
			http.Redirect(w, r, other.URL, http.StatusFound)
		case "/slow":
			<-release
		}
	}))
	defer srv.Close()
	defer close(release) // note: before srv.Close() (it waits for the active handlers)
	srvURL = srv.URL

	client := safehttp.NewClient(safehttp.Options{
		AllowPrivateTargets: true,
		UserAgent:           "test-agent",
		Timeout:             300 * time.Millisecond,
	})

	scenarios := []struct {
		name          string
		url           string
		opts          safehttp.FetchOptions
		expectStatus  int
		expectBody    string
		expectURL     string
		expectErr     string
		expectErrType error
	}{
		{"success", srv.URL + "/ok", safehttp.FetchOptions{Accept: "application/json"}, 200, `{"ok":true}`, srv.URL + "/ok", "", nil},
		{"non 2xx is returned", srv.URL + "/status", safehttp.FetchOptions{}, 404, "missing", srv.URL + "/status", "", nil},
		{"body limit", srv.URL + "/large", safehttp.FetchOptions{MaxBodySize: 100}, 0, "", "", "", safehttp.ErrResponseTooLarge},
		{"body at the limit", srv.URL + "/large", safehttp.FetchOptions{MaxBodySize: 101}, 200, strings.Repeat("a", 101), srv.URL + "/large", "", nil},
		{"same host redirects", srv.URL + "/redirect/1", safehttp.FetchOptions{MaxRedirects: 3, Accept: "application/json"}, 200, `{"ok":true}`, srv.URL + "/ok", "", nil},
		{"redirects not allowed", srv.URL + "/redirect/1", safehttp.FetchOptions{}, 0, "", "", "too many redirects", nil},
		{"too many redirects", srv.URL + "/redirect/loop", safehttp.FetchOptions{MaxRedirects: 3}, 0, "", "", "too many redirects", nil},
		{"cross-host redirect", srv.URL + "/redirect/cross", safehttp.FetchOptions{MaxRedirects: 3}, 0, "", "", "cross-host", nil},
		{"timeout", srv.URL + "/slow", safehttp.FetchOptions{}, 0, "", "", "timeout", nil},
		{"invalid url", "ftp://example.com", safehttp.FetchOptions{}, 0, "", "", "invalid target url", nil},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			res, err := client.Fetch(context.Background(), s.url, s.opts)

			if s.expectErr != "" || s.expectErrType != nil {
				if err == nil {
					t.Fatalf("Expected error, got %v", res)
				}
				if s.expectErr != "" && !strings.Contains(err.Error(), s.expectErr) {
					t.Fatalf("Expected error containing %q, got %v", s.expectErr, err)
				}
				if s.expectErrType != nil && !errors.Is(err, s.expectErrType) {
					t.Fatalf("Expected error %v, got %v", s.expectErrType, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if res.StatusCode != s.expectStatus || string(res.Body) != s.expectBody || res.URL != s.expectURL {
				t.Fatalf("Unexpected result %d %q %q", res.StatusCode, res.Body, res.URL)
			}
		})
	}
}

func TestClientFetchSSRFProtection(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := safehttp.NewClient(safehttp.Options{})

	_, err := client.Fetch(context.Background(), srv.URL, safehttp.FetchOptions{})
	if !errors.Is(err, safehttp.ErrBlockedTarget) {
		t.Fatalf("Expected ErrBlockedTarget, got %v", err)
	}
}
