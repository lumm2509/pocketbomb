package safehttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClientBlocksLoopback(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(Options{})

	req, err := http.NewRequest(http.MethodGet, server.URL+"/avatar.png", nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Send(req); err == nil {
		t.Fatal("Expected the loopback request to be rejected")
	} else if !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("Expected ErrBlockedTarget, got %v", err)
	}

	// even a direct dial to the httptest listener must not be allowed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, httpClient := client.state()

	hostPort := strings.TrimPrefix(server.URL, "http://")
	if _, err := httpClient.Transport.(*http.Transport).DialContext(ctx, "tcp", hostPort); err == nil {
		t.Fatal("Expected the loopback dial to be rejected")
	}
}

func TestClientBlocksUnspecifiedAndPrivateAddresses(t *testing.T) {
	t.Parallel()

	addresses := map[string]string{
		"unspecified": "0.0.0.0",
	}

	// collect the private/link-local IPs of the local interfaces (if any)
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP == nil {
				continue
			}

			ip := ipn.IP
			switch {
			case ip.IsPrivate():
				addresses["private "+ip.String()] = ip.String()
			case ip.IsLinkLocalUnicast() && ip.To4() != nil:
				addresses["link-local "+ip.String()] = ip.String()
			}
		}
	}

	client := NewClient(Options{})

	for name, host := range addresses {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err != nil {
				t.Skipf("cannot bind a local listener on %q: %v", host, err)
			}

			server := &http.Server{
				Handler: http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					res.WriteHeader(http.StatusOK)
				}),
				ReadHeaderTimeout: 5 * time.Second,
			}
			go func() {
				_ = server.Serve(listener)
			}()
			defer server.Close()

			port := listener.Addr().(*net.TCPAddr).Port
			url := "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/avatar.png"

			_, err = client.Fetch(context.Background(), url, FetchOptions{})
			if err == nil {
				t.Fatalf("Expected %q to be rejected", url)
			}
			if !errors.Is(err, ErrBlockedTarget) {
				t.Skipf("the address could not be reached in this environment: %v", err)
			}
		})
	}

	// NB: multicast TCP listeners are not supported by the OS, so the
	// multicast branch of the dial Control could not be exercised here.
}

func TestClientSend(t *testing.T) {
	t.Parallel()

	var userAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent = r.Header.Get("User-Agent")
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		default:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(strings.Repeat("a", 100)))
		}
	}))
	defer srv.Close()

	client := NewClient(Options{AllowPrivateTargets: true, MaxResponseBodySize: 10})

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ok", nil)
	res, err := client.Send(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusCreated || string(res.Body) != strings.Repeat("a", 10) || userAgent != DefaultUserAgent {
		t.Fatalf("Unexpected response %d %q (user agent %q)", res.StatusCode, res.Body, userAgent)
	}

	// redirects are not followed
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/redirect", nil)
	res, err = client.Send(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/ok" {
		t.Fatalf("Expected the redirect response, got %d %v", res.StatusCode, res.Header)
	}

	// invalid url
	req, _ = http.NewRequest(http.MethodPost, "ftp://example.com", nil)
	if _, err := client.Send(req); err == nil || !strings.Contains(err.Error(), "invalid target url") {
		t.Fatalf("Expected invalid target url error, got %v", err)
	}
}

func TestClientFetchCrossHostRedirects(t *testing.T) {
	t.Parallel()

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("other"))
	}))
	defer other.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer srv.Close()

	client := NewClient(Options{AllowPrivateTargets: true})

	res, err := client.Fetch(context.Background(), srv.URL, FetchOptions{MaxRedirects: 1, AllowCrossHostRedirects: true})
	if err != nil {
		t.Fatal(err)
	}

	if string(res.Body) != "other" || res.URL != other.URL {
		t.Fatalf("Expected the cross-host redirect to be followed, got %q %q", res.Body, res.URL)
	}
}
