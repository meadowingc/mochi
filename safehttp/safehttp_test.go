package safehttp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type staticResolver map[string][]string

func (r staticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	values, ok := r[host]
	if !ok {
		return nil, fmt.Errorf("unexpected lookup of %s", host)
	}
	result := make([]net.IPAddr, 0, len(values))
	for _, value := range values {
		result = append(result, net.IPAddr{IP: net.ParseIP(value)})
	}
	return result, nil
}

func TestValidateURLRejectsUnsafeURLs(t *testing.T) {
	t.Parallel()
	tests := []string{
		"ftp://example.com/file",
		"http:///missing-host",
		"http://user:password@example.com/",
		"http://localhost/",
		"http://127.0.0.1/",
		"http://0.0.0.0/",
		"http://10.1.2.3/",
		"http://100.100.100.200/",
		"http://100.64.0.1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://192.0.2.1/",
		"http://224.0.0.1/",
		"http://240.0.0.1/",
		"http://[::]/",
		"http://[::1]/",
		"http://[fc00::1]/",
		"http://[fd00:ec2::254]/",
		"http://[fe80::1]/",
		"http://[ff02::1]/",
		"http://[2001:db8::1]/",
		"http://[::ffff:127.0.0.1]/",
		"http://[::ffff:169.254.169.254]/",
	}
	for _, rawURL := range tests {
		rawURL := rawURL
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			if err := ValidateURLString(rawURL); err == nil {
				t.Fatalf("ValidateURLString(%q) unexpectedly succeeded", rawURL)
			}
		})
	}
}

func TestResolvedForbiddenOrMixedAnswersAreRejected(t *testing.T) {
	t.Parallel()
	tests := map[string][]string{
		"private-v4.example": {"10.0.0.8"},
		"metadata.example":   {"169.254.169.254"},
		"cgnat.example":      {"100.100.100.200"},
		"private-v6.example": {"fd00::8"},
		"linklocal.example":  {"fe80::8"},
		"mapped.example":     {"::ffff:10.0.0.8"},
		"mixed.example":      {"93.184.216.34", "127.0.0.1"},
	}
	for host, answers := range tests {
		host, answers := host, answers
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			dialed := false
			client := NewClient(
				WithResolver(staticResolver{host: answers}),
				WithDialContext(func(context.Context, string, string) (net.Conn, error) {
					dialed = true
					return nil, errorsForTest("dial should not be called")
				}),
			)
			_, err := client.Get("http://" + host)
			if err == nil {
				t.Fatal("request unexpectedly succeeded")
			}
			if dialed {
				t.Fatal("dial was called for a forbidden DNS answer")
			}
		})
	}
}

func TestAllowedPublicResolutionDialsValidatedAddressAndAlternatePort(t *testing.T) {
	t.Parallel()
	var gotNetwork, gotAddress string
	client := NewClient(
		WithResolver(staticResolver{"public.example": {"93.184.216.34"}}),
		WithDialContext(func(_ context.Context, network, address string) (net.Conn, error) {
			gotNetwork, gotAddress = network, address
			clientConn, serverConn := net.Pipe()
			go serveOneResponse(serverConn, "200 OK", nil, "ok")
			return clientConn, nil
		}),
	)

	resp, err := client.Get("http://public.example:8088/path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if gotNetwork != "tcp4" || gotAddress != "93.184.216.34:8088" {
		t.Fatalf("dial got (%q, %q)", gotNetwork, gotAddress)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
}

func TestRedirectToPrivateIsRejected(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	dialCount := 0
	client := NewClient(
		WithResolver(staticResolver{"public.example": {"93.184.216.34"}}),
		WithDialContext(func(_ context.Context, _, _ string) (net.Conn, error) {
			mu.Lock()
			dialCount++
			mu.Unlock()
			clientConn, serverConn := net.Pipe()
			go serveOneResponse(serverConn, "302 Found", map[string]string{
				"Location": "http://169.254.169.254/metadata",
			}, "")
			return clientConn, nil
		}),
	)

	_, err := client.Get("http://public.example/start")
	if err == nil || !strings.Contains(err.Error(), "unsafe redirect target") {
		t.Fatalf("expected unsafe redirect error, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if dialCount != 1 {
		t.Fatalf("dial count = %d, want 1", dialCount)
	}
}

func TestNoRedirectPolicyPreservesResponse(t *testing.T) {
	t.Parallel()
	client := NewClient(
		WithResolver(staticResolver{"public.example": {"93.184.216.34"}}),
		WithDialContext(func(_ context.Context, _, _ string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go serveOneResponse(serverConn, "302 Found", map[string]string{
				"Location": "https://other.example/",
			}, "")
			return clientConn, nil
		}),
		WithRedirectPolicy(func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}),
	)
	resp, err := client.Get("http://public.example/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestRedirectsAreCapped(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	dialCount := 0
	client := NewClient(
		WithResolver(staticResolver{"public.example": {"93.184.216.34"}}),
		WithDialContext(func(_ context.Context, _, _ string) (net.Conn, error) {
			mu.Lock()
			dialCount++
			mu.Unlock()
			clientConn, serverConn := net.Pipe()
			go serveOneResponse(serverConn, "302 Found", map[string]string{
				"Location": "http://public.example/again",
			}, "")
			return clientConn, nil
		}),
		WithMaxRedirects(1),
	)
	_, err := client.Get("http://public.example/start")
	if err == nil || !strings.Contains(err.Error(), "stopped after 1 redirects") {
		t.Fatalf("expected redirect limit error, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if dialCount != 2 {
		t.Fatalf("dial count = %d, want 2", dialCount)
	}
}

func TestTransportDisablesProxyAndLeavesTLSHostnameDerivedFromRequest(t *testing.T) {
	t.Parallel()
	transport := NewTransport()
	if transport.base.Proxy != nil {
		t.Fatal("proxy function is enabled")
	}
	if transport.base.TLSClientConfig != nil && transport.base.TLSClientConfig.ServerName != "" {
		t.Fatalf("fixed TLS ServerName = %q", transport.base.TLSClientConfig.ServerName)
	}
}

type errorsForTest string

func (e errorsForTest) Error() string { return string(e) }

func serveOneResponse(conn net.Conn, status string, headers map[string]string, body string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	req.Body.Close()
	fmt.Fprintf(conn, "HTTP/1.1 %s\r\nContent-Length: %d\r\n", status, len(body))
	for name, value := range headers {
		fmt.Fprintf(conn, "%s: %s\r\n", name, value)
	}
	fmt.Fprintf(conn, "Connection: close\r\n\r\n%s", body)
}
