package webmention_sender

import (
	"strings"
	"testing"

	"mochi/safehttp"
)

func TestSenderClientFactoryUsesSafeTransport(t *testing.T) {
	client := newHTTPClient()
	if _, ok := client.Transport.(*safehttp.Transport); !ok {
		t.Fatalf("sender transport is %T, want *safehttp.Transport", client.Transport)
	}
}

func TestDiscoverEndpointRejectsUnsafeTargetBeforeNetworkAccess(t *testing.T) {
	tests := []string{
		"http://127.0.0.1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]/",
		"file:///etc/passwd",
		"http://user@example.com/",
	}
	for _, target := range tests {
		t.Run(target, func(t *testing.T) {
			if _, err := discoverWebmentionEndpoint(target); err == nil {
				t.Fatalf("discoverWebmentionEndpoint(%q) unexpectedly succeeded", target)
			}
		})
	}
}

func TestResolveAndValidateEndpoint(t *testing.T) {
	t.Run("public relative endpoint", func(t *testing.T) {
		got, err := resolveAndValidateEndpoint("https://public.example/articles/one", "/webmention")
		if err != nil {
			t.Fatal(err)
		}
		if got != "https://public.example/webmention" {
			t.Fatalf("endpoint = %q", got)
		}
	})

	for _, endpoint := range []string{
		"//169.254.169.254/webmention",
		"http://10.0.0.1/webmention",
		"ftp://public.example/webmention",
		"http://user@public.example/webmention",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := resolveAndValidateEndpoint("https://public.example/post", endpoint); err == nil {
				t.Fatalf("endpoint %q unexpectedly accepted", endpoint)
			}
		})
	}
}

func TestReadLimitedBody(t *testing.T) {
	body, err := readLimitedBody(strings.NewReader("12345"), 5)
	if err != nil || string(body) != "12345" {
		t.Fatalf("exact limit: body=%q err=%v", body, err)
	}
	body, err = readLimitedBody(strings.NewReader("123456"), 5)
	if err == nil {
		t.Fatal("oversized body unexpectedly succeeded")
	}
	if body != nil {
		t.Fatalf("oversized body returned partial data %q", body)
	}
}
