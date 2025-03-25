package webmention_sender

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// StandardizeURL normalizes a URL to reduce duplicates and filters invalid URLs
func StandardizeURL(inputURL string) (string, error) {
	// Try to parse the URL
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}

	// Ensure URL has a scheme
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https" // Default to https if no scheme provided
	}

	// Only allow http and https schemes
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme: %s", parsedURL.Scheme)
	}

	// Check for localhost and other private/local addresses
	host := strings.ToLower(parsedURL.Hostname())

	// Reject localhost in various forms
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "", fmt.Errorf("localhost URLs are not allowed")
	}

	// Reject IP addresses that are private/local
	if ip := net.ParseIP(host); ip != nil {
		// Check for loopback addresses (127.0.0.1, ::1, etc)
		if ip.IsLoopback() {
			return "", fmt.Errorf("loopback IP addresses are not allowed")
		}

		// Check for private network addresses
		if ip.IsPrivate() {
			return "", fmt.Errorf("private network IP addresses are not allowed")
		}

		// Check for unspecified addresses (0.0.0.0, ::)
		if ip.IsUnspecified() {
			return "", fmt.Errorf("unspecified IP addresses are not allowed")
		}
	}

	// Convert hostname to lowercase
	parsedURL.Host = strings.ToLower(parsedURL.Host)

	// Remove trailing slash from path if present and path is not just "/"
	if parsedURL.Path != "/" && strings.HasSuffix(parsedURL.Path, "/") {
		parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
	}

	// Remove certain tracking parameters from URLs
	q := parsedURL.Query()
	parametersToRemove := []string{"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"}
	for _, param := range parametersToRemove {
		q.Del(param)
	}
	parsedURL.RawQuery = q.Encode()

	// Convert back to string
	return parsedURL.String(), nil
}
