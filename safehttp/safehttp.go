// Package safehttp provides HTTP clients that refuse requests to non-public
// network destinations.
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout      = 30 * time.Second
	defaultDialTimeout  = 10 * time.Second
	defaultMaxRedirects = 10
)

// Resolver is the subset of net.Resolver used by Transport.
type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// DialContextFunc opens a network connection.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// RedirectPolicy has the same semantics as http.Client.CheckRedirect.
type RedirectPolicy func(*http.Request, []*http.Request) error

type config struct {
	resolver       Resolver
	dialContext    DialContextFunc
	timeout        time.Duration
	maxRedirects   int
	redirectPolicy RedirectPolicy
}

// Option configures a Client or Transport.
type Option func(*config)

// WithResolver supplies the DNS resolver used immediately before dialing.
func WithResolver(resolver Resolver) Option {
	return func(c *config) { c.resolver = resolver }
}

// WithDialContext supplies the dial function used after resolution and
// validation. It receives an IP address rather than the original hostname.
func WithDialContext(dial DialContextFunc) Option {
	return func(c *config) { c.dialContext = dial }
}

// WithTimeout sets the overall client request timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *config) { c.timeout = timeout }
}

// WithMaxRedirects sets the maximum redirects followed by a client.
func WithMaxRedirects(max int) Option {
	return func(c *config) { c.maxRedirects = max }
}

// WithRedirectPolicy adds a redirect policy. Safe URL validation and the
// redirect limit are always enforced before this policy is called.
func WithRedirectPolicy(policy RedirectPolicy) Option {
	return func(c *config) { c.redirectPolicy = policy }
}

func newConfig(options []Option) config {
	dialer := &net.Dialer{Timeout: defaultDialTimeout, KeepAlive: 30 * time.Second}
	c := config{
		resolver:     net.DefaultResolver,
		dialContext:  dialer.DialContext,
		timeout:      defaultTimeout,
		maxRedirects: defaultMaxRedirects,
	}
	for _, option := range options {
		option(&c)
	}
	return c
}

// Transport validates request URLs and resolves and validates every
// destination at dial time.
type Transport struct {
	base        *http.Transport
	resolver    Resolver
	dialContext DialContextFunc
}

// NewTransport creates a transport with environment proxy support disabled.
func NewTransport(options ...Option) *Transport {
	c := newConfig(options)
	t := &Transport{
		resolver:    c.resolver,
		dialContext: c.dialContext,
	}
	t.base = &http.Transport{
		Proxy:                 nil,
		DialContext:           t.dial,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return t
}

// NewClient creates an SSRF-safe client.
func NewClient(options ...Option) *http.Client {
	c := newConfig(options)
	if c.maxRedirects < 0 {
		c.maxRedirects = 0
	}
	return &http.Client{
		Transport: NewTransport(options...),
		Timeout:   c.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if err := ValidateURL(req.URL); err != nil {
				return fmt.Errorf("unsafe redirect target: %w", err)
			}
			if len(via) > c.maxRedirects {
				return fmt.Errorf("stopped after %d redirects", c.maxRedirects)
			}
			if c.redirectPolicy != nil {
				return c.redirectPolicy(req, via)
			}
			return nil
		},
	}
}

// ValidateURL validates the URL properties that do not require DNS.
// Resolved addresses are validated separately at dial time.
func ValidateURL(u *url.URL) error {
	if u == nil {
		return errors.New("URL is nil")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if u.User != nil {
		return errors.New("URL userinfo is not allowed")
	}
	if u.Host == "" || u.Hostname() == "" {
		return errors.New("URL hostname is required")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("localhost is not allowed")
	}
	if port := u.Port(); port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return fmt.Errorf("invalid URL port %q", port)
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return validateAddr(ip)
	}
	return nil
}

// ValidateURLString parses and validates a URL without performing DNS.
func ValidateURLString(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	return ValidateURL(u)
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := ValidateURL(req.URL); err != nil {
		return nil, fmt.Errorf("unsafe request URL: %w", err)
	}
	return t.base.RoundTrip(req)
}

func (t *Transport) CloseIdleConnections() {
	t.base.CloseIdleConnections()
}

func (t *Transport) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid dial address: %w", err)
	}

	var addresses []net.IPAddr
	if addr, parseErr := netip.ParseAddr(strings.Trim(host, "[]")); parseErr == nil {
		addresses = []net.IPAddr{{IP: net.IP(addr.AsSlice())}}
	} else {
		addresses, err = t.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("resolve %q: no addresses", host)
		}
	}

	validated := make([]netip.Addr, 0, len(addresses))
	for _, ipAddress := range addresses {
		addr, ok := netip.AddrFromSlice(ipAddress.IP)
		if !ok {
			return nil, fmt.Errorf("resolve %q: invalid IP address", host)
		}
		addr = addr.Unmap()
		if err := validateAddr(addr); err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		validated = append(validated, addr)
	}

	var dialErrors []error
	for _, addr := range validated {
		dialNetwork := network
		if strings.HasPrefix(network, "tcp") {
			if addr.Is4() {
				dialNetwork = "tcp4"
			} else {
				dialNetwork = "tcp6"
			}
		}
		conn, dialErr := t.dialContext(ctx, dialNetwork, net.JoinHostPort(addr.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, dialErr)
	}
	return nil, fmt.Errorf("dial %q: %w", host, errors.Join(dialErrors...))
}

var forbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func validateAddr(addr netip.Addr) error {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return errors.New("invalid IP address")
	}
	for _, prefix := range forbiddenPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("forbidden IP address %s", addr)
		}
	}
	if !addr.IsGlobalUnicast() {
		return fmt.Errorf("non-global IP address %s", addr)
	}
	return nil
}
