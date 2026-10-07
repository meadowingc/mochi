package webmention_sender

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"mochi/safehttp"
	"mochi/shared_database"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

type senderResolver struct{}

func (senderResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if host != "source.example" && host != "target.example" {
		return nil, fmt.Errorf("unexpected DNS lookup: %s", host)
	}
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
}

func TestSenderDeliversAndPersistsWithoutRepeatingRecordedMentions(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "shared.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&shared_database.MonitoredURL{}, &shared_database.SentWebmention{}); err != nil {
		t.Fatal(err)
	}
	connection, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	originalDB, originalFactory := shared_database.Db, newHTTPClient
	shared_database.Db = db
	t.Cleanup(func() {
		shared_database.Db, newHTTPClient = originalDB, originalFactory
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
	})
	var deliveries atomic.Int32
	newHTTPClient = func(options ...safehttp.Option) *http.Client {
		options = append(options, safehttp.WithResolver(senderResolver{}),
			safehttp.WithDialContext(func(_ context.Context, _, address string) (net.Conn, error) {
				if address != "93.184.216.34:80" {
					return nil, fmt.Errorf("unexpected validated destination: %s", address)
				}
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					request, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil {
						t.Error(err)
						return
					}
					defer request.Body.Close()
					response := &http.Response{
						StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1,
						Header: make(http.Header), Close: true,
					}
					body := ""
					switch request.Host + request.URL.Path {
					case "source.example/feed":
						body = `<rss><channel><item><link>http://source.example/page</link></item><item><link>http://source.example/page</link></item></channel></rss>`
					case "source.example/page":
						body = `<a href="http://target.example/post">target</a><a href="/local">same domain</a>`
					case "target.example/post":
						response.Header.Set("Link", `</receive>; rel="webmention"`)
					case "target.example/receive":
						if err := request.ParseForm(); err != nil {
							t.Error(err)
						}
						if request.Method != http.MethodPost ||
							request.Form.Get("source") != "http://source.example/page" ||
							request.Form.Get("target") != "http://target.example/post" {
							t.Errorf("unexpected delivery: method=%s form=%v", request.Method, request.Form)
						}
						deliveries.Add(1)
						response.StatusCode, body = http.StatusAccepted, "accepted fixture"
					default:
						t.Errorf("unexpected fixture request: %s%s", request.Host, request.URL.Path)
						response.StatusCode = http.StatusNotFound
					}
					response.Body = io.NopCloser(strings.NewReader(body))
					response.ContentLength = int64(len(body))
					if err := response.Write(server); err != nil {
						t.Error(err)
					}
				}()
				return client, nil
			}))
		return safehttp.NewClient(options...)
	}
	monitored := shared_database.MonitoredURL{URL: "http://source.example/feed", IsRSS: true}
	if err := db.Create(&monitored).Error; err != nil {
		t.Fatal(err)
	}
	first := ProcessFeed(&monitored)
	if len(first) != 1 || first[0].StatusCode != http.StatusAccepted || first[0].ResponseBody != "accepted fixture" {
		t.Fatalf("first delivery = %#v", first)
	}
	if repeated := ProcessFeed(&monitored); len(repeated) != 0 {
		t.Fatalf("recorded mentions repeated: %#v", repeated)
	}
	if deliveries.Load() != 1 {
		t.Fatalf("deliveries = %d, want exactly one", deliveries.Load())
	}
	var saved shared_database.SentWebmention
	if err := db.First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	if saved.MonitoredURLID != monitored.ID || saved.SourceURL != "http://source.example/page" ||
		saved.TargetURL != "http://target.example/post" || saved.StatusCode != http.StatusAccepted {
		t.Fatalf("persisted result = %#v", saved)
	}
}
