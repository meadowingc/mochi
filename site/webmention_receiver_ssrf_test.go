package site

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"mochi/safehttp"
	"mochi/shared_database"
	"mochi/user_database"
)

type receiverStaticResolver map[string][]string

func (resolver receiverStaticResolver) LookupIPAddr(
	_ context.Context,
	host string,
) ([]net.IPAddr, error) {
	values, ok := resolver[host]
	if !ok {
		return nil, fmt.Errorf("unexpected DNS lookup for %s", host)
	}
	addresses := make([]net.IPAddr, 0, len(values))
	for _, value := range values {
		addresses = append(addresses, net.IPAddr{IP: net.ParseIP(value)})
	}
	return addresses, nil
}

func TestWebmentionReceiverRejectsUnsafeSourceAndTargetBeforeWork(t *testing.T) {
	originalFactory := newWebmentionReceiverHTTPClient
	factoryCalls := 0
	newWebmentionReceiverHTTPClient = func(...safehttp.Option) *http.Client {
		factoryCalls++
		return safehttp.NewClient()
	}
	t.Cleanup(func() {
		newWebmentionReceiverHTTPClient = originalFactory
	})

	resolved := &resolvedPublicSite{
		Route:  &shared_database.PublicSiteRoute{PublicID: "opaque", Username: "private-owner", SiteID: 1},
		UserDB: &user_database.UserDb{},
		Site:   &user_database.Site{URL: "https://target.example"},
	}
	testCases := []struct {
		name   string
		source string
		target string
	}{
		{name: "private source", source: "http://10.0.0.8/post", target: "https://target.example/post"},
		{name: "reserved source", source: "http://192.0.2.8/post", target: "https://target.example/post"},
		{name: "source userinfo", source: "******source.example/post", target: "https://target.example/post"},
		{name: "private target", source: "https://source.example/post", target: "http://127.0.0.1/post"},
		{name: "metadata target", source: "https://source.example/post", target: "http://169.254.169.254/latest"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			form := url.Values{
				"source": {testCase.source},
				"target": {testCase.target},
			}
			request := httptest.NewRequest(
				http.MethodPost,
				"/webmention/opaque/receive",
				strings.NewReader(form.Encode()),
			)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request = withResolvedPublicSite(request, resolved)
			recorder := httptest.NewRecorder()

			WebmentionReceive(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
			}
		})
	}
	if factoryCalls != 0 {
		t.Fatalf("HTTP client factory called %d times for preflight-rejected URLs", factoryCalls)
	}
}

func TestWebmentionReceiverSafeClientBlocksPrivateRedirectWithoutNetwork(t *testing.T) {
	var mutex sync.Mutex
	dialCount := 0
	client := newWebmentionReceiverHTTPClient(
		safehttp.WithResolver(receiverStaticResolver{
			"source.example": {"93.184.216.34"},
		}),
		safehttp.WithDialContext(func(_ context.Context, _, _ string) (net.Conn, error) {
			mutex.Lock()
			dialCount++
			mutex.Unlock()
			clientConnection, serverConnection := net.Pipe()
			go serveReceiverResponse(
				serverConnection,
				"http://169.254.169.254/latest/meta-data",
				"",
			)
			return clientConnection, nil
		}),
	)
	if _, ok := client.Transport.(*safehttp.Transport); !ok {
		t.Fatalf("receiver transport is %T, want *safehttp.Transport", client.Transport)
	}

	response, err := client.Get("http://source.example/post")
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "unsafe redirect target") {
		t.Fatalf("redirect error = %v, want unsafe redirect rejection", err)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if dialCount != 1 {
		t.Fatalf("dial count = %d, want one public destination only", dialCount)
	}
}

func TestWebmentionReceiverAllowedFlowUsesInjectedSafeTransport(t *testing.T) {
	fixture := newPublicSiteFixture(t, true)
	route, err := fixture.deps.createRoute(fixture.owner.Username, fixture.site.ID)
	if err != nil {
		t.Fatal(err)
	}
	resolved := &resolvedPublicSite{
		Route:  route,
		UserDB: fixture.userDB,
		Site:   &fixture.site,
	}

	callChannel := make(chan string, 3)
	originalFactory := newWebmentionReceiverHTTPClient
	newWebmentionReceiverHTTPClient = func(options ...safehttp.Option) *http.Client {
		options = append(options,
			safehttp.WithResolver(receiverStaticResolver{
				"source.example": {"93.184.216.34"},
				"target.example": {"93.184.216.34"},
			}),
			safehttp.WithDialContext(func(_ context.Context, _, _ string) (net.Conn, error) {
				clientConnection, serverConnection := net.Pipe()
				go func() {
					defer serverConnection.Close()
					request, readErr := http.ReadRequest(bufio.NewReader(serverConnection))
					if readErr != nil {
						return
					}
					_ = request.Body.Close()
					callChannel <- request.Method + " " + request.Host

					body := ""
					if request.Method == http.MethodGet && request.Host == "source.example" {
						body = `<a href="http://target.example/post">target</a>`
					}
					_, _ = fmt.Fprintf(
						serverConnection,
						"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
						len(body),
						body,
					)
				}()
				return clientConnection, nil
			}),
		)
		return safehttp.NewClient(options...)
	}
	t.Cleanup(func() {
		newWebmentionReceiverHTTPClient = originalFactory
	})

	notificationChannel := make(chan struct{}, 1)
	originalNotification := sendWebmentionNotification
	sendWebmentionNotification = func(string, string) error {
		notificationChannel <- struct{}{}
		return nil
	}
	t.Cleanup(func() {
		sendWebmentionNotification = originalNotification
	})

	form := url.Values{
		"source": {"http://source.example/post"},
		"target": {"http://target.example/post"},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/webmention/"+route.PublicID+"/receive",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = withResolvedPublicSite(request, resolved)
	recorder := httptest.NewRecorder()
	WebmentionReceive(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
	}

	select {
	case <-notificationChannel:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for allowed webmention processing")
	}

	calls := make(map[string]bool)
	for range 3 {
		select {
		case call := <-callChannel:
			calls[call] = true
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for receiver HTTP calls")
		}
	}
	for _, expected := range []string{
		"HEAD source.example",
		"GET source.example",
		"GET target.example",
	} {
		if !calls[expected] {
			t.Errorf("missing receiver request %q; got %v", expected, calls)
		}
	}

	var stored []user_database.WebMention
	if err := fixture.userDB.Db.Find(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].SiteID != fixture.site.ID {
		t.Fatalf("stored webmentions = %#v", stored)
	}
}

func serveReceiverResponse(connection net.Conn, redirectLocation string, body string) {
	defer connection.Close()
	request, err := http.ReadRequest(bufio.NewReader(connection))
	if err != nil {
		return
	}
	_ = request.Body.Close()
	status := "200 OK"
	headers := ""
	if redirectLocation != "" {
		status = "302 Found"
		headers = "Location: " + redirectLocation + "\r\n"
	}
	_, _ = fmt.Fprintf(
		connection,
		"HTTP/1.1 %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status,
		headers,
		len(body),
		body,
	)
}
