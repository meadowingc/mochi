package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"mochi/lifecycle"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func testRuntimeEnvironment(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	env := filepath.Join(directory, "mochi.env")
	if err := os.WriteFile(env, []byte("CSRF_KEY=32-byte-long-auth-key-for-testing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MOCHI_ENV_FILE", env)
	t.Setenv("CSRF_KEY", "32-byte-long-auth-key-for-testing")
	t.Setenv("MOCHI_STATE_DIR", directory)
	t.Setenv("MOCHI_WORKERS", "disabled")
	t.Setenv("MOCHI_WORKER_START_DELAY", "")
	t.Setenv("MOCHI_REQUIRE_EXISTING", "0")
	t.Setenv("MOCHI_AUTO_MIGRATE", "enabled")
	t.Setenv("MOCHI_HTTP_ADDR", "127.0.0.1:4738")
	return directory
}

func TestRuntimeConfigurationGuards(t *testing.T) {
	directory := testRuntimeEnvironment(t)
	config, err := loadRuntimeConfig()
	if err != nil || config.workers || config.workerDelay != 0 {
		t.Fatalf("configuration: %+v, %v", config, err)
	}
	for key, value := range map[string]string{
		"MOCHI_HTTP_ADDR": "127.0.0.1:0", "MOCHI_WORKERS": "typo",
		"MOCHI_WORKER_START_DELAY": "-1s", "MOCHI_REQUIRE_EXISTING": "typo",
		"MOCHI_AUTO_MIGRATE": "typo",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, value)
			if _, err := loadRuntimeConfig(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	t.Setenv("MOCHI_REQUIRE_EXISTING", "1")
	if _, err := loadRuntimeConfig(); err == nil {
		t.Fatal("missing existing user directory accepted")
	}
	if err := os.Mkdir(filepath.Join(directory, ".user_databases"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRuntimeConfig(); err != nil {
		t.Fatal(err)
	}
}

func TestOccupiedPortFailsBeforeCreatingDatabases(t *testing.T) {
	directory := testRuntimeEnvironment(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("MOCHI_HTTP_ADDR", listener.Addr().String())
	if err := run(); err == nil {
		t.Fatal("occupied port did not fail")
	}
	if _, err := os.Stat(filepath.Join(directory, "shared.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("listener failure opened a store")
	}
}

func TestHealthIdentifiesModeAndRevisionWithoutCookies(t *testing.T) {
	directory := testRuntimeEnvironment(t)
	if err := os.Mkdir(filepath.Join(directory, ".user_databases"), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler := healthHandler(db, runtimeConfig{workers: false})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/healthz", nil))
	var body struct {
		Status        string `json:"status"`
		Revision      string `json:"revision"`
		Workers       bool   `json:"workers"`
		UserDatabases int    `json:"userDatabases"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || body.Status != "ok" || body.Revision != buildRevision ||
		body.Workers || body.UserDatabases != 0 || len(response.Result().Cookies()) != 0 {
		t.Fatalf("health response: %+v, %s", body, response.Body.String())
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/healthz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("closed database reported healthy")
	}
}

func TestServerDrainsHTTPAndAcceptedNestedWork(t *testing.T) {
	testRuntimeEnvironment(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handlerEntered, releaseHandler := make(chan struct{}), make(chan struct{})
	childEntered, releaseChild := make(chan struct{}), make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(handlerEntered)
		<-releaseHandler
		lifecycle.Background.Go(func() {
			lifecycle.Background.Go(func() { close(childEntered); <-releaseChild })
		})
		w.WriteHeader(http.StatusAccepted)
	})
	stopped := make(chan error, 1)
	go func() { stopped <- serve(ctx, listener, handler, runtimeConfig{}) }()
	requestDone := make(chan error, 1)
	go func() {
		client := http.Client{Timeout: 5 * time.Second}
		response, err := client.Get("http://" + listener.Addr().String())
		if response != nil {
			response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-handlerEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP handler did not start")
	}
	cancel()
	select {
	case <-stopped:
		t.Fatal("server abandoned accepted HTTP work")
	default:
	}
	close(releaseHandler)
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	<-childEntered
	select {
	case <-stopped:
		t.Fatal("server abandoned accepted nested background work")
	default:
	}
	close(releaseChild)
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish its drain")
	}
}
