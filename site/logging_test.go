package site

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func captureLogs(t *testing.T, run func()) string {
	t.Helper()

	var output bytes.Buffer
	originalWriter := log.Writer()
	originalFlags := log.Flags()
	originalPrefix := log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(originalWriter)
		log.SetFlags(originalFlags)
		log.SetPrefix(originalPrefix)
	})

	run()
	return output.String()
}

func TestLoggerUsesMatchedRoutePattern(t *testing.T) {
	const (
		username = "logger-private-user"
		publicID = "public-id-884422"
	)

	router := chi.NewRouter()
	router.Use(Logger)
	router.Get("/users/{username}/sites/{publicID}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	logOutput := captureLogs(t, func() {
		router.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/users/"+username+"/sites/"+publicID, nil),
		)
	})

	if !strings.Contains(logOutput, "/users/{username}/sites/{publicID}") {
		t.Fatalf("log does not contain matched route pattern: %q", logOutput)
	}
	for _, sensitiveValue := range []string{username, publicID} {
		if strings.Contains(logOutput, sensitiveValue) {
			t.Errorf("log contains supplied identifier %q: %q", sensitiveValue, logOutput)
		}
	}
}

func TestLoggerUsesPlaceholderForUnmatchedPath(t *testing.T) {
	const attackerPath = "/not-found/private-user/public-id-998877"

	router := chi.NewRouter()
	router.Use(Logger)
	router.Get("/known", func(http.ResponseWriter, *http.Request) {})

	logOutput := captureLogs(t, func() {
		router.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, attackerPath, nil),
		)
	})

	if !strings.Contains(logOutput, "<unmatched>") {
		t.Fatalf("log does not contain unmatched placeholder: %q", logOutput)
	}
	for _, sensitiveValue := range []string{attackerPath, "private-user", "public-id-998877"} {
		if strings.Contains(logOutput, sensitiveValue) {
			t.Errorf("log contains unmatched path data %q: %q", sensitiveValue, logOutput)
		}
	}
}

func TestMalformedAuthenticationCookieValueIsNotLogged(t *testing.T) {
	const cookieValue = "secret-session-cookie-value"

	handler := TryPutUserInContextMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  string(AuthenticatedUserTokenCookieName),
		Value: cookieValue,
	})

	logOutput := captureLogs(t, func() {
		handler.ServeHTTP(httptest.NewRecorder(), request)
	})

	if strings.Contains(logOutput, cookieValue) {
		t.Fatalf("log contains malformed cookie value: %q", logOutput)
	}
	if !strings.Contains(logOutput, "Invalid authentication cookie") {
		t.Fatalf("log does not contain generic malformed-cookie diagnostic: %q", logOutput)
	}
}
