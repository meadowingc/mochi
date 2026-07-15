package site

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"mochi/constants"
	"mochi/user_database"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

func useTemporaryUserDatabases(t *testing.T) {
	t.Helper()

	originalWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	testDirectory, err := os.MkdirTemp(originalWorkingDirectory, ".mochi-security-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(testDirectory); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		user_database.CleanupOnAppClose()
		if err := os.Chdir(originalWorkingDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
		if err := os.RemoveAll(testDirectory); err != nil {
			t.Errorf("remove test directory: %v", err)
		}
	})
}

func cookieNamed(t *testing.T, recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q was not set", name)
	return nil
}

func assertSessionCookieSecurity(t *testing.T, cookie *http.Cookie) {
	t.Helper()
	if !cookie.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}
	if cookie.Secure != !constants.DEBUG_MODE {
		t.Errorf("session cookie Secure = %v, want %v", cookie.Secure, !constants.DEBUG_MODE)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("session cookie Path = %q, want /", cookie.Path)
	}
}

func TestSessionCookieAttributesAndClearing(t *testing.T) {
	expiresAt := newSessionExpiry()
	recorder := httptest.NewRecorder()
	setUserSession(recorder, "alice", "token", expiresAt)

	cookie := cookieNamed(t, recorder, string(AuthenticatedUserTokenCookieName))
	assertSessionCookieSecurity(t, cookie)
	if cookie.MaxAge != int(userSessionDuration/time.Second) {
		t.Errorf("MaxAge = %d, want %d", cookie.MaxAge, int(userSessionDuration/time.Second))
	}
	if !cookie.Expires.Equal(expiresAt) {
		t.Errorf("Expires = %v, want %v", cookie.Expires, expiresAt)
	}

	recorder = httptest.NewRecorder()
	clearUserSession(recorder)
	cookie = cookieNamed(t, recorder, string(AuthenticatedUserTokenCookieName))
	assertSessionCookieSecurity(t, cookie)
	if cookie.MaxAge != -1 {
		t.Errorf("clearing MaxAge = %d, want -1", cookie.MaxAge)
	}
	if !cookie.Expires.Before(time.Now()) {
		t.Errorf("clearing Expires = %v, want a past time", cookie.Expires)
	}

	recorder = httptest.NewRecorder()
	UserLogout(recorder, httptest.NewRequest(http.MethodPost, "/user/logout", nil))
	cookie = cookieNamed(t, recorder, string(AuthenticatedUserTokenCookieName))
	assertSessionCookieSecurity(t, cookie)
	if cookie.MaxAge != -1 {
		t.Errorf("logout MaxAge = %d, want -1", cookie.MaxAge)
	}
}

func TestSessionExpiryValidation(t *testing.T) {
	useTemporaryUserDatabases(t)

	testCases := []struct {
		name      string
		expiresAt time.Time
		accepted  bool
	}{
		{name: "zero", expiresAt: time.Time{}},
		{name: "expired", expiresAt: time.Now().Add(-time.Minute)},
		{name: "valid", expiresAt: time.Now().Add(time.Hour), accepted: true},
	}

	for index, testCase := range testCases {
		username := "session-" + testCase.name
		token := "token-" + testCase.name
		db := user_database.GetOrCreateDB(username)
		user := user_database.User{
			Username:         username,
			PasswordHash:     []byte(`"unused"`),
			SessionToken:     token,
			SessionExpiresAt: testCase.expiresAt,
		}
		if err := db.Db.Create(&user).Error; err != nil {
			t.Fatal(err)
		}

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{
			Name:  string(AuthenticatedUserTokenCookieName),
			Value: token + "///" + username,
		})
		handler := TryPutUserInContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := GetSignedInUserOrNil(r); (got != nil) != testCase.accepted {
				t.Errorf("case %d (%s): authenticated = %v, want %v", index, testCase.name, got != nil, testCase.accepted)
			}
		}))
		handler.ServeHTTP(recorder, request)

		if testCase.accepted {
			for _, cookie := range recorder.Result().Cookies() {
				if cookie.Name == string(AuthenticatedUserTokenCookieName) {
					t.Errorf("%s session unexpectedly cleared", testCase.name)
				}
			}
		} else {
			cleared := cookieNamed(t, recorder, string(AuthenticatedUserTokenCookieName))
			assertSessionCookieSecurity(t, cleared)
			if cleared.MaxAge != -1 {
				t.Errorf("%s session clearing MaxAge = %d", testCase.name, cleared.MaxAge)
			}
		}
	}
}

func TestEmptySessionTokenIsRejected(t *testing.T) {
	useTemporaryUserDatabases(t)

	const username = "active-user"
	db := user_database.GetOrCreateDB(username)
	user := user_database.User{
		Username:         username,
		PasswordHash:     []byte(`"unused"`),
		SessionToken:     "active-token",
		SessionExpiresAt: time.Now().Add(time.Hour),
	}
	if err := db.Db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  string(AuthenticatedUserTokenCookieName),
		Value: "///" + username,
	})
	handler := TryPutUserInContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := GetSignedInUserOrNil(r); got != nil {
			t.Errorf("empty session token authenticated user %q", got.Username)
		}
	}))
	handler.ServeHTTP(recorder, request)

	cleared := cookieNamed(t, recorder, string(AuthenticatedUserTokenCookieName))
	assertSessionCookieSecurity(t, cleared)
	if cleared.MaxAge != -1 {
		t.Errorf("empty-token session clearing MaxAge = %d, want -1", cleared.MaxAge)
	}
}

func TestAuthenticationFlowsSetSessionExpiry(t *testing.T) {
	useTemporaryUserDatabases(t)

	username := "lifecycle-user"
	password := "initial-password"
	registerForm := url.Values{"username": {username}, "password": {password}}
	registerRecorder := httptest.NewRecorder()
	registerRequest := httptest.NewRequest(http.MethodPost, "/user/register", strings.NewReader(registerForm.Encode()))
	registerRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	UserRegister(registerRecorder, registerRequest)

	db := user_database.GetDbIfExists(username)
	if db == nil {
		t.Fatal("registration did not create a user database")
	}
	var user user_database.User
	if err := db.Db.Where("username = ?", username).First(&user).Error; err != nil {
		t.Fatal(err)
	}
	assertNewSessionExpiry(t, registerRecorder, &user)
	registrationToken := user.SessionToken

	loginRecorder := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodPost, "/user/login", strings.NewReader(registerForm.Encode()))
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	UserLogin(loginRecorder, loginRequest)
	if err := db.Db.Where("username = ?", username).First(&user).Error; err != nil {
		t.Fatal(err)
	}
	assertNewSessionExpiry(t, loginRecorder, &user)
	if user.SessionToken == registrationToken {
		t.Error("login did not rotate the session token")
	}
	loginToken := user.SessionToken

	changeForm := url.Values{
		"current-password": {password},
		"new-password":     {"updated-password"},
		"confirm-password": {"updated-password"},
	}
	changeRecorder := httptest.NewRecorder()
	changeRequest := httptest.NewRequest(http.MethodPost, "/dashboard/settings/password", strings.NewReader(changeForm.Encode()))
	changeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	changeRequest = changeRequest.WithContext(context.WithValue(
		changeRequest.Context(), AuthenticatedUserCookieName, &user,
	))
	ChangePassword(changeRecorder, changeRequest)
	if err := db.Db.Where("username = ?", username).First(&user).Error; err != nil {
		t.Fatal(err)
	}
	assertNewSessionExpiry(t, changeRecorder, &user)
	if user.SessionToken == loginToken {
		t.Error("password change did not rotate the session token")
	}
}

func assertNewSessionExpiry(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	user *user_database.User,
) {
	t.Helper()
	if user.SessionExpiresAt.Before(time.Now().Add(userSessionDuration - time.Minute)) {
		t.Errorf("session expiry %v is not approximately 30 days in the future", user.SessionExpiresAt)
	}
	cookie := cookieNamed(t, recorder, string(AuthenticatedUserTokenCookieName))
	assertSessionCookieSecurity(t, cookie)
	if !cookie.Expires.Equal(user.SessionExpiresAt) {
		t.Errorf("cookie expiry %v does not match stored expiry %v", cookie.Expires, user.SessionExpiresAt)
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	useTemporaryUserDatabases(t)

	emptyUsername := "empty-user-db"
	user_database.GetOrCreateDB(emptyUsername)

	badPasswordUsername := "bad-password-user"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := user_database.GetOrCreateDB(badPasswordUsername).Db.Create(&user_database.User{
		Username:     badPasswordUsername,
		PasswordHash: passwordHash,
		SessionToken: "bad-password-token",
	}).Error; err != nil {
		t.Fatal(err)
	}

	usernames := []string{"missing-user-db", emptyUsername, badPasswordUsername}
	var expectedStatus int
	var expectedLocation string
	var expectedFlash string
	for index, username := range usernames {
		form := url.Values{"username": {username}, "password": {"wrong-password"}}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/user/login", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		UserLogin(recorder, request)

		flashCookie := cookieNamed(t, recorder, FlashMessageCookieName)
		decodedFlash, err := base64.StdEncoding.DecodeString(flashCookie.Value)
		if err != nil {
			t.Fatal(err)
		}
		var flash FlashMessage
		if err := json.Unmarshal(decodedFlash, &flash); err != nil {
			t.Fatal(err)
		}

		if index == 0 {
			expectedStatus = recorder.Code
			expectedLocation = recorder.Header().Get("Location")
			expectedFlash = flash.Message
		}
		if recorder.Code != expectedStatus ||
			recorder.Header().Get("Location") != expectedLocation ||
			flash.Message != expectedFlash {
			t.Errorf("login failure for %q differs from unknown-account response", username)
		}
		if flash.Message != "Invalid username or password" {
			t.Errorf("login failure message = %q", flash.Message)
		}
	}
}

func TestAnalyticsAPIAuthenticationFailuresAreUniform(t *testing.T) {
	useTemporaryUserDatabases(t)

	username := "api-user"
	db := user_database.GetOrCreateDB(username)
	apiKey := "correct-api-key"
	site := user_database.Site{URL: "https://example.com", APIKey: &apiKey}
	if err := db.Db.Create(&site).Error; err != nil {
		t.Fatal(err)
	}
	siteWithoutKey := user_database.Site{URL: "https://without-key.example"}
	if err := db.Db.Create(&siteWithoutKey).Error; err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name          string
		username      string
		siteID        string
		authorization string
	}{
		{name: "unknown user", username: "unknown-api-user", siteID: "1", authorization: "Bearer " + apiKey},
		{name: "malformed username", username: "%zz", siteID: "1", authorization: "Bearer " + apiKey},
		{name: "malformed site", username: username, siteID: "not-a-number", authorization: "Bearer " + apiKey},
		{name: "unknown site", username: username, siteID: "999999", authorization: "Bearer " + apiKey},
		{name: "absent authorization", username: username, siteID: uintToString(site.ID)},
		{name: "malformed authorization", username: username, siteID: uintToString(site.ID), authorization: "Basic " + apiKey},
		{name: "empty bearer token", username: username, siteID: uintToString(site.ID), authorization: "Bearer "},
		{name: "absent API key", username: username, siteID: uintToString(siteWithoutKey.ID), authorization: "Bearer " + apiKey},
		{name: "wrong API key", username: username, siteID: uintToString(site.ID), authorization: "Bearer wrong"},
	}

	for _, testCase := range testCases {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/analytics", nil)
		if testCase.authorization != "" {
			request.Header.Set("Authorization", testCase.authorization)
		}
		routeContext := chi.NewRouteContext()
		routeContext.URLParams.Add("username", testCase.username)
		routeContext.URLParams.Add("siteID", testCase.siteID)
		request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))

		AnalyticsAPI(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want 401", testCase.name, recorder.Code)
		}
		if recorder.Body.String() != "Unauthorized\n" {
			t.Errorf("%s body = %q, want uniform Unauthorized response", testCase.name, recorder.Body.String())
		}
	}
}

func uintToString(value uint) string {
	return strconv.FormatUint(uint64(value), 10)
}
