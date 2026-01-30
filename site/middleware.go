package site

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"mochi/constants"
	"mochi/user_database"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
)

// Add the site to the context
type contextKey string

const CSRFTokenKey contextKey = "csrf_token"
const siteKey contextKey = "site"
const userKey contextKey = "user"
const flashMessageKey contextKey = "flash_message"

// FlashMessageCookieName is the name of the cookie that stores flash messages
const FlashMessageCookieName = "mochi_flash"

// FlashMessage represents a message to be displayed to the user
type FlashMessage struct {
	Type    string `json:"type"`    // "success", "error", "warning", "info"
	Message string `json:"message"` // The message content
}

// RealIPMiddleware extracts the client's real IP address from the
// X-Forwarded-For header and sets it on the request's RemoteAddr field. Useful
// for when the app is running behind a reverse proxy
func RealIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// This assumes the first IP in the X-Forwarded-For list is the client's real IP
			// This may need to be adjusted depending on your reverse proxy setup
			i := strings.Index(xff, ", ")
			if i == -1 {
				i = len(xff)
			}
			r.RemoteAddr = xff[:i]
		}
		next.ServeHTTP(w, r)
	})
}

// FlashMiddleware extracts flash messages from cookies and adds them to context
func FlashMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for flash messages in the cookie
		cookie, err := r.Cookie(FlashMessageCookieName)
		if err == nil && cookie.Value != "" {
			// Decode the base64-encoded value
			decodedBytes, err := base64.StdEncoding.DecodeString(cookie.Value)
			if err != nil {
				log.Printf("Error decoding base64 cookie: %v", err)
			} else {
				// Unmarshal the JSON data
				var flashMessage FlashMessage
				err = json.Unmarshal(decodedBytes, &flashMessage)
				if err == nil {
					// Add flash message to context
					ctx := context.WithValue(r.Context(), flashMessageKey, &flashMessage)
					r = r.WithContext(ctx)

					// Clear the flash message by setting an expired cookie
					http.SetCookie(w, &http.Cookie{
						Name:     FlashMessageCookieName,
						Value:    "",
						Path:     "/",
						Expires:  time.Now().Add(-1 * time.Hour),
						MaxAge:   -1,
						HttpOnly: true,
						SameSite: http.SameSiteLaxMode,
						Secure:   !constants.DEBUG_MODE,
					})
				} else {
					log.Printf("Error unmarshaling flash message JSON: %v", err)
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// SetFlashMessage sets a flash message in a cookie
func SetFlashMessage(w http.ResponseWriter, messageType, message string) {
	flashMessage := FlashMessage{
		Type:    messageType,
		Message: message,
	}

	// Serialize the flash message
	flashData, err := json.Marshal(flashMessage)
	if err != nil {
		log.Printf("Error marshaling flash message: %v", err)
		return
	}

	// Base64 encode the JSON to avoid issues with special characters in cookies
	encodedValue := base64.StdEncoding.EncodeToString(flashData)

	cookie := &http.Cookie{
		Name:     FlashMessageCookieName,
		Value:    encodedValue,
		Path:     "/",
		MaxAge:   120, // 2 minutes - enough time for the redirect to complete and page to load
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Lax to allow redirects
		Secure:   !constants.DEBUG_MODE,
	}

	http.SetCookie(w, cookie)
}

// GetFlashMessage returns the flash message from the request context
func GetFlashMessage(r *http.Request) *FlashMessage {
	if flash, ok := r.Context().Value(flashMessageKey).(*FlashMessage); ok {
		return flash
	}
	return nil
}

func TryPutUserInContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// try to set admin user into context
		cookie, err := r.Cookie(string(AuthenticatedUserTokenCookieName))
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(w, r)
			return
		}

		cookieParts := strings.Split(cookie.Value, "///")

		if len(cookieParts) != 2 {
			log.Printf("Invalid cookie value: %s", cookie.Value)

			clearUserSession(w)

			next.ServeHTTP(w, r)
			return
		}

		authTokenItself, username := cookieParts[0], cookieParts[1]

		useruser_database := user_database.GetDbIfExists(username)
		if useruser_database == nil {
			log.Printf("User user_database not found for user: %s", username)
			clearUserSession(w)
			next.ServeHTTP(w, r)
			return
		}

		// Validate the token and retrieve the corresponding user
		var user user_database.User
		result := user_database.GetDbOrFatal(username).Db.Where(&user_database.User{SessionToken: authTokenItself}).First(&user)
		if result.Error != nil {
			// Clear the invalid cookie
			clearUserSession(w)
			next.ServeHTTP(w, r)
			return
		}

		// Store the admin user in the context
		ctx := context.WithValue(r.Context(), AuthenticatedUserCookieName, &user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func AuthProtectedMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// if logout then just continue
		if r.URL.Path == "/user/logout" {
			next.ServeHTTP(w, r)
			return
		}

		// check context for user
		adminUser := GetSignedInUserOrNil(r)
		if adminUser == nil {
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
			return
		}

		// try to set admin user into context
		cookie, err := r.Cookie(string(AuthenticatedUserTokenCookieName))
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/user/register", http.StatusSeeOther)
			return
		}

		// otherwise, continue to the next handler
		next.ServeHTTP(w, r)
	})
}

func UserSiteDashboardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check that user owns the site
		siteID := chi.URLParam(r, "siteID")

		signedInUser := GetSignedInUserOrFail(r)
		useruser_database := user_database.GetDbOrFatal(signedInUser.Username)

		var site user_database.Site
		result := useruser_database.Db.First(&site, siteID)
		if result.Error != nil {
			http.Error(w, "Site not found", http.StatusNotFound)
			return
		}

		if site.UserID != signedInUser.ID {
			http.Error(w, "You don't own this site", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), siteKey, &site)

		// otherwise, continue to the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetSiteFromContextOrFail(r *http.Request) *user_database.Site {
	site, ok := r.Context().Value(siteKey).(*user_database.Site)
	if !ok {
		log.Fatalf("Site not found in context")
	}
	return site
}

// CSRFMiddleware adds CSRF protection to form submissions
func CSRFMiddleware() func(http.Handler) http.Handler {
	// Get CSRF key from environment or use a default for dev (should be set in production)
	csrfKey := os.Getenv("CSRF_KEY")

	if constants.DEBUG_MODE {
		log.Println(">>> using dummy CSRF key for development")
		csrfKey = "32-byte-long-auth-key-for-dev-only"
	} else if csrfKey == "" {
		log.Panic("CSRF key is not set. This is required for CSRF protection. Please set the CSRF_KEY environment variable. You can generate a key using `openssl rand -base64 32`.")
	}

	return csrf.Protect(
		[]byte(csrfKey),
		csrf.Secure(!constants.DEBUG_MODE), // Secure cookie in production
		csrf.Path("/"),
		csrf.SameSite(csrf.SameSiteStrictMode),
	)
}

// CSRFTokenMiddleware injects the CSRF token into the request context and template data
func CSRFTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := csrf.Token(r)
		ctx := context.WithValue(r.Context(), CSRFTokenKey, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logger is a custom HTTP middleware that logs requests without IP addresses (for GDPR compliance)
func Logger(next http.Handler) http.Handler {
	// Define color functions
	gray := color.New(color.FgHiBlack).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process the request
		next.ServeHTTP(ww, r)

		// Log the request details (without IP address for GDPR compliance)
		duration := time.Since(start)

		// Determine log level and status color based on status code
		var logLevel string
		var statusStr string
		switch {
		case ww.statusCode >= 500:
			logLevel = "ERROR"
			statusStr = color.New(color.FgRed).Sprintf("%d", ww.statusCode)
		case ww.statusCode >= 400:
			logLevel = "WARN"
			statusStr = color.New(color.FgYellow).Sprintf("%d", ww.statusCode)
		case ww.statusCode >= 300:
			logLevel = "INFO"
			statusStr = color.New(color.FgCyan).Sprintf("%d", ww.statusCode)
		case ww.statusCode >= 200:
			logLevel = "INFO"
			statusStr = color.New(color.FgGreen).Sprintf("%d", ww.statusCode)
		default:
			logLevel = "INFO"
			statusStr = color.New(color.FgWhite).Sprintf("%d", ww.statusCode)
		}

		// Format duration with appropriate color
		var durationStr string
		if duration > 500*time.Millisecond {
			durationStr = color.New(color.FgRed).Sprintf("%v", duration)
		} else if duration > 100*time.Millisecond {
			durationStr = color.New(color.FgYellow).Sprintf("%v", duration)
		} else {
			durationStr = color.New(color.FgGreen).Sprintf("%v", duration)
		}

		// Format response size
		var sizeStr string
		if ww.bytesWritten > 1024*1024 {
			sizeStr = fmt.Sprintf("%.1fMB", float64(ww.bytesWritten)/(1024*1024))
		} else if ww.bytesWritten > 1024 {
			sizeStr = fmt.Sprintf("%.1fKB", float64(ww.bytesWritten)/1024)
		} else {
			sizeStr = fmt.Sprintf("%dB", ww.bytesWritten)
		}

		log.Printf("%s %s %s %s %s %s",
			gray(fmt.Sprintf("[%s]", logLevel)), // [INFO] in gray
			blue(r.Method),                      // GET in blue
			magenta(r.URL.Path),                 // /path in magenta
			statusStr,                           // 200 in appropriate color
			durationStr,                         // 2ms in appropriate color
			gray(fmt.Sprintf("(%s)", sizeStr)),  // (1.2KB) in gray
		)
	})
}

// responseWriter is a wrapper to capture the status code and bytes written
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
	wroteHeader  bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.statusCode = code
	rw.wroteHeader = true
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}
