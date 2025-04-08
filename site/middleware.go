package site

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"mochi/constants"
	"mochi/user_database"
	"net/http"
	"os"
	"strings"
	"time"

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
			// Cookie exists, extract the flash message
			log.Printf("Found encoded cookie value: %s", cookie.Value)

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

					log.Printf("Successfully decoded flash message: %s - %s", flashMessage.Type, flashMessage.Message)

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
	log.Printf("Setting flash message cookie with base64-encoded JSON: %s", encodedValue)

	// Set the cookie - with a short expiration to ensure it persists
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
