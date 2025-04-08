package site

import (
	"context"
	"log"
	"mochi/constants"
	"mochi/user_database"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
)

// Add the site to the context
type contextKey string

const CSRFTokenKey contextKey = "csrf_token"
const siteKey contextKey = "site"
const userKey contextKey = "user"

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
		log.Println("Warning: CSRF key is not set. This is insecure and should only be used in development.")
		csrfKey = "32-byte-long-auth-key-for-dev-only"
		log.Println("Warning: Using default CSRF key. Set CSRF_KEY environment variable in production.")
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
