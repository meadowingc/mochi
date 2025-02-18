package site

import (
	"context"
	"log"
	"mochi/database"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Add the site to the context
type contextKey string

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

		userDatabase := database.GetDbIfExists(username)
		if userDatabase == nil {
			log.Printf("User database not found for user: %s", username)
			clearUserSession(w)
			next.ServeHTTP(w, r)
			return
		}

		// Validate the token and retrieve the corresponding user
		var user database.User
		result := database.GetDbOrFatal(username).Db.Where(&database.User{SessionToken: authTokenItself}).First(&user)
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
		userDatabase := database.GetDbOrFatal(signedInUser.Username)

		var site database.Site
		result := userDatabase.Db.First(&site, siteID)
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

func GetSiteFromContextOrFail(r *http.Request) *database.Site {
	site, ok := r.Context().Value(siteKey).(*database.Site)
	if !ok {
		log.Fatalf("Site not found in context")
	}
	return site
}
