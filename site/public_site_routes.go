package site

import (
	"context"
	"errors"
	"fmt"
	"log"
	"mochi/shared_database"
	"mochi/user_database"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var errPublicSiteNotFound = errors.New("public site not found")

type resolvedPublicSite struct {
	Route  *shared_database.PublicSiteRoute
	UserDB *user_database.UserDb
	Site   *user_database.Site
}

type publicSiteDependencies struct {
	lookupRoute       func(string) (*shared_database.PublicSiteRoute, error)
	createRoute       func(string, uint) (*shared_database.PublicSiteRoute, error)
	getUserDBIfExists func(string) (*user_database.UserDb, error)
}

var defaultPublicSiteDependencies = publicSiteDependencies{
	lookupRoute:       shared_database.LookupPublicSiteRoute,
	createRoute:       shared_database.CreateOrGetPublicSiteRoute,
	getUserDBIfExists: user_database.GetDbIfExistsWithError,
}

const (
	resolvedPublicSiteKey contextKey = "resolved_public_site"
	publicSiteRouteKey    contextKey = "public_site_route"
)

func resolveCanonicalPublicSite(deps publicSiteDependencies, publicID string) (*resolvedPublicSite, error) {
	if publicID == "" {
		return nil, errPublicSiteNotFound
	}

	route, err := deps.lookupRoute(publicID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errPublicSiteNotFound
		}
		return nil, fmt.Errorf("look up public route: %w", err)
	}
	if route == nil || route.PublicID != publicID || route.Username == "" || route.SiteID == 0 {
		return nil, errPublicSiteNotFound
	}

	return loadResolvedPublicSite(deps, route)
}

func resolveLegacyPublicSite(
	deps publicSiteDependencies,
	username string,
	siteID uint,
) (*resolvedPublicSite, error) {
	if username == "" || siteID == 0 {
		return nil, errPublicSiteNotFound
	}

	userDB, site, err := loadExactUserSite(deps, username, siteID)
	if err != nil {
		return nil, err
	}

	route, err := deps.createRoute(username, site.ID)
	if err != nil {
		return nil, fmt.Errorf("resolve legacy public route: %w", err)
	}
	if route == nil || route.Username != username || route.SiteID != site.ID || route.PublicID == "" {
		return nil, errPublicSiteNotFound
	}

	return &resolvedPublicSite{Route: route, UserDB: userDB, Site: site}, nil
}

func loadResolvedPublicSite(
	deps publicSiteDependencies,
	route *shared_database.PublicSiteRoute,
) (*resolvedPublicSite, error) {
	userDB, site, err := loadExactUserSite(deps, route.Username, route.SiteID)
	if err != nil {
		return nil, err
	}
	return &resolvedPublicSite{Route: route, UserDB: userDB, Site: site}, nil
}

func loadExactUserSite(
	deps publicSiteDependencies,
	username string,
	siteID uint,
) (*user_database.UserDb, *user_database.Site, error) {
	userDB, err := deps.getUserDBIfExists(username)
	if err != nil {
		return nil, nil, fmt.Errorf("open mapped user database: %w", err)
	}
	if userDB == nil {
		return nil, nil, errPublicSiteNotFound
	}
	if userDB.Db == nil {
		return nil, nil, errors.New("mapped user database is not initialized")
	}

	db := userDB.Db.Session(&gorm.Session{Logger: userDB.Db.Logger.LogMode(logger.Silent)})
	var site user_database.Site
	if err := db.First(&site, siteID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, errPublicSiteNotFound
		}
		return nil, nil, fmt.Errorf("load mapped site: %w", err)
	}

	var ownerCount int64
	if err := db.Model(&user_database.User{}).
		Where("id = ? AND username = ?", site.UserID, username).
		Count(&ownerCount).Error; err != nil {
		return nil, nil, fmt.Errorf("verify mapped site owner: %w", err)
	}
	if ownerCount != 1 {
		return nil, nil, errPublicSiteNotFound
	}

	return userDB, &site, nil
}

func withResolvedPublicSite(r *http.Request, resolved *resolvedPublicSite) *http.Request {
	ctx := context.WithValue(r.Context(), resolvedPublicSiteKey, resolved)
	ctx = context.WithValue(ctx, publicSiteRouteKey, resolved.Route)
	return r.WithContext(ctx)
}

func getResolvedPublicSite(r *http.Request) (*resolvedPublicSite, bool) {
	resolved, ok := r.Context().Value(resolvedPublicSiteKey).(*resolvedPublicSite)
	return resolved, ok && resolved != nil && resolved.Route != nil &&
		resolved.UserDB != nil && resolved.Site != nil
}

func getPublicSiteRoute(r *http.Request) *shared_database.PublicSiteRoute {
	route, _ := r.Context().Value(publicSiteRouteKey).(*shared_database.PublicSiteRoute)
	return route
}

func canonicalPublicSiteMiddlewareWithDependencies(
	deps publicSiteDependencies,
	unknownStatus int,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resolved, err := resolveCanonicalPublicSite(deps, chi.URLParam(r, "publicID"))
			if err != nil {
				writePublicSiteResolutionError(w, err, unknownStatus)
				return
			}
			next.ServeHTTP(w, withResolvedPublicSite(r, resolved))
		})
	}
}

func legacyPublicSiteMiddlewareWithDependencies(
	deps publicSiteDependencies,
	unknownStatus int,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Deprecation", "true")

			escapedUsername := strings.TrimSpace(chi.URLParam(r, "username"))
			username, err := url.PathUnescape(escapedUsername)
			if err != nil {
				writePublicSiteResolutionError(w, errPublicSiteNotFound, unknownStatus)
				return
			}
			username = strings.TrimSpace(username)

			parsedSiteID, err := strconv.ParseUint(chi.URLParam(r, "siteID"), 10, 64)
			if err != nil || parsedSiteID == 0 || uint64(uint(parsedSiteID)) != parsedSiteID {
				writePublicSiteResolutionError(w, errPublicSiteNotFound, unknownStatus)
				return
			}

			resolved, err := resolveLegacyPublicSite(deps, username, uint(parsedSiteID))
			if err != nil {
				writePublicSiteResolutionError(w, err, unknownStatus)
				return
			}
			next.ServeHTTP(w, withResolvedPublicSite(r, resolved))
		})
	}
}

func writePublicSiteResolutionError(w http.ResponseWriter, err error, unknownStatus int) {
	if errors.Is(err, errPublicSiteNotFound) {
		if unknownStatus == http.StatusUnauthorized {
			writeUnauthorized(w)
			return
		}
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	log.Printf("Public site resolution failed")
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func writeUnauthorized(w http.ResponseWriter) {
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// CanonicalPublicSiteMiddleware resolves an opaque public site ID.
func CanonicalPublicSiteMiddleware(next http.Handler) http.Handler {
	return canonicalPublicSiteMiddlewareWithDependencies(
		defaultPublicSiteDependencies,
		http.StatusNotFound,
	)(next)
}

// CanonicalAnalyticsSiteMiddleware keeps protected-resource failures uniform.
func CanonicalAnalyticsSiteMiddleware(next http.Handler) http.Handler {
	return canonicalPublicSiteMiddlewareWithDependencies(
		defaultPublicSiteDependencies,
		http.StatusUnauthorized,
	)(next)
}

// LegacyAnalyticsReaperMiddleware adapts permanent username-based analytics routes.
func LegacyAnalyticsReaperMiddleware(next http.Handler) http.Handler {
	return legacyPublicSiteMiddlewareWithDependencies(
		defaultPublicSiteDependencies,
		http.StatusNotFound,
	)(next)
}

// LegacyWebmentionMiddleware adapts permanent username-based receiver routes.
func LegacyWebmentionMiddleware(next http.Handler) http.Handler {
	return legacyPublicSiteMiddlewareWithDependencies(
		defaultPublicSiteDependencies,
		http.StatusNotFound,
	)(next)
}

// LegacyAPIMiddleware adapts permanent username-based public API routes.
func LegacyAPIMiddleware(next http.Handler) http.Handler {
	return legacyPublicSiteMiddlewareWithDependencies(
		defaultPublicSiteDependencies,
		http.StatusNotFound,
	)(next)
}

// LegacyAnalyticsAPIMiddleware preserves uniform authentication failures.
func LegacyAnalyticsAPIMiddleware(next http.Handler) http.Handler {
	return legacyPublicSiteMiddlewareWithDependencies(
		defaultPublicSiteDependencies,
		http.StatusUnauthorized,
	)(next)
}

// DashboardPublicSiteRouteMiddleware supplies the route separately from ownership checks.
func DashboardPublicSiteRouteMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetSignedInUserOrNil(r)
		site, siteOK := r.Context().Value(siteKey).(*user_database.Site)
		if user == nil || !siteOK || site == nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		route, err := shared_database.CreateOrGetPublicSiteRoute(user.Username, site.ID)
		if err != nil || route == nil || route.Username != user.Username || route.SiteID != site.ID {
			log.Printf("Dashboard public site route resolution failed")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		ctx := context.WithValue(r.Context(), publicSiteRouteKey, route)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
