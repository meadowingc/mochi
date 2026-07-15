package site

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mochi/shared_database"
	"mochi/user_database"

	"github.com/go-chi/chi/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type publicSiteFixture struct {
	registryDB *gorm.DB
	userDB     *user_database.UserDb
	owner      user_database.User
	site       user_database.Site
	deps       publicSiteDependencies
}

func newPublicSiteFixture(t *testing.T, createRoute bool) *publicSiteFixture {
	t.Helper()

	registryDB := openSiteIntegrationTestDB(t, "registry.db")
	if err := registryDB.AutoMigrate(&shared_database.PublicSiteRoute{}); err != nil {
		t.Fatal(err)
	}
	userGormDB := openSiteIntegrationTestDB(t, "user.db")
	if err := userGormDB.AutoMigrate(
		&user_database.User{},
		&user_database.Site{},
		&user_database.Hit{},
		&user_database.WebMention{},
		&user_database.Kudo{},
	); err != nil {
		t.Fatal(err)
	}

	owner := user_database.User{Username: "owner@example.com", SessionToken: "fixture-token"}
	if err := userGormDB.Create(&owner).Error; err != nil {
		t.Fatal(err)
	}
	apiKey := "fixture-api-key"
	site := user_database.Site{
		UserID: owner.ID,
		URL:    "https://target.example",
		APIKey: &apiKey,
	}
	if err := userGormDB.Create(&site).Error; err != nil {
		t.Fatal(err)
	}

	originalRegistryDB := shared_database.Db
	shared_database.Db = registryDB
	t.Cleanup(func() {
		shared_database.Db = originalRegistryDB
	})

	userDB := &user_database.UserDb{Db: userGormDB}
	deps := defaultPublicSiteDependencies
	deps.getUserDBIfExists = func(username string) (*user_database.UserDb, error) {
		if username != owner.Username {
			return nil, nil
		}
		return userDB, nil
	}

	if createRoute {
		if _, err := deps.createRoute(owner.Username, site.ID); err != nil {
			t.Fatal(err)
		}
	}

	return &publicSiteFixture{
		registryDB: registryDB,
		userDB:     userDB,
		owner:      owner,
		site:       site,
		deps:       deps,
	}
}

func openSiteIntegrationTestDB(t *testing.T, name string) *gorm.DB {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".site-integration-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove test database directory: %v", err)
		}
	})

	db, err := gorm.Open(
		sqlite.Open(filepath.Join(directory, name)),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sqlDB, dbErr := db.DB()
		if dbErr == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func TestCanonicalPublicSiteResolutionRejectsUnknownStaleAndMismatchedMappings(t *testing.T) {
	fixture := newPublicSiteFixture(t, true)
	route, err := fixture.deps.createRoute(fixture.owner.Username, fixture.site.ID)
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := resolveCanonicalPublicSite(fixture.deps, route.PublicID)
	if err != nil {
		t.Fatalf("resolve canonical site: %v", err)
	}
	if resolved.Site.ID != fixture.site.ID || resolved.Route.PublicID != route.PublicID ||
		resolved.UserDB != fixture.userDB {
		t.Fatal("canonical resolution returned the wrong site context")
	}

	unknown := strings.Repeat("z", 43)
	if _, err := resolveCanonicalPublicSite(fixture.deps, unknown); !errors.Is(err, errPublicSiteNotFound) {
		t.Fatalf("unknown route error = %v, want generic not found", err)
	}

	stale, err := fixture.deps.createRoute(fixture.owner.Username, fixture.site.ID+100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCanonicalPublicSite(fixture.deps, stale.PublicID); !errors.Is(err, errPublicSiteNotFound) {
		t.Fatalf("stale route error = %v, want generic not found", err)
	}

	if err := fixture.userDB.Db.Model(&fixture.site).Update("user_id", fixture.owner.ID+100).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCanonicalPublicSite(fixture.deps, route.PublicID); !errors.Is(err, errPublicSiteNotFound) {
		t.Fatalf("mismatched route error = %v, want generic not found", err)
	}
}

func TestLegacyResolutionCreatesRouteAndTracksFamilies(t *testing.T) {
	fixture := newPublicSiteFixture(t, false)

	resolved, err := resolveLegacyPublicSite(
		fixture.deps,
		fixture.owner.Username,
		fixture.site.ID,
		shared_database.LegacyRouteFamilyAnalyticsReaper,
	)
	if err != nil {
		t.Fatalf("resolve legacy site: %v", err)
	}
	if resolved.Route.PublicID == "" {
		t.Fatal("legacy resolution did not create an opaque route")
	}

	if _, err := resolveLegacyPublicSite(
		fixture.deps,
		fixture.owner.Username,
		fixture.site.ID,
		shared_database.LegacyRouteFamilyAPI,
	); err != nil {
		t.Fatal(err)
	}

	var stored shared_database.PublicSiteRoute
	if err := fixture.registryDB.First(&stored, resolved.Route.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.LegacyAnalyticsLastSeenAt == nil || stored.LegacyAPILastSeenAt == nil {
		t.Fatal("legacy family timestamps were not recorded")
	}
	if stored.LegacyWebmentionLastSeenAt != nil {
		t.Fatal("unseen legacy family was modified")
	}
}

func TestPublicSiteMiddlewareUnknownResponsesAndLegacyHeader(t *testing.T) {
	fixture := newPublicSiteFixture(t, false)

	legacyRouter := chi.NewRouter()
	legacyRouter.With(legacyPublicSiteMiddlewareWithDependencies(
		fixture.deps,
		shared_database.LegacyRouteFamilyWebmention,
		http.StatusNotFound,
	)).Get("/legacy/{username}/{siteID}", func(w http.ResponseWriter, r *http.Request) {
		if resolved, ok := getResolvedPublicSite(r); !ok || resolved.Site.ID != fixture.site.ID {
			t.Error("legacy middleware did not supply the resolved context")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	legacyRequest := httptest.NewRequest(
		http.MethodGet,
		"/legacy/"+fixture.owner.Username+"/"+strconv.FormatUint(uint64(fixture.site.ID), 10),
		nil,
	)
	legacyResponse := httptest.NewRecorder()
	legacyRouter.ServeHTTP(legacyResponse, legacyRequest)
	if legacyResponse.Code != http.StatusNoContent {
		t.Fatalf("legacy status = %d", legacyResponse.Code)
	}
	if legacyResponse.Header().Get("Deprecation") != "true" {
		t.Fatal("legacy response is missing Deprecation: true")
	}

	var stored shared_database.PublicSiteRoute
	if err := fixture.registryDB.First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.LegacyWebmentionLastSeenAt == nil {
		t.Fatal("legacy middleware did not record receiver use")
	}

	for name, status := range map[string]int{
		"public":    http.StatusNotFound,
		"protected": http.StatusUnauthorized,
	} {
		t.Run(name, func(t *testing.T) {
			router := chi.NewRouter()
			router.With(canonicalPublicSiteMiddlewareWithDependencies(
				fixture.deps,
				status,
			)).Get("/{publicID}", func(w http.ResponseWriter, _ *http.Request) {
				t.Error("unknown public ID reached the handler")
				w.WriteHeader(http.StatusNoContent)
			})
			recorder := httptest.NewRecorder()
			router.ServeHTTP(
				recorder,
				httptest.NewRequest(http.MethodGet, "/"+strings.Repeat("q", 43), nil),
			)
			if recorder.Code != status {
				t.Errorf("status = %d, want %d", recorder.Code, status)
			}
			expectedBody := "Not Found\n"
			if status == http.StatusUnauthorized {
				expectedBody = "Unauthorized\n"
			}
			if recorder.Body.String() != expectedBody {
				t.Errorf("body = %q, want %q", recorder.Body.String(), expectedBody)
			}
		})
	}
}

func TestCanonicalAndLegacyAnalyticsAuthenticationFailuresAreUniform(t *testing.T) {
	fixture := newPublicSiteFixture(t, true)
	route, err := fixture.deps.createRoute(fixture.owner.Username, fixture.site.ID)
	if err != nil {
		t.Fatal(err)
	}
	siteWithoutKey := user_database.Site{
		UserID: fixture.owner.ID,
		URL:    "https://without-key.example",
	}
	if err := fixture.userDB.Db.Create(&siteWithoutKey).Error; err != nil {
		t.Fatal(err)
	}
	routeWithoutKey, err := fixture.deps.createRoute(fixture.owner.Username, siteWithoutKey.ID)
	if err != nil {
		t.Fatal(err)
	}

	canonical := chi.NewRouter()
	canonical.With(canonicalPublicSiteMiddlewareWithDependencies(
		fixture.deps,
		http.StatusUnauthorized,
	)).Get("/api/analytics/{publicID}", AnalyticsAPI)

	legacy := chi.NewRouter()
	legacy.With(legacyPublicSiteMiddlewareWithDependencies(
		fixture.deps,
		shared_database.LegacyRouteFamilyAPI,
		http.StatusUnauthorized,
	)).Get("/api/analytics/{username}/{siteID}", AnalyticsAPI)

	requests := []struct {
		name          string
		router        http.Handler
		path          string
		authorization string
	}{
		{name: "canonical unknown", router: canonical, path: "/api/analytics/" + strings.Repeat("x", 43), authorization: "Bearer fixture-api-key"},
		{name: "canonical missing key", router: canonical, path: "/api/analytics/" + route.PublicID},
		{name: "canonical site without key", router: canonical, path: "/api/analytics/" + routeWithoutKey.PublicID, authorization: strings.Join([]string{"Bear", "er fixture-api-key"}, "")},
		{name: "canonical malformed key", router: canonical, path: "/api/analytics/" + route.PublicID, authorization: "Basic fixture-api-key"},
		{name: "canonical wrong key", router: canonical, path: "/api/analytics/" + route.PublicID, authorization: "******"},
		{name: "legacy unknown owner", router: legacy, path: "/api/analytics/unknown/1", authorization: "Bearer fixture-api-key"},
		{name: "legacy malformed site", router: legacy, path: "/api/analytics/" + fixture.owner.Username + "/bad", authorization: "Bearer fixture-api-key"},
		{name: "legacy missing key", router: legacy, path: fmt.Sprintf("/api/analytics/%s/%d", fixture.owner.Username, fixture.site.ID)},
		{name: "legacy site without key", router: legacy, path: fmt.Sprintf("/api/analytics/%s/%d", fixture.owner.Username, siteWithoutKey.ID), authorization: strings.Join([]string{"Bear", "er fixture-api-key"}, "")},
		{name: "legacy wrong key", router: legacy, path: fmt.Sprintf("/api/analytics/%s/%d", fixture.owner.Username, fixture.site.ID), authorization: "Bearer wrong"},
	}

	for _, testCase := range requests {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, testCase.path, nil)
			request.Header.Set("Authorization", testCase.authorization)
			recorder := httptest.NewRecorder()
			testCase.router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized || recorder.Body.String() != "Unauthorized\n" {
				t.Fatalf("response = (%d, %q), want uniform 401", recorder.Code, recorder.Body.String())
			}
			if strings.HasPrefix(testCase.name, "legacy") &&
				recorder.Header().Get("Deprecation") != "true" {
				t.Fatal("legacy analytics failure is missing deprecation metadata")
			}
		})
	}

	for name, success := range map[string]struct {
		router http.Handler
		path   string
	}{
		"canonical": {canonical, "/api/analytics/" + route.PublicID},
		"legacy": {
			legacy,
			fmt.Sprintf("/api/analytics/%s/%d", fixture.owner.Username, fixture.site.ID),
		},
	} {
		t.Run(name+" success", func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, success.path, nil)
			request.Header.Set("Authorization", "Bearer fixture-api-key")
			recorder := httptest.NewRecorder()
			success.router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestSiteCreateAndDeleteRegistryLifecycle(t *testing.T) {
	fixture := newPublicSiteFixture(t, false)

	createdSite, route, err := createSiteWithPublicRoute(
		fixture.userDB.Db,
		fixture.owner.Username,
		fixture.owner.ID,
		"https://created.example",
		shared_database.CreateOrGetPublicSiteRoute,
		shared_database.DeletePublicSiteRoute,
	)
	if err != nil {
		t.Fatalf("create site with route: %v", err)
	}
	if route.SiteID != createdSite.ID {
		t.Fatal("created route does not map to the committed site")
	}

	sentinel := errors.New("registry unavailable")
	if _, _, err := createSiteWithPublicRoute(
		fixture.userDB.Db,
		fixture.owner.Username,
		fixture.owner.ID,
		"https://rollback.example",
		func(string, uint) (*shared_database.PublicSiteRoute, error) { return nil, sentinel },
		shared_database.DeletePublicSiteRoute,
	); !errors.Is(err, sentinel) {
		t.Fatalf("route creation failure = %v, want sentinel", err)
	}
	var rolledBackCount int64
	if err := fixture.userDB.Db.Model(&user_database.Site{}).
		Where("url = ?", "https://rollback.example").
		Count(&rolledBackCount).Error; err != nil {
		t.Fatal(err)
	}
	if rolledBackCount != 0 {
		t.Fatal("site committed despite route creation failure")
	}

	if err := fixture.userDB.Db.Create(&user_database.Hit{SiteID: createdSite.ID}).Error; err != nil {
		t.Fatal(err)
	}
	if err := fixture.userDB.Db.Create(&user_database.WebMention{SiteID: createdSite.ID}).Error; err != nil {
		t.Fatal(err)
	}
	if err := fixture.userDB.Db.Create(&user_database.Kudo{
		SiteID: createdSite.ID,
		Path:   "/",
		Date:   time.Now(),
	}).Error; err != nil {
		t.Fatal(err)
	}

	deleted, err := permanentlyDeleteSite(
		fixture.userDB.Db,
		fixture.owner.Username,
		createdSite.ID,
		shared_database.DeletePublicSiteRoute,
	)
	if err != nil || !deleted {
		t.Fatalf("delete site and route = %v, %v", deleted, err)
	}
	if _, err := fixture.deps.lookupRoute(route.PublicID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("route after deletion error = %v, want record not found", err)
	}

	staleSite, staleRoute, err := createSiteWithPublicRoute(
		fixture.userDB.Db,
		fixture.owner.Username,
		fixture.owner.ID,
		"https://cleanup-failure.example",
		shared_database.CreateOrGetPublicSiteRoute,
		shared_database.DeletePublicSiteRoute,
	)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err = permanentlyDeleteSite(
		fixture.userDB.Db,
		fixture.owner.Username,
		staleSite.ID,
		func(string, uint) error { return sentinel },
	)
	if !deleted || !errors.Is(err, sentinel) {
		t.Fatalf("cleanup failure = %v, %v; want primary deletion plus sentinel", deleted, err)
	}
	if _, err := resolveCanonicalPublicSite(fixture.deps, staleRoute.PublicID); !errors.Is(err, errPublicSiteNotFound) {
		t.Fatalf("stale cleanup mapping resolved deleted data: %v", err)
	}
}
