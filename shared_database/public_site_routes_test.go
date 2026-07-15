package shared_database

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mochi/user_database"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestGeneratePublicSiteIDShape(t *testing.T) {
	seen := make(map[string]struct{})
	for range 128 {
		publicID, err := generatePublicSiteID()
		if err != nil {
			t.Fatalf("generatePublicSiteID: %v", err)
		}
		if len(publicID) != 43 {
			t.Fatalf("encoded ID length = %d, want 43", len(publicID))
		}
		decoded, err := base64.RawURLEncoding.DecodeString(publicID)
		if err != nil {
			t.Fatalf("ID is not unpadded URL-safe base64: %v", err)
		}
		if len(decoded) != publicSiteIDBytes {
			t.Fatalf("decoded entropy length = %d, want %d", len(decoded), publicSiteIDBytes)
		}
		if _, duplicate := seen[publicID]; duplicate {
			t.Fatal("generated a duplicate public ID")
		}
		seen[publicID] = struct{}{}
	}
}

func TestPublicSiteRouteCreateLookupAndDelete(t *testing.T) {
	db := newRouteTestDB(t)

	first, err := createOrGetPublicSiteRoute(db, "owner", 7, generatePublicSiteID)
	if err != nil {
		t.Fatalf("create route: %v", err)
	}
	second, err := createOrGetPublicSiteRoute(db, "owner", 7, generatePublicSiteID)
	if err != nil {
		t.Fatalf("get route: %v", err)
	}
	if first.ID != second.ID || first.PublicID != second.PublicID {
		t.Fatalf("idempotent create returned different routes: %d and %d", first.ID, second.ID)
	}

	byPublicID, err := lookupPublicSiteRoute(db, first.PublicID)
	if err != nil {
		t.Fatalf("lookup by public ID: %v", err)
	}
	bySite, err := lookupPublicSiteRouteBySite(db, "owner", 7)
	if err != nil {
		t.Fatalf("lookup by site: %v", err)
	}
	if byPublicID.ID != first.ID || bySite.ID != first.ID {
		t.Fatal("lookups did not resolve the created route")
	}

	if err := deletePublicSiteRoute(db, "owner", 7); err != nil {
		t.Fatalf("delete route: %v", err)
	}
	if _, err := lookupPublicSiteRoute(db, first.PublicID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("lookup after delete error = %v, want record not found", err)
	}
	if err := deletePublicSiteRoute(db, "owner", 7); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("second delete error = %v, want record not found", err)
	}
}

func TestRemoveObsoletePublicSiteRouteColumnsPreservesRoutes(t *testing.T) {
	db := newRouteTestDB(t)
	for _, column := range []string{
		"legacy_analytics_last_seen_at",
		"legacy_webmention_last_seen_at",
		"legacy_api_last_seen_at",
	} {
		if err := db.Exec("ALTER TABLE public_site_routes ADD COLUMN " + column + " datetime").Error; err != nil {
			t.Fatal(err)
		}
	}

	route, err := createOrGetPublicSiteRoute(db, "owner", 1, generatePublicSiteID)
	if err != nil {
		t.Fatal(err)
	}
	if err := removeObsoletePublicSiteRouteColumns(db); err != nil {
		t.Fatal(err)
	}

	for _, column := range []string{
		"legacy_analytics_last_seen_at",
		"legacy_webmention_last_seen_at",
		"legacy_api_last_seen_at",
	} {
		var count int64
		if err := db.Raw(
			"SELECT COUNT(*) FROM pragma_table_info('public_site_routes') WHERE name = ?",
			column,
		).Scan(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("obsolete column %q still exists", column)
		}
	}

	stored, err := lookupPublicSiteRoute(db, route.PublicID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Username != route.Username || stored.SiteID != route.SiteID {
		t.Fatal("route changed while removing obsolete columns")
	}

	if _, err := createOrGetPublicSiteRoute(db, "other", 2, func() (string, error) {
		return route.PublicID, nil
	}); err == nil {
		t.Fatal("public ID uniqueness was lost while removing obsolete columns")
	}
}

func TestPublicSiteRouteCreationCollisionAndGeneratorErrors(t *testing.T) {
	db := newRouteTestDB(t)
	collidingID, err := generatePublicSiteID()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&PublicSiteRoute{PublicID: collidingID, Username: "first", SiteID: 1}).Error; err != nil {
		t.Fatal(err)
	}
	replacementID, err := generatePublicSiteID()
	if err != nil {
		t.Fatal(err)
	}
	generated := []string{collidingID, replacementID}
	route, err := createOrGetPublicSiteRoute(db, "second", 2, func() (string, error) {
		publicID := generated[0]
		generated = generated[1:]
		return publicID, nil
	})
	if err != nil {
		t.Fatalf("retry after collision: %v", err)
	}
	if route.PublicID != replacementID {
		t.Fatal("collision was not replaced with the next generated ID")
	}
	_, err = createOrGetPublicSiteRoute(db, "collision-limit", 5, func() (string, error) {
		return collidingID, nil
	})
	if err == nil || !strings.Contains(err.Error(), "collision retry limit") {
		t.Fatalf("collision exhaustion error = %v", err)
	}

	sentinel := errors.New("entropy unavailable")
	_, err = createOrGetPublicSiteRoute(db, "third", 3, func() (string, error) {
		return "", sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("generator error = %v, want sentinel", err)
	}

	_, err = createOrGetPublicSiteRoute(db, "fourth", 4, func() (string, error) {
		return "not-a-256-bit-token", nil
	})
	if err == nil {
		t.Fatal("invalid generated ID was accepted")
	}
}

func TestReconcilePublicSiteRoutes(t *testing.T) {
	sharedDB := newRouteTestDB(t)
	userDB := newUserTestDB(t)
	for _, siteID := range []uint{10, 20} {
		if err := userDB.Create(&user_database.Site{Model: gorm.Model{ID: siteID}}).Error; err != nil {
			t.Fatalf("create user site %d: %v", siteID, err)
		}
	}

	retained, err := createOrGetPublicSiteRoute(sharedDB, "owner", 10, generatePublicSiteID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := createOrGetPublicSiteRoute(sharedDB, "stale-owner", 30, generatePublicSiteID); err != nil {
		t.Fatal(err)
	}

	err = reconcilePublicSiteRoutes(
		sharedDB,
		func() ([]string, error) { return []string{"owner"}, nil },
		func(username string) (*user_database.UserDb, error) {
			if username != "owner" {
				return nil, fmt.Errorf("unexpected test owner")
			}
			return &user_database.UserDb{Db: userDB}, nil
		},
	)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var routes []PublicSiteRoute
	if err := sharedDB.Order("site_id").Find(&routes).Error; err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0].SiteID != 10 || routes[1].SiteID != 20 {
		siteIDs := make([]uint, 0, len(routes))
		for _, route := range routes {
			siteIDs = append(siteIDs, route.SiteID)
		}
		t.Fatalf("reconciled site IDs = %v, want [10 20]", siteIDs)
	}
	if routes[0].PublicID != retained.PublicID {
		t.Fatal("reconciliation replaced an existing live route")
	}
}

func TestReconcileRejectsDuplicatesWithoutLeakingOpaqueFields(t *testing.T) {
	sharedDB := newRouteTestDB(t)
	userDB := newUserTestDB(t)
	if err := sharedDB.Migrator().DropIndex(&PublicSiteRoute{}, "idx_public_site_route_owner"); err != nil {
		t.Fatal(err)
	}
	firstID, err := generatePublicSiteID()
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := generatePublicSiteID()
	if err != nil {
		t.Fatal(err)
	}
	for _, publicID := range []string{firstID, secondID} {
		if err := sharedDB.Create(&PublicSiteRoute{PublicID: publicID, Username: "private-owner", SiteID: 42}).Error; err != nil {
			t.Fatal(err)
		}
	}

	err = reconcilePublicSiteRoutes(
		sharedDB,
		func() ([]string, error) { return []string{"private-owner"}, nil },
		func(string) (*user_database.UserDb, error) { return &user_database.UserDb{Db: userDB}, nil },
	)
	if err == nil {
		t.Fatal("duplicate registry mappings were accepted")
	}
	for _, secret := range []string{"private-owner", firstID, secondID} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("reconciliation error leaked an opaque field: %v", err)
		}
	}
}

func TestReconcileFailureDoesNotDeleteStaleRoutes(t *testing.T) {
	sharedDB := newRouteTestDB(t)
	userDB := newUserTestDB(t)
	if err := userDB.Create(&user_database.Site{Model: gorm.Model{ID: 1}}).Error; err != nil {
		t.Fatal(err)
	}
	stale, err := createOrGetPublicSiteRoute(sharedDB, "stale-owner", 99, generatePublicSiteID)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("cannot open")

	err = reconcilePublicSiteRoutes(
		sharedDB,
		func() ([]string, error) { return []string{"available-owner", "unavailable-owner"}, nil },
		func(username string) (*user_database.UserDb, error) {
			if username == "available-owner" {
				return &user_database.UserDb{Db: userDB}, nil
			}
			return nil, sentinel
		},
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("reconciliation error = %v, want sentinel", err)
	}
	if _, err := lookupPublicSiteRoute(sharedDB, stale.PublicID); err != nil {
		t.Fatalf("stale route was deleted despite reconciliation failure: %v", err)
	}
	if _, err := lookupPublicSiteRouteBySite(sharedDB, "available-owner", 1); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("new route was not rolled back after reconciliation failure: %v", err)
	}
}

func newRouteTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := openTestSQLite(t, "shared.db")
	if err := db.AutoMigrate(&PublicSiteRoute{}); err != nil {
		t.Fatalf("migrate route database: %v", err)
	}
	return db
}

func newUserTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := openTestSQLite(t, "user.db")
	if err := db.AutoMigrate(&user_database.Site{}); err != nil {
		t.Fatalf("migrate user database: %v", err)
	}
	return db
}

func openTestSQLite(t *testing.T, name string) *gorm.DB {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".public-route-test-")
	if err != nil {
		t.Fatalf("create test database directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove test database directory: %v", err)
		}
	})
	path := filepath.Join(dir, name)
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() {
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}
