package shared_database

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var Db *gorm.DB

func InitSharedDb() {
	if err := InitSharedDbWithError(); err != nil {
		log.Fatalf("Shared database initialization failed: %v", err)
	}
}

func DatabasePath() string {
	return filepath.Join(os.Getenv("MOCHI_STATE_DIR"), "shared.db")
}

func InitSharedDbWithError() error {
	path := DatabasePath()
	mode := "rwc"
	if os.Getenv("MOCHI_REQUIRE_EXISTING") == "1" {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("required existing shared database is missing or redirected")
		}
		mode = "rw"
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dsn := (&url.URL{Scheme: "file", Path: absolute}).String() +
		"?cache=shared&mode=" + mode + "&_journal_mode=WAL"
	Db, err = gorm.Open(sqlite.Open(
		dsn,
	), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("connect shared database: %w", err)
	}

	// Migrate the schema
	err = Db.AutoMigrate(
		&MonitoredURL{},
		&SentWebmention{},
		&UserMonitoredURL{},
		&UserDiscordSettings{},
		&PasswordResetToken{}, // Add the new model for password reset
		&PublicSiteRoute{},
	)
	if err != nil {
		return fmt.Errorf("migrate shared database: %w", err)
	}

	if err := removeObsoletePublicSiteRouteColumns(Db); err != nil {
		return err
	}
	return nil
}

func removeObsoletePublicSiteRouteColumns(db *gorm.DB) error {
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
			return fmt.Errorf("check %s: %w", column, err)
		}
		if count == 0 {
			continue
		}
		if err := db.Exec("ALTER TABLE public_site_routes DROP COLUMN " + column).Error; err != nil {
			return fmt.Errorf("drop %s: %w", column, err)
		}
	}
	return nil
}

func CleanupOnAppClose() {
	sqlDB, err := Db.DB()
	if err != nil {
		log.Printf("Error on closing database connection: %v", err)
	} else {
		// Perform a checkpoint to consolidate the WAL file into the main database file
		if _, err := sqlDB.Exec("PRAGMA wal_checkpoint(FULL)"); err != nil {
			log.Printf("Error on checkpointing database: %v", err)
		}

		if err := sqlDB.Close(); err != nil {
			log.Printf("Error on closing database connection: %v", err)
		}
	}
}
