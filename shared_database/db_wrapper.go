package shared_database

import (
	"fmt"
	"log"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var Db *gorm.DB

func InitSharedDb() {
	var err error
	Db, err = gorm.Open(sqlite.Open(
		"file:shared.db?cache=shared&mode=rwc&_journal_mode=WAL",
	), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
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
		log.Fatalf("failed to migrate database: %v", err)
	}

	if err := removeObsoletePublicSiteRouteColumns(Db); err != nil {
		log.Fatalf("failed to remove obsolete public route columns: %v", err)
	}
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
