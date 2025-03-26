package shared_database

import (
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
	)
	if err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}
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
