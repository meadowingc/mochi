package storage

import (
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type schemaFixture struct {
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"uniqueIndex"`
}

func TestValidationRejectsMissingColumnsAndUniqueIndexesWithoutRepair(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := ValidateModels(db, &schemaFixture{}); err == nil {
		t.Fatal("missing table accepted")
	}
	if err := db.AutoMigrate(&schemaFixture{}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateModels(db, &schemaFixture{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrator().DropIndex(&schemaFixture{}, "idx_schema_fixtures_name"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateModels(db, &schemaFixture{}); err == nil || !strings.Contains(err.Error(), "unique index") {
		t.Fatalf("missing unique index accepted: %v", err)
	}
	if db.Migrator().HasIndex(&schemaFixture{}, "idx_schema_fixtures_name") {
		t.Fatal("validation repaired an index")
	}
	if err := db.Migrator().DropColumn(&schemaFixture{}, "Name"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateModels(db, &schemaFixture{}); err == nil || !strings.Contains(err.Error(), "column") {
		t.Fatalf("missing column accepted: %v", err)
	}
	if db.Migrator().HasColumn(&schemaFixture{}, "Name") {
		t.Fatal("validation repaired a column")
	}
}

func TestAutomaticMigrationSettingIsExplicit(t *testing.T) {
	for value, want := range map[string]bool{"": true, "enabled": true, "disabled": false} {
		t.Setenv("MOCHI_AUTO_MIGRATE", value)
		if got, err := AutomaticMigrationsEnabled(); err != nil || got != want {
			t.Fatalf("setting %q: %t, %v", value, got, err)
		}
	}
	t.Setenv("MOCHI_AUTO_MIGRATE", "typo")
	if _, err := AutomaticMigrationsEnabled(); err == nil {
		t.Fatal("invalid automatic migration setting accepted")
	}
}
