package storage

import (
	"errors"
	"fmt"
	"os"

	"gorm.io/gorm"
)

func AutomaticMigrationsEnabled() (bool, error) {
	switch os.Getenv("MOCHI_AUTO_MIGRATE") {
	case "", "enabled":
		return true, nil
	case "disabled":
		return false, nil
	default:
		return false, errors.New("MOCHI_AUTO_MIGRATE must be enabled or disabled")
	}
}

func ValidateModels(db *gorm.DB, models ...any) error {
	for _, model := range models {
		statement := &gorm.Statement{DB: db}
		if err := statement.Parse(model); err != nil {
			return err
		}
		if !db.Migrator().HasTable(model) {
			return fmt.Errorf("required existing table %s is missing", statement.Schema.Table)
		}
		columns, err := db.Migrator().ColumnTypes(model)
		if err != nil {
			return fmt.Errorf("read existing schema for %s: %w", statement.Schema.Table, err)
		}
		names := make(map[string]bool, len(columns))
		for _, column := range columns {
			names[column.Name()] = true
		}
		for _, field := range statement.Schema.Fields {
			if field.DBName != "" && !names[field.DBName] {
				return fmt.Errorf("required existing column %s.%s is missing", statement.Schema.Table, field.DBName)
			}
		}
		for _, index := range statement.Schema.ParseIndexes() {
			if index.Class == "UNIQUE" && !db.Migrator().HasIndex(model, index.Name) {
				return fmt.Errorf("required unique index %s is missing", index.Name)
			}
		}
	}
	return nil
}
