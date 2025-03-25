package shared_database

import (
	"time"

	"gorm.io/gorm"
)

type MonitoredURL struct {
	gorm.Model
	URL           string `gorm:"uniqueIndex"` // The actual URL, must be unique in the system
	IsRSS         bool
	LastCheckedAt *time.Time
}

type UserMonitoredURL struct {
	gorm.Model
	Username       string `gorm:"index"` // Username from the user database
	MonitoredURLID uint   `gorm:"index"` // Foreign key to MonitoredURL
	// Composite unique index ensures a user only monitors a URL once
	UniqueUsername string `gorm:"uniqueIndex:idx_user_monitoredurl"`
	UniqueURLID    uint   `gorm:"uniqueIndex:idx_user_monitoredurl"`
}

type SentWebmention struct {
	gorm.Model
	MonitoredURLID uint   `gorm:"index"` // Foreign key to source MonitoredURL
	SourceURL      string `gorm:"index"`
	TargetURL      string `gorm:"index"`
	StatusCode     int
	ResponseBody   string
	// Composite unique constraint to ensure uniqueness of source-target pairs
	UniqueSource string `gorm:"uniqueIndex:idx_source_target"`
	UniqueTarget string `gorm:"uniqueIndex:idx_source_target"`
}
