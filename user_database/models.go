package user_database

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username     string `gorm:"uniqueIndex"`
	CreatedAt    time.Time
	PasswordHash datatypes.JSON `gorm:"type:json"`
	SessionToken string         `gorm:"index;unique"`
	Sites        []Site         `gorm:"foreignKey:UserID"`
}

type Site struct {
	gorm.Model
	UserID                  uint `gorm:"index"`
	CreatedAt               time.Time
	URL                     string
	DataRetentionMonths     int       `gorm:"default:6"`
	LastDataCleanupDate     time.Time `gorm:"default:0"`
	Hits                    []Hit     `gorm:"foreignKey:SiteID"`
	MetricsNotificationFreq string    // Frequency of site metrics notifications: "none", "daily", "weekly", "monthly"
	LastMetricsSentAt       time.Time `gorm:"default:0"`
}

type Hit struct {
	gorm.Model
	SiteID            uint `gorm:"index"`
	Path              string
	Date              time.Time
	VisitorIpUaHash   *string
	HTTPReferer       *string
	CountryCode       *string
	VisitorOS         *string
	VisitorDeviceType *string
	VisitorBrowser    *string
}

type WebMention struct {
	gorm.Model
	SiteID    uint `gorm:"index"`
	SourceURL string
	TargetURL string
	Status    string
}

type Kudo struct {
	gorm.Model
	SiteID          uint      `gorm:"index;uniqueIndex:idx_kudo_dedup"`
	Path            string    `gorm:"uniqueIndex:idx_kudo_dedup"`
	Date            time.Time
	VisitorIpUaHash *string   `gorm:"uniqueIndex:idx_kudo_dedup"`
}
