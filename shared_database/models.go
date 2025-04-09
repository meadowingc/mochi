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
}

type SentWebmention struct {
	gorm.Model
	MonitoredURLID uint   `gorm:"index"` // Foreign key to source MonitoredURL
	SourceURL      string `gorm:"index"`
	TargetURL      string `gorm:"index"`
	StatusCode     int
	ResponseBody   string
}

type UserDiscordSettings struct {
	gorm.Model
	Username                   string    `gorm:"uniqueIndex"` // Username from the user database
	DiscordUsername            string    // Discord username of the connected account
	DiscordVerified            bool      // Whether Discord integration is verified
	DiscordVerifyCode          string    `gorm:"index"` // Temporary verification code
	DiscordVerifyCodeExpiresAt time.Time // When the verification code expires
	NotificationsEnabled       bool      // Whether to send Discord notifications
	Timezone                   string    `gorm:"default:'UTC'"` // User's preferred timezone for notifications
	NotificationTime           int       `gorm:"default:19"`    // Hour of the day to send notifications (0-23, default is 7PM)
}

type PasswordResetToken struct {
	gorm.Model
	Username  string `gorm:"index"`
	Token     string `gorm:"index;uniqueIndex"`
	ExpiresAt time.Time
	Used      bool
}
