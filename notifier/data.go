package notifier

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"mochi/shared_database"
	"time"

	"gorm.io/gorm"
)

func GenerateDiscordVerifyCode(username string) (string, error) {
	// Generate random verification code
	codeBytes := make([]byte, 6) // 6 bytes = 12 hex chars
	if _, err := rand.Read(codeBytes); err != nil {
		return "", err
	}
	code := hex.EncodeToString(codeBytes)

	// Define expiration time (30 minutes from now)
	expiresAt := time.Now().Add(30 * time.Minute)

	// Find or create user settings
	var settings shared_database.UserDiscordSettings
	result := shared_database.Db.Where("username = ?", username).First(&settings)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			// Create new settings
			settings = shared_database.UserDiscordSettings{
				Username:                   username,
				DiscordVerifyCode:          code,
				DiscordVerifyCodeExpiresAt: expiresAt,
			}
			if err := shared_database.Db.Create(&settings).Error; err != nil {
				return "", err
			}
		} else {
			return "", result.Error
		}
	} else {
		// Update existing settings
		settings.DiscordVerifyCode = code
		settings.DiscordVerifyCodeExpiresAt = expiresAt
		if err := shared_database.Db.Save(&settings).Error; err != nil {
			return "", err
		}
	}

	return code, nil
}

// FindUserByDiscordVerifyCode looks up a user by their verification code
func FindUserByDiscordVerifyCode(code string) (*shared_database.UserDiscordSettings, error) {
	var settings shared_database.UserDiscordSettings
	result := shared_database.Db.Where("discord_verify_code = ?", code).First(&settings)

	if result.Error != nil {
		return nil, result.Error
	}

	// Check if code is expired
	if time.Now().After(settings.DiscordVerifyCodeExpiresAt) {
		return nil, fmt.Errorf("verification code expired")
	}

	return &settings, nil
}

// UpdateDiscordSettings updates the discord settings for a user
func UpdateDiscordSettings(settings *shared_database.UserDiscordSettings) error {
	return shared_database.Db.Save(settings).Error
}

// GetDiscordSettingsByUsername gets discord settings for a specific username
func GetDiscordSettingsByUsername(username string) (*shared_database.UserDiscordSettings, error) {
	var settings shared_database.UserDiscordSettings
	result := shared_database.Db.Where("username = ?", username).First(&settings)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			// Return empty settings object
			return &shared_database.UserDiscordSettings{
				Username:             username,
				NotificationsEnabled: false,
				DiscordVerified:      false,
			}, nil
		}
		return nil, result.Error
	}

	return &settings, nil
}

// DisconnectDiscord removes discord connection for a user
func DisconnectDiscord(username string) error {
	return shared_database.Db.Model(&shared_database.UserDiscordSettings{}).
		Where("username = ?", username).
		Updates(map[string]interface{}{
			"discord_username":      "",
			"discord_verified":      false,
			"notifications_enabled": false,
		}).Error
}
