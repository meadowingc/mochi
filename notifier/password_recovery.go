package notifier

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"mochi/constants"
	"mochi/shared_database"
	"mochi/user_database"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const (
	resetTokenValidityHours = 24 // Password reset tokens are valid for 24 hours
	resetTokenLength        = 32 // 32 bytes = 64 character hex string
	salt1Length             = 16
	salt2Length             = 16
	timeParam               = 1
	memoryParam             = 64 * 1024
	threadsParam            = 4
	keyLength               = 32
)

// GeneratePasswordResetToken creates a password reset token for a user and stores it in the database
func GeneratePasswordResetToken(username string) (string, error) {
	// Check if the user exists first
	userDb := user_database.GetDbIfExists(username)
	if userDb == nil {
		return "", fmt.Errorf("user does not exist")
	}

	var user user_database.User
	if err := userDb.Db.Where(&user_database.User{Username: username}).First(&user).Error; err != nil {
		return "", fmt.Errorf("user not found: %v", err)
	}

	// Generate a random token
	tokenBytes := make([]byte, resetTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	// Set expiration time (24 hours from now)
	expiresAt := time.Now().Add(resetTokenValidityHours * time.Hour)

	// Store the token in the database
	resetToken := shared_database.PasswordResetToken{
		Username:  username,
		Token:     token,
		ExpiresAt: expiresAt,
		Used:      false,
	}

	if err := shared_database.Db.Create(&resetToken).Error; err != nil {
		return "", fmt.Errorf("error creating reset token: %v", err)
	}

	return token, nil
}

// SendPasswordResetTokenViaDiscord sends a password reset link to the user via Discord
func SendPasswordResetTokenViaDiscord(username string, token string) error {
	// Check if user has Discord notifications enabled
	settings, err := GetDiscordSettingsByUsername(username)
	if err != nil {
		return fmt.Errorf("error getting discord settings: %v", err)
	}

	if !settings.DiscordVerified || !settings.NotificationsEnabled || settings.DiscordUsername == "" {
		return fmt.Errorf("user has not enabled discord notifications")
	}

	// Create a password reset link
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", constants.PUBLIC_URL, token)

	// Create a nicely formatted message
	message := fmt.Sprintf(":key: **Password Reset Request**\n\n"+
		"Someone (hopefully you) requested a password reset for your Mochi account.\n\n"+
		"Click the link below to reset your password:\n"+
		"%s\n\n"+
		"This link will expire in %d hours.\n\n"+
		"If you did not request this reset, you can safely ignore this message.",
		resetLink, resetTokenValidityHours)

	// Send the message to the user
	return SendMessageToUsername(username, message)
}

// ValidatePasswordResetToken checks if a password reset token is valid
func ValidatePasswordResetToken(token string) (*shared_database.PasswordResetToken, error) {
	var resetToken shared_database.PasswordResetToken
	result := shared_database.Db.Where("token = ? AND used = ?", token, false).First(&resetToken)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("invalid or expired token")
		}
		return nil, fmt.Errorf("error validating token: %v", result.Error)
	}

	// Check if token has expired
	if time.Now().After(resetToken.ExpiresAt) {
		return nil, fmt.Errorf("token has expired")
	}

	return &resetToken, nil
}

// ResetUserPassword updates a user's password given a valid reset token
func ResetUserPassword(token string, newPassword string) error {
	// Validate the token
	resetToken, err := ValidatePasswordResetToken(token)
	if err != nil {
		return err
	}

	// Get user database
	userDb := user_database.GetDbIfExists(resetToken.Username)
	if userDb == nil {
		return fmt.Errorf("user database not found")
	}

	// Get the user
	var user user_database.User
	if err := userDb.Db.Where(&user_database.User{
		Username: resetToken.Username,
	}).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %v", err)
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error generating password hash: %v", err)
	}

	user.PasswordHash = datatypes.JSON(newPasswordHash)

	// Update the password in the database
	if err := userDb.Db.Save(&user).Error; err != nil {
		return fmt.Errorf("error updating password: %v", err)
	}

	// Delete the reset token after use
	if err := shared_database.Db.Unscoped().Delete(resetToken).Error; err != nil {
		return fmt.Errorf("error deleting reset token: %v", err)
	}

	return nil
}
