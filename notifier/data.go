package notifier

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"mochi/constants"
	"mochi/shared_database"
	"mochi/user_database"
	"sort"
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

// SendSiteMetricsSummary sends a site metrics summary to a user
func SendSiteMetricsSummary(username string, siteID uint) error {
	// Check if the user has metrics notifications enabled
	settings, err := GetDiscordSettingsByUsername(username)
	if err != nil {
		return fmt.Errorf("error getting discord settings: %v", err)
	}

	// Check if metrics notifications are enabled
	if !settings.DiscordVerified || !settings.NotificationsEnabled {
		return fmt.Errorf("user has not enabled metrics notifications")
	}

	// Get the user database
	userDb := user_database.GetDbIfExists(username)
	if userDb == nil {
		return fmt.Errorf("user database not found")
	}

	// Get the site
	var site user_database.Site
	if err := userDb.Db.First(&site, siteID).Error; err != nil {
		return fmt.Errorf("site not found: %v", err)
	}

	// Generate metrics report based on frequency
	var startDate time.Time
	reportType := ""

	switch site.MetricsNotificationFreq {
	case "daily":
		startDate = time.Now().AddDate(0, 0, -1) // Yesterday
		reportType = "Daily"
	case "weekly":
		startDate = time.Now().AddDate(0, 0, -7) // Last 7 days
		reportType = "Weekly"
	case "monthly":
		startDate = time.Now().AddDate(0, -1, 0) // Last 30 days
		reportType = "Monthly"
	default:
		return fmt.Errorf("invalid metrics notification frequency")
	}

	// Get hits within the date range
	var hits []user_database.Hit
	if err := userDb.Db.Where("site_id = ? AND date >= ?", siteID, startDate).
		Find(&hits).Error; err != nil {
		return fmt.Errorf("error fetching hits: %v", err)
	}

	// Count unique visitors
	uniqueVisitors := make(map[string]bool)
	for _, hit := range hits {
		if hit.VisitorIpUaHash != nil {
			uniqueVisitors[*hit.VisitorIpUaHash] = true
		}
	}

	// Count visits by page
	pageVisits := make(map[string]int)
	for _, hit := range hits {
		pageVisits[hit.Path]++
	}

	// Sort pages by visit count
	type PageCount struct {
		Path  string
		Count int
	}
	sortedPages := []PageCount{}
	for path, count := range pageVisits {
		sortedPages = append(sortedPages, PageCount{Path: path, Count: count})
	}
	sort.Slice(sortedPages, func(i, j int) bool {
		return sortedPages[i].Count > sortedPages[j].Count
	})

	// Prepare the message
	var topPagesStr string
	for i, page := range sortedPages {
		if i >= 5 { // Show top 5 pages
			break
		}
		topPagesStr += fmt.Sprintf("• %s: %d visits\n", page.Path, page.Count)
	}
	if topPagesStr == "" {
		topPagesStr = "No page visits recorded in this period."
	}

	// Count kudos by page in this period
	var kudos []user_database.Kudo
	userDb.Db.Where("site_id = ? AND created_at >= ?", siteID, startDate).Find(&kudos)

	kudosByPage := make(map[string]int)
	for _, kudo := range kudos {
		if kudo.Path != "" {
			kudosByPage[kudo.Path]++
		}
	}

	var kudosStr string
	if len(kudosByPage) > 0 {
		type KudoCount struct {
			Path  string
			Count int
		}
		sortedKudos := []KudoCount{}
		for path, count := range kudosByPage {
			sortedKudos = append(sortedKudos, KudoCount{Path: path, Count: count})
		}
		sort.Slice(sortedKudos, func(i, j int) bool {
			return sortedKudos[i].Count > sortedKudos[j].Count
		})
		for _, kc := range sortedKudos {
			kudosStr += fmt.Sprintf("• %s: %d\n", kc.Path, kc.Count)
		}
	}

	// Create the formatted message
	kudosSection := ""
	if kudosStr != "" {
		kudosSection = fmt.Sprintf("\n:wave: **Kudos (%d):**\n%s", len(kudos), kudosStr)
	}

	message := fmt.Sprintf(":chart_with_upwards_trend: **%s Metrics Summary for %s**\n\n"+
		":calendar: Period: %s to %s\n"+
		":eyes: Total Page Views: %d\n"+
		":bust_in_silhouette: Unique Visitors: %d\n\n"+
		"**Top Pages:**\n%s%s\n\n"+
		"View full analytics in your dashboard: %s/dashboard/%d/analytics",
		reportType, site.URL,
		startDate.Format("Jan 2"), time.Now().Format("Jan 2"),
		len(hits),
		len(uniqueVisitors),
		topPagesStr,
		kudosSection,
		constants.PUBLIC_URL, siteID,
	)

	// Send the message to the user
	return SendMessageToUsername(username, message)
}

// SendSiteMetricsReport generates and sends a metrics report for a specific site
func SendSiteMetricsReport(username string, site user_database.Site) error {
	// Check if the user has Discord notifications enabled
	settings, err := GetDiscordSettingsByUsername(username)
	if err != nil {
		return fmt.Errorf("error getting discord settings: %v", err)
	}

	// Check if Discord notifications are enabled
	if !settings.DiscordVerified || !settings.NotificationsEnabled {
		return fmt.Errorf("user has not enabled Discord notifications")
	}

	// Check if metrics notifications are enabled for this site
	if site.MetricsNotificationFreq == "" || site.MetricsNotificationFreq == "none" {
		return fmt.Errorf("metrics notifications not enabled for this site")
	}

	// Generate metrics report based on frequency
	var startDate time.Time
	reportType := ""

	switch site.MetricsNotificationFreq {
	case "daily":
		startDate = time.Now().AddDate(0, 0, -1) // Yesterday
		reportType = "Daily"
	case "weekly":
		startDate = time.Now().AddDate(0, 0, -7) // Last 7 days
		reportType = "Weekly"
	case "monthly":
		startDate = time.Now().AddDate(0, -1, 0) // Last 30 days
		reportType = "Monthly"
	default:
		return fmt.Errorf("invalid metrics notification frequency")
	}

	// Get the user database
	userDb := user_database.GetDbIfExists(username)
	if userDb == nil {
		return fmt.Errorf("user database not found")
	}

	// Get hits within the date range
	var hits []user_database.Hit
	if err := userDb.Db.Where("site_id = ? AND date >= ?", site.ID, startDate).
		Find(&hits).Error; err != nil {
		return fmt.Errorf("error fetching hits: %v", err)
	}

	// Count unique visitors
	uniqueVisitors := make(map[string]bool)
	for _, hit := range hits {
		if hit.VisitorIpUaHash != nil {
			uniqueVisitors[*hit.VisitorIpUaHash] = true
		}
	}

	// Count visits by page
	pageVisits := make(map[string]int)
	for _, hit := range hits {
		pageVisits[hit.Path]++
	}

	// Sort pages by visit count
	type PageCount struct {
		Path  string
		Count int
	}
	sortedPages := []PageCount{}
	for path, count := range pageVisits {
		sortedPages = append(sortedPages, PageCount{Path: path, Count: count})
	}
	sort.Slice(sortedPages, func(i, j int) bool {
		return sortedPages[i].Count > sortedPages[j].Count
	})

	// Prepare the message
	var topPagesStr string
	for i, page := range sortedPages {
		if i >= 5 { // Show top 5 pages
			break
		}
		topPagesStr += fmt.Sprintf("• %s: %d visits\n", page.Path, page.Count)
	}
	if topPagesStr == "" {
		topPagesStr = "No page visits recorded in this period."
	}

	// Create the formatted message
	message := fmt.Sprintf(":chart_with_upwards_trend: **%s Metrics Summary for %s**\n\n"+
		":calendar: Period: %s to %s\n"+
		":eyes: Total Page Views: %d\n"+
		":bust_in_silhouette: Unique Visitors: %d\n\n"+
		"**Top Pages:**\n%s\n\n"+
		"View full analytics in your dashboard: %s/dashboard/%d/analytics",
		reportType, site.URL,
		startDate.Format("Jan 2"), time.Now().Format("Jan 2"),
		len(hits),
		len(uniqueVisitors),
		topPagesStr,
		constants.PUBLIC_URL, site.ID,
	)

	// Send the message to the user
	return SendMessageToUsername(username, message)
}

// CheckAndSendScheduledMetricsReports checks if users need metrics reports sent
// based on their notification frequency settings and timezone preferences
func CheckAndSendScheduledMetricsReports() {
	log.Println("Checking for scheduled metrics reports...")

	now := time.Now()

	// Get all users with verified Discord settings
	var allSettings []shared_database.UserDiscordSettings
	if err := shared_database.Db.Where(
		&shared_database.UserDiscordSettings{
			DiscordVerified:      true,
			NotificationsEnabled: true,
		},
	).Find(&allSettings).Error; err != nil {
		log.Printf("Error fetching Discord settings: %v", err)
		return
	}

	for _, settings := range allSettings {
		// Skip users with notifications disabled
		if !settings.NotificationsEnabled {
			continue
		}

		// Check if it's the right time to send notifications based on user's timezone
		tzLocation, err := time.LoadLocation(settings.Timezone)
		if err != nil {
			log.Printf("Invalid timezone %s for user %s: %v", settings.Timezone, settings.Username, err)
			tzLocation = time.UTC // Default to UTC if timezone is invalid
		}

		// Get current time in user's timezone
		userLocalTime := now.In(tzLocation)
		userLocalHour := userLocalTime.Hour()

		// Check if it's notification hour (default to 7PM if not set)
		notificationHour := settings.NotificationTime
		if notificationHour < 0 || notificationHour > 23 {
			notificationHour = 19 // Default to 7PM
		}

		// Only send notifications during the preferred hour
		if userLocalHour != notificationHour {
			continue
		}

		// Get the user's database and sites
		userDb := user_database.GetDbIfExists(settings.Username)
		if userDb == nil {
			log.Printf("User database not found for %s", settings.Username)
			continue
		}

		// Get all sites for this user
		var sites []user_database.Site
		if err := userDb.Db.Find(&sites).Error; err != nil {
			log.Printf("Error fetching sites for user %s: %v", settings.Username, err)
			continue
		}

		// Check each site for whether it needs a metrics report
		for _, site := range sites {
			// Skip sites with no metrics notifications
			if site.MetricsNotificationFreq == "" || site.MetricsNotificationFreq == "none" {
				continue
			}

			// Get the previous send date in the user's timezone to ensure consistent timing
			lastSentInUserTZ := site.LastMetricsSentAt.In(tzLocation)
			todayInUserTZ := userLocalTime.Truncate(24 * time.Hour) // Start of today in user's timezone

			// Determine if it's time to send a report based on frequency and last sent time
			shouldSend := false

			if site.LastMetricsSentAt.IsZero() {
				// If never sent before, send it now
				shouldSend = true
			} else {
				// Calculate days since last notification
				daysSinceLastSent := userLocalTime.Sub(lastSentInUserTZ) / (24 * time.Hour)

				// Round to account for daylight savings time
				daysSinceLastSentInt := int(daysSinceLastSent)

				switch site.MetricsNotificationFreq {
				case "daily":
					// Send if last sent was yesterday or earlier
					shouldSend = lastSentInUserTZ.Day() != todayInUserTZ.Day() ||
						lastSentInUserTZ.Month() != todayInUserTZ.Month() ||
						lastSentInUserTZ.Year() != todayInUserTZ.Year()
				case "weekly":
					// Send once a week (if 7+ days have passed since last notification)
					shouldSend = daysSinceLastSentInt >= 7
				case "monthly":
					// Send once a month (if 30+ days have passed since last notification)
					shouldSend = daysSinceLastSentInt >= 30
				}
			}

			if shouldSend {
				// Send the metrics report
				if err := SendSiteMetricsReport(settings.Username, site); err != nil {
					log.Printf("Error sending metrics report for user %s, site %s: %v",
						settings.Username, site.URL, err)
					continue
				}

				// Update the last notification time to now
				site.LastMetricsSentAt = time.Now()
				if err := userDb.Db.Save(&site).Error; err != nil {
					log.Printf("Error updating LastMetricsSentAt for site %s: %v",
						site.URL, err)
				} else {
					log.Printf("Sent %s metrics report to %s for site %s at their local time (%s %d:00)",
						site.MetricsNotificationFreq, settings.Username, site.URL,
						settings.Timezone, notificationHour)
				}
			}
		}
	}

	log.Println("Scheduled metrics reports check complete")
}
