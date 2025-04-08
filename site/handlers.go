package site

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"mochi/constants"
	"mochi/notifier"
	"mochi/shared_database"
	"mochi/user_database"
	"mochi/webmention_sender"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mileusna/useragent"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/datatypes"
)

func UserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		adminUser := GetSignedInUserOrNil(r)
		if adminUser == nil {
			RenderTemplate(w, r, "pages/user/login.html", nil)
			return
		} else {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	} else {
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		user_db := user_database.GetDbIfExists(username)

		if user_db == nil {
			SetFlashMessage(w, "error", "User not found. You're trying to sign in, but perhaps you still need to sign up?")
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
			return
		}

		var admin user_database.User
		result := user_db.Db.Where(&user_database.User{Username: username}).First(&admin)
		if result.Error != nil {
			SetFlashMessage(w, "error", "User not found. You're trying to sign in, but perhaps you still need to sign up?")
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
		if err != nil {
			SetFlashMessage(w, "error", "Invalid password")
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
			return
		}

		// Generate a new token for the session
		token, err := generateAuthToken()
		if err != nil {
			log.Printf("Error generating auth token: %v", err)
			SetFlashMessage(w, "error", "Error signing in")
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
			return
		}

		admin.SessionToken = token
		user_db.Db.Save(&admin)

		setUserSession(
			w, username, token,
		)

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func UserRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		adminUser := GetSignedInUserOrNil(r)
		if adminUser == nil {
			RenderTemplate(w, r, "pages/user/register.html", nil)
			return
		} else {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	} else {
		if constants.MAX_USERS > 0 {
			// Check if the maximum user limit has been reached
			usernames, err := user_database.GetAllUsernames()
			if err != nil {
				SetFlashMessage(w, "error", "Error checking user limit: "+err.Error())
				http.Redirect(w, r, "/user/register", http.StatusSeeOther)
				return
			}

			if len(usernames) >= constants.MAX_USERS {
				SetFlashMessage(w, "error", "Registration is currently closed. We've reached the maximum number of allowed users. Please reach out to meadowingc@proton.me to be informed when registrations are opened up again!")
				http.Redirect(w, r, "/user/register", http.StatusSeeOther)
				return
			}
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		if username == "" || password == "" {
			SetFlashMessage(w, "error", "Username and password are required")
			http.Redirect(w, r, "/user/register", http.StatusSeeOther)
			return
		}

		if strings.Contains(username, "/") {
			SetFlashMessage(w, "error", "Username cannot contain a forward slash")
			http.Redirect(w, r, "/user/register", http.StatusSeeOther)
			return
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			SetFlashMessage(w, "error", "Error creating account: "+err.Error())
			http.Redirect(w, r, "/user/register", http.StatusSeeOther)
			return
		}

		// Create a new token and store it in a cookie
		token, err := generateAuthToken()
		if err != nil {
			SetFlashMessage(w, "error", "Error creating account: "+err.Error())
			http.Redirect(w, r, "/user/register", http.StatusSeeOther)
			return
		}

		userDb := user_database.GetDbIfExists(username)
		var userExistsInDb bool = false

		if userDb != nil {
			userExistsInDb = userDb.Db.Where(&user_database.User{Username: username}).First(&user_database.User{}).Error == nil
		}

		if userDb != nil && userExistsInDb {
			SetFlashMessage(w, "error", "User already exists. You can sign in instead.")
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
			return
		}

		newAdmin := user_database.User{Username: username, PasswordHash: passwordHash, SessionToken: token}

		result := user_database.GetOrCreateDB(username).Db.Create(&newAdmin)
		if result.Error != nil {
			SetFlashMessage(w, "error", "Error creating account: "+result.Error.Error())
			http.Redirect(w, r, "/user/register", http.StatusSeeOther)
			return
		}

		setUserSession(
			w, username, token,
		)

		// Redirect to the admin sign-in page after successful sign-up
		SetFlashMessage(w, "success", "Account created successfully! Welcome to Mochi 🤗")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func UserLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   string(AuthenticatedUserTokenCookieName),
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	SetFlashMessage(w, "success", "You have been logged out successfully.")
	http.Redirect(w, r, "/user/login", http.StatusSeeOther)
}

func UserDashboardHome(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)

	userDb := user_database.GetDbOrFatal(signedInUser.Username)
	userSites := []user_database.Site{}

	// Get all sites for this user
	result := userDb.Db.Where(&user_database.Site{
		UserID: signedInUser.ID,
	}).Find(&userSites)

	if result.Error != nil {
		SetFlashMessage(w, "error", "Error fetching sites")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Calculate today's hits and total hits for each site
	today := time.Now().Truncate(24 * time.Hour) // Start of today

	type SiteStats struct {
		SiteID    uint
		TodayHits int
		TotalHits int
	}

	siteStats := make(map[uint]SiteStats)

	// Initialize stats for all sites
	for _, site := range userSites {
		siteStats[site.ID] = SiteStats{
			SiteID:    site.ID,
			TodayHits: 0,
			TotalHits: 0,
		}
	}

	// Calculate today's hits
	var todayResults []struct {
		SiteID uint
		Count  int
	}
	userDb.Db.Model(&user_database.Hit{}).
		Select("site_id, count(*) as count").
		Where("date >= ?", today).
		Group("site_id").
		Scan(&todayResults)

	for _, result := range todayResults {
		if stats, ok := siteStats[result.SiteID]; ok {
			stats.TodayHits = result.Count
			siteStats[result.SiteID] = stats
		}
	}

	// Calculate total hits
	var totalResults []struct {
		SiteID uint
		Count  int
	}
	userDb.Db.Model(&user_database.Hit{}).
		Select("site_id, count(*) as count").
		Group("site_id").
		Scan(&totalResults)

	for _, result := range totalResults {
		if stats, ok := siteStats[result.SiteID]; ok {
			stats.TotalHits = result.Count
			siteStats[result.SiteID] = stats
		}
	}

	RenderTemplate(w, r, "pages/dashboard/dashboard.html",
		&map[string]CustomDeclaration{
			"userSites": {(*[]user_database.Site)(nil), &userSites},
			"siteStats": {(*map[uint]SiteStats)(nil), &siteStats},
		},
	)
}

func SettingsPage(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)

	userSites := []user_database.Site{}

	result := user_database.GetDbOrFatal(signedInUser.Username).Db.Where(&user_database.Site{
		UserID: signedInUser.ID,
	}).Find(&userSites)

	if result.Error != nil {
		http.Error(w, "Error fetching sites", http.StatusInternalServerError)
		return
	}

	// Get Discord settings for the user
	discordSettings, err := notifier.GetDiscordSettingsByUsername(signedInUser.Username)
	if err != nil {
		log.Printf("Error fetching Discord settings: %v", err)
		http.Error(w, "Error fetching Discord settings", http.StatusInternalServerError)
		return
	}

	// Get flash messages (success/error) from session, if you have a session mechanism
	var success, errorMsg string

	// If you have FlashMessage functionality, use it:
	// success := GetFlashMessage(r, "success")
	// errorMsg := GetFlashMessage(r, "error")

	// Otherwise, you can use URL parameters temporarily:
	success = r.URL.Query().Get("success")
	errorMsg = r.URL.Query().Get("error")

	RenderTemplate(w, r, "pages/dashboard/settings.html",
		&map[string]CustomDeclaration{
			"userSites":       {(*[]user_database.Site)(nil), &userSites},
			"discordSettings": {(*shared_database.UserDiscordSettings)(nil), discordSettings},
			"success":         {(*string)(nil), &success},
			"error":           {(*string)(nil), &errorMsg},
		},
	)
}

// DiscordVerifyGenerate generates a verification code for Discord integration
func DiscordVerifyGenerate(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)

	_, err := notifier.GenerateDiscordVerifyCode(signedInUser.Username)
	if err != nil {
		SetFlashMessage(w, "error", "Failed to generate verification code")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	SetFlashMessage(w, "success", "Verification code generated successfully")
	http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
}

// DiscordVerifyRefresh refreshes an existing verification code
func DiscordVerifyRefresh(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)

	_, err := notifier.GenerateDiscordVerifyCode(signedInUser.Username)
	if err != nil {
		SetFlashMessage(w, "error", "Failed to refresh verification code")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	SetFlashMessage(w, "success", "Verification code refreshed successfully")
	http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
}

// DiscordToggle toggles Discord notifications
func DiscordToggle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		SetFlashMessage(w, "error", "Failed to parse form")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	signedInUser := GetSignedInUserOrFail(r)

	settings, err := notifier.GetDiscordSettingsByUsername(signedInUser.Username)
	if err != nil {
		SetFlashMessage(w, "error", "Failed to get Discord settings")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	// Check if the user has verified their Discord account
	if !settings.DiscordVerified {
		SetFlashMessage(w, "error", "You must verify your Discord account first")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	// Toggle notifications based on checkbox value
	settings.NotificationsEnabled = r.FormValue("discord-notifications") == "on"

	err = notifier.UpdateDiscordSettings(settings)
	if err != nil {
		SetFlashMessage(w, "error", "Failed to update settings")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	SetFlashMessage(w, "success", "Notification settings updated successfully")
	http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
}

// DiscordDisconnect disconnects Discord integration
func DiscordDisconnect(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)

	err := notifier.DisconnectDiscord(signedInUser.Username)
	if err != nil {
		SetFlashMessage(w, "error", "Failed to disconnect Discord")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	SetFlashMessage(w, "success", "Discord account disconnected successfully")
	http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
}

func CreateNewSite(w http.ResponseWriter, r *http.Request) {
	user := GetSignedInUserOrFail(r)
	urlParam := r.FormValue("url")

	siteURL, err := url.Parse(urlParam)
	if err != nil {
		SetFlashMessage(w, "error", "Unable to parse site URL")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	hostname := siteURL.Hostname()
	if hostname == "" {
		// If no hostname was found, try again by prepending https:// and reparsing
		siteURL, err = url.Parse("https://" + urlParam)
		if err != nil || siteURL.Hostname() == "" {
			SetFlashMessage(w, "error", "Unable to extract hostname from URL")
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		hostname = siteURL.Hostname()
	}

	// Create a standardized URL with just the hostname (using https://)
	standardizedURL := "https://" + hostname

	// Check if the site already exists
	user_db := user_database.GetDbOrFatal(user.Username)

	var existingSite user_database.Site
	result := user_db.Db.Where(&user_database.Site{
		URL:    standardizedURL,
		UserID: user.ID,
	}).First(&existingSite)

	if result.Error == nil {
		SetFlashMessage(w, "error", "Site already exists")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	newSite := user_database.Site{URL: standardizedURL, UserID: user.ID}

	result = user_db.Db.Create(&newSite)
	if result.Error != nil {
		SetFlashMessage(w, "error", "Error creating site: "+result.Error.Error())
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	SetFlashMessage(w, "success", "New site added successfully")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func SiteAnalytics(w http.ResponseWriter, r *http.Request) {
	// Check for minDate in query params
	minDateStr := r.URL.Query().Get("minDate")
	var minDate time.Time
	var err error
	if minDateStr != "" {
		minDate, err = time.Parse("2006-01-02", minDateStr)
		if err != nil {
			http.Error(w, "Invalid date format", http.StatusBadRequest)
			return
		}
	} else {
		minDate = time.Now().AddDate(0, 0, -7) // 7 days ago
	}

	// Check for maxDate in query params
	maxDateStr := r.URL.Query().Get("maxDate")
	var maxDate time.Time
	if maxDateStr != "" {
		maxDate, err = time.Parse("2006-01-02", maxDateStr)
		if err != nil {
			http.Error(w, "Invalid date format", http.StatusBadRequest)
			return
		}
	} else {
		maxDate = time.Now() // today
	}

	// make sure min date is the very beginning of the day and max date is the very end of the day
	minDate = time.Date(minDate.Year(), minDate.Month(), minDate.Day(), 0, 0, 0, 0, time.UTC)
	maxDate = time.Date(maxDate.Year(), maxDate.Month(), maxDate.Day(), 23, 59, 59, 0, time.UTC)

	signedInUser := GetSignedInUserOrFail(r)

	useruser_database := user_database.GetDbOrFatal(signedInUser.Username)

	site := GetSiteFromContextOrFail(r)

	// get all hits for the site within the date and filters
	pagePathFilter := r.URL.Query().Get("pagePathFilter")

	referrerFilter := stringWithValueOrNil(r.URL.Query().Get("referrerFilter"))
	countryFilter := stringWithValueOrNil(r.URL.Query().Get("countryFilter"))
	osFilter := stringWithValueOrNil(r.URL.Query().Get("osFilter"))
	browserFilter := stringWithValueOrNil(r.URL.Query().Get("browserFilter"))
	deviceFilter := stringWithValueOrNil(r.URL.Query().Get("deviceFilter"))

	var hits []user_database.Hit
	query := useruser_database.Db.Where(
		"date >= ? AND date <= ?", minDate, maxDate,
	).Where(&user_database.Hit{
		Path:              pagePathFilter,
		SiteID:            site.ID,
		HTTPReferer:       referrerFilter,
		CountryCode:       countryFilter,
		VisitorOS:         osFilter,
		VisitorBrowser:    browserFilter,
		VisitorDeviceType: deviceFilter,
	})

	result := query.Order("date ASC").Find(&hits)
	if result.Error != nil {
		http.Error(w, "Error fetching hits: "+result.Error.Error(), http.StatusInternalServerError)
		return
	}

	// Process and sort the data
	countsForPath := make(map[string]int)
	countsForReferrer := make(map[string]int)
	countsForCountry := make(map[string]int)
	countsForOS := make(map[string]int)
	countsForBrowser := make(map[string]int)
	countsForDevice := make(map[string]int)

	visitsByDay := make(map[string]int)
	uniqueVisitors := make(map[string]bool)

	// Create a map of all days between minDate and maxDate, with 0 visits
	for d := minDate; !d.After(maxDate); d = d.AddDate(0, 0, 1) {
		dateStr := d.Format("2006-01-02")
		visitsByDay[dateStr] = 0
	}

	for _, hit := range hits {
		if hit.Path != "" {
			countsForPath[hit.Path]++
		}
		if hit.HTTPReferer != nil {
			countsForReferrer[*hit.HTTPReferer]++
		}
		if hit.CountryCode != nil {
			countsForCountry[*hit.CountryCode]++
		}
		if hit.VisitorOS != nil {
			countsForOS[*hit.VisitorOS]++
		}
		if hit.VisitorBrowser != nil {
			countsForBrowser[*hit.VisitorBrowser]++
		}
		if hit.VisitorDeviceType != nil {
			countsForDevice[*hit.VisitorDeviceType]++
		}

		date := hit.Date.Format("2006-01-02")
		visitsByDay[date]++

		if hit.VisitorIpUaHash != nil {
			uniqueVisitors[*hit.VisitorIpUaHash] = true
		}
	}

	graphDays := make([]string, 0, len(visitsByDay))
	graphVisits := make([]int, 0, len(visitsByDay))

	// Collect the keys and sort them
	sortedDays := make([]string, 0, len(visitsByDay))
	for day := range visitsByDay {
		sortedDays = append(sortedDays, day)
	}
	sort.Strings(sortedDays)

	// Append the sorted values
	for _, day := range sortedDays {
		graphDays = append(graphDays, day)
		graphVisits = append(graphVisits, visitsByDay[day])
	}

	countryCountsWithEmoji := make(map[string]int)
	for countryCode, count := range countsForCountry {
		emoji := countryCodeToFlagEmoji(countryCode)

		countryCodeWithFlag := fmt.Sprintf("%s %s", emoji, countryCode)

		countryCountsWithEmoji[countryCodeWithFlag] = count
	}

	makeSortedDeclaration := func(m map[string]int) CustomDeclaration {
		sortedMap := sortMapByValue(m)

		return CustomDeclaration{(*[]struct {
			Key   string
			Value int
		})(nil),
			&sortedMap,
		}
	}

	numUniqueVisitors := len(uniqueVisitors)
	RenderTemplate(w, r, "pages/dashboard/analytics/analytics_details.html",
		&map[string]CustomDeclaration{
			"site":                    {(*user_database.Site)(nil), site},
			"minDate":                 {(*time.Time)(nil), &minDate},
			"maxDate":                 {(*time.Time)(nil), &maxDate},
			"hits":                    {(*[]user_database.Hit)(nil), &hits},
			"numUniqueVisitors":       {(*int)(nil), &numUniqueVisitors},
			"sortedCountsForPath":     makeSortedDeclaration(countsForPath),
			"sortedCountsForReferrer": makeSortedDeclaration(countsForReferrer),
			"sortedCountsForCountry":  makeSortedDeclaration(countryCountsWithEmoji),
			"sortedCountsForOS":       makeSortedDeclaration(countsForOS),
			"sortedCountsForBrowser":  makeSortedDeclaration(countsForBrowser),
			"sortedCountsForDevice":   makeSortedDeclaration(countsForDevice),
			"visitsByDay":             {(*map[string]int)(nil), &visitsByDay},
			"graphDays":               {(*[]string)(nil), &graphDays},
			"graphVisits":             {(*[]int)(nil), &graphVisits},
		},
	)
}

func SiteEmbedInstructions(w http.ResponseWriter, r *http.Request) {
	site := GetSiteFromContextOrFail(r)
	RenderTemplate(w, r, "pages/dashboard/analytics/embed_instructions.html",
		&map[string]CustomDeclaration{
			"site": {(*user_database.Site)(nil), site},
		},
	)
}

func SiteSettingsPage(w http.ResponseWriter, r *http.Request) {
	siteFromContext := GetSiteFromContextOrFail(r)
	if siteFromContext == nil {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}

	// Get user DB
	signedInUser := GetSignedInUserOrFail(r)
	userDb := user_database.GetDbOrFatal(signedInUser.Username)

	// Calculate total hits for the site
	var totalHits int64
	userDb.Db.Model(&user_database.Hit{}).Where(
		&user_database.Hit{
			SiteID: siteFromContext.ID,
		}).Count(&totalHits)

	// Get Discord settings for the user
	discordSettings, err := notifier.GetDiscordSettingsByUsername(signedInUser.Username)
	if err != nil {
		SetFlashMessage(w, "error", "Error fetching Discord settings")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Get flash messages (success/error) from session, if you have a session mechanism
	var success, errorMsg string

	// Otherwise, you can use URL parameters temporarily:
	success = r.URL.Query().Get("success")
	errorMsg = r.URL.Query().Get("error")

	RenderTemplate(w, r, "pages/dashboard/site_settings.html",
		&map[string]CustomDeclaration{
			"site":            {(*user_database.Site)(nil), siteFromContext},
			"totalHits":       {(*int64)(nil), &totalHits},
			"success":         {(*string)(nil), &success},
			"error":           {(*string)(nil), &errorMsg},
			"discordSettings": {(*shared_database.UserDiscordSettings)(nil), discordSettings},
		},
	)
}

func UpdateSiteSettings(w http.ResponseWriter, r *http.Request) {
	siteFromContext := GetSiteFromContextOrFail(r)
	if siteFromContext == nil {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}

	// Get form values
	pageUrl := strings.TrimSpace(r.FormValue("url"))
	dataRetentionMonthsStr := r.FormValue("dataRetentionMonths")

	// Basic validation
	if pageUrl == "" {
		SetFlashMessage(w, "error", "URL cannot be empty")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", siteFromContext.ID), http.StatusSeeOther)
		return
	}

	// Validate URL format
	if _, err := url.Parse(pageUrl); err != nil {
		SetFlashMessage(w, "error", "Invalid URL format")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", siteFromContext.ID), http.StatusSeeOther)
		return
	}

	// Parse and validate data retention months
	dataRetentionMonths, err := strconv.Atoi(dataRetentionMonthsStr)
	if err != nil || dataRetentionMonths < 1 || dataRetentionMonths > 12 {
		SetFlashMessage(w, "error", "Data retention period must be between 1 and 12 months")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", siteFromContext.ID), http.StatusSeeOther)
		return
	}

	// Get user DB
	signedInUser := GetSignedInUserOrFail(r)
	userDb := user_database.GetDbOrFatal(signedInUser.Username)

	// Update site
	siteFromContext.URL = pageUrl
	siteFromContext.DataRetentionMonths = dataRetentionMonths
	result := userDb.Db.Save(siteFromContext)
	if result.Error != nil {
		SetFlashMessage(w, "error", "Error updating site: "+result.Error.Error())
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", siteFromContext.ID), http.StatusSeeOther)
		return
	}

	// Redirect with success message
	SetFlashMessage(w, "success", "Site updated successfully")
	http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", siteFromContext.ID), http.StatusSeeOther)
}

func DeleteSite(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)
	site := GetSiteFromContextOrFail(r)

	// Parse form
	if err := r.ParseForm(); err != nil {
		SetFlashMessage(w, "error", "Failed to parse form")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
		return
	}

	// Confirm deletion with a confirmation field
	confirmation := r.FormValue("confirm_deletion")
	if confirmation != "DELETE" {
		SetFlashMessage(w, "error", "Please type DELETE to confirm site deletion")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
		return
	}

	userDb := user_database.GetDbOrFatal(signedInUser.Username)

	// First delete related records (hits and webmentions) - PERMANENT DELETE
	if err := userDb.Db.Unscoped().Where("site_id = ?", site.ID).Delete(&user_database.Hit{}).Error; err != nil {
		SetFlashMessage(w, "error", fmt.Sprintf("Failed to delete site hits: %s", err))
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
		return
	}

	if err := userDb.Db.Unscoped().Where("site_id = ?", site.ID).Delete(&user_database.WebMention{}).Error; err != nil {
		SetFlashMessage(w, "error", fmt.Sprintf("Failed to delete site webmentions: %s", err))
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
		return
	}

	// Now delete the site itself - PERMANENT DELETE
	if err := userDb.Db.Unscoped().Delete(site).Error; err != nil {
		SetFlashMessage(w, "error", fmt.Sprintf("Failed to delete site: %s", err))
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
		return
	}

	// Redirect to dashboard with success message
	SetFlashMessage(w, "success", "Site permanently deleted")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func ReaperGetEmbedJs(w http.ResponseWriter, r *http.Request) {
	escapedUsername := chi.URLParam(r, "username")
	escapedUsername = strings.TrimSpace(escapedUsername)

	username, err := url.PathUnescape(escapedUsername)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error unescaping username '%s': %v", escapedUsername, err), http.StatusBadRequest)
		return
	}

	siteID := chi.URLParam(r, "siteID")

	useruser_database := user_database.GetDbIfExists(username)

	if useruser_database == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var site user_database.Site
	result := useruser_database.Db.First(&site, siteID)
	if result.Error != nil {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}

	urlOfIncomingRequest := r.Header.Get("origin")

	if urlOfIncomingRequest == "" {
		urlOfIncomingRequest = r.Header.Get("referer")
	}

	if urlOfIncomingRequest != "" {
		siteURL, err := url.Parse(site.URL)
		if err != nil {
			http.Error(w, "Invalid site URL", http.StatusInternalServerError)
			return
		}

		incomingURL, err := url.Parse(urlOfIncomingRequest)
		if err != nil {
			http.Error(w, "Invalid origin URL", http.StatusBadRequest)
			return
		}

		if siteURL.Host != incomingURL.Host &&
			// if we're in debug mode then we allow the test-embed-page
			!(constants.DEBUG_MODE && strings.Contains(constants.PUBLIC_URL, incomingURL.Host)) {
			http.Error(w, "Origin mismatch", http.StatusForbidden)
			return
		}
	}

	// TODO: getting these directly from the hits is quite inneficient. Would be better to maybe keep a separate table?
	countryCodes := []string{"BE", "IT", "US", "FR", "DE"}
	var countryFlagsStr string
	for _, code := range countryCodes {
		countryFlagsStr += countryCodeToFlagEmoji(code)
	}

	RenderTemplate(w, r, "pages/reaper/embed/reaper_embed.js",
		&map[string]CustomDeclaration{
			"site":          {(*user_database.Site)(nil), &site},
			"ownerUsername": {(*string)(nil), &username},
			"countryFlags":  {(*string)(nil), &countryFlagsStr},
		},
	)
}

func ReaperPostHit(w http.ResponseWriter, r *http.Request) {
	// Return immediately
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Request received"))

	// Execute the rest of the logic in a goroutine
	go func() {
		pagePathParam := r.URL.Query().Get("path")
		referrerParam := stringWithValueOrNil(r.URL.Query().Get("referrer"))

		if pagePathParam == "" {
			log.Printf("ReaperPostHit: Path parameter is required")
			return
		}

		// remove rightmost slash
		if strings.HasSuffix(pagePathParam, "/") {
			pagePathParam = strings.TrimRight(pagePathParam, "/")
		}

		escapedUsername := chi.URLParam(r, "username")
		escapedUsername = strings.TrimSpace(escapedUsername)

		username, err := url.PathUnescape(escapedUsername)
		if err != nil {
			log.Printf("ReaperPostHit: Error unescaping username '%s': %v", escapedUsername, err)
			return
		}

		siteID := chi.URLParam(r, "siteID")

		useruser_database := user_database.GetDbIfExists(username)

		if useruser_database == nil {
			log.Printf("ReaperPostHit: User not found: %s", username)
			return
		}

		var site user_database.Site
		result := useruser_database.Db.First(&site, siteID)
		if result.Error != nil {
			log.Printf("ReaperPostHit: Site '%s' not found for user '%s'", siteID, username)
			return
		}

		siteURL, err := url.Parse(site.URL)
		if err != nil {
			log.Printf("ReaperPostHit: Can't parse site URL '%s' for user '%s'", site.URL, username)
			return
		}

		urlOfIncomingRequest := r.Header.Get("origin")

		if urlOfIncomingRequest == "" {
			urlOfIncomingRequest = r.Header.Get("referer")
		}

		if urlOfIncomingRequest != "" {
			incomingURL, err := url.Parse(urlOfIncomingRequest)
			if err != nil {
				log.Printf("ReaperPostHit: Can't parse origin URL: %s", urlOfIncomingRequest)
				return
			}

			if siteURL.Host != incomingURL.Host &&
				// if we're in debug mode then we allow the test-embed-page
				!(constants.DEBUG_MODE && strings.Contains(constants.PUBLIC_URL, incomingURL.Host)) {
				log.Printf("ReaperPostHit: Origin mismatch. Site URL: %s, Origin URL: %s", siteURL.Host, incomingURL.Host)
				return
			}
		}

		if referrerParam != nil {
			referrerURL, err := url.Parse(*referrerParam)
			if err != nil {
				log.Printf("ReaperPostHit: Unable to parse referrer URL: %s", *referrerParam)
				return
			}

			// if the referer is the same as the site URL, then it's likely a self visit and we should set the referrer to nil
			if referrerURL.Host == siteURL.Host {
				referrerParam = nil
			} else {
				// Standardize the protocol to https
				referrerURL.Scheme = "https"
				standardizedReferrer := referrerURL.String()
				referrerParam = &standardizedReferrer
			}
		}

		cloudflareCountryCode := stringWithValueOrNil(r.Header.Get("CF-IPCountry"))
		userAgent := r.Header.Get("User-Agent")
		userIp := r.Header.Get("CF-Connecting-IP")

		if userIp == "" {
			// fallback
			userIp = r.Header.Get("X-Forwarded-For")
		}

		var userIpAgentHash *string = nil
		if userIp != "" {
			hash := sha256.Sum256([]byte(userIp + userAgent))
			hashString := hex.EncodeToString(hash[:])
			userIpAgentHash = &hashString
		}

		var visitorOS *string
		var visitorBrowser *string
		var visitorDeviceType *string

		if userAgent != "" {
			ua := useragent.Parse(userAgent)

			// some bots are not detected by the useragent package, so we have to
			// check for them manually
			var agentNameDenylist = []string{
				"Dataprovider.com",
			}

			for _, denylistedAgent := range agentNameDenylist {
				if strings.Contains(ua.Name, denylistedAgent) {
					return
				}
			}

			if ua.Bot {
				return
			}

			if ua.OS != "" {
				visitorOS = &ua.OS
			}

			if ua.Name != "" {
				visitorBrowser = &ua.Name
			}

			switch {
			case ua.Device == "iPhone":
				visitorDeviceType = stringWithValueOrNil("iPhone")
			case ua.Device == "iPad":
				visitorDeviceType = stringWithValueOrNil("iPad")
			case ua.Mobile:
				visitorDeviceType = stringWithValueOrNil("Mobile")
			case ua.Tablet:
				visitorDeviceType = stringWithValueOrNil("Tablet")
			case ua.Desktop:
				visitorDeviceType = stringWithValueOrNil("Desktop")
			default:
				visitorDeviceType = stringWithValueOrNil("Other")
			}
		}

		hit := user_database.Hit{
			SiteID:            site.ID,
			Path:              pagePathParam,
			Date:              time.Now(), // Add 8 hours to get to UTC time
			VisitorIpUaHash:   userIpAgentHash,
			HTTPReferer:       referrerParam,
			CountryCode:       cloudflareCountryCode,
			VisitorOS:         visitorOS,
			VisitorDeviceType: visitorDeviceType,
			VisitorBrowser:    visitorBrowser,
		}

		result = useruser_database.Db.Create(&hit)

		if result.Error != nil {
			log.Printf("ReaperPostHit: Error saving hit: %v", result.Error)
			return
		}
	}()
}

// WebmentionSenderDashboard handles the webmention sender dashboard page
func WebmentionSenderDashboard(w http.ResponseWriter, r *http.Request) {
	user := GetSignedInUserOrNil(r)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Get monitored URLs for this user
	monitoredURLs, err := webmention_sender.GetMonitoredURLsForUser(user.Username)
	if err != nil {
		log.Printf("Error fetching monitored URLs: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get recent sent webmentions
	sentWebmentions, err := webmention_sender.GetRecentSentWebmentionsForUser(user.Username, 20)
	if err != nil {
		log.Printf("Error fetching sent webmentions: %v", err)
	}

	RenderTemplate(w, r, "pages/dashboard/webmention_sender/webmention_sender.html",
		&map[string]CustomDeclaration{
			"monitoredURLs":   {(*[]shared_database.MonitoredURL)(nil), &monitoredURLs},
			"sentWebmentions": {(*[]shared_database.SentWebmention)(nil), &sentWebmentions},
		})
}

// WebmentionSenderAddURLs handles adding URLs for monitoring
func WebmentionSenderAddURLs(w http.ResponseWriter, r *http.Request) {
	user := GetSignedInUserOrFail(r)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	pageUrlsText := r.FormValue("page-urls")
	rssUrlsText := r.FormValue("rss-urls")
	isRss := r.FormValue("is-rss") == "true"

	var urlsList []string
	if isRss {
		urlsList = strings.Split(rssUrlsText, "\n")
	} else {
		urlsList = strings.Split(pageUrlsText, "\n")
	}

	// First, get all currently monitored URLs of this type for the user
	if err := webmention_sender.RemoveUserMonitoredURLsByType(user.Username, isRss); err != nil {
		log.Printf("Error removing monitored URLs: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	for _, urlStr := range urlsList {
		urlStr = strings.TrimSpace(urlStr)
		if urlStr == "" {
			continue
		}

		urlStr, err := webmention_sender.StandardizeURL(urlStr)
		if err != nil {
			log.Printf("Error standardizing URL %s: %v", urlStr, err)
			continue
		}

		// Add URL to database
		err = webmention_sender.AddURLToMonitor(user.Username, urlStr, isRss)
		if err != nil {
			log.Printf("Error adding URL %s: %v", urlStr, err)
		}
	}

	http.Redirect(w, r, "/dashboard/webmention-sender", http.StatusSeeOther)
}

// WebmentionSenderProcessURL handles processing a URL immediately
func WebmentionSenderProcessURL(w http.ResponseWriter, r *http.Request) {
	user := GetSignedInUserOrNil(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	urlBeingProcessed := r.FormValue("process-url")
	isRSS := r.FormValue("is-rss") == "on"

	if urlBeingProcessed == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// Process URL immediately
	var sentWebmentions []shared_database.SentWebmention
	if isRSS {
		sentWebmentions = webmention_sender.ProcessFeed(&shared_database.MonitoredURL{
			URL: urlBeingProcessed,
		})
	} else {
		sentWebmentions = webmention_sender.ProcessSingleURL(&shared_database.MonitoredURL{
			URL: urlBeingProcessed,
		})
	}

	RenderTemplate(w, r, "pages/dashboard/webmention_sender/process_single_webmention_results.html",
		&map[string]CustomDeclaration{
			"urlBeingProcessed": {(*string)(nil), &urlBeingProcessed},
			"sentWebmentions":   {(*[]shared_database.SentWebmention)(nil), &sentWebmentions},
		})
}

// ChangePassword handles the password change functionality
func ChangePassword(w http.ResponseWriter, r *http.Request) {
	// Get the current signed-in user
	signedInUser := GetSignedInUserOrFail(r)
	if signedInUser == nil {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return
	}

	// Parse the form
	if err := r.ParseForm(); err != nil {
		SetFlashMessage(w, "error", "Error processing form")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	// Get the form values
	currentPassword := r.FormValue("current-password")
	newPassword := r.FormValue("new-password")
	confirmPassword := r.FormValue("confirm-password")

	// Validate input
	if currentPassword == "" || newPassword == "" || confirmPassword == "" {
		SetFlashMessage(w, "error", "All fields are required")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	// Check if new password and confirmation match
	if newPassword != confirmPassword {
		SetFlashMessage(w, "error", "New password and confirmation do not match")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	// Minimum password length check
	const minPasswordLength = 4
	if len(newPassword) < minPasswordLength {
		SetFlashMessage(w, "error", "New password must be at least "+strconv.Itoa(minPasswordLength)+" characters long")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	// Get the user DB
	userDb := user_database.GetDbOrFatal(signedInUser.Username)

	// Verify current password
	err := bcrypt.CompareHashAndPassword([]byte(signedInUser.PasswordHash), []byte(currentPassword))
	if err != nil {
		SetFlashMessage(w, "error", "Current password is incorrect")
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	// Hash the new password
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		SetFlashMessage(w, "error", "Error updating password: "+err.Error())
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	// Update the user's password
	signedInUser.PasswordHash = datatypes.JSON(newPasswordHash)
	result := userDb.Db.Save(signedInUser)
	if result.Error != nil {
		SetFlashMessage(w, "error", "Error saving password: "+result.Error.Error())
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	// Generate a new session token to force login on other devices
	token, err := generateAuthToken()
	if err != nil {
		SetFlashMessage(w, "error", "Error updating session: "+err.Error())
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	// Update the session token
	signedInUser.SessionToken = token
	result = userDb.Db.Save(signedInUser)
	if result.Error != nil {
		SetFlashMessage(w, "error", "Error updating session: "+result.Error.Error())
		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
		return
	}

	// Update the cookie
	setUserSession(w, signedInUser.Username, token)

	// Redirect with success message
	SetFlashMessage(w, "success", "Password changed successfully")
	http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
}

// MetricsNotificationSettings handles form submissions for site metrics notification settings
func MetricsNotificationSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		SetFlashMessage(w, "error", "Failed to parse form")
		http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
		return
	}

	signedInUser := GetSignedInUserOrFail(r)
	siteIDStr := chi.URLParam(r, "siteID")
	siteID, err := strconv.Atoi(siteIDStr)
	if err != nil {
		SetFlashMessage(w, "error", "Invalid site ID")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Verify the site belongs to this user
	userDb := user_database.GetDbOrFatal(signedInUser.Username)
	var site user_database.Site
	if err := userDb.Db.First(&site, siteID).Error; err != nil || site.UserID != signedInUser.ID {
		SetFlashMessage(w, "error", "Site not found or you don't have permission")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Get the user's Discord settings to verify they have Discord set up
	discordSettings, err := notifier.GetDiscordSettingsByUsername(signedInUser.Username)
	if err != nil {
		SetFlashMessage(w, "error", "Error fetching Discord settings")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
		return
	}

	// Check if Discord is verified and notifications are enabled
	if !discordSettings.DiscordVerified || !discordSettings.NotificationsEnabled {
		SetFlashMessage(w, "error", "You must enable Discord notifications in your account settings first")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
		return
	}

	// Get the selected frequency from the form
	frequency := r.FormValue("metricsFrequency")
	// Validate frequency
	validFrequencies := map[string]bool{
		"none":    true,
		"daily":   true,
		"weekly":  true,
		"monthly": true,
	}

	if !validFrequencies[frequency] {
		SetFlashMessage(w, "error", "Invalid notification frequency")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
		return
	}

	// Update the site settings
	site.MetricsNotificationFreq = frequency
	// Reset last notification time if changing frequency
	if frequency != "none" {
		site.LastMetricsSentAt = time.Now()
	}

	if err := userDb.Db.Save(&site).Error; err != nil {
		SetFlashMessage(w, "error", "Failed to update notification settings")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
		return
	}

	SetFlashMessage(w, "success", "Metrics notification settings updated successfully")
	http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
}
