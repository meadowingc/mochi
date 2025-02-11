package site

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"mochi/constants"
	"mochi/database"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mileusna/useragent"
	"golang.org/x/crypto/bcrypt"
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

		userDatabase := database.GetDbIfExists(username)

		if userDatabase == nil {
			http.Error(w, "You're trying to sign in, but perhaps you still need to sign up?", http.StatusUnauthorized)
			return
		}

		var admin database.User
		result := userDatabase.Db.Where(&database.User{Username: username}).First(&admin)
		if result.Error != nil {
			http.Error(w, "Invalid username. You're trying to sign in, but perhaps you still need to sign up?", http.StatusUnauthorized)
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
		if err != nil {
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}

		// Generate a new token for the session
		token, err := generateAuthToken()
		if err != nil {
			http.Error(w, "Error signing in", http.StatusInternalServerError)
			return
		}

		admin.SessionToken = token
		userDatabase.Db.Save(&admin)

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
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		if username == "" || password == "" {
			http.Error(w, "Username and password are required", http.StatusBadRequest)
			return
		}

		if strings.Contains(username, "/") {
			http.Error(w, "Username cannot contain a forward slash", http.StatusBadRequest)
			return
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error creating account: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Create a new token and store it in a cookie
		token, err := generateAuthToken()
		if err != nil {
			http.Error(w, "Error creating account: "+err.Error(), http.StatusInternalServerError)
			return
		}

		userDb := database.GetDbIfExists(username)
		var userExistsInDb bool = false

		if userDb != nil {
			userExistsInDb = userDb.Db.Where(&database.User{Username: username}).First(&database.User{}).Error == nil
		}

		if userDb != nil && userExistsInDb {
			http.Error(w, "User already exists. You can sign in instead.", http.StatusUnauthorized)
			return
		}

		newAdmin := database.User{Username: username, PasswordHash: passwordHash, SessionToken: token}

		result := database.GetOrCreateDB(username).Db.Create(&newAdmin)
		if result.Error != nil {
			http.Error(w, "Error creating account: "+result.Error.Error(), http.StatusInternalServerError)
			return
		}

		setUserSession(
			w, username, token,
		)

		// Redirect to the admin sign-in page after successful sign-up
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
	http.Redirect(w, r, "/user/login", http.StatusSeeOther)
}

func UserDashboardHome(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)

	userSites := []database.Site{}

	result := database.GetDbOrFatal(signedInUser.Username).Db.Where(&database.Site{
		UserID: signedInUser.ID,
	}).Find(&userSites)

	if result.Error != nil {
		http.Error(w, "Error fetching sites", http.StatusInternalServerError)
		return
	}

	RenderTemplate(w, r, "pages/dashboard/dashboard.html",
		&map[string]CustomDeclaration{
			"userSites": {(*[]database.Site)(nil), &userSites},
		},
	)
}

func CreateNewSite(w http.ResponseWriter, r *http.Request) {
	user := GetSignedInUserOrFail(r)
	urlParam := r.FormValue("url")

	siteURL, err := url.Parse(urlParam)
	if err != nil {
		http.Error(w, "Unable to parse site URL", http.StatusBadRequest)
		return
	}

	// Check if the site already exists
	userDatabase := database.GetDbOrFatal(user.Username)

	var existingSite database.Site
	result := userDatabase.Db.Where(&database.Site{
		URL:    siteURL.String(),
		UserID: user.ID,
	}).First(&existingSite)

	if result.Error == nil {
		http.Error(w, "Site already exists", http.StatusBadRequest)
		return
	}

	newSite := database.Site{URL: siteURL.String(), UserID: user.ID}

	result = userDatabase.Db.Create(&newSite)
	if result.Error != nil {
		http.Error(w, "Error creating site: "+result.Error.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func SiteDetails(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "siteID")
	siteIDUint, err := strconv.ParseUint(siteID, 10, 32)
	if err != nil {
		http.Error(w, "Invalid site ID", http.StatusBadRequest)
		return
	}

	// Check for minDate in query params
	minDateStr := r.URL.Query().Get("minDate")
	var minDate time.Time
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

	userDatabase := database.GetDbOrFatal(signedInUser.Username)

	var site database.Site
	result := userDatabase.Db.First(&site, siteIDUint)
	if result.Error != nil {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}

	if site.UserID != signedInUser.ID {
		http.Error(w, "You don't own this site", http.StatusUnauthorized)
		return
	}

	// get all hits for the site within the date and filters
	pagePathFilter := r.URL.Query().Get("pagePathFilter")

	referrerFilter := stringWithValueOrNil(r.URL.Query().Get("referrerFilter"))
	countryFilter := stringWithValueOrNil(r.URL.Query().Get("countryFilter"))
	osFilter := stringWithValueOrNil(r.URL.Query().Get("osFilter"))
	browserFilter := stringWithValueOrNil(r.URL.Query().Get("browserFilter"))
	deviceFilter := stringWithValueOrNil(r.URL.Query().Get("deviceFilter"))

	var hits []database.Hit
	query := userDatabase.Db.Where(
		"date >= ? AND date <= ?", minDate, maxDate,
	).Where(&database.Hit{
		Path:              pagePathFilter,
		SiteID:            uint(siteIDUint),
		HTTPReferer:       referrerFilter,
		CountryCode:       countryFilter,
		VisitorOS:         osFilter,
		VisitorBrowser:    browserFilter,
		VisitorDeviceType: deviceFilter,
	})

	result = query.Order("date ASC").Find(&hits)
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
	RenderTemplate(w, r, "pages/dashboard/site/site_details.html",
		&map[string]CustomDeclaration{
			"site":                    {(*database.Site)(nil), &site},
			"minDate":                 {(*time.Time)(nil), &minDate},
			"maxDate":                 {(*time.Time)(nil), &maxDate},
			"hits":                    {(*[]database.Hit)(nil), &hits},
			"numUniqueVisitors":       {(*int)(nil), &numUniqueVisitors},
			"sortedCountsForPath":     makeSortedDeclaration(countsForPath),
			"sortedCountsForReferrer": makeSortedDeclaration(countsForReferrer),
			"sortedCountsForCountry":  makeSortedDeclaration(countsForCountry),
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
	siteID := chi.URLParam(r, "siteID")

	signedInUser := GetSignedInUserOrFail(r)
	userDatabase := database.GetDbOrFatal(signedInUser.Username)

	var site database.Site
	result := userDatabase.Db.First(&site, siteID)
	if result.Error != nil {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}

	if site.UserID != signedInUser.ID {
		http.Error(w, "You don't own this site", http.StatusUnauthorized)
		return
	}

	RenderTemplate(w, r, "pages/dashboard/site/embed_instructions.html",
		&map[string]CustomDeclaration{
			"site": {(*database.Site)(nil), &site},
		},
	)
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

	userDatabase := database.GetDbIfExists(username)

	if userDatabase == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var site database.Site
	result := userDatabase.Db.First(&site, siteID)
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
			"site":          {(*database.Site)(nil), &site},
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

		userDatabase := database.GetDbIfExists(username)

		if userDatabase == nil {
			log.Printf("ReaperPostHit: User not found: %s", username)
			return
		}

		var site database.Site
		result := userDatabase.Db.First(&site, siteID)
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

		// if the referer is the same as the site URL, then it's likely a direct visit and we should set the referrer to nil
		if referrerParam != nil {
			referrerURL, err := url.Parse(*referrerParam)
			if err != nil {
				log.Printf("ReaperPostHit: Unable to parse referrer URL: %s", *referrerParam)
				return
			}

			if referrerURL.Host == siteURL.Host {
				referrerParam = nil
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

		hit := database.Hit{
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

		result = userDatabase.Db.Create(&hit)

		if result.Error != nil {
			log.Printf("ReaperPostHit: Error saving hit: %v", result.Error)
			return
		}
	}()
}
