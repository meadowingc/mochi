package site

import (
	"mochi/constants"
	"mochi/database"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mileusna/useragent"
	"github.com/open2b/scriggo/native"
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
		username := r.FormValue("username")
		password := r.FormValue("password")

		var admin database.User
		result := database.GetDB().Where(&database.User{Username: username}).First(&admin)
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
		database.GetDB().Save(&admin)

		http.SetCookie(w, &http.Cookie{
			Name:  string(AuthenticatedUserTokenCookieName),
			Value: token,
			Path:  "/",
		})

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
		username := r.FormValue("username")
		password := r.FormValue("password")

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

		newAdmin := database.User{Username: username, PasswordHash: passwordHash, SessionToken: token}

		result := database.GetDB().Create(&newAdmin)
		if result.Error != nil {
			http.Error(w, "Error creating account: "+result.Error.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  string(AuthenticatedUserTokenCookieName),
			Value: token,
			Path:  "/",
		})

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

	result := database.GetDB().Where(&database.Site{
		UserID: signedInUser.ID,
	}).Find(&userSites)

	if result.Error != nil {
		http.Error(w, "Error fetching sites", http.StatusInternalServerError)
		return
	}

	RenderTemplate(w, r, "pages/dashboard/dashboard.html", &native.Declarations{
		"userSites": &userSites,
	})
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
	var existingSite database.Site
	result := database.GetDB().Where(&database.Site{
		URL:    siteURL.String(),
		UserID: user.ID,
	}).First(&existingSite)

	if result.Error == nil {
		http.Error(w, "Site already exists", http.StatusBadRequest)
		return
	}

	newSite := database.Site{URL: siteURL.String(), UserID: user.ID}

	result = database.GetDB().Create(&newSite)
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
		maxDate = time.Now().AddDate(0, 0, 1) // tomorrow
	}

	var site database.Site
	result := database.GetDB().First(&site, siteIDUint)
	if result.Error != nil {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}

	signedInUser := GetSignedInUserOrFail(r)
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
	query := database.GetDB().Where(
		"site_id = ? AND date >= ? AND date <= ?", siteIDUint, minDate, maxDate,
	).Where(&database.Hit{
		Path:              pagePathFilter,
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
	}

	sortedCountsForPath := sortMapByValue(countsForPath)
	sortedCountsForReferrer := sortMapByValue(countsForReferrer)
	sortedCountsForCountry := sortMapByValue(countsForCountry)
	sortedCountsForOS := sortMapByValue(countsForOS)
	sortedCountsForBrowser := sortMapByValue(countsForBrowser)
	sortedCountsForDevice := sortMapByValue(countsForDevice)

	graphDays := make([]string, 0, len(visitsByDay))
	graphVisits := make([]int, 0, len(visitsByDay))

	for day, visits := range visitsByDay {
		graphDays = append(graphDays, day)
		graphVisits = append(graphVisits, visits)
	}

	RenderTemplate(w, r, "pages/dashboard/site/site_details.html", &native.Declarations{
		"site":                    &site,
		"minDate":                 &minDate,
		"maxDate":                 &maxDate,
		"hits":                    &hits,
		"sortedCountsForPath":     &sortedCountsForPath,
		"sortedCountsForReferrer": &sortedCountsForReferrer,
		"sortedCountsForCountry":  &sortedCountsForCountry,
		"sortedCountsForOS":       &sortedCountsForOS,
		"sortedCountsForBrowser":  &sortedCountsForBrowser,
		"sortedCountsForDevice":   &sortedCountsForDevice,
		"visitsByDay":             &visitsByDay,
		"graphDays":               &graphDays,
		"graphVisits":             &graphVisits,
	})
}

func SiteEmbedInstructions(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "siteID")

	var site database.Site
	result := database.GetDB().First(&site, siteID)
	if result.Error != nil {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}

	signedInUser := GetSignedInUserOrFail(r)
	if site.UserID != signedInUser.ID {
		http.Error(w, "You don't own this site", http.StatusUnauthorized)
		return
	}

	RenderTemplate(w, r, "pages/dashboard/site/embed_instructions.html", &native.Declarations{
		"site": &site,
	})
}

func ReaperGetEmbedJs(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "siteID")

	var site database.Site
	result := database.GetDB().First(&site, siteID)
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

	RenderTemplate(w, r, "pages/reaper/embed/reaper_embed.js", &native.Declarations{
		"site":         &site,
		"countryFlags": "🇦🇹🇧🇷🇨🇦🇨🇭🇨🇱🇨🇷🇩🇪🇫🇷🇬🇧🇮🇩🇮🇱🇮🇳🇳🇱🇳🇴🇳🇿🇵🇭🇷🇸🇹🇭🇺🇸",
	})
}

func ReaperPostHit(w http.ResponseWriter, r *http.Request) {
	siteID := chi.URLParam(r, "siteID")

	var site database.Site
	result := database.GetDB().First(&site, siteID)
	if result.Error != nil {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}

	siteURL, err := url.Parse(site.URL)
	if err != nil {
		http.Error(w, "Invalid site URL", http.StatusInternalServerError)
		return
	}

	urlOfIncomingRequest := r.Header.Get("origin")

	if urlOfIncomingRequest == "" {
		urlOfIncomingRequest = r.Header.Get("referer")
	}

	if urlOfIncomingRequest != "" {
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

	// currentDomainParam := r.URL.Query().Get("url")
	pagePathParam := r.URL.Query().Get("path")
	referrerParam := stringWithValueOrNil(r.URL.Query().Get("referrer"))

	if pagePathParam == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Path parameter is required"))
		return
	}

	// remove rightmost slash
	if strings.HasSuffix(pagePathParam, "/") {
		pagePathParam = strings.TrimRight(pagePathParam, "/")
	}

	// if the referer is the same as the site URL, then it's likely a direct visit and we should set the referrer to nil
	if referrerParam != nil {
		referrerURL, err := url.Parse(*referrerParam)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unable to parse referrer URL"))
			return
		}

		if referrerURL.Host == siteURL.Host {
			referrerParam = nil
		}
	}

	cloudflareCountryCode := stringWithValueOrNil(r.Header.Get("CF-IPCountry"))
	userAgent := r.Header.Get("User-Agent")

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
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Bot detected"))
				return
			}
		}

		if ua.Bot {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Bot detected"))
			return
		}

		if ua.OS != "" {
			visitorOS = &ua.OS
		}

		if ua.Name != "" {
			visitorBrowser = &ua.Name
		}

		if ua.Device != "" {
			visitorDeviceType = &ua.Device
		} else {
			switch {
			case ua.Mobile:
				visitorDeviceType = stringWithValueOrNil("Mobile")
			case ua.Tablet:
				visitorDeviceType = stringWithValueOrNil("Tablet")
			case ua.Desktop:
				visitorDeviceType = stringWithValueOrNil("Desktop")
			}
		}
	}

	hit := database.Hit{
		SiteID:            site.ID,
		Path:              pagePathParam,
		Date:              time.Now(), // Add 8 hours to get to UTC time
		HTTPReferer:       referrerParam,
		CountryCode:       cloudflareCountryCode,
		VisitorOS:         visitorOS,
		VisitorDeviceType: visitorDeviceType,
		VisitorBrowser:    visitorBrowser,
	}

	result = database.GetDB().Create(&hit)

	if result.Error != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error saving hit"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hit saved"))
}
