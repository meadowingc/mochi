package site

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mochi/notifier"
	"mochi/user_database"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// PublicWebMention represents the public-facing structure of a webmention
type PublicWebMention struct {
	SourceURL string    `json:"source"`
	TargetURL string    `json:"target"`
	CreatedAt time.Time `json:"created_at"`
}

// WebmentionPublicAPI handles serving approved webmentions as JSON
func WebmentionPublicAPI(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	siteID := chi.URLParam(r, "siteID")

	// Get the user database
	userDB := user_database.GetDbIfExists(username)
	if userDB == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Get the site
	var site user_database.Site
	result := userDB.Db.First(&site, siteID)
	if result.Error != nil {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}

	// Get approved webmentions for the site
	var webmentions []user_database.WebMention
	result = userDB.Db.Where(&user_database.WebMention{
		SiteID: site.ID,
		Status: "approved",
	}).Find(&webmentions)

	if result.Error != nil {
		http.Error(w, "Error fetching webmentions", http.StatusInternalServerError)
		return
	}

	// Convert to public-facing structure
	publicWebmentions := make([]PublicWebMention, len(webmentions))
	for i, wm := range webmentions {
		publicWebmentions[i] = PublicWebMention{
			SourceURL: wm.SourceURL,
			TargetURL: wm.TargetURL,
			CreatedAt: wm.CreatedAt,
		}
	}

	// Set headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Return JSON response
	json.NewEncoder(w).Encode(publicWebmentions)
}

func WebmentionsDetails(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)
	useruser_database := user_database.GetDbOrFatal(signedInUser.Username)

	site := GetSiteFromContextOrFail(r)

	allWebmentions := []user_database.WebMention{}
	result := useruser_database.Db.Where(&user_database.WebMention{
		SiteID: site.ID,
	}).Find(&allWebmentions)

	if result.Error != nil {
		http.Error(w, "Error fetching webmentions: "+result.Error.Error(), http.StatusInternalServerError)
		return
	}

	// sort webmentions by CreatedAt
	sort.Slice(allWebmentions, func(i, j int) bool {
		return allWebmentions[i].CreatedAt.After(allWebmentions[j].CreatedAt)
	})

	// Group webmentions by status
	pendingWebmentions := []user_database.WebMention{}
	approvedWebmentions := []user_database.WebMention{}
	rejectedWebmentions := []user_database.WebMention{}

	for _, wm := range allWebmentions {
		switch wm.Status {
		case "approved":
			approvedWebmentions = append(approvedWebmentions, wm)
		case "rejected":
			rejectedWebmentions = append(rejectedWebmentions, wm)
		default:
			pendingWebmentions = append(pendingWebmentions, wm)
		}
	}

	RenderTemplate(w, r, "pages/dashboard/webmentions/webmentions_details.html",
		&map[string]CustomDeclaration{
			"site":                {(*user_database.Site)(nil), site},
			"pendingWebmentions":  {(*[]user_database.WebMention)(nil), &pendingWebmentions},
			"approvedWebmentions": {(*[]user_database.WebMention)(nil), &approvedWebmentions},
			"rejectedWebmentions": {(*[]user_database.WebMention)(nil), &rejectedWebmentions},
		},
	)
}

// WebmentionApprove approves a webmention
func WebmentionApprove(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)
	site := GetSiteFromContextOrFail(r)
	webmentionID := chi.URLParam(r, "webmentionID")

	userDb := user_database.GetDbOrFatal(signedInUser.Username)

	var webmention user_database.WebMention
	if err := userDb.Db.First(&webmention, webmentionID).Error; err != nil {
		SetFlashMessage(w, "error", "Webmention not found")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
		return
	}

	// Check if the webmention belongs to the site
	if webmention.SiteID != site.ID {
		SetFlashMessage(w, "error", "Webmention does not belong to this site")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
		return
	}

	// Update the status to "approved"
	webmention.Status = "approved"
	if err := userDb.Db.Save(&webmention).Error; err != nil {
		SetFlashMessage(w, "error", "Failed to approve webmention: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
		return
	}

	SetFlashMessage(w, "success", "Webmention approved successfully")
	http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
}

// WebmentionReject rejects a webmention
func WebmentionReject(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)
	site := GetSiteFromContextOrFail(r)
	webmentionID := chi.URLParam(r, "webmentionID")

	userDb := user_database.GetDbOrFatal(signedInUser.Username)

	var webmention user_database.WebMention
	if err := userDb.Db.First(&webmention, webmentionID).Error; err != nil {
		SetFlashMessage(w, "error", "Webmention not found")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
		return
	}

	// Check if the webmention belongs to the site
	if webmention.SiteID != site.ID {
		SetFlashMessage(w, "error", "Webmention does not belong to this site")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
		return
	}

	// Update the status to "rejected"
	webmention.Status = "rejected"
	if err := userDb.Db.Save(&webmention).Error; err != nil {
		SetFlashMessage(w, "error", "Failed to reject webmention: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
		return
	}

	SetFlashMessage(w, "success", "Webmention rejected successfully")
	http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
}

// WebmentionChangeStatus changes the status of a webmention
func WebmentionChangeStatus(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)
	site := GetSiteFromContextOrFail(r)
	webmentionID := chi.URLParam(r, "webmentionID")
	status := chi.URLParam(r, "status")

	// Validate status
	validStatuses := map[string]bool{
		"pending":  true,
		"approved": true,
		"rejected": true,
	}

	if !validStatuses[status] {
		SetFlashMessage(w, "error", "Invalid status")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
		return
	}

	userDb := user_database.GetDbOrFatal(signedInUser.Username)

	var webmention user_database.WebMention
	if err := userDb.Db.First(&webmention, webmentionID).Error; err != nil {
		SetFlashMessage(w, "error", "Webmention not found")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
		return
	}

	// Check if the webmention belongs to the site
	if webmention.SiteID != site.ID {
		SetFlashMessage(w, "error", "Webmention does not belong to this site")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
		return
	}

	// Update the status
	webmention.Status = status
	if err := userDb.Db.Save(&webmention).Error; err != nil {
		SetFlashMessage(w, "error", "Failed to update webmention status: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
		return
	}

	SetFlashMessage(w, "success", "Webmention status updated successfully")
	http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/webmentions", site.ID), http.StatusSeeOther)
}

func WebmentionReceive(w http.ResponseWriter, r *http.Request) {

	//	extract request data
	escapedUsername := chi.URLParam(r, "username")
	siteID := chi.URLParam(r, "siteId")

	escapedUsername = strings.TrimSpace(escapedUsername)
	username, err := url.PathUnescape(escapedUsername)
	if err != nil {
		log.Printf("WebmentionPost: Error unescaping username '%s': %v", escapedUsername, err)
		return
	}

	// Process the webmention
	sourceUrlStr := r.FormValue("source")
	targetUrlStr := r.FormValue("target")

	sourceUrl, err := url.Parse(sourceUrlStr)
	if err != nil {
		log.Printf("WebmentionPost: Can't parse source URL '%s' for user '%s'", sourceUrlStr, username)
		return
	}

	targetUrl, err := url.Parse(targetUrlStr)
	if err != nil {
		log.Printf("WebmentionPost: Can't parse target URL '%s' for user '%s'", targetUrlStr, username)
		return
	}

	// Check if the target URL is a loopback address
	if isLoopbackAddress(targetUrl.Hostname()) {
		log.Printf("WebmentionPost: Target URL '%s' is a loopback address for user '%s'", targetUrlStr, username)
		return
	}

	// Return immediately and defer the rest of the logic
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Request received"))

	// Execute the rest of the logic in a goroutine
	go func() {

		user_db := user_database.GetDbIfExists(username)

		if user_db == nil {
			log.Printf("WebmentionPost: User not found: '%s'", username)
			return
		}

		var site user_database.Site
		result := user_db.Db.First(&site, siteID)
		if result.Error != nil {
			log.Printf("WebmentionPost: Site '%s' not found for user '%s'", siteID, username)
			return
		}

		siteURL, err := url.Parse(site.URL)
		if err != nil {
			log.Printf("WebmentionPost: Can't parse site URL '%s' for user '%s'", site.URL, username)
			return
		}

		// Check if the target URL is the same as the site URL
		if targetUrl.Hostname() != siteURL.Hostname() {
			log.Printf("WebmentionPost: Target URL '%s' does not match site URL '%s' for user '%s'", targetUrlStr, site.URL, username)
			return
		}

		// Check if the target is in the same domain as the source
		if sourceUrl.Hostname() == targetUrl.Hostname() {
			log.Printf("WebmentionPost: Source URL '%s' and target URL '%s' are in the same domain for user '%s'", sourceUrlStr, targetUrlStr, username)
			return
		}

		// now validate that the source URL contains a link to the target URL
		client := &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 20 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}

		// Make an initial HEAD request
		req, err := http.NewRequest("HEAD", sourceUrlStr, nil)
		if err != nil {
			log.Printf("WebmentionPost: Error creating HEAD request for source URL '%s' for user '%s': %v", sourceUrlStr, username, err)
			return
		}

		// some servers reject requests that don't have standard headers (eg, from bots)
		const userAgent = "Mochi (https://mochi.meadow.cafe)"
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("WebmentionPost: Error fetching source URL '%s' for user '%s': %v", sourceUrlStr, username, err)
			return
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("WebmentionPost: [HEAD] Source URL '%s' returned status code %d for user '%s'", sourceUrlStr, resp.StatusCode, username)
			return
		}

		resp.Body.Close()

		// Make a full GET request to fetch the source URL
		req, err = http.NewRequest("GET", sourceUrlStr, nil)
		if err != nil {
			log.Printf("WebmentionPost: Error creating GET request for source URL '%s' for user '%s': %v", sourceUrlStr, username, err)
			return
		}

		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		resp, err = client.Do(req)
		if err != nil {
			log.Printf("WebmentionPost: Error fetching source URL '%s' for user '%s': %v", sourceUrlStr, username, err)
			return
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("WebmentionPost: [GET] Source URL '%s' returned status code %d for user '%s'", sourceUrlStr, resp.StatusCode, username)
			return
		}

		// Limit the amount of data fetched to 1MB
		sourceHtmlBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB
		if err != nil {
			log.Printf("WebmentionPost: Error reading source URL '%s' for user '%s': %v", sourceUrlStr, username, err)
			return
		}

		resp.Body.Close()

		sourceHtml := string(sourceHtmlBytes)

		// Check if the target URL is wrapped in an href attribute
		hrefPattern := fmt.Sprintf(`href\s*=\s*(?:['"])%s(?:['"])`, regexp.QuoteMeta(targetUrlStr))
		hrefRegex := regexp.MustCompile(hrefPattern)

		if !hrefRegex.MatchString(sourceHtml) {
			log.Printf("WebmentionPost: Source URL '%s' does not contain target URL '%s' wrapped in href for user '%s'", sourceUrlStr, targetUrlStr, username)
			return
		}

		// now verify that the target URL is valid and exists
		req, err = http.NewRequest("GET", targetUrlStr, nil)
		if err != nil {
			log.Printf("WebmentionPost: Error creating GET request for target URL '%s' for user '%s': %v", targetUrlStr, username, err)
			return
		}

		req.Header.Set("Accept", "text/html")
		resp, err = client.Do(req)
		if err != nil {
			log.Printf("WebmentionPost: Error fetching target URL '%s' for user '%s': %v", targetUrlStr, username, err)
			return
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("WebmentionPost: Target URL '%s' returned status code %d for user '%s'", targetUrlStr, resp.StatusCode, username)
			return
		}

		resp.Body.Close()

		// normalize the target and source URLs
		normalizeURL := func(u *url.URL) string {
			if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
				u.Host = u.Hostname() // remove default port
			}

			u.Scheme = "https"
			u.Host = strings.ToLower(u.Host)
			u.Fragment = "" // remove fragment (the part after #)

			queryParams := u.Query()
			u.RawQuery = queryParams.Encode() // sort query params

			return strings.TrimRight(u.String(), "/")
		}

		targetUrlStr = normalizeURL(targetUrl)
		sourceUrlStr = normalizeURL(sourceUrl)

		// Check if the webmention already exists
		var existingWebmention user_database.WebMention
		result = user_db.Db.Where(&user_database.WebMention{
			SiteID:    site.ID,
			SourceURL: sourceUrlStr,
			TargetURL: targetUrlStr,
		}).First(&existingWebmention)

		if result.Error == nil {
			log.Printf("WebmentionPost: Webmention already exists for source URL '%s' and target URL '%s' for user '%s'", sourceUrlStr, targetUrlStr, username)
			return
		}

		// actually save webmention
		webmention := user_database.WebMention{
			SiteID:    site.ID,
			SourceURL: sourceUrlStr,
			TargetURL: targetUrlStr,
			Status:    "pending",
		}

		result = user_db.Db.Create(&webmention)
		if result.Error != nil {
			log.Printf("WebmentionPost: Error creating webmention for user '%s': %v", username, result.Error)
			return
		}

		// Send a Discord notification
		go func() {
			// Extract target path for better context
			targetPath := targetUrl.Path
			if targetPath == "" {
				targetPath = "/"
			}

			// Create a nicely formatted message
			message := fmt.Sprintf(":bell: **New Webmention Received!**\n\n"+
				"Your page has been mentioned by another site.\n\n"+
				":link: **From:** %s\n"+
				":page_facing_up: **To:** %s%s\n\n"+
				"View all webmentions in your dashboard: https://mochi.meadow.cafe/dashboard/%d/webmentions",
				sourceUrlStr, targetUrl.Hostname(), targetPath, site.ID)

			err := notifier.SendMessageToUsername(username, message)
			if err != nil {
				// Just log the error but don't interrupt the flow
				log.Printf("Failed to send Discord notification for webmention: %v", err)
			} else {
				log.Printf("Discord notification sent to %s for new webmention", username)
			}
		}()

	}()
}

// Helper function to check if a hostname is a loopback address
func isLoopbackAddress(hostname string) bool {
	ip := net.ParseIP(hostname)
	if ip != nil {
		return ip.IsLoopback()
	}

	// Resolve the hostname to an IP address
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.IsLoopback() {
			return true
		}
	}

	return false
}
