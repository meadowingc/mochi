package site

import (
	"fmt"
	"io"
	"log"
	"mochi/database"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi"
)

func WebmentionPost(w http.ResponseWriter, r *http.Request) {
	escapedUsername := chi.URLParam(r, "username")
	siteID := chi.URLParam(r, "siteId")

	log.Printf("WebmentionPost: username='%s', siteID='%s'", escapedUsername, siteID)

	if escapedUsername == "" {
		log.Printf("WebmentionPost: Username is empty")
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	if siteID == "" {
		log.Printf("WebmentionPost: SiteID is empty")
		http.Error(w, "SiteID is required", http.StatusBadRequest)
		return
	}

	// Return immediately
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Request received"))

	// Execute the rest of the logic in a goroutine
	go func() {
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

		userDatabase := database.GetDbIfExists(username)

		if userDatabase == nil {
			log.Printf("WebmentionPost: User not found: '%s'", username)
			return
		}

		var site database.Site
		result := userDatabase.Db.First(&site, siteID)
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
		client := &http.Client{}
		req, err := http.NewRequest("GET", sourceUrlStr, nil)
		if err != nil {
			log.Printf("WebmentionPost: Error creating GET request for source URL '%s' for user '%s': %v", sourceUrlStr, username, err)
			return
		}

		req.Header.Set("Accept", "text/html")
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("WebmentionPost: Error fetching source URL '%s' for user '%s': %v", sourceUrlStr, username, err)
			return
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("WebmentionPost: Source URL '%s' returned status code %d for user '%s'", sourceUrlStr, resp.StatusCode, username)
			return
		}

		sourceHtmlBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("WebmentionPost: Error reading source URL '%s' for user '%s': %v", sourceUrlStr, username, err)
			return
		}

		sourceHtml := string(sourceHtmlBytes)

		// Check if the target URL is wrapped in an href attribute
		if !strings.Contains(sourceHtml, fmt.Sprintf(`href="%s"`, targetUrlStr)) {
			log.Printf("WebmentionPost: Source URL '%s' does not contain target URL '%s' wrapped in href for user '%s'", sourceUrlStr, targetUrlStr, username)
			return
		}

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
		var existingWebmention database.WebMention
		result = userDatabase.Db.Where(&database.WebMention{
			SiteID:    site.ID,
			SourceURL: sourceUrlStr,
			TargetURL: targetUrlStr,
		}).First(&existingWebmention)

		if result.Error == nil {
			log.Printf("WebmentionPost: Webmention already exists for source URL '%s' and target URL '%s' for user '%s'", sourceUrlStr, targetUrlStr, username)
			return
		}

		// actually save webmention
		webmention := database.WebMention{
			SiteID:    site.ID,
			SourceURL: sourceUrlStr,
			TargetURL: targetUrlStr,
			Status:    "pending",
		}

		result = userDatabase.Db.Create(&webmention)
		if result.Error != nil {
			log.Printf("WebmentionPost: Error creating webmention for user '%s': %v", username, result.Error)
			return
		}

	}()
}
