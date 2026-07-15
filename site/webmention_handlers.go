package site

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mochi/notifier"
	"mochi/safehttp"
	"mochi/user_database"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

var newWebmentionReceiverHTTPClient = safehttp.NewClient
var sendWebmentionNotification = notifier.SendMessageToUsername

// PublicWebMention represents the public-facing structure of a webmention
type PublicWebMention struct {
	SourceURL string    `json:"source"`
	TargetURL string    `json:"target"`
	CreatedAt time.Time `json:"created_at"`
}

// WebmentionPublicAPI handles serving approved webmentions as JSON.
// @Summary Get approved webmentions for a site
// @Description Returns the approved webmentions for the site identified by an opaque public ID.
// @Tags webmentions
// @Produce json
// @Param publicID path string true "Opaque public site ID"
// @Success 200 {array} PublicWebMention
// @Failure 404 {string} string "Not found"
// @Failure 500 {string} string "Internal server error"
// @Router /api/webmentions/{publicID} [get]
func WebmentionPublicAPI(w http.ResponseWriter, r *http.Request) {
	resolved, ok := getResolvedPublicSite(r)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	userDB := resolved.UserDB
	site := resolved.Site

	// Get approved webmentions for the site
	var webmentions []user_database.WebMention
	result := userDB.Db.Where(&user_database.WebMention{
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
	resolved, ok := getResolvedPublicSite(r)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	sourceUrlStr := strings.TrimSpace(r.FormValue("source"))
	targetUrlStr := strings.TrimSpace(r.FormValue("target"))
	sourceUrl, err := url.Parse(sourceUrlStr)
	if err != nil || safehttp.ValidateURL(sourceUrl) != nil {
		http.Error(w, "Invalid source URL", http.StatusBadRequest)
		return
	}
	targetUrl, err := url.Parse(targetUrlStr)
	if err != nil || safehttp.ValidateURL(targetUrl) != nil {
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	siteURL, err := url.Parse(resolved.Site.URL)
	if err != nil || siteURL.Hostname() == "" {
		log.Printf("WebmentionReceive: configured site URL is invalid")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !strings.EqualFold(targetUrl.Hostname(), siteURL.Hostname()) {
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(sourceUrl.Hostname(), targetUrl.Hostname()) {
		http.Error(w, "Invalid source URL", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Request received"))

	go func() {
		user_db := resolved.UserDB
		site := resolved.Site
		username := resolved.Route.Username

		client := newWebmentionReceiverHTTPClient(
			safehttp.WithTimeout(5*time.Second),
			safehttp.WithMaxRedirects(20),
		)
		if client == nil {
			log.Printf("WebmentionReceive: HTTP client initialization failed site_id=%d", site.ID)
			return
		}
		defer client.CloseIdleConnections()

		// Make an initial HEAD request
		req, err := http.NewRequest("HEAD", sourceUrlStr, nil)
		if err != nil {
			log.Printf("WebmentionReceive: error creating source HEAD request site_id=%d", site.ID)
			return
		}

		// some servers reject requests that don't have standard headers (eg, from bots)
		const userAgent = "Mochi (https://mochi.meadow.cafe)"
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		resp, err := client.Do(req)
		if err != nil {
			_ = closeResponseBody(resp)
			log.Printf("WebmentionReceive: source HEAD request failed site_id=%d", site.ID)
			return
		}
		statusCode := resp.StatusCode
		if err := closeResponseBody(resp); err != nil {
			log.Printf("WebmentionReceive: source HEAD response close failed site_id=%d", site.ID)
			return
		}
		if statusCode != http.StatusOK {
			log.Printf("WebmentionReceive: source HEAD status=%d site_id=%d", statusCode, site.ID)
			return
		}

		// Make a full GET request to fetch the source URL
		req, err = http.NewRequest("GET", sourceUrlStr, nil)
		if err != nil {
			log.Printf("WebmentionReceive: error creating source GET request site_id=%d", site.ID)
			return
		}

		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		resp, err = client.Do(req)
		if err != nil {
			_ = closeResponseBody(resp)
			log.Printf("WebmentionReceive: source GET request failed site_id=%d", site.ID)
			return
		}

		if resp.StatusCode != http.StatusOK {
			statusCode = resp.StatusCode
			_ = closeResponseBody(resp)
			log.Printf("WebmentionReceive: source GET status=%d site_id=%d", statusCode, site.ID)
			return
		}

		sourceHtmlBytes, err := readAndCloseLimitedBody(resp, 1<<20)
		if err != nil {
			log.Printf("WebmentionReceive: error reading source response site_id=%d", site.ID)
			return
		}

		sourceHtml := string(sourceHtmlBytes)

		// Check if the target URL is wrapped in an href attribute
		hrefPattern := fmt.Sprintf(`href\s*=\s*(?:['"])%s(?:['"])`, regexp.QuoteMeta(targetUrlStr))
		hrefRegex := regexp.MustCompile(hrefPattern)

		if !hrefRegex.MatchString(sourceHtml) {
			log.Printf("WebmentionReceive: source does not link to target site_id=%d", site.ID)
			return
		}

		// now verify that the target URL is valid and exists
		req, err = http.NewRequest("GET", targetUrlStr, nil)
		if err != nil {
			log.Printf("WebmentionReceive: error creating target GET request site_id=%d", site.ID)
			return
		}

		req.Header.Set("Accept", "text/html")
		resp, err = client.Do(req)
		if err != nil {
			_ = closeResponseBody(resp)
			log.Printf("WebmentionReceive: target GET request failed site_id=%d", site.ID)
			return
		}
		statusCode = resp.StatusCode
		if err := closeResponseBody(resp); err != nil {
			log.Printf("WebmentionReceive: target response close failed site_id=%d", site.ID)
			return
		}
		if statusCode != http.StatusOK {
			log.Printf("WebmentionReceive: target GET status=%d site_id=%d", statusCode, site.ID)
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
		var existingWebmention user_database.WebMention
		result := user_db.Db.Where(&user_database.WebMention{
			SiteID:    site.ID,
			SourceURL: sourceUrlStr,
			TargetURL: targetUrlStr,
		}).First(&existingWebmention)

		if result.Error == nil {
			log.Printf("WebmentionReceive: duplicate webmention site_id=%d", site.ID)
			return
		}
		if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.Printf("WebmentionReceive: duplicate check failed site_id=%d", site.ID)
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
			log.Printf("WebmentionReceive: error creating webmention site_id=%d", site.ID)
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

			err := sendWebmentionNotification(username, message)
			if err != nil {
				// Just log the error but don't interrupt the flow
				log.Printf("WebmentionReceive: Discord notification failed site_id=%d", site.ID)
			} else {
				log.Printf("WebmentionReceive: Discord notification sent site_id=%d", site.ID)
			}
		}()

	}()
}

func readAndCloseLimitedBody(response *http.Response, limit int64) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, errors.New("response body is missing")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(body)) > limit {
		return nil, errors.New("response body exceeds limit")
	}
	return body, nil
}

func closeResponseBody(response *http.Response) error {
	if response == nil || response.Body == nil {
		return nil
	}
	return response.Body.Close()
}
