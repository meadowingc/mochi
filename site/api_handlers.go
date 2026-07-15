package site

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mochi/user_database"
	"net/http"
	"strings"
	"time"
)

// GenerateAPIKey generates or regenerates an API key for a site
func GenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	signedInUser := GetSignedInUserOrFail(r)
	site := GetSiteFromContextOrFail(r)

	userDb := user_database.GetDbOrFatal(signedInUser.Username)

	// Generate a random 32-byte API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		SetFlashMessage(w, "error", "Failed to generate API key")
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
		return
	}

	apiKey := hex.EncodeToString(keyBytes)
	site.APIKey = &apiKey

	if err := userDb.Db.Save(site).Error; err != nil {
		SetFlashMessage(w, "error", "Failed to save API key: "+err.Error())
		http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings", site.ID), http.StatusSeeOther)
		return
	}

	SetFlashMessage(w, "success", "API key generated successfully. Copy it now — it won't be shown in full again.")
	http.Redirect(w, r, fmt.Sprintf("/dashboard/%d/settings?newAPIKey=%s", site.ID, apiKey), http.StatusSeeOther)
}

// AnalyticsAPIResponse is the response body for the analytics API endpoint
type AnalyticsAPIResponse struct {
	SiteURL        string              `json:"site_url"`
	Period         AnalyticsAPIPeriod  `json:"period"`
	Referrers      []AnalyticsReferrer `json:"referrers"`
	Pages          []AnalyticsPage     `json:"pages"`
	TotalHits      int                 `json:"total_hits"`
	UniqueVisitors int                 `json:"unique_visitors"`
}

type AnalyticsAPIPeriod struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type AnalyticsReferrer struct {
	URL          string   `json:"url"`
	Count        int      `json:"count"`
	PagesVisited []string `json:"pages_visited"`
}

type AnalyticsPage struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// AnalyticsAPI returns analytics data for a site as JSON
// @Summary Get analytics data for a site
// @Description Returns referrer URLs, page paths, hit counts, and unique visitor counts for a site within a date range. Useful for backlink analysis.
// @Tags analytics
// @Accept json
// @Produce json
// @Param publicID path string true "Opaque public site ID"
// @Param minDate query string false "Start date (YYYY-MM-DD format, defaults to 30 days ago)"
// @Param maxDate query string false "End date (YYYY-MM-DD format, defaults to today)"
// @Security BearerAuth
// @Success 200 {object} AnalyticsAPIResponse
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "Internal server error"
// @Router /api/analytics/{publicID} [get]
func AnalyticsAPI(w http.ResponseWriter, r *http.Request) {
	resolved, ok := getResolvedPublicSite(r)
	if !ok {
		writeUnauthorized(w)
		return
	}
	userDB := resolved.UserDB
	site := resolved.Site

	// Validate API key
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || site.APIKey == nil {
		writeUnauthorized(w)
		return
	}

	providedKey, found := strings.CutPrefix(authHeader, "Bearer ")
	if !found || providedKey == "" ||
		subtle.ConstantTimeCompare([]byte(providedKey), []byte(*site.APIKey)) != 1 {
		writeUnauthorized(w)
		return
	}

	// Parse date range
	now := time.Now()
	minDate := now.AddDate(0, 0, -30)
	maxDate := now

	if minDateStr := r.URL.Query().Get("minDate"); minDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", minDateStr); err == nil {
			minDate = parsed
		}
	}

	if maxDateStr := r.URL.Query().Get("maxDate"); maxDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", maxDateStr); err == nil {
			maxDate = parsed.Add(24*time.Hour - time.Second) // end of day
		}
	}

	// Query hits
	var hits []user_database.Hit
	if err := userDB.Db.Where(
		"site_id = ? AND date >= ? AND date <= ?", site.ID, minDate, maxDate,
	).Find(&hits).Error; err != nil {
		http.Error(w, "Error fetching data", http.StatusInternalServerError)
		return
	}

	// Aggregate data
	countsForPath := make(map[string]int)
	countsForReferrer := make(map[string]int)
	referrerPages := make(map[string]map[string]bool) // referrer -> set of pages
	uniqueVisitors := make(map[string]bool)

	for _, hit := range hits {
		if hit.Path != "" {
			countsForPath[hit.Path]++
		}
		if hit.HTTPReferer != nil && *hit.HTTPReferer != "" {
			countsForReferrer[*hit.HTTPReferer]++
			if referrerPages[*hit.HTTPReferer] == nil {
				referrerPages[*hit.HTTPReferer] = make(map[string]bool)
			}
			if hit.Path != "" {
				referrerPages[*hit.HTTPReferer][hit.Path] = true
			}
		}
		if hit.VisitorIpUaHash != nil {
			uniqueVisitors[*hit.VisitorIpUaHash] = true
		}
	}

	// Build response
	referrers := make([]AnalyticsReferrer, 0, len(countsForReferrer))
	for refURL, count := range countsForReferrer {
		pages := make([]string, 0)
		for page := range referrerPages[refURL] {
			pages = append(pages, page)
		}
		referrers = append(referrers, AnalyticsReferrer{
			URL:          refURL,
			Count:        count,
			PagesVisited: pages,
		})
	}

	// Sort referrers by count descending
	sortReferrers(referrers)

	pages := make([]AnalyticsPage, 0, len(countsForPath))
	for path, count := range countsForPath {
		pages = append(pages, AnalyticsPage{Path: path, Count: count})
	}

	// Sort pages by count descending
	sortPages(pages)

	response := AnalyticsAPIResponse{
		SiteURL: site.URL,
		Period: AnalyticsAPIPeriod{
			From: minDate.Format("2006-01-02"),
			To:   maxDate.Format("2006-01-02"),
		},
		Referrers:      referrers,
		Pages:          pages,
		TotalHits:      len(hits),
		UniqueVisitors: len(uniqueVisitors),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func sortReferrers(refs []AnalyticsReferrer) {
	for i := 0; i < len(refs); i++ {
		for j := i + 1; j < len(refs); j++ {
			if refs[j].Count > refs[i].Count {
				refs[i], refs[j] = refs[j], refs[i]
			}
		}
	}
}

func sortPages(pages []AnalyticsPage) {
	for i := 0; i < len(pages); i++ {
		for j := i + 1; j < len(pages); j++ {
			if pages[j].Count > pages[i].Count {
				pages[i], pages[j] = pages[j], pages[i]
			}
		}
	}
}
