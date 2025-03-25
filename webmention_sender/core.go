package webmention_sender

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"mochi/shared_database"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

const (
	maxRSSEntriesToCheck = 20
	userAgent            = "Mochi Webmention Sender (https://mochi.meadow.cafe)"
)

// RSS feed structures
type RSS struct {
	Channel Channel `xml:"channel"`
}

type Channel struct {
	Items []Item `xml:"item"`
}

type Item struct {
	Link string `xml:"link"`
}

// StartPeriodicChecker starts the periodic checking of monitored URLs
func StartPeriodicChecker() {
	ticker := time.NewTicker(24 * time.Hour) // Check once per day
	go func() {
		for {
			log.Println("Running scheduled webmention checks")
			CheckAllMonitoredURLs()
			<-ticker.C
		}
	}()
}

// CheckAllMonitoredURLs processes all monitored URLs
func CheckAllMonitoredURLs() {
	var monitoredURLs []shared_database.MonitoredURL

	if err := shared_database.Db.Find(&monitoredURLs).Error; err != nil {
		log.Printf("Error querying monitored URLs: %v", err)
		return
	}

	for _, monitoredURL := range monitoredURLs {
		// only check if the URL is older than 24 hours
		if monitoredURL.LastCheckedAt != nil && time.Since(*monitoredURL.LastCheckedAt) < 24*time.Hour {
			log.Printf("Skipping %s, last checked at %s", monitoredURL.URL, monitoredURL.LastCheckedAt)
			continue
		}

		// Update last_checked_at timestamp
		now := time.Now()
		if err := shared_database.Db.Model(&monitoredURL).Update("last_checked_at", now).Error; err != nil {
			log.Printf("Error updating last_checked_at: %v", err)
		}

		if monitoredURL.IsRSS {
			ProcessRSSFeed(&monitoredURL, false)
		} else {
			ProcessSingleURL(&monitoredURL, false)
		}
	}
}

// ProcessRSSFeed fetches an RSS feed and processes recent entries
func ProcessRSSFeed(monitoredURL *shared_database.MonitoredURL, skipSave bool) []shared_database.SentWebmention {
	feedURL := monitoredURL.URL
	log.Printf("Processing RSS feed: %s", feedURL)

	sentWebmentions := []shared_database.SentWebmention{}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", feedURL, nil)
	if err != nil {
		log.Printf("Error creating request for RSS feed %s: %v", feedURL, err)
		return sentWebmentions
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching RSS feed %s: %v", feedURL, err)
		return sentWebmentions
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Non-200 status code for RSS feed %s: %d", feedURL, resp.StatusCode)
		return sentWebmentions
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading RSS feed body %s: %v", feedURL, err)
		return sentWebmentions
	}

	var rss RSS
	if err := xml.Unmarshal(body, &rss); err != nil {
		log.Printf("Error parsing RSS feed %s: %v", feedURL, err)
		return sentWebmentions
	}

	count := 0
	alreadyCheckdeItems := make(map[string]struct{})

	for _, item := range rss.Channel.Items {
		if count >= maxRSSEntriesToCheck {
			break
		}

		itemUrl, err := StandardizeURL(item.Link)
		if err != nil {
			log.Printf("Error standardizing URL %s: %v", itemUrl, err)
			continue
		}

		if _, exists := alreadyCheckdeItems[itemUrl]; exists {
			alreadyCheckdeItems[itemUrl] = struct{}{}
			continue
		}
		if itemUrl != "" {
			pageLinks := getLinksInPageForWhichWeHaventSentWebmentionsTo(itemUrl)

			for _, targetURL := range pageLinks {
				if _, exists := alreadyCheckdeItems[targetURL]; exists {
					alreadyCheckdeItems[targetURL] = struct{}{}
					continue
				}

				log.Printf("Processing link: %s", targetURL)
				webmentionResult, err := SendWebmention(itemUrl, targetURL)
				if err != nil {
					log.Printf("Error sending webmention: %v", err)
					continue
				}

				sentWebmentions = append(sentWebmentions, shared_database.SentWebmention{
					MonitoredURLID: monitoredURL.ID,
					SourceURL:      itemUrl,
					TargetURL:      targetURL,
					StatusCode:     webmentionResult.StatusCode,
					ResponseBody:   webmentionResult.ResponseBody,
					UniqueSource:   "",
					UniqueTarget:   "",
				})

				if !skipSave {
					RecordSentWebmention(monitoredURL, itemUrl, targetURL, webmentionResult.StatusCode, webmentionResult.ResponseBody)
				}
			}

			count++
		}
	}

	return sentWebmentions
}

// ProcessSingleURL processes a single URL for webmentions
func ProcessSingleURL(monitoredURL *shared_database.MonitoredURL, skipSave bool) []shared_database.SentWebmention {
	pageURL := monitoredURL.URL
	sentWebmentions := []shared_database.SentWebmention{}
	pageLinks := getLinksInPageForWhichWeHaventSentWebmentionsTo(pageURL)

	for _, targetURL := range pageLinks {
		log.Printf("Processing link: %s", targetURL)
		webmentionResult, err := SendWebmention(pageURL, targetURL)
		if err != nil {
			log.Printf("Error sending webmention: %v", err)
			continue
		}

		sentWebmentions = append(sentWebmentions, shared_database.SentWebmention{
			MonitoredURLID: monitoredURL.ID,
			SourceURL:      pageURL,
			TargetURL:      targetURL,
			UniqueSource:   "",
			UniqueTarget:   "",
			StatusCode:     webmentionResult.StatusCode,
			ResponseBody:   webmentionResult.ResponseBody,
		})

		if !skipSave {
			RecordSentWebmention(monitoredURL, pageURL, targetURL, webmentionResult.StatusCode, webmentionResult.ResponseBody)
		}
	}

	return sentWebmentions
}

func getLinksInPageForWhichWeHaventSentWebmentionsTo(pageURL string) []string {
	filteredLinks := []string{}

	// Fetch the page content
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		log.Printf("Error creating request for %s: %v", pageURL, err)
		return filteredLinks
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching %s: %v", pageURL, err)
		return filteredLinks
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Non-200 status code for %s: %d", pageURL, resp.StatusCode)
		return filteredLinks
	}

	// Parse source URL to get domain
	sourceURLParsed, err := url.Parse(pageURL)
	if err != nil {
		log.Printf("Error parsing source URL %s: %v", pageURL, err)
		return filteredLinks
	}
	sourceDomain := sourceURLParsed.Hostname()

	// Parse the HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Printf("Error parsing HTML from %s: %v", pageURL, err)
		return filteredLinks
	}

	// Extract all links

	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			targetURL, err := resolveURL(pageURL, href)
			if err != nil {
				return
			}

			// Skip if the target URL is the same as the source, or if it's not HTTP(S)
			if targetURL == pageURL || (!strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://")) {
				return
			}

			// Skip if target URL is on the same domain as source URL
			targetURLParsed, err := url.Parse(targetURL)
			if err != nil {
				return
			}
			targetDomain := targetURLParsed.Hostname()
			if targetDomain == sourceDomain {
				log.Printf("Skipping webmention to %s (same domain as source)", targetURL)
				return
			}

			// Check if we've already sent this webmention
			sent, err := HasWebmentionBeenSent(pageURL, targetURL)
			if err != nil {
				log.Printf("Error checking if webmention has been sent: %v", err)
				return
			}

			if !sent {
				filteredLinks = append(filteredLinks, targetURL)
			}
		}
	})

	return filteredLinks
}

// resolveURL resolves a potentially relative URL to an absolute URL
func resolveURL(base, ref string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	refURL, err := url.Parse(ref)
	if err != nil {
		return "", err
	}

	resolvedURL := baseURL.ResolveReference(refURL)
	return resolvedURL.String(), nil
}

// SendWebmention sends a webmention from source to target
type SendWebmentionResult struct {
	ResponseBody string
	StatusCode   int
}

func SendWebmention(sourceURL, targetURL string) (*SendWebmentionResult, error) {
	log.Printf("Sending webmention from %s to %s", sourceURL, targetURL)

	// First, check if the target has a webmention endpoint
	endpoint, err := discoverWebmentionEndpoint(targetURL)
	if err != nil {
		return nil, fmt.Errorf("error discovering webmention endpoint for %s: %v", targetURL, err)
	}

	if endpoint == "" {
		return nil, fmt.Errorf("no webmention endpoint found for %s", targetURL)
	}

	// Send the webmention
	values := url.Values{}
	values.Set("source", sourceURL)
	values.Set("target", targetURL)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creating webmention request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending webmention: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading webmention response: %v", err)
	}

	log.Printf("Webmention response from %s: %d", endpoint, resp.StatusCode)

	return &SendWebmentionResult{
		ResponseBody: string(body),
		StatusCode:   resp.StatusCode,
	}, nil
}

// discoverWebmentionEndpoint discovers the webmention endpoint for a given URL
func discoverWebmentionEndpoint(targetURL string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check HTTP Link headers
	linkHeaders := resp.Header.Values("Link")
	for _, header := range linkHeaders {
		if strings.Contains(header, "rel=\"webmention\"") || strings.Contains(header, "rel=webmention") {
			parts := strings.Split(header, ";")
			if len(parts) > 0 {
				url := strings.Trim(parts[0], " <>")
				return url, nil
			}
		}
	}

	// Parse HTML for endpoint
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", err
	}

	// Check for <link> element
	var endpoint string
	doc.Find("link[rel~=webmention]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			endpoint = href
		}
	})

	// If not found, check for <a> element
	if endpoint == "" {
		doc.Find("a[rel~=webmention]").Each(func(i int, s *goquery.Selection) {
			if href, exists := s.Attr("href"); exists {
				endpoint = href
			}
		})
	}

	// Resolve relative URLs
	if endpoint != "" && !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint, err = resolveURL(targetURL, endpoint)
		if err != nil {
			return "", err
		}
	}

	return endpoint, nil
}

// AddURLToMonitor adds a URL for a user to monitor
// If the URL already exists in the system, it just creates the relationship
func AddURLToMonitor(username string, urlToMonitor string, isRSS bool) error {
	// Begin a transaction
	tx := shared_database.Db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// First, find or create the monitored URL
	var monitoredURL shared_database.MonitoredURL
	if err := tx.FirstOrCreate(&monitoredURL, shared_database.MonitoredURL{URL: urlToMonitor}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Update the URL properties if needed
	if monitoredURL.IsRSS != isRSS {
		monitoredURL.IsRSS = isRSS
		if err := tx.Save(&monitoredURL).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	// Now create the user-URL monitoring relationship
	userURL := shared_database.UserMonitoredURL{
		Username:       username,
		MonitoredURLID: monitoredURL.ID,
		UniqueUsername: username,
		UniqueURLID:    monitoredURL.ID,
	}

	// Use FirstOrCreate to handle cases where the relationship already exists
	if err := tx.FirstOrCreate(&userURL, shared_database.UserMonitoredURL{
		Username:       username,
		MonitoredURLID: monitoredURL.ID,
	}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction
	return tx.Commit().Error
}

// GetMonitoredURLs returns all monitored URLs for a user
func GetMonitoredURLs(userID uint) ([]shared_database.MonitoredURL, error) {
	var urls []shared_database.MonitoredURL
	err := shared_database.Db.Where("user_id = ?", userID).Find(&urls).Error
	return urls, err
}

// RemoveMonitoredURL removes a URL from monitoring
func RemoveMonitoredURL(id uint, userID uint) error {
	// Ensure we only delete URLs owned by this user
	result := shared_database.Db.Where("id = ? AND user_id = ?", id, userID).Delete(&shared_database.MonitoredURL{})
	return result.Error
}

// GetMonitoredURLsForUser returns all URLs that a user is monitoring
func GetMonitoredURLsForUser(username string) ([]shared_database.MonitoredURL, error) {
	var urls []shared_database.MonitoredURL

	// Using explicit table references to improve clarity
	err := shared_database.Db.Table("monitored_urls").
		Select("monitored_urls.*").
		Joins("JOIN user_monitored_urls ON monitored_urls.id = user_monitored_urls.monitored_url_id").
		Where("user_monitored_urls.username = ?", username).
		Find(&urls).Error

	return urls, err
}

// RemoveURLMonitor removes a URL from a user's monitoring list
func RemoveURLMonitor(username string, monitoredURLID uint) error {
	// NOTE: this leaves orphaned entries in the MonitoredURL table
	// which is acceptable for this use case
	return shared_database.Db.Where("username = ? AND monitored_url_id = ?", username, monitoredURLID).
		Delete(&shared_database.UserMonitoredURL{}).Error
}

// RecordSentWebmention saves a record of a webmention that has been sent
func RecordSentWebmention(monitoredURL *shared_database.MonitoredURL, sourceURL, targetURL string, statusCode int, responseBody string) error {
	// Create the webmention record with all details
	webmention := shared_database.SentWebmention{
		MonitoredURLID: monitoredURL.ID,
		SourceURL:      sourceURL,
		TargetURL:      targetURL,
		StatusCode:     statusCode,
		ResponseBody:   responseBody,
		UniqueSource:   sourceURL,
		UniqueTarget:   targetURL,
	}

	// Use FirstOrCreate to avoid duplicates based on source and target URLs
	result := shared_database.Db.FirstOrCreate(&webmention, shared_database.SentWebmention{
		UniqueSource: sourceURL,
		UniqueTarget: targetURL,
	})

	// If found existing, update the status and response
	if result.RowsAffected == 0 {
		return shared_database.Db.Model(&shared_database.SentWebmention{}).
			Where("unique_source = ? AND unique_target = ?", sourceURL, targetURL).
			Updates(map[string]interface{}{
				"status_code":   statusCode,
				"response_body": responseBody,
			}).Error
	}

	return result.Error
}

// HasWebmentionBeenSent checks if a webmention has already been sent from source to target
func HasWebmentionBeenSent(sourceURL, targetURL string) (bool, error) {
	var count int64

	// Check for existing webmention based on unique source and target combination
	err := shared_database.Db.Model(&shared_database.SentWebmention{}).
		Where("unique_source = ? AND unique_target = ?", sourceURL, targetURL).
		Count(&count).Error

	return count > 0, err
}

// GetRecentSentWebmentionsForUser returns webmentions sent from URLs monitored by a user
// Only returns webmentions for URLs the user is actually monitoring
func GetRecentSentWebmentionsForUser(username string, limit int) ([]shared_database.SentWebmention, error) {
	var webmentions []shared_database.SentWebmention

	// More explicit query using table references and preloading
	err := shared_database.Db.Table("sent_webmentions").
		Select("sent_webmentions.*").
		Joins("JOIN user_monitored_urls ON sent_webmentions.monitored_url_id = user_monitored_urls.monitored_url_id").
		Where("user_monitored_urls.username = ?", username).
		Order("sent_webmentions.created_at DESC").
		Limit(limit).
		Find(&webmentions).Error

	return webmentions, err
}
