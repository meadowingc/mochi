package main

import (
	"log"
	"mochi/constants"
	"mochi/notifier"
	"mochi/shared_database"
	"mochi/site"
	"mochi/user_database"
	"mochi/webmention_sender"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/cors"
	"github.com/joho/godotenv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	shared_database.InitSharedDb()
	user_database.InitDb()

	r := initRouter()

	go notifier.StartInteractionHandler()
	go webmention_sender.StartPeriodicChecker()
	go startDataCleanupScheduler()
	go startMetricsReportScheduler()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	const portNum = ":" + constants.LOCAL_PORT_NUM
	go func() {
		log.Printf("Running on http://localhost" + ":" + constants.LOCAL_PORT_NUM)
		if err := http.ListenAndServe(portNum, r); err != nil {
			log.Printf("HTTP server stopped: %v", err)
		}
	}()

	// Block until a signal is received
	<-signals
	log.Println("Shutting down gracefully...")

	// Close open user_database connections
	user_database.CleanupOnAppClose()
	shared_database.CleanupOnAppClose()

}

func initRouter() *chi.Mux {

	r := chi.NewRouter()

	CORSEverywhereMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	})

	r.Use(site.RealIPMiddleware)
	r.Use(site.Logger)
	// r.Use(middleware.Recoverer)
	r.Use(httprate.LimitByIP(600, time.Minute)) // general rate limiter for all routes (shared across all routes)
	r.Use(site.TryPutUserInContextMiddleware)
	r.Use(site.FlashMiddleware)

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		site.RenderTemplate(w, r, "pages/not_found.html", nil)
	})

	fileServer := http.FileServer(http.Dir("./assets"))
	r.Handle("/assets/*", http.StripPrefix("/assets", fileServer))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		signedInUser := site.GetSignedInUserOrNil(r)
		if signedInUser != nil {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}

		site.RenderTemplate(w, r, "pages/home.html", nil)
	})

	r.Get("/terms-and-conditions", func(w http.ResponseWriter, r *http.Request) {
		site.RenderTemplate(w, r, "pages/terms_and_conditions.html", nil)
	})

	if constants.DEBUG_MODE {
		r.Get("/test-embed-page", func(w http.ResponseWriter, r *http.Request) {
			site.RenderTemplate(w, r, "pages/test_embed_page.html", nil)
		})
	}

	r.With(httprate.LimitByIP(30, time.Minute)).Route("/user", func(r chi.Router) {
		r.Use(site.CSRFMiddleware())
		r.Use(site.CSRFTokenMiddleware)
		r.HandleFunc("/login", site.UserLogin)
		r.HandleFunc("/register", site.UserRegister)
		r.HandleFunc("/logout", site.UserLogout)
	})

	// Password recovery routes with rate limiting
	r.With(httprate.LimitByIP(10, time.Hour)).Group(func(r chi.Router) {
		r.Use(site.CSRFMiddleware())
		r.Use(site.CSRFTokenMiddleware)
		r.Get("/forgot-password", site.PasswordResetRequestPage)
		r.Post("/forgot-password", site.PasswordResetRequest)
		r.Get("/reset-password", site.PasswordResetPage)
		r.Post("/reset-password", site.PasswordResetSubmit)
	})

	r.With(site.AuthProtectedMiddleware).Route("/dashboard", func(r chi.Router) {
		r.Use(site.CSRFMiddleware())
		r.Use(site.CSRFTokenMiddleware)
		r.Get("/", site.UserDashboardHome)

		r.With(httprate.LimitByIP(10, time.Hour)).Post("/create-site", site.CreateNewSite)

		r.Route("/webmention-sender", func(r chi.Router) {
			r.Get("/", site.WebmentionSenderDashboard)
			r.With(httprate.LimitByIP(20, time.Hour)).Group(func(r chi.Router) {
				r.Post("/add", site.WebmentionSenderAddURLs)
				r.Post("/process", site.WebmentionSenderProcessURL)
			})
		})

		r.Route("/settings", func(r chi.Router) {
			r.Get("/", site.SettingsPage)
			r.With(httprate.LimitByIP(5, time.Hour)).Post("/change-password", site.ChangePassword)
			r.Route("/discord", func(r chi.Router) {
				r.With(httprate.LimitByIP(10, time.Hour)).Group(func(r chi.Router) {
					r.Post("/verify/generate", site.DiscordVerifyGenerate)
					r.Post("/verify/refresh", site.DiscordVerifyRefresh)
					r.Post("/toggle", site.DiscordToggle)
					r.Post("/disconnect", site.DiscordDisconnect)
					r.Post("/timezone", site.DiscordTimezoneUpdate)
				})
			})
		})

		r.With(site.UserSiteDashboardMiddleware).Route("/{siteID}", func(r chi.Router) {
			r.Get("/analytics", site.SiteAnalytics)
			r.Get("/analytics/embed-instructions", site.SiteEmbedInstructions)

			r.Get("/webmentions", site.WebmentionsDetails)

			r.With(httprate.LimitByIP(30, time.Minute)).Group(func(r chi.Router) {
				r.Post("/webmentions/{webmentionID}/approve", site.WebmentionApprove)
				r.Post("/webmentions/{webmentionID}/reject", site.WebmentionReject)
				r.Post("/webmentions/{webmentionID}/status/{status}", site.WebmentionChangeStatus)
			})

			r.Get("/settings", site.SiteSettingsPage)
			r.With(httprate.LimitByIP(10, time.Hour)).Group(func(r chi.Router) {
				r.Post("/settings/update", site.UpdateSiteSettings)
				r.Post("/settings/delete", site.DeleteSite)
				r.Post("/settings/metrics-notification", site.MetricsNotificationSettings)
			})
		})
	})

	r.With(CORSEverywhereMiddleware.Handler).Group(func(r chi.Router) {
		r.Route("/reaper/{username}", func(r chi.Router) {
			r.Get("/embed/{siteID}.js", site.ReaperGetEmbedJs)
			r.Post("/{siteID}", site.ReaperPostHit)
			r.Get("/{siteID}/kudo", site.ReaperGetKudos)
			r.With(httprate.LimitByIP(30, time.Minute)).Post("/{siteID}/kudo", site.ReaperPostKudo)
		})

		r.Route("/webmention/{username}/{siteId}", func(r chi.Router) {
			r.Post("/receive", site.WebmentionReceive)
		})

		r.Route("/api", func(r chi.Router) {
			r.Get("/webmentions/{username}/{siteID}", site.WebmentionPublicAPI)
		})
	})

	return r
}

// cleanupOldData deletes data older than the retention period for each site
func cleanupOldData() {
	log.Println("Starting scheduled data cleanup check...")

	// Get all usernames
	usernames, err := user_database.GetAllUsernames()
	if err != nil {
		log.Printf("Error getting usernames: %v", err)
		return
	}

	now := time.Now()
	sitesChecked := 0
	sitesUpdated := 0
	totalHitsDeleted := int64(0)

	for _, username := range usernames {
		userDB := user_database.GetDbIfExists(username)
		if userDB == nil {
			continue
		}

		// Get all sites for the user
		var sites []user_database.Site
		if err := userDB.Db.Find(&sites).Error; err != nil {
			log.Printf("Error fetching sites for user %s: %v", username, err)
			continue
		}

		for _, siteData := range sites {
			// Default to 6 months if not set
			retentionMonths := siteData.DataRetentionMonths
			if retentionMonths <= 0 {
				retentionMonths = 6
			}

			sitesChecked++

			// Check if it's time to run cleanup for this site
			// We'll clean up if LastDataCleanupDate is zero time (never cleaned up before)
			// or if it's been at least 7 days since the last cleanup
			shouldCleanup := siteData.LastDataCleanupDate.IsZero() ||
				now.Sub(siteData.LastDataCleanupDate) >= 7*24*time.Hour

			if !shouldCleanup {
				continue
			}

			// Calculate the cutoff date based on retention period
			cutoffDate := now.AddDate(0, -retentionMonths, 0)

			// Count hits to be deleted, then archive to all-time counter
			var hitsToDelete int64
			userDB.Db.Model(&user_database.Hit{}).Where("site_id = ? AND date < ?", siteData.ID, cutoffDate).Count(&hitsToDelete)
			if hitsToDelete > 0 {
				userDB.Db.Exec("UPDATE sites SET all_time_hits = all_time_hits + ? WHERE id = ?", hitsToDelete, siteData.ID)
			}

			// Delete hits older than the cutoff date
			var hitsDeleted int64
			if result := userDB.Db.Where("site_id = ? AND date < ?", siteData.ID, cutoffDate).Delete(&user_database.Hit{}); result.Error != nil {
				log.Printf("Error deleting old hits for site %d: %v", siteData.ID, result.Error)
			} else {
				hitsDeleted = result.RowsAffected
				totalHitsDeleted += hitsDeleted
			}

			// Count kudos to be deleted, then archive to all-time counter
			var kudosToDelete int64
			userDB.Db.Model(&user_database.Kudo{}).Where("site_id = ? AND date < ?", siteData.ID, cutoffDate).Count(&kudosToDelete)
			if kudosToDelete > 0 {
				userDB.Db.Exec("UPDATE sites SET all_time_kudos = all_time_kudos + ? WHERE id = ?", kudosToDelete, siteData.ID)
			}

			// Delete kudos older than the cutoff date
			if result := userDB.Db.Where("site_id = ? AND date < ?", siteData.ID, cutoffDate).Delete(&user_database.Kudo{}); result.Error != nil {
				log.Printf("Error deleting old kudos for site %d: %v", siteData.ID, result.Error)
			}

			// Update the LastDataCleanupDate field
			siteData.LastDataCleanupDate = now
			if err := userDB.Db.Save(&siteData).Error; err != nil {
				log.Printf("Error updating LastDataCleanupDate for site %d: %v", siteData.ID, err)
			} else {
				sitesUpdated++
				if hitsDeleted > 0 {
					log.Printf("Site %d (user: %s): Deleted %d hits older than %s",
						siteData.ID, username, hitsDeleted, cutoffDate.Format("2006-01-02"))
				}
			}
		}
	}

	log.Printf("Data cleanup completed: checked %d and updated %d sites, deleted %d hits",
		sitesChecked, sitesUpdated, totalHitsDeleted)
}

// startDataCleanupScheduler runs the data cleanup process on a regular schedule
func startDataCleanupScheduler() {
	ticker := time.NewTicker(2 * 7 * 24 * time.Hour) // Run once every 2 weeks
	defer ticker.Stop()

	// Run an initial cleanup on startup
	cleanupOldData()

	for range ticker.C {
		cleanupOldData()
	}
}

// startMetricsReportScheduler runs the metrics reporting process on a regular schedule
func startMetricsReportScheduler() {
	// Check for metrics reports to send every hour
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Run an initial check on startup
	notifier.CheckAndSendScheduledMetricsReports()

	for range ticker.C {
		notifier.CheckAndSendScheduledMetricsReports()
	}
}
