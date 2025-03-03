package main

import (
	"log"
	"mochi/constants"
	"mochi/database"
	"mochi/notifier"
	"mochi/site"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/cors"
	"github.com/joho/godotenv"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	notifier.SendMessageToUsername("meadow_37", "Mochi is starting up")

	database.InitDb()

	r := initRouter()

	go notifier.StartInteractionHandler()

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

	// Close open database connections
	database.CleanupOnAppClose()

	notifier.SendMessageToUsername("meadow_37", "Mochi is shutting down")
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
	r.Use(middleware.Logger)
	// r.Use(middleware.Recoverer)
	r.Use(httprate.LimitByIP(600, time.Minute)) // general rate limiter for all routes (shared across all routes)
	r.Use(site.TryPutUserInContextMiddleware)

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
		r.HandleFunc("/login", site.UserLogin)
		r.HandleFunc("/register", site.UserRegister)
		r.HandleFunc("/logout", site.UserLogout)
	})

	r.With(site.AuthProtectedMiddleware).Route("/dashboard", func(r chi.Router) {
		r.Get("/", site.UserDashboardHome)
		r.Post("/create-site", site.CreateNewSite)

		r.With(site.UserSiteDashboardMiddleware).Route("/{siteID}", func(r chi.Router) {
			r.Get("/analytics", site.SiteAnalytics)
			r.Get("/analytics/embed-instructions", site.SiteEmbedInstructions)

			r.Get("/webmentions", site.WebmentionsDetails)
			r.Get("/webmentions/setup-instructions", site.WebmentionSetupInstructions)
		})
	})

	r.With(CORSEverywhereMiddleware.Handler).Group(func(r chi.Router) {
		r.Route("/reaper/{username}", func(r chi.Router) {
			r.Get("/embed/{siteID}.js", site.ReaperGetEmbedJs)
			r.Post("/{siteID}", site.ReaperPostHit)
		})

		r.Route("/webmention/{username}/{siteId}", func(r chi.Router) {
			r.Post("/receive", site.WebmentionReceive)
		})
	})

	return r
}
