package main

import (
	"log"
	"mochi/constants"
	"mochi/database"
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

	database.InitDb()

	r := initRouter()

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
	r.Use(httprate.LimitByIP(600, time.Minute)) // general rate limiter for all routes (shared across all routes)
	r.Use(middleware.Recoverer)
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

	if constants.DEBUG_MODE {
		r.Get("/test-embed-page", func(w http.ResponseWriter, r *http.Request) {
			site.RenderTemplate(w, r, "pages/test_embed_page.html", nil)
		})
	}

	// r.Get("/terms-and-conditions", func(w http.ResponseWriter, r *http.Request) {
	// 	site.RenderTemplate(w, r, "terms_and_conditions", nil)
	// })

	r.With(httprate.LimitByIP(30, time.Minute)).Route("/user", func(r chi.Router) {
		r.HandleFunc("/login", site.UserLogin)
		r.HandleFunc("/register", site.UserRegister)
		r.HandleFunc("/logout", site.UserLogout)
	})

	r.With(CORSEverywhereMiddleware.Handler).Route("/reaper/{username}", func(r chi.Router) {
		r.Get("/embed/{siteID}.js", site.ReaperGetEmbedJs)
		r.Post("/{siteID}", site.ReaperPostHit)
	})

	r.With(site.AuthProtectedMiddleware).Route("/dashboard", func(r chi.Router) {
		r.Get("/", site.UserDashboardHome)
		r.Post("/create-site", site.CreateNewSite)

		r.HandleFunc("/site/{siteID}", site.SiteDetails)
		r.HandleFunc("/site/embed_instructions/{siteID}", site.SiteEmbedInstructions)
	})

	return r
}
