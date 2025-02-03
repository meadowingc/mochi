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
	"github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/token"
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

	_ = database.GetDB() // force database initialization
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

	// Close the database connection
	database.CloseDB()
}

func initOauth() *auth.Service {
	options := auth.Opts{
		SecretReader: token.SecretFunc(func(id string) (string, error) { // secret key for JWT
			secret := os.Getenv("JWT_SECRET")
			if secret == "" {
				log.Println("JWT_SECRET is not set, using default secret")
				return "dev_secret", nil
			} else {
				return secret, nil
			}
		}),
		TokenDuration:  time.Minute * 5,    // token expires in 5 minutes
		CookieDuration: time.Hour * 24 * 7, // cookie expires in 7 days
		Issuer:         constants.APP_NAME,
		URL:            constants.PUBLIC_URL,
		AvatarStore:    avatar.NewNoOp(),
	}

	// create auth service with providers
	service := auth.NewService(options)

	ghClientID, varPresent := os.LookupEnv("GITHUB_CLIENT_ID")
	if !varPresent {
		log.Fatal("GITHUB_CLIENT_ID is not set")
	}

	ghClientSecret, varPresent := os.LookupEnv("GITHUB_CLIENT_SECRET")
	if !varPresent {
		log.Fatal("GITHUB_CLIENT_SECRET is not set")
	}

	service.AddProvider("github", ghClientID, ghClientSecret)

	// return the middleware
	return service
}

func initRouter() *chi.Mux {

	r := chi.NewRouter()

	authService := initOauth()
	authMiddleware := authService.Middleware()

	CORSMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	})

	r.Use(CORSMiddleware.Handler)
	r.Use(site.RealIPMiddleware)
	r.Use(middleware.Logger)
	r.Use(httprate.LimitByIP(50, time.Minute)) // general rate limiter for all routes (shared across all routes)
	r.Use(middleware.Recoverer)
	r.Use(authMiddleware.Trace)
	// r.Use(site.TryPutUserInContextMiddleware)

	fileServer := http.FileServer(http.Dir("./assets"))
	r.Handle("/assets/*", http.StripPrefix("/assets", fileServer))

	authRoutes, _ := authService.Handlers()
	r.Mount("/auth", authRoutes)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		site.RenderTemplate(w, r, "pages/home.html", nil)
	})

	r.Get("/user/login", func(w http.ResponseWriter, r *http.Request) {
		site.RenderTemplate(w, r, "pages/user/login.html", nil)
	})

	r.Get("/user/post-login", func(w http.ResponseWriter, r *http.Request) {
		// save to db and redirect to dashboard
		userContext, err := token.GetUserInfo(r)
		log.Println(userContext)
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// r.Get("/terms-and-conditions", func(w http.ResponseWriter, r *http.Request) {
	// 	site.RenderTemplate(w, r, "terms_and_conditions", nil)
	// })
	// r.HandleFunc("/signin", site.UserSignIn)
	// r.HandleFunc("/signup", site.UserSignUp)
	// r.Post("/logout", site.UserLogout)

	// r.With(site.AuthProtectedMiddleware).Route("/dashboard", func(r chi.Router) {
	// 	r.Get("/", site.UserDashboardHome)
	// 	r.Get("/list-posts", site.UserPostList)
	// 	r.Get("/list-pages", site.UserPageList)

	// 	r.HandleFunc("/import", site.ImportPosts)

	// 	r.HandleFunc("/post/new", site.CreatePost)
	// 	r.HandleFunc("/post/{postID}", site.UpdatePost)
	// 	r.HandleFunc("/post/{postID}/delete", site.DeletePost)
	// })

	// r.Get("/post/{postID}", site.PublicViewPost)
	// r.Get("/u/{userID}", site.PublicViewUser)

	// r.Route("/api", func(r chi.Router) {
	// 	r.Route("/v1", func(r chi.Router) {
	// 		r.Get("/get-user-posts-messages/{userID}", func(w http.ResponseWriter, r *http.Request) {
	// 			userID := chi.URLParam(r, "userID")

	// 			var posts []database.Post
	// 			userIDUint, err := strconv.ParseUint(userID, 10, 64)
	// 			if err != nil {
	// 				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	// 				return
	// 			}

	// 			result := database.GetDB().Where(&database.Post{AdminUserID: uint(userIDUint)}).
	// 				Limit(10).
	// 				Find(&posts)
	// 			if result.Error != nil {
	// 				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	// 				return
	// 			}

	// 			w.Header().Set("Content-Type", "application/json")
	// 			json.NewEncoder(w).Encode(posts)
	// 		})
	// 	})
	// })

	return r
}
