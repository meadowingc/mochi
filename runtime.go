package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mochi/constants"
	"mochi/lifecycle"
	"mochi/notifier"
	"mochi/shared_database"
	"mochi/user_database"
	"mochi/webmention_sender"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"
)

var buildRevision = "development"

type runtimeConfig struct {
	address     string
	workers     bool
	workerDelay time.Duration
}

func loadRuntimeConfig() (runtimeConfig, error) {
	var config runtimeConfig
	envPath := os.Getenv("MOCHI_ENV_FILE")
	if envPath == "" {
		envPath = ".env"
	}
	if err := godotenv.Load(envPath); err != nil {
		return config, errors.New("required configuration file is unavailable")
	}
	if !constants.DEBUG_MODE && os.Getenv("CSRF_KEY") == "" {
		return config, errors.New("CSRF_KEY is required")
	}
	config.address = os.Getenv("MOCHI_HTTP_ADDR")
	if config.address == "" {
		config.address = ":" + constants.LOCAL_PORT_NUM
	}
	_, port, err := net.SplitHostPort(config.address)
	if err != nil {
		return config, errors.New("MOCHI_HTTP_ADDR must be host:port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return config, errors.New("MOCHI_HTTP_ADDR port must be between 1 and 65535")
	}
	switch os.Getenv("MOCHI_WORKERS") {
	case "", "enabled":
		config.workers = !(constants.DEBUG_MODE && os.Getenv("MOCHI_E2E_MODE") == "true")
	case "disabled":
		config.workers = false
	default:
		return config, errors.New("MOCHI_WORKERS must be enabled or disabled")
	}
	if value := os.Getenv("MOCHI_WORKER_START_DELAY"); value != "" {
		delay, err := time.ParseDuration(value)
		if err != nil || delay < 0 || delay > time.Hour {
			return config, errors.New("MOCHI_WORKER_START_DELAY must be between 0s and 1h")
		}
		config.workerDelay = delay
	}
	switch os.Getenv("MOCHI_REQUIRE_EXISTING") {
	case "", "0":
	case "1":
		info, err := os.Lstat(user_database.DatabaseDirectory())
		if err != nil || !info.IsDir() {
			return config, errors.New("required existing user database directory is missing or redirected")
		}
	default:
		return config, errors.New("MOCHI_REQUIRE_EXISTING must be 0 or 1")
	}
	return config, nil
}

func healthHandler(db *sql.DB, config runtimeConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var tables int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&tables); err != nil {
			log.Print("Health shared database check failed")
			http.Error(w, "Database unavailable", http.StatusServiceUnavailable)
			return
		}
		usernames, err := user_database.GetAllUsernames()
		if err != nil {
			log.Print("Health user database inventory failed")
			http.Error(w, "Database directory unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(struct {
			Status        string `json:"status"`
			Revision      string `json:"revision"`
			Workers       bool   `json:"workers"`
			UserDatabases int    `json:"userDatabases"`
		}{"ok", buildRevision, config.workers, len(usernames)}); err != nil {
			log.Print("Health response write failed")
		}
	})
}

func run() error {
	config, err := loadRuntimeConfig()
	if err != nil {
		return err
	}
	// Bind before opening/migrating stores or starting outbound work.
	listener, err := net.Listen("tcp", config.address)
	if err != nil {
		return fmt.Errorf("HTTP listener: %w", err)
	}
	defer listener.Close()
	if err := shared_database.InitSharedDbWithError(); err != nil {
		return err
	}
	defer shared_database.CleanupOnAppClose()
	defer user_database.CleanupOnAppClose()
	if err := shared_database.ReconcilePublicSiteRoutes(); err != nil {
		return errors.New("public site route reconciliation failed")
	}
	db, err := shared_database.Db.DB()
	if err != nil {
		return err
	}
	router := http.NewServeMux()
	router.Handle("/healthz", healthHandler(db, config))
	router.Handle("/", initRouter())
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, listener, router, config)
}

func serve(ctx context.Context, listener net.Listener, handler http.Handler, config runtimeConfig) error {
	workersContext, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	var workers sync.WaitGroup
	startWorker := func(fn func()) {
		workers.Add(1)
		go func() { defer workers.Done(); fn() }()
	}
	startWorker(func() { user_database.RunCacheCleanup(workersContext) })
	if config.workers {
		startWorker(func() { notifier.StartInteractionHandlerContext(workersContext) })
		startWorker(func() { webmention_sender.StartPeriodicCheckerContext(workersContext, config.workerDelay) })
		startWorker(func() { startDataCleanupScheduler(workersContext, config.workerDelay) })
		startWorker(func() { startMetricsReportScheduler(workersContext, config.workerDelay) })
	} else {
		log.Print("Scheduled work and Discord gateway explicitly disabled")
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	log.Printf("HTTP listening on %s; scheduled workers enabled=%t", listener.Addr(), config.workers)
	var result error
	select {
	case <-ctx.Done():
	case err := <-done:
		result = fmt.Errorf("HTTP server stopped unexpectedly: %w", err)
		done = nil
	}
	cancelWorkers()
	log.Print("Draining HTTP, scheduled workers and accepted background work")
	drain, cancelDrain := context.WithTimeout(context.Background(), 60*time.Second)
	err := server.Shutdown(drain)
	cancelDrain()
	if errors.Is(err, context.DeadlineExceeded) {
		log.Print("HTTP drain exceeded 60 seconds; waiting without closing databases")
		err = server.Shutdown(context.Background())
	}
	result = errors.Join(result, err)
	if done != nil {
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			result = errors.Join(result, err)
		}
	}
	workers.Wait()
	drain, cancelDrain = context.WithTimeout(context.Background(), 60*time.Second)
	err = lifecycle.Background.Wait(drain)
	cancelDrain()
	if err != nil {
		log.Print("Background drain exceeded 60 seconds; waiting without closing databases")
		err = lifecycle.Background.Wait(context.Background())
	}
	return errors.Join(result, err)
}
