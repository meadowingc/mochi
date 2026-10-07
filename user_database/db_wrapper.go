package user_database

import (
	"context"
	"fmt"
	"log"
	"mochi/storage"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	databaseFolder         = ".user_databases"
	databaseNameFormat     = "mochi_%s.db"
	databaseFilePathFormat = databaseFolder + "/" + databaseNameFormat
	cleanupInterval        = 10 * time.Minute    // Interval to run the cleanup process
	cacheDuration          = cleanupInterval * 2 // Maximum duration to keep a database connection in cache
)

type UserDb struct {
	Db *gorm.DB
}

type cachedDb struct {
	userDb     *UserDb
	lastAccess time.Time
}

var (
	dbCache     = make(map[string]*cachedDb)
	cacheMutex  sync.Mutex
	cleanupOnce sync.Once
)

func InitDb() {
	// Start the cleanup process once
	cleanupOnce.Do(func() {
		go RunCacheCleanup(context.Background())
	})
}

func RunCacheCleanup(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanupCache()
		}
	}
}

func DatabaseDirectory() string {
	return filepath.Join(os.Getenv("MOCHI_STATE_DIR"), databaseFolder)
}

func databasePath(username string) string {
	return filepath.Join(DatabaseDirectory(), fmt.Sprintf(databaseNameFormat, username))
}

func (u *UserDb) close() {
	sqlDB, err := u.Db.DB()
	if err != nil {
		log.Printf("Error on closing database connection: %v", err)
	} else {
		// Perform a checkpoint to consolidate the WAL file into the main database file
		if _, err := sqlDB.Exec("PRAGMA wal_checkpoint(FULL)"); err != nil {
			log.Printf("Error on checkpointing database: %v", err)
		}

		if err := sqlDB.Close(); err != nil {
			log.Printf("Error on closing database connection: %v", err)
		}
	}
}

func databaseFileExists(username string) bool {
	_, err := os.Stat(databasePath(username))
	return !os.IsNotExist(err)
}

func GetDbIfExists(username string) *UserDb {
	userDb, err := GetDbIfExistsWithError(username)
	if err != nil {
		log.Fatalf("failed to open user database: %v", err)
	}

	return userDb
}

func GetDbIfExistsWithError(username string) (*UserDb, error) {
	_, err := os.Stat(databasePath(username))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat user database: %w", err)
	}

	return openUserDB(username, false)
}

func GetDbOrFatal(username string) *UserDb {
	if !databaseFileExists(username) {
		log.Fatalf("Database file for user %s does not exist", username)
	}

	userDB, err := openUserDB(username, false)
	if err != nil {
		log.Fatalf("failed to open existing user database: %v", err)
	}
	return userDB
}

func GetOrCreateDB(username string) *UserDb {
	return getCachedOrCreateDB(username)
}

func CleanupOnAppClose() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	// expire everything
	closedConnections := 0
	for username, cached := range dbCache {
		cached.userDb.close()
		delete(dbCache, username)
		closedConnections++
	}

	log.Printf("Closed %d database connections", closedConnections)
}

func cleanupCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	now := time.Now()
	for username, cached := range dbCache {
		if now.Sub(cached.lastAccess) > cacheDuration {
			cached.userDb.close()
			delete(dbCache, username)
		}
	}
}

// GetAllUsernames returns a list of all usernames that have databases
func GetAllUsernames() ([]string, error) {
	// Create the database folder if it doesn't exist
	folder := DatabaseDirectory()
	if _, err := os.Stat(folder); os.IsNotExist(err) {
		if os.Getenv("MOCHI_REQUIRE_EXISTING") == "1" {
			return nil, fmt.Errorf("required user database directory is missing")
		}
		return []string{}, nil
	}

	// Get all files in the database folder
	files, err := os.ReadDir(folder)
	if err != nil {
		return nil, fmt.Errorf("error reading database directory: %v", err)
	}

	// Extract usernames from database filenames
	uniqueUsernames := make(map[string]struct{})
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		username := strings.TrimSpace(file.Name())

		if !strings.HasSuffix(file.Name(), ".db") {
			continue
		}

		username = strings.TrimSuffix(username, ".db")
		username = strings.TrimPrefix(username, "mochi_")
		username = strings.TrimSpace(username)

		uniqueUsernames[username] = struct{}{}
	}

	usernames := make([]string, 0, len(uniqueUsernames))
	for username := range uniqueUsernames {
		usernames = append(usernames, username)
	}

	return usernames, nil
}

func getCachedOrCreateDB(username string) *UserDb {
	userDb, err := getCachedOrCreateDBWithError(username)
	if err != nil {
		log.Fatalf("failed to open user database: %v", err)
	}
	return userDb
}

func getCachedOrCreateDBWithError(username string) (*UserDb, error) {
	return openUserDB(username, true)
}

func openUserDB(username string, allowCreate bool) (*UserDb, error) {
	if username == "" || strings.Contains(username, "/") {
		return nil, fmt.Errorf("invalid user database identifier")
	}
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if cached, exists := dbCache[username]; exists {
		cached.lastAccess = time.Now()
		return cached.userDb, nil
	}

	// create the database folder if it doesn't exist
	folder := DatabaseDirectory()
	if info, err := os.Lstat(folder); os.IsNotExist(err) {
		if os.Getenv("MOCHI_REQUIRE_EXISTING") == "1" {
			return nil, fmt.Errorf("required user database directory is missing")
		}
		if err := os.Mkdir(folder, 0755); err != nil {
			return nil, fmt.Errorf("create user database directory: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("stat user database directory: %w", err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("user database directory is redirected")
	}

	path := databasePath(username)
	mode := "rw"
	if info, err := os.Lstat(path); os.IsNotExist(err) && allowCreate {
		mode = "rwc"
	} else if err != nil {
		return nil, fmt.Errorf("existing user database is missing: %w", err)
	} else if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("user database is redirected")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: absolute}).String() +
		"?cache=shared&mode=" + mode + "&_journal_mode=WAL"
	db, err := gorm.Open(sqlite.Open(
		dsn,
	), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("connect user database: %w", err)
	}

	models := []any{
		&User{},
		&Site{},
		&Hit{},
		&WebMention{},
		&Kudo{},
	}
	migrate, err := storage.AutomaticMigrationsEnabled()
	if err == nil {
		if migrate || mode == "rwc" {
			err = db.AutoMigrate(models...)
		} else {
			err = storage.ValidateModels(db, models...)
		}
	}
	if err != nil {
		sqlDB, dbErr := db.DB()
		if dbErr == nil {
			_ = sqlDB.Close()
		}
		return nil, fmt.Errorf("initialize user database schema: %w", err)
	}

	userDb := &UserDb{Db: db}

	dbCache[username] = &cachedDb{
		userDb:     userDb,
		lastAccess: time.Now(),
	}

	return userDb, nil
}
