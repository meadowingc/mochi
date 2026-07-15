package user_database

import (
	"fmt"
	"log"
	"os"
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
		go func() {
			for {
				time.Sleep(cleanupInterval)
				cleanupCache()
			}
		}()
	})
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
	_, err := os.Stat(fmt.Sprintf(databaseFilePathFormat, username))
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
	_, err := os.Stat(fmt.Sprintf(databaseFilePathFormat, username))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat user database: %w", err)
	}

	return getCachedOrCreateDBWithError(username)
}

func GetDbOrFatal(username string) *UserDb {
	if !databaseFileExists(username) {
		log.Fatalf("Database file for user %s does not exist", username)
	}

	return getCachedOrCreateDB(username)
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
	if _, err := os.Stat(databaseFolder); os.IsNotExist(err) {
		return []string{}, nil
	}

	// Get all files in the database folder
	files, err := os.ReadDir(databaseFolder)
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
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if cached, exists := dbCache[username]; exists {
		cached.lastAccess = time.Now()
		return cached.userDb, nil
	}

	// create the database folder if it doesn't exist
	if _, err := os.Stat(databaseFolder); os.IsNotExist(err) {
		if err := os.Mkdir(databaseFolder, 0755); err != nil {
			return nil, fmt.Errorf("create user database directory: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("stat user database directory: %w", err)
	}

	db, err := gorm.Open(sqlite.Open(
		fmt.Sprintf("file:"+databaseFilePathFormat+"?cache=shared&mode=rwc&_journal_mode=WAL", username),
	), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("connect user database: %w", err)
	}

	// Migrate the schema
	err = db.AutoMigrate(
		&User{},
		&Site{},
		&Hit{},
		&WebMention{},
		&Kudo{},
	)
	if err != nil {
		sqlDB, dbErr := db.DB()
		if dbErr == nil {
			_ = sqlDB.Close()
		}
		return nil, fmt.Errorf("migrate user database: %w", err)
	}

	userDb := &UserDb{Db: db}

	dbCache[username] = &cachedDb{
		userDb:     userDb,
		lastAccess: time.Now(),
	}

	return userDb, nil
}
