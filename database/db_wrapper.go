package database

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	databaseFolder              = ".user_databases"
	databaseNameFormat          = "mochi_%s.db"
	databaseFilePathFormat      = databaseFolder + "/" + databaseNameFormat
	databaseConnectionStrFormat = "file:" + databaseFilePathFormat + "?cache=shared&mode=rwc&_journal_mode=WAL"
	cleanupInterval             = 10 * time.Minute    // Interval to run the cleanup process
	cacheDuration               = cleanupInterval * 2 // Maximum duration to keep a database connection in cache
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
	if !databaseFileExists(username) {
		return nil
	}

	return getCachedOrCreateDB(username)
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

func getCachedOrCreateDB(username string) *UserDb {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if cached, exists := dbCache[username]; exists {
		cached.lastAccess = time.Now()
		return cached.userDb
	}

	// create the database folder if it doesn't exist
	if _, err := os.Stat(databaseFolder); os.IsNotExist(err) {
		os.Mkdir(databaseFolder, 0755)
	}

	var err error
	db, err := gorm.Open(sqlite.Open(
		fmt.Sprintf(databaseConnectionStrFormat, username),
	), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// Migrate the schema
	err = db.AutoMigrate(
		&User{},
		&Site{},
		&Hit{},
	)
	if err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	userDb := &UserDb{Db: db}

	dbCache[username] = &cachedDb{
		userDb:     userDb,
		lastAccess: time.Now(),
	}

	return userDb
}
