package user_database

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestGetAllUsernamesPreservesEmailShapedIdentifiers(t *testing.T) {
	t.Setenv("MOCHI_STATE_DIR", t.TempDir())
	if err := os.Mkdir(DatabaseDirectory(), 0o755); err != nil {
		t.Fatal(err)
	}
	expected := []string{"owner.db@example.com", "plain-owner"}
	for _, username := range expected {
		path := filepath.Join(DatabaseDirectory(), "mochi_"+username+".db")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	usernames, err := GetAllUsernames()
	if err != nil {
		t.Fatal(err)
	}
	for _, username := range expected {
		if !slices.Contains(usernames, username) {
			t.Errorf("usernames %v do not preserve %q", usernames, username)
		}
	}
}

func TestRelocatedExistingStoresAndIntentionalRegistration(t *testing.T) {
	t.Setenv("MOCHI_STATE_DIR", t.TempDir())
	t.Setenv("MOCHI_REQUIRE_EXISTING", "1")
	CleanupOnAppClose()
	t.Cleanup(CleanupOnAppClose)
	if _, err := GetAllUsernames(); err == nil {
		t.Fatal("missing required directory appeared to be an empty installation")
	}
	if err := os.Mkdir(DatabaseDirectory(), 0o700); err != nil {
		t.Fatal(err)
	}
	username := "owner.db@example.com"
	if _, err := openUserDB(username, false); err == nil {
		t.Fatal("existing-user opener created a missing database")
	}
	if _, err := os.Stat(databasePath(username)); !os.IsNotExist(err) {
		t.Fatal("missing-user lookup created a database")
	}
	userDB, err := getCachedOrCreateDBWithError(username)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	RunCacheCleanup(ctx)
	sqlDB, err := userDB.Db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("stopping the cache cleaner closed an in-use store: %v", err)
	}
	user := User{Username: username, SessionToken: "synthetic-session"}
	if err := userDB.Db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	CleanupOnAppClose()
	userDB, err = openUserDB(username, false)
	if err != nil {
		t.Fatal(err)
	}
	var restored User
	if err := userDB.Db.First(&restored).Error; err != nil || restored.Username != username {
		t.Fatalf("relocated user not preserved: %v", err)
	}
}

func TestUserDatabaseURIQuotesFilename(t *testing.T) {
	t.Setenv("MOCHI_STATE_DIR", t.TempDir())
	CleanupOnAppClose()
	t.Cleanup(CleanupOnAppClose)
	username := "owner?mode=ro.db@example.com"
	if _, err := getCachedOrCreateDBWithError(username); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(databasePath(username)); err != nil || !info.Mode().IsRegular() {
		t.Fatal("filename was interpreted as database URI parameters")
	}
}
