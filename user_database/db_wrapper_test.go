package user_database

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestGetAllUsernamesPreservesEmailShapedIdentifiers(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	testDirectory, err := os.MkdirTemp(".", ".username-list-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(testDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(workingDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
		if err := os.RemoveAll(testDirectory); err != nil {
			t.Errorf("remove test directory: %v", err)
		}
	})

	if err := os.Mkdir(databaseFolder, 0o755); err != nil {
		t.Fatal(err)
	}
	expected := []string{"owner.db@example.com", "plain-owner"}
	for _, username := range expected {
		path := filepath.Join(databaseFolder, "mochi_"+username+".db")
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
