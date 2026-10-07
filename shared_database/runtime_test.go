package shared_database

import (
	"os"
	"testing"
)

func TestRequiredSharedStoreCannotBeCreatedOrRedirected(t *testing.T) {
	t.Setenv("MOCHI_STATE_DIR", t.TempDir())
	t.Setenv("MOCHI_REQUIRE_EXISTING", "1")
	if err := InitSharedDbWithError(); err == nil {
		t.Fatal("missing required store accepted")
	}
	if _, err := os.Stat(DatabasePath()); !os.IsNotExist(err) {
		t.Fatal("required store was created")
	}
	if err := os.Symlink("/dev/null", DatabasePath()); err != nil {
		t.Fatal(err)
	}
	if err := InitSharedDbWithError(); err == nil {
		t.Fatal("redirected shared store accepted")
	}
}
