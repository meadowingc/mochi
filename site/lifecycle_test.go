package site

import (
	"context"
	"errors"
	"mochi/lifecycle"
	"mochi/shared_database"
	"mochi/user_database"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestAcceptedAnalyticsWriteIsRetainedUntilStoreCompletes(t *testing.T) {
	fixture := newPublicSiteFixture(t, true)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		if err := lifecycle.Background.Wait(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if err := fixture.userDB.Db.Callback().Create().Before("gorm:create").Register(
		"test:held-analytics", func(db *gorm.DB) {
			if db.Statement.Table == "hits" {
				close(entered)
				<-release
			}
		},
	); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/reaper/opaque?path=/test/", nil)
	request = withResolvedPublicSite(request, &resolvedPublicSite{
		Route: &shared_database.PublicSiteRoute{Username: fixture.owner.Username, SiteID: fixture.site.ID},
		Site:  &fixture.site, UserDB: fixture.userDB,
	})
	response := httptest.NewRecorder()
	ReaperPostHit(response, request)
	if response.Code != http.StatusOK {
		t.Fatal("analytics request was not accepted")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("accepted analytics did not reach storage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := lifecycle.Background.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("accepted write was not retained: %v", err)
	}
	once.Do(func() { close(release) })
	if err := lifecycle.Background.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	var hits []user_database.Hit
	if err := fixture.userDB.Db.Find(&hits).Error; err != nil || len(hits) != 1 ||
		hits[0].Path != "/test" || hits[0].SiteID != fixture.site.ID {
		t.Fatalf("accepted hit was not stored exactly once: %+v, %v", hits, err)
	}
}
