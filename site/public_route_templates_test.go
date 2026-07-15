package site

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mochi/shared_database"

	"github.com/go-chi/chi/v5"
)

func runFromRepositoryRoot(t *testing.T) {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repositoryRoot := filepath.Clean(filepath.Join(workingDirectory, ".."))
	if err := os.Chdir(repositoryRoot); err != nil {
		t.Fatal(err)
	}
	templateCache = sync.Map{}
	t.Cleanup(func() {
		templateCache = sync.Map{}
		if err := os.Chdir(workingDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
}

func TestLegacyEmbedUsesCanonicalOpaqueEndpoints(t *testing.T) {
	fixture := newPublicSiteFixture(t, true)
	route, err := fixture.deps.createRoute(fixture.owner.Username, fixture.site.ID)
	if err != nil {
		t.Fatal(err)
	}
	runFromRepositoryRoot(t)

	router := chi.NewRouter()
	router.With(legacyPublicSiteMiddlewareWithDependencies(
		fixture.deps,
		shared_database.LegacyRouteFamilyAnalyticsReaper,
		http.StatusNotFound,
	)).Get("/reaper/{username}/embed/{siteID}.js", ReaperGetEmbedJs)

	request := httptest.NewRequest(
		http.MethodGet,
		"/reaper/"+fixture.owner.Username+"/embed/"+uintToString(fixture.site.ID)+".js?kudos",
		nil,
	)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Deprecation") != "true" {
		t.Fatal("legacy embed response is missing Deprecation: true")
	}

	body := recorder.Body.String()
	for _, endpoint := range []string{
		"/reaper/" + route.PublicID,
		"/reaper/" + route.PublicID + "/kudo",
	} {
		if !strings.Contains(body, endpoint) {
			t.Errorf("legacy embed body does not use canonical endpoint %q", endpoint)
		}
	}
	if strings.Contains(body, fixture.owner.Username) {
		t.Fatal("legacy embed JavaScript contains the internal username")
	}
	if strings.Contains(body, `const siteID =`) {
		t.Fatal("embed JavaScript still uses the internal site ID")
	}
}

func TestGeneratedDashboardSnippetsUseOnlyPublicIDAndShowMigrationState(t *testing.T) {
	fixture := newPublicSiteFixture(t, true)
	route, err := fixture.deps.createRoute(fixture.owner.Username, fixture.site.ID)
	if err != nil {
		t.Fatal(err)
	}
	lastSeen := time.Date(2026, 7, 14, 20, 0, 0, 0, time.UTC)
	route.LegacyAnalyticsLastSeenAt = &lastSeen
	route.LegacyWebmentionLastSeenAt = &lastSeen
	route.LegacyAPILastSeenAt = &lastSeen
	runFromRepositoryRoot(t)

	request := httptest.NewRequest(http.MethodGet, "/dashboard/site/embed", nil)
	ctx := context.WithValue(request.Context(), AuthenticatedUserCookieName, &fixture.owner)
	ctx = context.WithValue(ctx, siteKey, &fixture.site)
	ctx = context.WithValue(ctx, publicSiteRouteKey, route)
	request = request.WithContext(ctx)
	recorder := httptest.NewRecorder()
	SiteEmbedInstructions(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	for _, expected := range []string{
		"/reaper/" + route.PublicID + "/embed.js",
		"Old snippets continue to work",
		"Analytics and kudos",
		"Webmention receiver",
		"Public/API access",
		"2026-07-14 20:00 UTC",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("dashboard snippet page is missing %q", expected)
		}
	}
	if strings.Contains(body, fixture.owner.Username) {
		t.Fatal("generated dashboard page rendered the internal username")
	}
}

func TestIntegrationTemplatesDoNotGenerateLegacyIdentifiers(t *testing.T) {
	templates := map[string][]string{
		"../templates/pages/dashboard/analytics/embed_instructions.html": {
			"/reaper/{{publicID}}/embed.js",
		},
		"../templates/pages/reaper/embed/reaper_embed.js": {
			"/reaper/{{publicID}}",
			"/reaper/{{publicID}}/kudo",
		},
		"../templates/pages/dashboard/webmentions/webmentions_details.html": {
			"/webmention/{{publicID}}/receive",
			"/api/webmentions/{{publicID}}",
		},
		"../templates/pages/dashboard/site_settings.html": {
			"/api/analytics/{{publicID}}",
		},
		"../templates/pages/test_embed_page.html": {
			"/reaper/{{selfSitePublicID}}/embed.js",
		},
		"../templates/layouts/standard.html": {
			"/reaper/{{selfSitePublicID}}/embed.js",
			"/webmention/{{selfSitePublicID}}/receive",
		},
	}
	for templatePath, canonicalFragments := range templates {
		content, err := os.ReadFile(templatePath)
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		for _, forbidden := range []string{
			"signedInUser.Username",
			"ownerUsername",
			"reaper/meadow/embed/7.js",
			"webmention/meadow/7/receive",
		} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s contains legacy integration value %q", templatePath, forbidden)
			}
		}
		for _, fragment := range canonicalFragments {
			if !strings.Contains(text, fragment) {
				t.Errorf("%s is missing canonical integration %q", templatePath, fragment)
			}
		}
	}
}

func TestSelfIntegrationIsOptionalAndCanonical(t *testing.T) {
	runFromRepositoryRoot(t)
	const selfPublicID = "self-public-id"
	t.Setenv("SELF_SITE_PUBLIC_ID", selfPublicID)
	templateCache = sync.Map{}

	recorder := httptest.NewRecorder()
	RenderTemplate(
		recorder,
		httptest.NewRequest(http.MethodGet, "/test-embed-page", nil),
		"pages/test_embed_page.html",
		nil,
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, expected := range []string{
		"/reaper/" + selfPublicID + "/embed.js",
		"/webmention/" + selfPublicID + "/receive",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("self integration is missing canonical endpoint %q", expected)
		}
	}
}

func TestSelfIntegrationIsOmittedWhenUnset(t *testing.T) {
	runFromRepositoryRoot(t)
	t.Setenv("SELF_SITE_PUBLIC_ID", "")
	templateCache = sync.Map{}

	recorder := httptest.NewRecorder()
	RenderTemplate(
		recorder,
		httptest.NewRequest(http.MethodGet, "/test-embed-page", nil),
		"pages/test_embed_page.html",
		nil,
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, `<script src="http://localhost:4738/reaper/`) ||
		strings.Contains(body, `rel="webmention"`) {
		t.Fatal("self integrations rendered without SELF_SITE_PUBLIC_ID")
	}
}
