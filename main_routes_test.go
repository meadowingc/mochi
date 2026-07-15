package main

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestCanonicalAndLegacyPublicRoutesAreRegistered(t *testing.T) {
	router := initRouter()
	routes := make(map[string]bool)
	if err := chi.Walk(router, func(
		method string,
		route string,
		_ http.Handler,
		_ ...func(http.Handler) http.Handler,
	) error {
		routes[method+" "+route] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	expected := []string{
		"GET /reaper/{publicID}/embed.js",
		"POST /reaper/{publicID}",
		"GET /reaper/{publicID}/kudo",
		"POST /reaper/{publicID}/kudo",
		"POST /webmention/{publicID}/receive",
		"GET /api/webmentions/{publicID}",
		"GET /api/analytics/{publicID}",
		"GET /reaper/{username}/embed/{siteID}.js",
		"POST /reaper/{username}/{siteID}",
		"GET /reaper/{username}/{siteID}/kudo",
		"POST /reaper/{username}/{siteID}/kudo",
		"POST /webmention/{username}/{siteID}/receive",
		"GET /api/webmentions/{username}/{siteID}",
		"GET /api/analytics/{username}/{siteID}",
	}
	for _, route := range expected {
		if !routes[route] {
			t.Errorf("missing route %s", route)
		}
	}
}
