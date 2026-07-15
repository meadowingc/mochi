package shared_database

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"mochi/user_database"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	publicSiteIDBytes            = 32
	publicSiteIDCreationAttempts = 5
	legacySeenThrottle           = 24 * time.Hour
)

type LegacyRouteFamily uint8

const (
	LegacyRouteFamilyAnalyticsReaper LegacyRouteFamily = iota + 1
	LegacyRouteFamilyWebmention
	LegacyRouteFamilyAPI

	LegacyRouteFamilyAnalytics = LegacyRouteFamilyAnalyticsReaper
)

type publicIDGenerator func() (string, error)

func generatePublicSiteID() (string, error) {
	random := make([]byte, publicSiteIDBytes)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate public site ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

func CreateOrGetPublicSiteRoute(username string, siteID uint) (*PublicSiteRoute, error) {
	return createOrGetPublicSiteRoute(Db, username, siteID, generatePublicSiteID)
}

func createOrGetPublicSiteRoute(db *gorm.DB, username string, siteID uint, generate publicIDGenerator) (*PublicSiteRoute, error) {
	if db == nil {
		return nil, errors.New("create public site route: database is not initialized")
	}
	if username == "" {
		return nil, errors.New("create public site route: username is empty")
	}
	if siteID == 0 {
		return nil, errors.New("create public site route: site ID is zero")
	}
	db = quietDB(db)

	var existing PublicSiteRoute
	err := db.Where("username = ? AND site_id = ?", username, siteID).First(&existing).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("look up route for site ID %d: %w", siteID, err)
	}

	for attempt := 0; attempt < publicSiteIDCreationAttempts; attempt++ {
		publicID, err := generate()
		if err != nil {
			return nil, fmt.Errorf("create route for site ID %d: %w", siteID, err)
		}
		if !isValidPublicSiteID(publicID) {
			return nil, fmt.Errorf("create route for site ID %d: generated invalid public site ID", siteID)
		}

		route := PublicSiteRoute{
			PublicID: publicID,
			Username: username,
			SiteID:   siteID,
		}
		if err := db.Create(&route).Error; err == nil {
			return &route, nil
		} else {
			var concurrent PublicSiteRoute
			if lookupErr := db.Where("username = ? AND site_id = ?", username, siteID).First(&concurrent).Error; lookupErr == nil {
				return &concurrent, nil
			} else if !errors.Is(lookupErr, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("resolve concurrent route creation for site ID %d: %w", siteID, lookupErr)
			}

			var collision PublicSiteRoute
			if lookupErr := db.Where("public_id = ?", publicID).First(&collision).Error; lookupErr == nil {
				continue
			} else if !errors.Is(lookupErr, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("check public site ID collision for site ID %d: %w", siteID, lookupErr)
			}

			return nil, fmt.Errorf("create route for site ID %d: %w", siteID, err)
		}
	}

	return nil, fmt.Errorf("create route for site ID %d: public site ID collision retry limit reached", siteID)
}

func LookupPublicSiteRoute(publicID string) (*PublicSiteRoute, error) {
	return lookupPublicSiteRoute(Db, publicID)
}

func lookupPublicSiteRoute(db *gorm.DB, publicID string) (*PublicSiteRoute, error) {
	if db == nil {
		return nil, errors.New("look up public site route: database is not initialized")
	}
	db = quietDB(db)
	var route PublicSiteRoute
	if err := db.Where("public_id = ?", publicID).First(&route).Error; err != nil {
		return nil, fmt.Errorf("look up public site route: %w", err)
	}
	return &route, nil
}

func LookupPublicSiteRouteBySite(username string, siteID uint) (*PublicSiteRoute, error) {
	return lookupPublicSiteRouteBySite(Db, username, siteID)
}

func lookupPublicSiteRouteBySite(db *gorm.DB, username string, siteID uint) (*PublicSiteRoute, error) {
	if db == nil {
		return nil, errors.New("look up route by site: database is not initialized")
	}
	db = quietDB(db)
	var route PublicSiteRoute
	if err := db.Where("username = ? AND site_id = ?", username, siteID).First(&route).Error; err != nil {
		return nil, fmt.Errorf("look up route for site ID %d: %w", siteID, err)
	}
	return &route, nil
}

func DeletePublicSiteRoute(username string, siteID uint) error {
	return deletePublicSiteRoute(Db, username, siteID)
}

func deletePublicSiteRoute(db *gorm.DB, username string, siteID uint) error {
	if db == nil {
		return errors.New("delete public site route: database is not initialized")
	}
	db = quietDB(db)
	result := db.Unscoped().Where("username = ? AND site_id = ?", username, siteID).Delete(&PublicSiteRoute{})
	if result.Error != nil {
		return fmt.Errorf("delete route for site ID %d: %w", siteID, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("delete route for site ID %d: %w", siteID, gorm.ErrRecordNotFound)
	}
	return nil
}

func UpdatePublicSiteRouteLegacyLastSeen(publicID string, family LegacyRouteFamily) (bool, error) {
	return updatePublicSiteRouteLegacyLastSeen(Db, publicID, family, time.Now())
}

func updatePublicSiteRouteLegacyLastSeen(db *gorm.DB, publicID string, family LegacyRouteFamily, now time.Time) (bool, error) {
	if db == nil {
		return false, errors.New("update legacy last-seen: database is not initialized")
	}
	db = quietDB(db)

	column, err := legacyLastSeenColumn(family)
	if err != nil {
		return false, err
	}
	result := db.Model(&PublicSiteRoute{}).
		Where("public_id = ? AND ("+column+" IS NULL OR "+column+" <= ?)", publicID, now.Add(-legacySeenThrottle)).
		Update(column, now)
	if result.Error != nil {
		return false, fmt.Errorf("update legacy last-seen: %w", result.Error)
	}
	if result.RowsAffected > 0 {
		return true, nil
	}

	var count int64
	if err := db.Model(&PublicSiteRoute{}).Where("public_id = ?", publicID).Count(&count).Error; err != nil {
		return false, fmt.Errorf("verify legacy last-seen route: %w", err)
	}
	if count == 0 {
		return false, fmt.Errorf("update legacy last-seen: %w", gorm.ErrRecordNotFound)
	}
	return false, nil
}

func legacyLastSeenColumn(family LegacyRouteFamily) (string, error) {
	switch family {
	case LegacyRouteFamilyAnalyticsReaper:
		return "legacy_analytics_last_seen_at", nil
	case LegacyRouteFamilyWebmention:
		return "legacy_webmention_last_seen_at", nil
	case LegacyRouteFamilyAPI:
		return "legacy_api_last_seen_at", nil
	default:
		return "", fmt.Errorf("update legacy last-seen: unknown route family %d", family)
	}
}

func isValidPublicSiteID(publicID string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(publicID)
	return err == nil &&
		len(decoded) == publicSiteIDBytes &&
		base64.RawURLEncoding.EncodeToString(decoded) == publicID
}

type reconciliationUserDBGetter func(string) (*user_database.UserDb, error)

func ReconcilePublicSiteRoutes() error {
	return reconcilePublicSiteRoutes(Db, user_database.GetAllUsernames, user_database.GetDbIfExistsWithError)
}

func reconcilePublicSiteRoutes(
	db *gorm.DB,
	getUsernames func() ([]string, error),
	getUserDB reconciliationUserDBGetter,
) error {
	if db == nil {
		return errors.New("reconcile public site routes: database is not initialized")
	}
	if getUsernames == nil || getUserDB == nil {
		return errors.New("reconcile public site routes: user database source is not initialized")
	}
	db = quietDB(db)

	usernames, err := getUsernames()
	if err != nil {
		return fmt.Errorf("list user databases for route reconciliation: %w", err)
	}

	return db.Transaction(func(tx *gorm.DB) error {
		var routes []PublicSiteRoute
		if err := tx.Unscoped().Find(&routes).Error; err != nil {
			return fmt.Errorf("load public site routes: %w", err)
		}

		type siteKey struct {
			username string
			siteID   uint
		}
		routeBySite := make(map[siteKey]PublicSiteRoute, len(routes))
		routeByPublicID := make(map[string]uint, len(routes))
		for _, route := range routes {
			key := siteKey{username: route.Username, siteID: route.SiteID}
			if previous, exists := routeBySite[key]; exists {
				return fmt.Errorf("inconsistent duplicate routes %d and %d for site ID %d", previous.ID, route.ID, route.SiteID)
			}
			if previousID, exists := routeByPublicID[route.PublicID]; exists {
				return fmt.Errorf("inconsistent duplicate public IDs on registry rows %d and %d", previousID, route.ID)
			}
			if route.Username == "" || route.SiteID == 0 || !isValidPublicSiteID(route.PublicID) {
				return fmt.Errorf("inconsistent public site route row %d for site ID %d", route.ID, route.SiteID)
			}
			routeBySite[key] = route
			routeByPublicID[route.PublicID] = route.ID
		}

		liveSites := make(map[siteKey]struct{})
		seenUsernames := make(map[string]struct{}, len(usernames))
		for userIndex, username := range usernames {
			if username == "" {
				return fmt.Errorf("user database list contains an empty username at index %d", userIndex)
			}
			if _, duplicate := seenUsernames[username]; duplicate {
				return fmt.Errorf("user database list contains a duplicate at index %d", userIndex)
			}
			seenUsernames[username] = struct{}{}

			userDB, err := getUserDB(username)
			if err != nil {
				return fmt.Errorf("open user database at index %d: %w", userIndex, err)
			}
			if userDB == nil || userDB.Db == nil {
				return fmt.Errorf("user database at index %d disappeared during route reconciliation", userIndex)
			}

			var sites []user_database.Site
			if err := userDB.Db.Find(&sites).Error; err != nil {
				return fmt.Errorf("load sites from user database at index %d: %w", userIndex, err)
			}
			for _, site := range sites {
				if site.ID == 0 {
					return fmt.Errorf("user database at index %d contains a site with zero ID", userIndex)
				}
				key := siteKey{username: username, siteID: site.ID}
				if _, duplicate := liveSites[key]; duplicate {
					return fmt.Errorf("user database at index %d contains duplicate site ID %d", userIndex, site.ID)
				}
				liveSites[key] = struct{}{}

				if _, exists := routeBySite[key]; !exists {
					route, err := createOrGetPublicSiteRoute(tx, username, site.ID, generatePublicSiteID)
					if err != nil {
						return fmt.Errorf("create missing route for site ID %d: %w", site.ID, err)
					}
					routeBySite[key] = *route
				}
			}
		}

		for key, route := range routeBySite {
			if _, live := liveSites[key]; live {
				continue
			}
			result := tx.Unscoped().Delete(&PublicSiteRoute{}, route.ID)
			if result.Error != nil {
				return fmt.Errorf("delete stale route row %d for site ID %d: %w", route.ID, route.SiteID, result.Error)
			}
			if result.RowsAffected != 1 {
				return fmt.Errorf("delete stale route row %d for site ID %d: affected %d rows", route.ID, route.SiteID, result.RowsAffected)
			}
		}
		return nil
	})
}

func quietDB(db *gorm.DB) *gorm.DB {
	return db.Session(&gorm.Session{Logger: db.Logger.LogMode(logger.Silent)})
}
