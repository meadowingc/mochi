package site

import (
	"errors"
	"fmt"
	"mochi/shared_database"
	"mochi/user_database"

	"gorm.io/gorm"
)

var errSiteAlreadyExists = errors.New("site already exists")

type createPublicSiteRouteFunc func(string, uint) (*shared_database.PublicSiteRoute, error)
type deletePublicSiteRouteFunc func(string, uint) error

func createSiteWithPublicRoute(
	userDB *gorm.DB,
	username string,
	userID uint,
	siteURL string,
	createRoute createPublicSiteRouteFunc,
	deleteRoute deletePublicSiteRouteFunc,
) (*user_database.Site, *shared_database.PublicSiteRoute, error) {
	if userDB == nil || createRoute == nil || deleteRoute == nil {
		return nil, nil, errors.New("create site: dependencies are not initialized")
	}

	var createdSite user_database.Site
	var publicRoute *shared_database.PublicSiteRoute
	routeEstablished := false

	err := userDB.Transaction(func(tx *gorm.DB) error {
		var existingCount int64
		if err := tx.Model(&user_database.Site{}).
			Where("url = ? AND user_id = ?", siteURL, userID).
			Count(&existingCount).Error; err != nil {
			return fmt.Errorf("check existing site: %w", err)
		}
		if existingCount != 0 {
			return errSiteAlreadyExists
		}

		createdSite = user_database.Site{URL: siteURL, UserID: userID}
		if err := tx.Create(&createdSite).Error; err != nil {
			return fmt.Errorf("create site: %w", err)
		}

		route, err := createRoute(username, createdSite.ID)
		if err != nil {
			return fmt.Errorf("create public site route: %w", err)
		}
		publicRoute = route
		routeEstablished = route != nil
		if route == nil || route.Username != username || route.SiteID != createdSite.ID ||
			route.PublicID == "" {
			return errors.New("create public site route: invalid route")
		}
		return nil
	})
	if err == nil {
		return &createdSite, publicRoute, nil
	}

	if routeEstablished {
		compensationErr := deleteRoute(username, createdSite.ID)
		if compensationErr != nil && !errors.Is(compensationErr, gorm.ErrRecordNotFound) {
			return nil, nil, errors.Join(
				err,
				fmt.Errorf("compensate public site route: %w", compensationErr),
			)
		}
	}
	return nil, nil, err
}

func permanentlyDeleteSite(
	userDB *gorm.DB,
	username string,
	siteID uint,
	deleteRoute deletePublicSiteRouteFunc,
) (bool, error) {
	if userDB == nil || deleteRoute == nil {
		return false, errors.New("delete site: dependencies are not initialized")
	}

	err := userDB.Transaction(func(tx *gorm.DB) error {
		for _, model := range []any{
			&user_database.Hit{},
			&user_database.WebMention{},
			&user_database.Kudo{},
		} {
			if err := tx.Unscoped().Where("site_id = ?", siteID).Delete(model).Error; err != nil {
				return fmt.Errorf("delete site data: %w", err)
			}
		}

		result := tx.Unscoped().Where("id = ?", siteID).Delete(&user_database.Site{})
		if result.Error != nil {
			return fmt.Errorf("delete site: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("delete site: %w", gorm.ErrRecordNotFound)
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	if err := deleteRoute(username, siteID); err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return true, fmt.Errorf("delete public site route: %w", err)
	}
	return true, nil
}
