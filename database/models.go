package database

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username     string `gorm:"uniqueIndex"`
	CreatedAt    time.Time
	PasswordHash datatypes.JSON `gorm:"type:json"`
	SessionToken string         `gorm:"index;unique"`
	Sites        []Site         `gorm:"foreignKey:UserID"`
}

type Site struct {
	gorm.Model
	UserID    uint `gorm:"index"`
	CreatedAt time.Time
	URL       string
	Hits      []Hit `gorm:"foreignKey:SiteID"`
}

type Hit struct {
	gorm.Model
	SiteID            uint `gorm:"index"`
	Path              string
	Date              time.Time
	VisitorIpHash     *string
	HTTPReferer       *string
	CountryCode       *string
	VisitorOS         *string
	VisitorDeviceType *string
	VisitorBrowser    *string
}
