package models

import (
	"time"
)

type Session struct {
	ID               string
	RefreshTokenHash string
	IsRevoked        bool
	UserAgent        string
	IpAddress        string
	Expiry           time.Time
	UpdatedAt        time.Time
	CreatedAt        time.Time
}

type TokensInfo struct {
	SessionID    string
	UserID       string
	AccessToken  string
	RefreshToken string
}

type RequestMeta struct {
	UserAgent string
	IP        string
}
