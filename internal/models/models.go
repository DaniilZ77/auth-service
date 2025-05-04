package models

import "github.com/golang-jwt/jwt/v5"

type TokenClaims struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

type TokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenRequest struct {
	RefreshToken string `json:"refresh_token" example:"1fe0f4a0-9de9-4192-93b8-1a702b1eda2d"`
}
