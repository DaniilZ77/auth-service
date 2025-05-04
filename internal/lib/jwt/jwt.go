package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/DaniilZ77/auth-service/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

type TokenHandler struct {
	secret  string
	methods []string
	ttl     time.Duration
}

func NewTokenHandler(secret string, methods []string, ttl time.Duration) (*TokenHandler, error) {
	if secret == "" {
		return nil, errors.New("jwt secret cannot be empty")
	}
	if len(methods) == 0 {
		return nil, errors.New("methods cannot be empty")
	}
	if ttl <= 0 {
		return nil, errors.New("ttl must be greater than zero")
	}
	return &TokenHandler{
		secret:  secret,
		methods: methods,
		ttl:     ttl,
	}, nil
}

func (th *TokenHandler) ParseToken(token string) (*models.TokenClaims, error) {
	jwtToken, err := jwt.ParseWithClaims(token, &models.TokenClaims{}, func(jwtToken *jwt.Token) (any, error) {
		return []byte(th.secret), nil
	}, jwt.WithValidMethods(th.methods))
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return nil, fmt.Errorf("invalid token: %w", err)
	} else if tokenClaims, ok := jwtToken.Claims.(*models.TokenClaims); ok {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return tokenClaims, fmt.Errorf("invalid token: %w", err)
		}
		return tokenClaims, nil
	}

	return nil, errors.New("invalid token claims")
}

func (th *TokenHandler) NewToken(userID, sessionID string) (string, error) {
	tokenClaims := &models.TokenClaims{}
	tokenClaims.UserID = userID
	tokenClaims.SessionID = sessionID
	tokenClaims.ExpiresAt = jwt.NewNumericDate(time.Now().UTC().Add(th.ttl))

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS512, tokenClaims)
	token, err := jwtToken.SignedString([]byte(th.secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return token, nil
}
