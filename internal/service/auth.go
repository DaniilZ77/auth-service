package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/DaniilZ77/auth-service/internal/domain/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultSendWebhookRetries = 3
	defaultSendWebhookDelay   = time.Second
)

//go:generate mockery --name=SessionStorage --case=snake --inpackage --inpackage-suffix --with-expecter
type SessionStorage interface {
	GetSessionByID(ctx context.Context, sessionID string) (*models.Session, error)
	NewSession(ctx context.Context, session *models.Session) error
	RotateSession(ctx context.Context, oldSessionID string, newSession *models.Session) error
	RevokeSession(ctx context.Context, sessionID string) error
}

//go:generate mockery --name=TokenHandler --case=snake --inpackage --inpackage-suffix --with-expecter
type TokenHandler interface {
	NewToken(userID, sessionID string) (token string, err error)
}

//go:generate mockery --name=SessionBlacklist --case=snake --inpackage --inpackage-suffix --with-expecter
type SessionBlacklist interface {
	In(sessionID string) bool
	Add(sessionID string)
}

type AuthService struct {
	sessionStorage     SessionStorage
	sendWebhookRetries int
	sendWebhookDelay   time.Duration
	tokenHandler       TokenHandler
	sessionBlacklist   SessionBlacklist
	refreshTokenTTL    time.Duration
	webhookURL         string
	log                *slog.Logger
}

func NewAuthService(
	refreshTokenTTL time.Duration,
	webhookURL string,
	sessionStorage SessionStorage,
	tokenHandler TokenHandler,
	sessionBlacklist SessionBlacklist,
	log *slog.Logger,
) (*AuthService, error) {
	if refreshTokenTTL <= 0 {
		return nil, errors.New("refresh token ttl must be greater than zero")
	}
	if sessionStorage == nil {
		return nil, errors.New("session storage cannot be nil")
	}
	if webhookURL == "" {
		return nil, errors.New("webhook url cannot be empty")
	}
	if tokenHandler == nil {
		return nil, errors.New("token handler cannot be nil")
	}
	if sessionBlacklist == nil {
		return nil, errors.New("session blacklist cannot be nil")
	}
	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}
	return &AuthService{
		webhookURL:         webhookURL,
		sendWebhookRetries: defaultSendWebhookRetries,
		sendWebhookDelay:   defaultSendWebhookDelay,
		sessionStorage:     sessionStorage,
		refreshTokenTTL:    refreshTokenTTL,
		sessionBlacklist:   sessionBlacklist,
		tokenHandler:       tokenHandler,
		log:                log,
	}, nil
}

func (a *AuthService) newSession(refreshToken string, requestMeta *models.RequestMeta) (*models.Session, error) {
	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		a.log.Error("failed to create session", slog.Any("error", err))
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &models.Session{
		ID:               uuid.NewString(),
		RefreshTokenHash: string(refreshTokenHash),
		UserAgent:        requestMeta.UserAgent,
		IpAddress:        requestMeta.IP,
		Expiry:           time.Now().Add(a.refreshTokenTTL),
	}, nil
}

// Create new session with access token and refresh token, save session in database and return tokens
func (a *AuthService) Login(ctx context.Context, userID string, requestMeta *models.RequestMeta) (tokens *models.TokensInfo, err error) {
	tokens = &models.TokensInfo{}

	tokens.RefreshToken = uuid.NewString()
	newSession, err := a.newSession(tokens.RefreshToken, requestMeta)
	if err != nil {
		return nil, err
	}

	tokens.AccessToken, err = a.tokenHandler.NewToken(userID, newSession.ID)
	if err != nil {
		a.log.Error("failed to generate token", slog.Any("error", err))
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	err = a.sessionStorage.NewSession(ctx, newSession)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

func (a *AuthService) validateSessions(
	oldTokens *models.TokensInfo,
	requestMeta *models.RequestMeta,
	oldSession *models.Session) error {
	if oldSession.IsRevoked {
		return &models.DomainError{Err: models.ErrSessionRevoked}
	}
	if oldSession.Expiry.Before(time.Now()) {
		return &models.DomainError{Err: models.ErrSessionExpired}
	}
	if oldSession.UserAgent != requestMeta.UserAgent {
		return &models.DomainError{Err: models.ErrUserAgentMismatch}
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(oldSession.RefreshTokenHash),
		[]byte(oldTokens.RefreshToken),
	); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return &models.DomainError{Err: models.ErrInvalidRefreshToken}
		}
		a.log.Error("failed to compare hash and refresh token", slog.Any("error", err))
		return fmt.Errorf("failed to compare hash and refresh token: %w", err)
	}

	return nil
}

func (a *AuthService) sendWebhook(payload map[string]string) {
	retries := a.sendWebhookRetries
	body, err := json.Marshal(payload)
	if err != nil {
		a.log.Error("failed to marshal payload", slog.Any("error", err))
		return
	}

	req, err := http.NewRequest(http.MethodPost, a.webhookURL, bytes.NewReader(body))
	if err != nil {
		a.log.Error("failed send request", slog.Any("error", err))
		return
	}
	for retries > 0 {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			defer resp.Body.Close() // nolint
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		a.log.Warn("failed to send webhook", slog.Any("error", err))
		time.Sleep(a.sendWebhookDelay)
		retries--
	}
}

// Get session from database by session id from access token that came from the request, validate it, check if ip addresses from current session and session in database are not equal, then send data on webhook. Generate new session, invalidate old one and insert new.
func (a *AuthService) RefreshToken(ctx context.Context, oldTokens *models.TokensInfo, requestMeta *models.RequestMeta) (newTokens *models.TokensInfo, err error) {
	oldSession, err := a.sessionStorage.GetSessionByID(ctx, oldTokens.SessionID)
	if err != nil {
		return nil, err
	}

	if err := a.validateSessions(oldTokens, requestMeta, oldSession); err != nil {
		if errors.Is(err, models.ErrUserAgentMismatch) {
			if err := a.Logout(ctx, oldSession.ID); err != nil {
				a.log.Error("failed to logout", slog.Any("error", err))
			}
		}
		return nil, err
	}

	if oldSession.IpAddress != requestMeta.IP {
		go a.sendWebhook(map[string]string{
			"old_ip":  oldSession.IpAddress,
			"new_ip":  requestMeta.IP,
			"user_id": oldTokens.UserID,
		})
	}

	newRefreshToken := uuid.NewString()
	newSession, err := a.newSession(newRefreshToken, requestMeta)
	if err != nil {
		return nil, err
	}

	newAccessToken, err := a.tokenHandler.NewToken(oldTokens.UserID, newSession.ID)
	if err != nil {
		a.log.Error("failed to create access token", slog.Any("error", err))
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	if err := a.sessionStorage.RotateSession(ctx, oldSession.ID, newSession); err != nil {
		return nil, err
	}

	return &models.TokensInfo{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

// Invalidate session in database by session id and add session id in blacklist to protect from using same access token in the future
func (a *AuthService) Logout(ctx context.Context, sessionID string) error {
	if err := a.sessionStorage.RevokeSession(ctx, sessionID); err != nil {
		return err
	}

	a.sessionBlacklist.Add(sessionID)
	return nil
}

// Check if provided session id in black list
func (a *AuthService) CheckSession(ctx context.Context, sessionID string) error {
	if a.sessionBlacklist.In(sessionID) {
		return &models.DomainError{Err: models.ErrSessionRevoked}
	}

	return nil
}
