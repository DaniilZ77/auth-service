package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/DaniilZ77/auth-service/internal/domain/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type dependencies struct {
	sessionStorage   *MockSessionStorage
	sessionBlacklist *MockSessionBlacklist
	tokenHandler     *MockTokenHandler
	authService      *AuthService
}

func newDependencies(t *testing.T) *dependencies {
	t.Helper()

	sessionStorage := NewMockSessionStorage(t)
	sessionBlacklist := NewMockSessionBlacklist(t)
	tokenHandler := NewMockTokenHandler(t)

	authService, err := NewAuthService(
		time.Hour,
		"http://localhost:8081/webhook",
		sessionStorage,
		tokenHandler,
		sessionBlacklist,
		slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	return &dependencies{
		authService:      authService,
		sessionStorage:   sessionStorage,
		sessionBlacklist: sessionBlacklist,
		tokenHandler:     tokenHandler,
	}
}

func TestLogin(t *testing.T) {
	t.Parallel()

	deps := newDependencies(t)

	userID := uuid.NewString()
	userAgent := "Safari"
	ip := "127.0.0.1"
	var sessionID string
	var refreshTokenHash string

	deps.tokenHandler.EXPECT().NewToken(userID, mock.MatchedBy(func(id string) bool {
		sessionID = id
		return uuid.Validate(id) == nil
	})).Return("access_token", nil).Once()
	deps.sessionStorage.EXPECT().NewSession(mock.Anything, mock.MatchedBy(func(session *models.Session) bool {
		refreshTokenHash = session.RefreshTokenHash
		return session.ID == sessionID && !session.IsRevoked && session.UserAgent == userAgent && session.IpAddress == ip && session.RefreshTokenHash != ""
	})).Return(nil).Once()

	tokens, err := deps.authService.Login(context.Background(), userID, &models.RequestMeta{
		UserAgent: userAgent,
		IP:        ip,
	})
	require.NoError(t, err)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(refreshTokenHash), []byte(tokens.RefreshToken)))
	assert.Equal(t, "access_token", tokens.AccessToken)
}

func TestLoginFail(t *testing.T) {
	t.Parallel()

	deps := newDependencies(t)

	tests := []struct {
		name      string
		behaviour func()
	}{
		{
			name: "new token error",
			behaviour: func() {
				deps.tokenHandler.EXPECT().NewToken(mock.Anything, mock.Anything).Return("", errors.New("failed to generate token")).Once()
			},
		},
		{
			name: "new session error",
			behaviour: func() {
				deps.tokenHandler.EXPECT().NewToken(mock.Anything, mock.Anything).Return("", nil).Once()
				deps.sessionStorage.EXPECT().NewSession(mock.Anything, mock.Anything).Return(errors.New("failed to create new session")).Once()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.behaviour()
			_, err := deps.authService.Login(context.Background(), "", &models.RequestMeta{})
			assert.Error(t, err)
		})
	}
}

func TestCheckSession(t *testing.T) {
	t.Parallel()

	deps := newDependencies(t)

	sessionID := uuid.NewString()
	deps.sessionBlacklist.EXPECT().In(sessionID).Return(false).Once()

	err := deps.authService.CheckSession(context.Background(), sessionID)
	assert.NoError(t, err)
}

func TestCheckSessionFail(t *testing.T) {
	t.Parallel()

	deps := newDependencies(t)

	deps.sessionBlacklist.EXPECT().In(mock.Anything).Return(true).Once()
	err := deps.authService.CheckSession(context.Background(), "")
	assert.ErrorIs(t, err, models.ErrSessionRevoked)
}

func TestLogout(t *testing.T) {
	t.Parallel()

	deps := newDependencies(t)

	sessionID := uuid.NewString()
	deps.sessionStorage.EXPECT().RevokeSession(mock.Anything, sessionID).Return(nil).Once()
	deps.sessionBlacklist.EXPECT().Add(sessionID).Return().Once()

	err := deps.authService.Logout(context.Background(), sessionID)
	assert.NoError(t, err)
}

func TestLogoutFail(t *testing.T) {
	t.Parallel()

	deps := newDependencies(t)

	deps.sessionStorage.EXPECT().RevokeSession(mock.Anything, mock.Anything).Return(errors.New("failed to revoke session")).Once()
	err := deps.authService.Logout(context.Background(), "")
	assert.Error(t, err)
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()

	deps := newDependencies(t)

	oldSessionID := uuid.NewString()
	userID := uuid.NewString()
	oldRefreshToken := uuid.NewString()
	oldRefreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(oldRefreshToken), defaultBcryptCost)
	require.NoError(t, err)
	userAgent := "Safari"
	ip := "127.0.0.1"
	var refreshTokenHash string
	var sessionID string

	deps.sessionStorage.EXPECT().GetSessionByID(mock.Anything, oldSessionID).Return(&models.Session{
		ID:               oldSessionID,
		RefreshTokenHash: string(oldRefreshTokenHash),
		UserAgent:        userAgent,
		IpAddress:        ip,
		Expiry:           time.Now().Add(10 * time.Minute),
	}, nil).Once()
	deps.tokenHandler.EXPECT().NewToken(userID, mock.MatchedBy(func(id string) bool {
		sessionID = id
		return uuid.Validate(id) == nil
	})).Return("access_token", nil).Once()
	deps.sessionStorage.EXPECT().RotateSession(mock.Anything, oldSessionID, mock.MatchedBy(func(session *models.Session) bool {
		refreshTokenHash = session.RefreshTokenHash
		return session.ID == sessionID && !session.IsRevoked && session.UserAgent == userAgent && session.IpAddress == ip && session.RefreshTokenHash != ""
	})).Return(nil).Once()

	newTokens, err := deps.authService.RefreshToken(context.Background(), &models.TokensInfo{
		SessionID:    oldSessionID,
		UserID:       userID,
		RefreshToken: oldRefreshToken,
	}, &models.RequestMeta{
		UserAgent: userAgent,
		IP:        ip,
	})
	require.NoError(t, err)

	assert.Equal(t, "access_token", newTokens.AccessToken)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(refreshTokenHash), []byte(newTokens.RefreshToken)))
}

func TestRefreshTokenFail(t *testing.T) {
	t.Parallel()

	deps := newDependencies(t)

	refreshToken := uuid.NewString()
	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), defaultBcryptCost)
	require.NoError(t, err)

	tests := []struct {
		name        string
		tokensInfo  *models.TokensInfo
		requestMeta *models.RequestMeta
		behaviour   func()
		expectedErr error
	}{
		{
			name:        "session not found",
			tokensInfo:  &models.TokensInfo{},
			requestMeta: &models.RequestMeta{},
			behaviour: func() {
				deps.sessionStorage.EXPECT().GetSessionByID(mock.Anything, mock.Anything).Return(nil, errors.New("session not found")).Once()
			},
		},
		{
			name:        "session revoked",
			tokensInfo:  &models.TokensInfo{},
			requestMeta: &models.RequestMeta{},
			behaviour: func() {
				deps.sessionStorage.EXPECT().GetSessionByID(mock.Anything, mock.Anything).Return(&models.Session{IsRevoked: true}, nil).Once()
			},
			expectedErr: models.ErrSessionRevoked,
		},
		{
			name:        "session expired",
			tokensInfo:  &models.TokensInfo{},
			requestMeta: &models.RequestMeta{},
			behaviour: func() {
				deps.sessionStorage.EXPECT().GetSessionByID(mock.Anything, mock.Anything).Return(&models.Session{}, nil).Once()
			},
			expectedErr: models.ErrSessionExpired,
		},
		{
			name:        "user agent mismatch",
			tokensInfo:  &models.TokensInfo{RefreshToken: refreshToken},
			requestMeta: &models.RequestMeta{UserAgent: "Safari"},
			behaviour: func() {
				deps.sessionStorage.EXPECT().GetSessionByID(mock.Anything, mock.Anything).Return(&models.Session{RefreshTokenHash: string(refreshTokenHash), Expiry: time.Now().Add(10 * time.Minute)}, nil).Once()
				deps.sessionStorage.EXPECT().RevokeSession(mock.Anything, mock.Anything).Return(nil).Once()
				deps.sessionBlacklist.EXPECT().Add(mock.Anything).Return().Once()
			},
			expectedErr: models.ErrUserAgentMismatch,
		},
		{
			name:        "refresh token mismatch",
			tokensInfo:  &models.TokensInfo{},
			requestMeta: &models.RequestMeta{},
			behaviour: func() {
				deps.sessionStorage.EXPECT().GetSessionByID(mock.Anything, mock.Anything).Return(&models.Session{RefreshTokenHash: string(refreshTokenHash), Expiry: time.Now().Add(10 * time.Minute)}, nil).Once()
			},
			expectedErr: models.ErrInvalidRefreshToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.behaviour()
			_, err := deps.authService.RefreshToken(context.Background(), tt.tokensInfo, tt.requestMeta)
			if tt.expectedErr == nil {
				assert.Error(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.expectedErr)
		})
	}
}
