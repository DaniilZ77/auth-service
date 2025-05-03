package http

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"

	domain "github.com/DaniilZ77/auth-service/internal/domain/models"
	"github.com/DaniilZ77/auth-service/internal/models"
	"github.com/google/uuid"
)

//go:generate mockery --name=AuthService --case=snake --inpackage --inpackage-suffix --with-expecter
type AuthService interface {
	Login(ctx context.Context, userID, userAgent string) (tokens *domain.TokensInfo, err error)
	RefreshToken(ctx context.Context, oldTokens *domain.TokensInfo, requestMeta *domain.RequestMeta) (newTokens *domain.TokensInfo, err error)
	Logout(ctx context.Context, sessionID string) error
	CheckSession(ctx context.Context, sessionID string) error
}

//go:generate mockery --name=TokenHandler --case=snake --inpackage --inpackage-suffix --with-expecter
type TokenHandler interface {
	ParseToken(token string) (*models.TokenClaims, error)
}

func (r *router) me(w http.ResponseWriter, req *http.Request) {
	tokenClaims, err := getTokenClaimsFromContext(req.Context())
	if err != nil {
		r.log.Error("failed to get token claims from context")
		r.response(w, http.StatusInternalServerError, models.NewErrorResponse(err.Error()))
		return
	}

	if err := r.authService.CheckSession(req.Context(), tokenClaims.SessionID); err != nil {
		r.log.Warn("bad session id", slog.Any("error", err))
		r.response(w, http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	r.response(w, http.StatusOK, models.NewOKResponse(tokenClaims.UserID))
}

func (r *router) login(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("user_id")
	if err := uuid.Validate(userID); err != nil {
		r.log.Warn("invalid user id", slog.Any("error", err))
		r.response(w, http.StatusBadRequest, models.NewErrorResponse("user id must be uuid"))
		return
	}

	userAgent := req.Header.Get("User-Agent")
	tokens, err := r.authService.Login(req.Context(), userID, userAgent)
	if err != nil {
		r.log.Error("failed to login", slog.Any("error", err))
		r.response(w, http.StatusInternalServerError, models.NewErrorResponse(err.Error()))
		return
	}

	r.response(w, http.StatusOK, models.NewOKResponse(&models.TokensResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}))
}

func (r *router) refreshToken(w http.ResponseWriter, req *http.Request) {
	var tokenRequest *models.TokenRequest
	if err := json.NewDecoder(req.Body).Decode(&tokenRequest); err != nil {
		r.log.Error("failed to decode request body", slog.Any("error", err))
		r.response(w, http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}
	if tokenRequest.RefreshToken == "" {
		r.log.Warn("refresh token is empty")
		r.response(w, http.StatusBadRequest, models.NewErrorResponse("refresh token is empty"))
		return
	}

	tokenClaims, err := getTokenClaimsFromContext(req.Context())
	if err != nil {
		r.log.Error("failed to get token claims from context", slog.Any("error", err))
		r.response(w, http.StatusInternalServerError, models.NewErrorResponse(err.Error()))
		return
	}

	requestMeta := &domain.RequestMeta{}
	requestMeta.UserAgent = req.Header.Get("User-Agent")
	requestMeta.IP, _, err = net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		r.log.Error("failed to get client ip", slog.Any("error", err))
		r.response(w, http.StatusInternalServerError, models.NewErrorResponse(err.Error()))
		return
	}
	oldTokens := &domain.TokensInfo{
		SessionID:    tokenClaims.SessionID,
		UserID:       tokenClaims.UserID,
		RefreshToken: tokenRequest.RefreshToken,
	}

	var newTokens *domain.TokensInfo
	if newTokens, err = r.authService.RefreshToken(req.Context(), oldTokens, requestMeta); err != nil {
		if errors.Is(err, domain.ErrSessionExpired) {
			r.response(w, http.StatusUnauthorized, models.NewErrorResponse(err.Error()))
			return
		}
		var domainErr *domain.DomainError
		if errors.As(err, &domainErr) {
			r.response(w, http.StatusBadRequest, models.NewErrorResponse(err.Error()))
			return
		}
		r.log.Error("failed to refresh tokens", slog.Any("error", err))
		r.response(w, http.StatusInternalServerError, models.NewErrorResponse(err.Error()))
		return
	}

	r.response(w, http.StatusOK, models.NewOKResponse(&models.TokensResponse{
		AccessToken:  newTokens.AccessToken,
		RefreshToken: newTokens.RefreshToken,
	}))
}

func (r *router) logout(w http.ResponseWriter, req *http.Request) {
	tokenClaims, err := getTokenClaimsFromContext(req.Context())
	if err != nil {
		r.log.Error("failed to get token claims from context", slog.Any("error", err))
		r.response(w, http.StatusInternalServerError, models.NewErrorResponse(err.Error()))
		return
	}

	if err := r.authService.Logout(req.Context(), tokenClaims.SessionID); err != nil {
		r.log.Error("failed to logout", slog.Any("error", err))
		r.response(w, http.StatusInternalServerError, models.NewErrorResponse(err.Error()))
		return
	}
}
