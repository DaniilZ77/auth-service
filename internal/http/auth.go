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

type AuthService interface {
	Login(ctx context.Context, userID string, requestMeta *domain.RequestMeta) (tokens *domain.TokensInfo, err error)
	RefreshToken(ctx context.Context, oldTokens *domain.TokensInfo, requestMeta *domain.RequestMeta) (newTokens *domain.TokensInfo, err error)
	Logout(ctx context.Context, sessionID string) error
	CheckSession(ctx context.Context, sessionID string) error
}

type TokenHandler interface {
	ParseToken(token string) (*models.TokenClaims, error)
}

func (r *router) getRequestIP(w http.ResponseWriter, req *http.Request) (string, error) {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		r.log.Error("failed to get client ip", slog.Any("error", err))
		r.response(w, http.StatusInternalServerError, models.NewErrorResponse(err.Error()))
		return "", err
	}
	return ip, nil
}

func (r *router) getTokenClaims(w http.ResponseWriter, req *http.Request) (*models.TokenClaims, error) {
	tokenClaims, err := getTokenClaimsFromContext(req.Context())
	if err != nil {
		r.log.Error("failed to get token claims from context", slog.Any("error", err))
		r.response(w, http.StatusInternalServerError, models.NewErrorResponse(err.Error()))
		return nil, err
	}
	return tokenClaims, nil
}

// @Summary		Get user id
// @Tags			Me
// @Description	Get user id from access token
// @ID				me
// @Security		ApiKeyAuthBasic
// @Accept			json
// @Produce		json
// @Success		200	{object}	models.Response
// @Failure		401	{object}	models.Response
// @Router			/me [get]
func (r *router) me(w http.ResponseWriter, req *http.Request) {
	tokenClaims, err := r.getTokenClaims(w, req)
	if err != nil {
		return
	}

	r.response(w, http.StatusOK, models.NewOKResponse(tokenClaims.UserID))
}

// @Summary		Login
// @Tags			Auth
// @Description	Login with user id
// @ID				login
// @Accept			json
// @Produce		json
// @Param			user_id	query		string	true	"user id"	format(uuid)	example(1fe0f4a0-9de9-4192-93b8-1a702b1eda2d)
// @Success		200		{object}	models.Response{data=models.TokensResponse}
// @Failure		400		{object}	models.Response
// @Failure		500		{object}	models.Response
// @Router			/login [post]
func (r *router) login(w http.ResponseWriter, req *http.Request) {
	userID := req.URL.Query().Get("user_id")
	if err := uuid.Validate(userID); err != nil {
		r.log.Warn("invalid user id", slog.Any("error", err))
		r.response(w, http.StatusBadRequest, models.NewErrorResponse("user id must be uuid"))
		return
	}

	var err error
	requestMeta := &domain.RequestMeta{UserAgent: req.Header.Get("User-Agent")}
	requestMeta.IP, err = r.getRequestIP(w, req)
	if err != nil {
		return
	}
	tokens, err := r.authService.Login(req.Context(), userID, requestMeta)
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

// @Summary		Refresh
// @Tags			Auth
// @Description	Refresh tokens with both access and refresh tokens
// @ID				refresh
// @Security		ApiKeyAuthBasic
// @Accept			json
// @Produce		json
// @Param			refresh_token	body		models.TokenRequest	true	"refresh token"
// @Success		200				{object}	models.Response{data=models.TokensResponse}
// @Failure		400				{object}	models.Response
// @Failure		401				{object}	models.Response
// @Failure		500				{object}	models.Response
// @Router			/token/refresh [post]
func (r *router) refreshToken(w http.ResponseWriter, req *http.Request) {
	var tokenRequest *models.TokenRequest
	if err := json.NewDecoder(req.Body).Decode(&tokenRequest); err != nil {
		r.log.Error("failed to decode request body", slog.Any("error", err))
		r.response(w, http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	tokenClaims, err := r.getTokenClaims(w, req)
	if err != nil {
		return
	}
	requestMeta := &domain.RequestMeta{UserAgent: req.Header.Get("User-Agent")}
	requestMeta.IP, err = r.getRequestIP(w, req)
	if err != nil {
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

// @Summary		Logout
// @Tags			Auth
// @Description	Logout with access token
// @ID				logout
// @Security		ApiKeyAuthBasic
// @Accept			json
// @Produce		json
// @Success		200	{object}	models.Response
// @Failure		401	{object}	models.Response
// @Failure		500	{object}	models.Response
// @Router			/logout [post]
func (r *router) logout(w http.ResponseWriter, req *http.Request) {
	tokenClaims, err := r.getTokenClaims(w, req)
	if err != nil {
		return
	}

	if err := r.authService.Logout(req.Context(), tokenClaims.SessionID); err != nil {
		r.log.Error("failed to logout", slog.Any("error", err))
		r.response(w, http.StatusInternalServerError, models.NewErrorResponse(err.Error()))
		return
	}
}

// @Summary		Ping
// @Tags			Ping
// @Description	Check health of the service
// @ID				ping
// @Accept			json
// @Produce		json
// @Success		200	{object}	models.Response
// @Router			/ping [get]
func (r *router) ping(w http.ResponseWriter, req *http.Request) {
	r.response(w, http.StatusOK, models.NewOKResponse("pong"))
}
