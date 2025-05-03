package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/DaniilZ77/auth-service/internal/models"
)

const (
	canExpire    = true
	cannotExpire = false
)

type router struct {
	authService  AuthService
	tokenHandler TokenHandler
	log          *slog.Logger
}

func NewRouter(
	mux *http.ServeMux,
	authService AuthService,
	tokenHandler TokenHandler,
	log *slog.Logger,
) error {
	if mux == nil {
		return errors.New("mux cannot be nil")
	}
	if authService == nil {
		return errors.New("auth service cannot be nil")
	}
	if tokenHandler == nil {
		return errors.New("token handler cannot be nil")
	}
	if log == nil {
		return errors.New("logger cannot be nil")
	}
	r := router{
		authService:  authService,
		tokenHandler: tokenHandler,
		log:          log,
	}
	mux.HandleFunc("GET /api/v1/me", r.protectedMiddleware(r.me, cannotExpire))
	mux.HandleFunc("POST /api/v1/login", r.login)
	mux.HandleFunc("POST /api/v1/token/refresh", r.protectedMiddleware(r.refreshToken, canExpire))
	mux.HandleFunc("POST /api/v1/logout", r.protectedMiddleware(r.logout, cannotExpire))
	return nil
}

func (r *router) response(w http.ResponseWriter, code int, response *models.Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		r.log.Error("failed to encode response", slog.Any("error", err))
		return
	}
}
