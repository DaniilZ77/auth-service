package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	_ "github.com/DaniilZ77/auth-service/docs"
	"github.com/DaniilZ77/auth-service/internal/models"
	httpSwagger "github.com/swaggo/http-swagger"
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
	httpPort string,
	authService AuthService,
	tokenHandler TokenHandler,
	log *slog.Logger,
) error {
	if httpPort == "" {
		return errors.New("http port cannot be empty")
	}
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
	mux.HandleFunc("GET /api/v1/ping", r.ping)
	mux.HandleFunc("GET /api/v1/me", r.protectedMiddleware(r.me, cannotExpire))
	mux.HandleFunc("POST /api/v1/login", r.login)
	mux.HandleFunc("POST /api/v1/token/refresh", r.protectedMiddleware(r.refreshToken, canExpire))
	mux.HandleFunc("POST /api/v1/logout", r.protectedMiddleware(r.logout, cannotExpire))
	mux.HandleFunc("GET /swagger/", httpSwagger.Handler(
		httpSwagger.URL(fmt.Sprintf("http://%s/swagger/doc.json", httpPort)),
	))
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
