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
	mux.HandleFunc("GET /api/v1/ping", r.loggingMiddleware(r.ping))
	mux.HandleFunc("GET /api/v1/me", r.loggingMiddleware(r.protectedMiddleware(r.me)))
	mux.HandleFunc("POST /api/v1/login", r.loggingMiddleware(r.login))
	mux.HandleFunc("POST /api/v1/token/refresh", r.loggingMiddleware(r.injectionMiddleware(r.refreshToken)))
	mux.HandleFunc("POST /api/v1/logout", r.loggingMiddleware(r.protectedMiddleware(r.logout)))
	mux.HandleFunc("GET /swagger/", r.loggingMiddleware(httpSwagger.Handler(
		httpSwagger.URL(fmt.Sprintf("http://localhost:%s/swagger/doc.json", httpPort)),
	)))
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
