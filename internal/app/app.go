package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/DaniilZ77/auth-service/internal/config"
	router "github.com/DaniilZ77/auth-service/internal/http"
	myjwt "github.com/DaniilZ77/auth-service/internal/lib/jwt"
	"github.com/DaniilZ77/auth-service/internal/lib/postgres"
	"github.com/DaniilZ77/auth-service/internal/service"
	"github.com/DaniilZ77/auth-service/internal/store"
	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultAccessTokenTTL  = 2 * time.Minute
	defaultRefreshTokenTTL = 10 * time.Hour
	defaultHttpPort        = "0.0.0.0:8081"
)

type App struct {
	httpServer *http.Server
	httpPort   string
	database   *postgres.Postgres
	log        *slog.Logger
}

func NewApp(config *config.Config, log *slog.Logger) (*App, error) {
	if config.AccessTokenTTL <= 0 {
		config.AccessTokenTTL = defaultAccessTokenTTL
	}
	if config.RefreshTokenTTL <= 0 {
		config.RefreshTokenTTL = defaultRefreshTokenTTL
	}
	if config.HttpPort == "" {
		config.HttpPort = defaultHttpPort
	}
	if config.JwtSecret == "" {
		return nil, errors.New("jwt secret cannot be empty")
	}
	if config.DBURL == "" {
		return nil, errors.New("database url cannot be empty")
	}
	if config.WebhookURL == "" {
		return nil, errors.New("webhook url cannot be empty")
	}

	ctx := context.Background()
	database, err := postgres.New(ctx, config.DBURL, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	sessionBlacklist := store.NewSessionBlacklist()

	sessionStore, err := store.NewSessionStore(database, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create session store: %w", err)
	}

	tokenHandler, err := myjwt.NewTokenHandler(config.JwtSecret, []string{jwt.SigningMethodHS512.Alg()}, config.AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to create token handler: %w", err)
	}

	authService, err := service.NewAuthService(
		config.RefreshTokenTTL,
		config.WebhookURL,
		sessionStore,
		tokenHandler,
		sessionBlacklist,
		log)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service: %w", err)
	}

	mux := http.NewServeMux()
	if err := router.NewRouter(mux, config.HttpPort, authService, tokenHandler, log); err != nil {
		return nil, fmt.Errorf("failed to create router: %w", err)
	}
	httpServer := &http.Server{
		Addr:    config.HttpPort,
		Handler: mux,
	}

	return &App{
		httpServer: httpServer,
		httpPort:   config.HttpPort,
		database:   database,
		log:        log,
	}, nil
}

func (a *App) Run() error {
	a.log.Info("starting http server", slog.String("port", a.httpPort))
	return a.httpServer.ListenAndServe()
}

func (a *App) Close(ctx context.Context) {
	a.database.Close()
	if err := a.httpServer.Shutdown(ctx); err != nil {
		a.log.Warn("failed to close http server", slog.Any("error", err))
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		a.log.Error("failed to run http server", slog.Any("error", err))
		panic(err)
	}
}
