package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DaniilZ77/auth-service/internal/app"
	"github.com/DaniilZ77/auth-service/internal/config"
)

//	@title			Auth Service API
//	@version		1.0
//	@description	This is the API for the Auth Service.

//	@host		localhost:8081
//	@BasePath	/api/v1

// @securityDefinitions.apiKey	ApiKeyAuthBasic
// @in							header
// @name						Authorization
// @description				Authorization token in the format "Bearer your_token". Also can use without "Bearer", just "your_token"
func main() {
	config := config.MustConfig()
	log := newLogger(config.LogLevel)

	app, err := app.NewApp(config, log)
	if err != nil {
		panic(err)
	}

	go app.MustRun()

	notifyCh := make(chan os.Signal, 1)
	signal.Notify(notifyCh, syscall.SIGINT, os.Interrupt)

	<-notifyCh
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	app.Close(ctx)
}

func newLogger(logLevel string) *slog.Logger {
	if logLevel == "" {
		logLevel = "INFO"
	}

	var log *slog.Logger

	opts := &slog.HandlerOptions{AddSource: true}
	switch strings.ToUpper(logLevel) {
	case "DEBUG":
		opts.Level = slog.LevelDebug
		log = slog.New(slog.NewTextHandler(os.Stdout, opts))
	case "ERROR":
		opts.Level = slog.LevelError
		log = slog.New(slog.NewJSONHandler(os.Stdout, opts))
	case "INFO":
		opts.Level = slog.LevelInfo
		log = slog.New(slog.NewJSONHandler(os.Stdout, opts))
	case "WARN":
		opts.Level = slog.LevelWarn
		log = slog.New(slog.NewJSONHandler(os.Stdout, opts))
	default:
		panic("unknown log level")
	}

	return log
}
