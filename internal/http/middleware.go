package http

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/DaniilZ77/auth-service/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	tokenClaimsContextKey = contextKey("token-claims")
)

func (r *router) getAuthorizationHeader(w http.ResponseWriter, req *http.Request) (string, error) {
	token := req.Header.Get("authorization")
	token = strings.TrimSpace(token)
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")
	if token == "" {
		r.log.Warn("authorization token empty")
		r.response(w, http.StatusUnauthorized, models.NewErrorResponse("authorization token empty"))
		return "", errors.New("authorization token empty")
	}
	return token, nil
}

func (r *router) protectedMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		token, err := r.getAuthorizationHeader(w, req)
		if err != nil {
			return
		}

		tokenClaims, err := r.tokenHandler.ParseToken(token)
		if err != nil {
			r.log.Warn("invalid token", slog.Any("error", err))
			r.response(w, http.StatusUnauthorized, models.NewErrorResponse(err.Error()))
			return
		}

		if err := r.authService.CheckSession(ctx, tokenClaims.SessionID); err != nil {
			r.log.Warn("session is expired", slog.Any("error", err))
			r.response(w, http.StatusUnauthorized, models.NewErrorResponse(err.Error()))
			return
		}

		ctx = context.WithValue(ctx, tokenClaimsContextKey, tokenClaims)
		next.ServeHTTP(w, req.WithContext(ctx))
	}
}

func (r *router) injectionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		token, err := r.getAuthorizationHeader(w, req)
		if err != nil {
			return
		}

		tokenClaims, err := r.tokenHandler.ParseToken(token)
		if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
			r.log.Warn("invalid token", slog.Any("error", err))
			r.response(w, http.StatusUnauthorized, models.NewErrorResponse(err.Error()))
			return
		}

		ctx = context.WithValue(ctx, tokenClaimsContextKey, tokenClaims)
		next.ServeHTTP(w, req.WithContext(ctx))
	}
}

func getTokenClaimsFromContext(ctx context.Context) (*models.TokenClaims, error) {
	value := ctx.Value(tokenClaimsContextKey)
	tokenClaims, ok := value.(*models.TokenClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return tokenClaims, nil
}

func (r *router) loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.log.Info("request",
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
			slog.String("remote_addr", req.RemoteAddr),
		)
		next.ServeHTTP(w, req)
	})
}
