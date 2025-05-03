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

func (r *router) protectedMiddleware(next http.HandlerFunc, canExpire bool) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		token := req.Header.Get("authorization")
		token = strings.TrimSpace(token)
		token = strings.TrimPrefix(token, "bearer ")
		if token == "" {
			r.log.Warn("authorization token is empty")
			r.response(w, http.StatusUnauthorized, models.NewErrorResponse("authorization header is empty"))
			return
		}

		tokenClaims, err := r.tokenHandler.ParseToken(token)
		if err != nil && !(errors.Is(err, jwt.ErrTokenExpired) && canExpire) {
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
