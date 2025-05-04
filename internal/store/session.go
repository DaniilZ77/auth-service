package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/DaniilZ77/auth-service/internal/domain/models"
	"github.com/DaniilZ77/auth-service/internal/lib/postgres"
)

type SessionStore struct {
	db  *postgres.Postgres
	log *slog.Logger
}

func NewSessionStore(db *postgres.Postgres, log *slog.Logger) (*SessionStore, error) {
	if db == nil {
		return nil, errors.New("database cannot be nil")
	}
	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}
	return &SessionStore{
		db:  db,
		log: log,
	}, nil
}

func (s *SessionStore) GetSessionByID(ctx context.Context, sessionID string) (*models.Session, error) {
	session := &models.Session{}
	err := s.db.DB.QueryRowContext(
		ctx,
		"select id, refresh_token_hash, is_revoked, user_agent, ip_address, expiry, updated_at, created_at from sessions where id = $1",
		sessionID,
	).Scan(
		&session.ID,
		&session.RefreshTokenHash,
		&session.IsRevoked,
		&session.UserAgent,
		&session.IpAddress,
		&session.Expiry,
		&session.UpdatedAt,
		&session.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &models.DomainError{Err: models.ErrSessionNotFound}
		}
		s.log.Error("failed to get session", slog.Any("error", err))
		return nil, err
	}

	return session, nil
}

func (s *SessionStore) NewSession(ctx context.Context, session *models.Session) error {
	_, err := s.db.DB.ExecContext(
		ctx,
		"insert into sessions (id, refresh_token_hash, is_revoked, user_agent, ip_address, expiry) values ($1, $2, $3, $4, $5, $6)",
		session.ID,
		session.RefreshTokenHash,
		session.IsRevoked,
		session.UserAgent,
		session.IpAddress,
		session.Expiry)
	if err != nil {
		s.log.Error("failed to create session", slog.Any("error", err))
		return err
	}
	return nil
}

func (s *SessionStore) RotateSession(ctx context.Context, oldSessionID string, newSession *models.Session) error {
	fail := func(err error) error {
		s.log.Error("failed to rotate session", slog.Any("error", err))
		return fmt.Errorf("failed to rotate session: %w", err)
	}

	tx, err := s.db.DB.Begin()
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback() // nolint

	_, err = tx.ExecContext(ctx, "update sessions set is_revoked = true, updated_at = now() where id = $1", oldSessionID)
	if err != nil {
		return fail(err)
	}

	_, err = tx.ExecContext(
		ctx,
		"insert into sessions (id, refresh_token_hash, is_revoked, user_agent, ip_address, expiry) values ($1, $2, $3, $4, $5, $6)",
		newSession.ID,
		newSession.RefreshTokenHash,
		newSession.IsRevoked,
		newSession.UserAgent,
		newSession.IpAddress,
		newSession.Expiry)
	if err != nil {
		return fail(err)
	}

	if err := tx.Commit(); err != nil {
		return fail(err)
	}

	return nil
}

func (s *SessionStore) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := s.db.DB.ExecContext(
		ctx,
		"update sessions set is_revoked = true, updated_at = now() where id = $1",
		sessionID)
	if err != nil {
		s.log.Error("failed to revoke session", slog.Any("error", err))
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	return nil
}
