package models

import "errors"

var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrSessionRevoked      = errors.New("session revoked")
	ErrSessionExpired      = errors.New("session expired")
	ErrUserAgentMismatch   = errors.New("user agent mismatch")
)

type DomainError struct {
	Err error
}

func (de *DomainError) Error() string {
	return de.Err.Error()
}

func (de *DomainError) Unwrap() error {
	return de.Err
}
