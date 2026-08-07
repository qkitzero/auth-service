package token

import "errors"

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrInvalidGrant = errors.New("invalid grant")
)
