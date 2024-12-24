package token

import "github.com/google/uuid"

type TokenID struct {
	uuid.UUID
}

func NewTokenID() TokenID {
	return TokenID{uuid.New()}
}
