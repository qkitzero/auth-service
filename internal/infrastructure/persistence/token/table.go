package token

import (
	"time"
	"token/internal/domain/token"
)

type TokenTable struct {
	ID        token.TokenID
	CreatedAt time.Time
}

func (TokenTable) TableName() string {
	return "token"
}
