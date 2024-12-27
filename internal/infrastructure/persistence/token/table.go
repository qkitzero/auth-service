package token

import (
	"time"
	"token/internal/domain/token"
	"token/internal/domain/user"
)

type TokenTable struct {
	ID           token.TokenID
	AccessToken  string
	RefreshToken string
	UserID       user.UserID
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (TokenTable) TableName() string {
	return "token"
}
