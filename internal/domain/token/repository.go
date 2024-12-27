package token

import "token/internal/domain/user"

type TokenRepository interface {
	Create(token Token) error
	Read(userID user.UserID) (Token, error)
	Update(token Token) error
}
