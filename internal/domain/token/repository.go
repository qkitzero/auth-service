package token

type TokenRepository interface {
	Create(token Token) error
}
