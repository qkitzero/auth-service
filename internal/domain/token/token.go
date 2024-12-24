package token

import "time"

type Token interface {
	ID() TokenID
	CreatedAt() time.Time
}

type token struct {
	id        TokenID
	createdAt time.Time
}

func (t token) ID() TokenID {
	return t.id
}

func (t token) CreatedAt() time.Time {
	return t.createdAt
}

func NewToken(id TokenID) Token {
	now := time.Now()
	return token{
		id:        id,
		createdAt: now,
	}
}
