package token

import (
	"time"
	"token/internal/domain/user"
)

type Token interface {
	ID() TokenID
	AccessToken() string
	RefreshToken() string
	UserID() user.UserID
	CreatedAt() time.Time
	UpdatedAt() time.Time
	Update(accessToken, refreshToken string)
}

type token struct {
	id           TokenID
	accessToken  string
	refreshToken string
	userID       user.UserID
	createdAt    time.Time
	updatedAt    time.Time
}

func (t token) ID() TokenID {
	return t.id
}

func (t token) AccessToken() string {
	return t.accessToken
}

func (t token) RefreshToken() string {
	return t.refreshToken
}

func (t token) UserID() user.UserID {
	return t.userID
}

func (t token) CreatedAt() time.Time {
	return t.createdAt
}

func (t token) UpdatedAt() time.Time {
	return t.updatedAt
}

func (t *token) Update(accessToken, refreshToken string) {
	t.accessToken = accessToken
	t.refreshToken = refreshToken
	t.updatedAt = time.Now()
}

func NewToken(id TokenID, accessToken, refreshToken string, userID user.UserID, createdAt, updatedAt time.Time) Token {
	return &token{
		id:           id,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		userID:       userID,
		createdAt:    createdAt,
		updatedAt:    updatedAt,
	}
}
