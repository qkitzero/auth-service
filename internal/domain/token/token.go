package token

import "errors"

type Token interface {
	AccessToken() string
	RefreshToken() string
}

type token struct {
	accessToken  string
	refreshToken string
}

func (t token) AccessToken() string {
	return t.accessToken
}

func (t token) RefreshToken() string {
	return t.refreshToken
}

func NewToken(accessToken, refreshToken string) (Token, error) {
	if accessToken == "" {
		return nil, errors.New("access token is empty")
	}
	if refreshToken == "" {
		return nil, errors.New("refresh token is empty")
	}
	return &token{
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}, nil
}
