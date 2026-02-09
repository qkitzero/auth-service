package token

import "errors"

type M2MToken interface {
	AccessToken() string
}

type m2mToken struct {
	accessToken string
}

func (m m2mToken) AccessToken() string {
	return m.accessToken
}

func NewM2MToken(accessToken string) (M2MToken, error) {
	if accessToken == "" {
		return nil, errors.New("access token is empty")
	}
	return &m2mToken{
		accessToken: accessToken,
	}, nil
}
