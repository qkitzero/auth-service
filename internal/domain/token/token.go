package token

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

func NewToken(accessToken, refreshToken string) Token {
	return &token{
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}
}
