package identity

type TokenResult struct {
	AccessToken  string
	RefreshToken string
}

type VerifyResult struct {
	Subject string
}

type Provider interface {
	Login(redirectURI string) (string, error)
	ExchangeCode(code, redirectURI string) (*TokenResult, error)
	VerifyToken(accessToken string) (*VerifyResult, error)
	RefreshToken(refreshToken string) (*TokenResult, error)
	RevokeToken(refreshToken string) error
	Logout(returnTo string) (string, error)
	GetM2MToken(clientID, clientSecret string) (*TokenResult, error)
}
