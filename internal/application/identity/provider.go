package identity

import "context"

type TokenResult struct {
	AccessToken  string
	RefreshToken string
}

type VerifyResult struct {
	Subject string
}

type Provider interface {
	Login(ctx context.Context, redirectURI string) (string, error)
	ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenResult, error)
	VerifyToken(ctx context.Context, accessToken string) (*VerifyResult, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenResult, error)
	RevokeToken(ctx context.Context, refreshToken string) error
	Logout(ctx context.Context, returnTo string) (string, error)
	GetM2MToken(ctx context.Context, clientID, clientSecret string) (*TokenResult, error)
}
