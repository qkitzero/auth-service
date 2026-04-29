package auth

import (
	"context"

	"github.com/qkitzero/auth-service/internal/application/identity"
	"github.com/qkitzero/auth-service/internal/domain/token"
	"github.com/qkitzero/auth-service/internal/domain/user"
)

type AuthUsecase interface {
	Login(ctx context.Context, redirectURI string) (string, error)
	ExchangeCode(ctx context.Context, code, redirectURI string) (token.Token, error)
	VerifyToken(ctx context.Context, accessToken string) (user.User, error)
	RefreshToken(ctx context.Context, refreshToken string) (token.Token, error)
	RevokeToken(ctx context.Context, refreshToken string) error
	Logout(ctx context.Context, returnTo string) (string, error)
	GetM2MToken(ctx context.Context, clientID, clientSecret string) (token.M2MToken, error)
}

type authUsecase struct {
	identityProvider identity.Provider
}

func NewAuthUsecase(identityProvider identity.Provider) AuthUsecase {
	return &authUsecase{
		identityProvider: identityProvider,
	}
}

func (u *authUsecase) Login(ctx context.Context, redirectURI string) (string, error) {
	return u.identityProvider.Login(ctx, redirectURI)
}

func (u *authUsecase) ExchangeCode(ctx context.Context, code, redirectURI string) (token.Token, error) {
	result, err := u.identityProvider.ExchangeCode(ctx, code, redirectURI)
	if err != nil {
		return nil, err
	}

	return token.NewToken(result.AccessToken, result.RefreshToken)
}

func (u *authUsecase) VerifyToken(ctx context.Context, accessToken string) (user.User, error) {
	result, err := u.identityProvider.VerifyToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	userID, err := user.NewUserID(result.Subject)
	if err != nil {
		return nil, err
	}

	return user.NewUser(userID), nil
}

func (u *authUsecase) RefreshToken(ctx context.Context, refreshToken string) (token.Token, error) {
	result, err := u.identityProvider.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	return token.NewToken(result.AccessToken, result.RefreshToken)
}

func (u *authUsecase) RevokeToken(ctx context.Context, refreshToken string) error {
	return u.identityProvider.RevokeToken(ctx, refreshToken)
}

func (u *authUsecase) Logout(ctx context.Context, returnTo string) (string, error) {
	return u.identityProvider.Logout(ctx, returnTo)
}

func (u *authUsecase) GetM2MToken(ctx context.Context, clientID, clientSecret string) (token.M2MToken, error) {
	result, err := u.identityProvider.GetM2MToken(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	return token.NewM2MToken(result.AccessToken)
}
