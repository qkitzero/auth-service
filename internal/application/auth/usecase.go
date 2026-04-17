package auth

import (
	"github.com/qkitzero/auth-service/internal/application/identity"
	"github.com/qkitzero/auth-service/internal/domain/token"
	"github.com/qkitzero/auth-service/internal/domain/user"
)

type AuthUsecase interface {
	Login(redirectURI string) (string, error)
	ExchangeCode(code, redirectURI string) (token.Token, error)
	VerifyToken(accessToken string) (user.User, error)
	RefreshToken(refreshToken string) (token.Token, error)
	RevokeToken(refreshToken string) error
	Logout(returnTo string) (string, error)
	GetM2MToken(clientID, clientSecret string) (token.M2MToken, error)
}

type authUsecase struct {
	identityProvider identity.Provider
}

func NewAuthUsecase(identityProvider identity.Provider) AuthUsecase {
	return &authUsecase{
		identityProvider: identityProvider,
	}
}

func (u *authUsecase) Login(redirectURI string) (string, error) {
	return u.identityProvider.Login(redirectURI)
}

func (u *authUsecase) ExchangeCode(code, redirectURI string) (token.Token, error) {
	result, err := u.identityProvider.ExchangeCode(code, redirectURI)
	if err != nil {
		return nil, err
	}

	return token.NewToken(result.AccessToken, result.RefreshToken)
}

func (u *authUsecase) VerifyToken(accessToken string) (user.User, error) {
	result, err := u.identityProvider.VerifyToken(accessToken)
	if err != nil {
		return nil, err
	}

	userID, err := user.NewUserID(result.Subject)
	if err != nil {
		return nil, err
	}

	return user.NewUser(userID), nil
}

func (u *authUsecase) RefreshToken(refreshToken string) (token.Token, error) {
	result, err := u.identityProvider.RefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	return token.NewToken(result.AccessToken, result.RefreshToken)
}

func (u *authUsecase) RevokeToken(refreshToken string) error {
	return u.identityProvider.RevokeToken(refreshToken)
}

func (u *authUsecase) Logout(returnTo string) (string, error) {
	return u.identityProvider.Logout(returnTo)
}

func (u *authUsecase) GetM2MToken(clientID, clientSecret string) (token.M2MToken, error) {
	result, err := u.identityProvider.GetM2MToken(clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	return token.NewM2MToken(result.AccessToken)
}
