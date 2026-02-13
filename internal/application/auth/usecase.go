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

func (s *authUsecase) Login(redirectURI string) (string, error) {
	return s.identityProvider.Login(redirectURI)
}

func (s *authUsecase) ExchangeCode(code, redirectURI string) (token.Token, error) {
	result, err := s.identityProvider.ExchangeCode(code, redirectURI)
	if err != nil {
		return nil, err
	}

	return token.NewToken(result.AccessToken, result.RefreshToken)
}

func (s *authUsecase) VerifyToken(accessToken string) (user.User, error) {
	result, err := s.identityProvider.VerifyToken(accessToken)
	if err != nil {
		return nil, err
	}

	userID, err := user.NewUserID(result.Subject)
	if err != nil {
		return nil, err
	}

	return user.NewUser(userID), nil
}

func (s *authUsecase) RefreshToken(refreshToken string) (token.Token, error) {
	result, err := s.identityProvider.RefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	return token.NewToken(result.AccessToken, result.RefreshToken)
}

func (s *authUsecase) RevokeToken(refreshToken string) error {
	return s.identityProvider.RevokeToken(refreshToken)
}

func (s *authUsecase) Logout(returnTo string) (string, error) {
	return s.identityProvider.Logout(returnTo)
}

func (s *authUsecase) GetM2MToken(clientID, clientSecret string) (token.M2MToken, error) {
	result, err := s.identityProvider.GetM2MToken(clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	return token.NewM2MToken(result.AccessToken)
}
