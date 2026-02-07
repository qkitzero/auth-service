package auth

import (
	"github.com/qkitzero/auth-service/internal/domain/token"
	"github.com/qkitzero/auth-service/internal/domain/user"
	"github.com/qkitzero/auth-service/internal/infrastructure/api/auth0"
	"github.com/qkitzero/auth-service/internal/infrastructure/api/keycloak"
)

type AuthUsecase interface {
	Login(redirectURI string) (string, error)
	ExchangeCode(code, redirectURI string) (token.Token, error)
	VerifyToken(accessToken string) (user.User, error)
	RefreshToken(refreshToken string) (token.Token, error)
	RevokeToken(refreshToken string) error
	Logout(returnTo string) (string, error)
	GetM2MToken() (token.M2MToken, error)
}

type authUsecase struct {
	keycloakClient keycloak.Client
	auth0Client    auth0.Client
}

func NewAuthUsecase(
	keycloakClient keycloak.Client,
	auth0Client auth0.Client,
) AuthUsecase {
	return &authUsecase{
		keycloakClient: keycloakClient,
		auth0Client:    auth0Client,
	}
}

func (s *authUsecase) Login(redirectURI string) (string, error) {
	url, err := s.auth0Client.Login(redirectURI)
	if err != nil {
		return "", err
	}

	return url, nil
}

func (s *authUsecase) ExchangeCode(code, redirectURI string) (token.Token, error) {
	tokenResponse, err := s.auth0Client.ExchangeCode(code, redirectURI)
	if err != nil {
		return nil, err
	}

	return token.NewToken(tokenResponse.AccessToken, tokenResponse.RefreshToken)
}

func (s *authUsecase) VerifyToken(accessToken string) (user.User, error) {
	verifiedToken, err := s.auth0Client.VerifyToken(accessToken)
	if err != nil {
		return nil, err
	}

	sub, _ := verifiedToken.Claims.GetSubject()

	userID, err := user.NewUserID(sub)
	if err != nil {
		return nil, err
	}

	return user.NewUser(userID), nil
}

func (s *authUsecase) RefreshToken(refreshToken string) (token.Token, error) {
	tokenResponse, err := s.auth0Client.RefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	return token.NewToken(tokenResponse.AccessToken, tokenResponse.RefreshToken)
}

func (s *authUsecase) RevokeToken(refreshToken string) error {
	return s.auth0Client.RevokeToken(refreshToken)
}

func (s *authUsecase) Logout(returnTo string) (string, error) {
	url, err := s.auth0Client.Logout(returnTo)
	if err != nil {
		return "", err
	}

	return url, nil
}

func (s *authUsecase) GetM2MToken() (token.M2MToken, error) {
	tokenResponse, err := s.auth0Client.GetM2MToken()
	if err != nil {
		return nil, err
	}

	return token.NewM2MToken(tokenResponse.AccessToken)
}
