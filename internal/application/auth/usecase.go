package auth

import (
	"github.com/qkitzero/auth/internal/domain/token"
	"github.com/qkitzero/auth/internal/domain/user"
	"github.com/qkitzero/auth/internal/infrastructure/api"
)

type AuthUsecase interface {
	ExchangeCodeForToken(code string) (token.Token, error)
	RefreshToken(refreshToken string) (token.Token, error)
	VerifyToken(accessToken string) (user.User, error)
	RevokeToken(refreshToken string) error
}

type authUsecase struct {
	keycloakClient api.KeycloakClient
}

func NewAuthUsecase(keycloakClient api.KeycloakClient) AuthUsecase {
	return &authUsecase{keycloakClient: keycloakClient}
}

func (s *authUsecase) ExchangeCodeForToken(code string) (token.Token, error) {
	tokenResponse, err := s.keycloakClient.ExchangeCodeForToken(code)
	if err != nil {
		return nil, err
	}

	token := token.NewToken(tokenResponse.AccessToken, tokenResponse.RefreshToken)

	return token, nil
}

func (s *authUsecase) RefreshToken(refreshToken string) (token.Token, error) {
	tokenResponse, err := s.keycloakClient.RefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	token := token.NewToken(tokenResponse.AccessToken, tokenResponse.RefreshToken)

	return token, nil
}

func (s *authUsecase) VerifyToken(accessToken string) (user.User, error) {
	verifiedToken, err := s.keycloakClient.VerifyToken(accessToken)
	if err != nil {
		return nil, err
	}

	sub, err := verifiedToken.Claims.GetSubject()
	if err != nil {
		return nil, err
	}

	userID, err := user.NewUserID(sub)
	if err != nil {
		return nil, err
	}

	return user.NewUser(userID), nil
}

func (s *authUsecase) RevokeToken(refreshToken string) error {
	return s.keycloakClient.RevokeToken(refreshToken)
}
