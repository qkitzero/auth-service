package auth

import (
	"github.com/qkitzero/auth/internal/domain/token"
	"github.com/qkitzero/auth/internal/infrastructure/api"
)

type AuthService interface {
	ExchangeCodeForToken(code string) (token.Token, error)
	RefreshToken(refreshToken string) (token.Token, error)
	VerifyToken(accessToken string) (string, error)
	RevokeToken(refreshToken string) error
}

type authService struct {
	keycloakClient api.KeycloakClient
}

func NewTokenService(keycloakClient api.KeycloakClient) AuthService {
	return &authService{keycloakClient: keycloakClient}
}

func (s *authService) ExchangeCodeForToken(code string) (token.Token, error) {
	tokenResponse, err := s.keycloakClient.ExchangeCodeForToken(code)
	if err != nil {
		return nil, err
	}

	token := token.NewToken(tokenResponse.AccessToken, tokenResponse.RefreshToken)

	return token, nil
}

func (s *authService) RefreshToken(refreshToken string) (token.Token, error) {
	tokenResponse, err := s.keycloakClient.RefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	token := token.NewToken(tokenResponse.AccessToken, tokenResponse.RefreshToken)

	return token, nil
}

func (s *authService) VerifyToken(accessToken string) (string, error) {
	verifiedToken, err := s.keycloakClient.VerifyToken(accessToken)
	if err != nil {
		return "", err
	}

	sub, err := verifiedToken.Claims.GetSubject()
	if err != nil {
		return "", err
	}

	return sub, nil
}

func (s *authService) RevokeToken(refreshToken string) error {
	return s.keycloakClient.RevokeToken(refreshToken)
}
