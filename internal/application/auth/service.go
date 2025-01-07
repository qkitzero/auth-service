package auth

import (
	"token/internal/domain/token"
	"token/internal/infrastructure/api"
)

type AuthService struct {
	keycloakClient api.KeycloakClient
}

func NewTokenService(keycloakClient api.KeycloakClient) *AuthService {
	return &AuthService{keycloakClient: keycloakClient}
}

func (s *AuthService) ExchangeCodeForToken(code string) (token.Token, error) {
	tokenResponse, err := s.keycloakClient.ExchangeCodeForToken(code)
	if err != nil {
		return nil, err
	}

	token := token.NewToken(tokenResponse.AccessToken, tokenResponse.RefreshToken)

	return token, nil
}

func (s *AuthService) RefreshToken(refreshToken string) (token.Token, error) {
	tokenResponse, err := s.keycloakClient.RefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	token := token.NewToken(tokenResponse.AccessToken, tokenResponse.RefreshToken)

	return token, nil
}

func (s *AuthService) VerifyToken(accessToken string) (string, error) {
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

func (s *AuthService) RevokeToken(refreshToken string) error {
	return s.keycloakClient.RevokeToken(refreshToken)
}
