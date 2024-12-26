package auth

import (
	"token/internal/infrastructure/api"
)

type AuthService struct {
	keycloakClient api.KeycloakClient
}

func NewTokenService(keycloakClient api.KeycloakClient) *AuthService {
	return &AuthService{keycloakClient: keycloakClient}
}

func (s *AuthService) GetTokne(code string) (*api.TokenResponse, error) {
	tokenResponse, err := s.keycloakClient.GetToken(code)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}

func (s *AuthService) ValidateToken(token string) (string, error) {
	verifiedToken, err := s.keycloakClient.VerifyToken(token)
	if err != nil {
		return "", err
	}

	userID, err := verifiedToken.Claims.GetSubject()
	if err != nil {
		return "", err
	}

	return userID, nil
}
