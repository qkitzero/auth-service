package auth

import (
	"token/internal/infrastructure/api"

	"github.com/golang-jwt/jwt/v5"
)

type AuthService struct {
	keycloakClient api.KeycloakClient
}

func NewTokenService(keycloakClient api.KeycloakClient) *AuthService {
	return &AuthService{keycloakClient: keycloakClient}
}

func (s *AuthService) Tokne(code string) (*api.TokenResponse, error) {
	tokenResponse, err := s.keycloakClient.Token(code)
	if err != nil {
		return nil, err
	}
	return tokenResponse, nil
}

func (s *AuthService) VerifyTokne(token string) (*jwt.Token, error) {
	verifiedToken, err := s.keycloakClient.VerifyToken(token)
	if err != nil {
		return nil, err
	}
	return verifiedToken, nil
}
