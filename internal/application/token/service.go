package token

import "token/internal/domain/token"

type TokenService struct {
	repo token.TokenRepository
}

func NewTokenService(repo token.TokenRepository) *TokenService {
	return &TokenService{repo: repo}
}

func (s *TokenService) CreateTokne() (token.Token, error) {
	tokenID := token.NewTokenID()
	token := token.NewToken(tokenID)
	if err := s.repo.Create(token); err != nil {
		return nil, err
	}
	return token, nil
}
