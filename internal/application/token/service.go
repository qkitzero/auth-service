package token

import (
	"errors"
	"time"
	"token/internal/domain/token"
	"token/internal/domain/user"

	"gorm.io/gorm"
)

type TokenService struct {
	repo token.TokenRepository
}

func NewTokenService(repo token.TokenRepository) *TokenService {
	return &TokenService{repo: repo}
}

func (s *TokenService) CreateOrUpdateToken(accessToken, refreshToken string, userID user.UserID) (token.Token, error) {
	existingToken, err := s.repo.Read(userID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if existingToken != nil {
		existingToken.Update(accessToken, refreshToken)
		if err := s.repo.Update(existingToken); err != nil {
			return nil, err
		}
		return existingToken, nil
	}

	tokenID := token.NewTokenID()
	newToken := token.NewToken(tokenID, accessToken, refreshToken, userID, time.Now(), time.Now())
	if err := s.repo.Create(newToken); err != nil {
		return nil, err
	}

	return newToken, nil
}

func (s *TokenService) GetTokne(userID user.UserID) (token.Token, error) {
	return s.repo.Read(userID)
}
