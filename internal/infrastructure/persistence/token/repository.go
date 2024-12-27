package token

import (
	"token/internal/domain/token"
	"token/internal/domain/user"

	"gorm.io/gorm"
)

type tokenRepository struct {
	db *gorm.DB
}

func NewTokenRepository(db *gorm.DB) token.TokenRepository {
	return &tokenRepository{db: db}
}

func (r *tokenRepository) Create(token token.Token) error {
	tokenTable := TokenTable{
		ID:           token.ID(),
		AccessToken:  token.AccessToken(),
		RefreshToken: token.RefreshToken(),
		UserID:       token.UserID(),
		CreatedAt:    token.CreatedAt(),
		UpdatedAt:    token.UpdatedAt(),
	}

	if err := r.db.Create(&tokenTable).Error; err != nil {
		return err
	}

	return nil
}

func (r *tokenRepository) Read(userID user.UserID) (token.Token, error) {
	var tokenTable TokenTable

	if err := r.db.Where(TokenTable{UserID: userID}).First(&tokenTable).Error; err != nil {
		return nil, err
	}

	return token.NewToken(
		tokenTable.ID,
		tokenTable.AccessToken,
		tokenTable.RefreshToken,
		tokenTable.UserID,
		tokenTable.CreatedAt,
		tokenTable.UpdatedAt,
	), nil
}

func (r *tokenRepository) Update(token token.Token) error {
	tokenTable := TokenTable{
		ID:           token.ID(),
		AccessToken:  token.AccessToken(),
		RefreshToken: token.RefreshToken(),
		UserID:       token.UserID(),
		CreatedAt:    token.CreatedAt(),
		UpdatedAt:    token.UpdatedAt(),
	}

	if err := r.db.Save(&tokenTable).Error; err != nil {
		return err
	}

	return nil
}
