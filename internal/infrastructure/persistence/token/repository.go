package token

import (
	"token/internal/domain/token"

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
		ID:        token.ID(),
		CreatedAt: token.CreatedAt(),
	}
	r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&tokenTable).Error; err != nil {
			return err
		}
		return nil
	})
	return nil
}
