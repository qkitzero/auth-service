package user

import (
	"fmt"

	"github.com/google/uuid"
)

type UserID struct {
	uuid.UUID
}

func NewUserID(s string) (UserID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return UserID{}, fmt.Errorf("invalid UUID format: %w", err)
	}
	return UserID{id}, nil
}
