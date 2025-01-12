package user

import (
	"auth/internal/domain/user"
)

type UserTable struct {
	ID user.UserID
}

func (UserTable) TableName() string {
	return "user"
}
