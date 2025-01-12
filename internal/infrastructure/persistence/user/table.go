package user

import (
	"github.com/qkitzero/auth/internal/domain/user"
)

type UserTable struct {
	ID user.UserID
}

func (UserTable) TableName() string {
	return "user"
}
