package user

import "errors"

type UserID string

func (id UserID) String() string {
	return string(id)
}

func NewUserID(s string) (UserID, error) {
	if s == "" {
		return "", errors.New("user id is empty")
	}
	return UserID(s), nil
}
