package user

import "errors"

type UserID string

func NewUserID(s string) (UserID, error) {
	if s == "" {
		return "", errors.New("user id is empty")
	}
	return UserID(s), nil
}
