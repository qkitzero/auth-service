package user

import (
	"auth/internal/domain/user"
	"errors"

	"gorm.io/gorm"
)

type UserService interface {
	GetOrCreateUser(sub string) (user.User, error)
	GetUser(sub string) (user.User, error)
}

type userService struct {
	repo user.UserRepository
}

func NewUserService(repo user.UserRepository) UserService {
	return &userService{repo: repo}
}

func (s *userService) GetOrCreateUser(sub string) (user.User, error) {
	userID, err := user.NewUserID(sub)
	if err != nil {
		return nil, err
	}

	existingUser, err := s.repo.Read(userID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if existingUser != nil {
		return existingUser, nil
	}

	user := user.NewUser(userID)

	if err := s.repo.Create(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *userService) GetUser(sub string) (user.User, error) {
	userID, err := user.NewUserID(sub)
	if err != nil {
		return nil, err
	}

	user, err := s.repo.Read(userID)
	if err != nil {
		return nil, err
	}

	return user, nil
}
