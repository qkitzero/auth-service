package user

import (
	"errors"
	"token/internal/domain/user"

	"gorm.io/gorm"
)

type UserService struct {
	repo user.UserRepository
}

func NewUserService(repo user.UserRepository) *UserService {
	return &UserService{repo: repo}
}

func (s *UserService) GetOrCreateUser(sub string) (user.User, error) {
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

func (s *UserService) GetUser(sub string) (user.User, error) {
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
