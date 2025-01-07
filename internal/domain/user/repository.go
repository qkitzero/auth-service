package user

type UserRepository interface {
	Create(user User) error
	Read(id UserID) (User, error)
}
