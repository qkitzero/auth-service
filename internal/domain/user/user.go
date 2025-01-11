package user

type User interface {
	ID() UserID
}

type user struct {
	id UserID
}

func (u user) ID() UserID {
	return u.id
}

func NewUser(id UserID) User {
	return user{
		id: id,
	}
}
