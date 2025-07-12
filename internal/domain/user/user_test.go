package user

import (
	"testing"
)

func TestNewUser(t *testing.T) {
	t.Parallel()
	id, err := NewUserID("792bae02-3587-435f-a98e-3756f8695441")
	if err != nil {
		t.Errorf("failed to new user id: %v", err)
	}
	tests := []struct {
		name    string
		success bool
		id      UserID
	}{
		{"success new user", true, id},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			user := NewUser(tt.id)
			if tt.success && user == nil {
				t.Errorf("NewUser() = nil")
			}
			if tt.success && user.ID() != tt.id {
				t.Errorf("ID() = %v, want %v", user.ID(), tt.id)
			}
		})
	}
}
