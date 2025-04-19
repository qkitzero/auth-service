package token

import (
	"testing"
)

func TestNewToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		success      bool
		accessToken  string
		refreshToken string
	}{
		{"success new token", true, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := NewToken(tt.accessToken, tt.refreshToken)
			if tt.success && token == nil {
				t.Errorf("NewToken() = nil")
			}
			if tt.success && token.AccessToken() != tt.accessToken {
				t.Errorf("AccessToken() = %v, want %v", token.AccessToken(), tt.accessToken)
			}
			if tt.success && token.RefreshToken() != tt.refreshToken {
				t.Errorf("RefreshToken() = %v, want %v", token.RefreshToken(), tt.refreshToken)
			}
		})
	}
}
