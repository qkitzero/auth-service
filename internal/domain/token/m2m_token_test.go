package token

import (
	"testing"
)

func TestNewM2MToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		success     bool
		accessToken string
	}{
		{"success new m2m token", true, "m2mAccessToken"},
		{"failure empty access token", false, ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			token, err := NewM2MToken(tt.accessToken)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
			if tt.success && token.AccessToken() != tt.accessToken {
				t.Errorf("AccessToken() = %v, want %v", token.AccessToken(), tt.accessToken)
			}
		})
	}
}
