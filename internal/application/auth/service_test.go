package auth

import (
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/qkitzero/auth/internal/infrastructure/api"
	mocks "github.com/qkitzero/auth/mocks/infrastructure/api"
	"go.uber.org/mock/gomock"
)

func TestExchangeCodeForToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                       string
		success                    bool
		code                       string
		expectExchangeCodeForToken bool
		exchangeCodeForTokenErr    error
	}{
		{"success exchange code for token", true, "code", true, nil},
		{"failure exchange code for token error", false, "code", true, fmt.Errorf("exchange code for token error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocks.NewMockKeycloakClient(ctrl)
			authService := NewAuthService(mockKeycloakClient)
			tokenResponse := &api.TokenResponse{
				AccessToken:      "accessToken",
				RefreshToken:     "refreshToken",
				ExpiresIn:        3600,
				RefreshExpiresIn: 3600,
			}
			if tt.expectExchangeCodeForToken {
				mockKeycloakClient.EXPECT().ExchangeCodeForToken(gomock.Any()).Return(tokenResponse, tt.exchangeCodeForTokenErr)
			}
			_, err := authService.ExchangeCodeForToken(tt.code)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error but got nil")
			}
		})
	}
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		success            bool
		refreshToken       string
		expectRefreshToken bool
		refreshTokenErr    error
	}{
		{"success refresh token", true, "refreshToken", true, nil},
		{"failure refresh token error", false, "refreshToken", true, fmt.Errorf("refresh token error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocks.NewMockKeycloakClient(ctrl)
			authService := NewAuthService(mockKeycloakClient)
			tokenResponse := &api.TokenResponse{
				AccessToken:      "accessToken",
				RefreshToken:     "refreshToken",
				ExpiresIn:        3600,
				RefreshExpiresIn: 3600,
			}
			if tt.expectRefreshToken {
				mockKeycloakClient.EXPECT().RefreshToken(gomock.Any()).Return(tokenResponse, tt.refreshTokenErr)
			}
			_, err := authService.RefreshToken(tt.refreshToken)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error but got nil")
			}
		})
	}
}

func TestVerifyToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		success           bool
		accessToken       string
		claims            jwt.Claims
		expectVerifyToken bool
		verifyTokenErr    error
	}{
		{"success verify token", true, "accessToken", jwt.MapClaims{"sub": "126ff835-d63f-4f44-a3aa-b5e530b98991"}, true, nil},
		{"failure verify token error", false, "accessToken", jwt.MapClaims{"sub": "126ff835-d63f-4f44-a3aa-b5e530b98991"}, true, fmt.Errorf("verify token error")},
		{"failure invalid sub", false, "accessToken", jwt.MapClaims{"sub": ""}, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocks.NewMockKeycloakClient(ctrl)
			authService := NewAuthService(mockKeycloakClient)
			jwtToken := &jwt.Token{
				Claims: tt.claims,
			}
			if tt.expectVerifyToken {
				mockKeycloakClient.EXPECT().VerifyToken(gomock.Any()).Return(jwtToken, tt.verifyTokenErr)
			}
			_, err := authService.VerifyToken(tt.accessToken)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error but got nil")
			}
		})
	}
}

func TestRevokeToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		success           bool
		refreshToken      string
		expectRevokeToken bool
		revokeTokenErr    error
	}{
		{"success revoke token", true, "refreshToken", true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocks.NewMockKeycloakClient(ctrl)
			authService := NewAuthService(mockKeycloakClient)
			if tt.expectRevokeToken {
				mockKeycloakClient.EXPECT().RevokeToken(gomock.Any()).Return(tt.revokeTokenErr)
			}
			err := authService.RevokeToken(tt.refreshToken)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error but got nil")
			}
		})
	}
}
