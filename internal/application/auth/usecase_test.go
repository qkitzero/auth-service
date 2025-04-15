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
		name                    string
		success                 bool
		code                    string
		exchangeCodeForTokenErr error
	}{
		{"success exchange code for token", true, "code", nil},
		{"failure exchange code for token error", false, "code", fmt.Errorf("exchange code for token error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocks.NewMockKeycloakClient(ctrl)
			authUsecase := NewAuthUsecase(mockKeycloakClient)
			tokenResponse := &api.TokenResponse{
				AccessToken:      "accessToken",
				RefreshToken:     "refreshToken",
				ExpiresIn:        3600,
				RefreshExpiresIn: 3600,
			}
			mockKeycloakClient.EXPECT().ExchangeCodeForToken(gomock.Any()).Return(tokenResponse, tt.exchangeCodeForTokenErr).AnyTimes()
			_, err := authUsecase.ExchangeCodeForToken(tt.code)
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
		name            string
		success         bool
		refreshToken    string
		refreshTokenErr error
	}{
		{"success refresh token", true, "refreshToken", nil},
		{"failure refresh token error", false, "refreshToken", fmt.Errorf("refresh token error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocks.NewMockKeycloakClient(ctrl)
			authUsecase := NewAuthUsecase(mockKeycloakClient)
			tokenResponse := &api.TokenResponse{
				AccessToken:      "accessToken",
				RefreshToken:     "refreshToken",
				ExpiresIn:        3600,
				RefreshExpiresIn: 3600,
			}
			mockKeycloakClient.EXPECT().RefreshToken(gomock.Any()).Return(tokenResponse, tt.refreshTokenErr).AnyTimes()
			_, err := authUsecase.RefreshToken(tt.refreshToken)
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
		name           string
		success        bool
		accessToken    string
		claims         jwt.Claims
		verifyTokenErr error
	}{
		{"success verify token", true, "accessToken", jwt.MapClaims{"sub": "126ff835-d63f-4f44-a3aa-b5e530b98991"}, nil},
		{"failure verify token error", false, "accessToken", jwt.MapClaims{"sub": "126ff835-d63f-4f44-a3aa-b5e530b98991"}, fmt.Errorf("verify token error")},
		{"failure invalid sub", false, "accessToken", jwt.MapClaims{"sub": ""}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocks.NewMockKeycloakClient(ctrl)
			authUsecase := NewAuthUsecase(mockKeycloakClient)
			jwtToken := &jwt.Token{
				Claims: tt.claims,
			}
			mockKeycloakClient.EXPECT().VerifyToken(gomock.Any()).Return(jwtToken, tt.verifyTokenErr).AnyTimes()
			_, err := authUsecase.VerifyToken(tt.accessToken)
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
		name           string
		success        bool
		refreshToken   string
		revokeTokenErr error
	}{
		{"success revoke token", true, "refreshToken", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocks.NewMockKeycloakClient(ctrl)
			authUsecase := NewAuthUsecase(mockKeycloakClient)
			mockKeycloakClient.EXPECT().RevokeToken(gomock.Any()).Return(tt.revokeTokenErr).AnyTimes()
			err := authUsecase.RevokeToken(tt.refreshToken)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error but got nil")
			}
		})
	}
}
