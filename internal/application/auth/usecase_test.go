package auth

import (
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/qkitzero/auth/internal/infrastructure/api/auth0"
	mocksAuth0 "github.com/qkitzero/auth/mocks/infrastructure/api/auth0"
	mocksKeycloak "github.com/qkitzero/auth/mocks/infrastructure/api/keycloak"
	"go.uber.org/mock/gomock"
)

func TestLogin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		success     bool
		redirectURI string
		loginErr    error
	}{
		{
			name:        "success login",
			success:     true,
			redirectURI: "http://localhost:3000/callback",
			loginErr:    nil,
		},
		{
			name:        "failure login error",
			success:     false,
			redirectURI: "http://localhost:3000/callback",
			loginErr:    fmt.Errorf("login error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocksKeycloak.NewMockClient(ctrl)
			mockAuth0Client := mocksAuth0.NewMockClient(ctrl)
			authUsecase := NewAuthUsecase(mockKeycloakClient, mockAuth0Client)
			mockAuth0Client.EXPECT().Login(tt.redirectURI).Return("login url", tt.loginErr).AnyTimes()
			_, err := authUsecase.Login(tt.redirectURI)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error but got nil")
			}
		})
	}
}

func TestExchangeCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		success         bool
		code            string
		redirectURI     string
		exchangeCodeErr error
	}{
		{
			name:            "success exchange code",
			success:         true,
			code:            "code",
			redirectURI:     "http://localhost:3000/callback",
			exchangeCodeErr: nil,
		},
		{
			name:            "failure exchange code error",
			success:         false,
			code:            "code",
			redirectURI:     "http://localhost:3000/callback",
			exchangeCodeErr: fmt.Errorf("exchange code error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocksKeycloak.NewMockClient(ctrl)
			mockAuth0Client := mocksAuth0.NewMockClient(ctrl)
			authUsecase := NewAuthUsecase(mockKeycloakClient, mockAuth0Client)
			tokenResponse := &auth0.TokenResponse{
				AccessToken:      "accessToken",
				RefreshToken:     "refreshToken",
				ExpiresIn:        3600,
				RefreshExpiresIn: 3600,
			}
			mockAuth0Client.EXPECT().ExchangeCode(tt.code, tt.redirectURI).Return(tokenResponse, tt.exchangeCodeErr).AnyTimes()
			_, err := authUsecase.ExchangeCode(tt.code, tt.redirectURI)
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
		{
			name:           "success verify token",
			success:        true,
			accessToken:    "accessToken",
			claims:         jwt.MapClaims{"sub": "126ff835-d63f-4f44-a3aa-b5e530b98991"},
			verifyTokenErr: nil,
		},
		{
			name:           "failure verify token error",
			success:        false,
			accessToken:    "accessToken",
			claims:         jwt.MapClaims{"sub": "126ff835-d63f-4f44-a3aa-b5e530b98991"},
			verifyTokenErr: fmt.Errorf("verify token error"),
		},
		{
			name:           "failure invalid sub",
			success:        false,
			accessToken:    "accessToken",
			claims:         jwt.MapClaims{"sub": ""},
			verifyTokenErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocksKeycloak.NewMockClient(ctrl)
			mockAuth0Client := mocksAuth0.NewMockClient(ctrl)
			authUsecase := NewAuthUsecase(mockKeycloakClient, mockAuth0Client)
			jwtToken := &jwt.Token{
				Claims: tt.claims,
			}
			mockAuth0Client.EXPECT().VerifyToken(gomock.Any()).Return(jwtToken, tt.verifyTokenErr).AnyTimes()
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

func TestRefreshToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		success         bool
		refreshToken    string
		refreshTokenErr error
	}{
		{
			name:            "success refresh token",
			success:         true,
			refreshToken:    "refreshToken",
			refreshTokenErr: nil,
		},
		{
			name:            "failure refresh token error",
			success:         false,
			refreshToken:    "refreshToken",
			refreshTokenErr: fmt.Errorf("refresh token error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocksKeycloak.NewMockClient(ctrl)
			mockAuth0Client := mocksAuth0.NewMockClient(ctrl)
			authUsecase := NewAuthUsecase(mockKeycloakClient, mockAuth0Client)
			tokenResponse := &auth0.TokenResponse{
				AccessToken:      "accessToken",
				RefreshToken:     "refreshToken",
				ExpiresIn:        3600,
				RefreshExpiresIn: 3600,
			}
			mockAuth0Client.EXPECT().RefreshToken(gomock.Any()).Return(tokenResponse, tt.refreshTokenErr).AnyTimes()
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

func TestRevokeToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		success        bool
		refreshToken   string
		revokeTokenErr error
	}{
		{
			name:           "success revoke token",
			success:        true,
			refreshToken:   "refreshToken",
			revokeTokenErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockKeycloakClient := mocksKeycloak.NewMockClient(ctrl)
			mockAuth0Client := mocksAuth0.NewMockClient(ctrl)
			authUsecase := NewAuthUsecase(mockKeycloakClient, mockAuth0Client)
			mockAuth0Client.EXPECT().RevokeToken(gomock.Any()).Return(tt.revokeTokenErr).AnyTimes()
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
