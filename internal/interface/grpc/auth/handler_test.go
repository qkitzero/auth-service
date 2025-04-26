package auth

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/mock/gomock"

	authv1 "github.com/qkitzero/auth/gen/go/proto/auth/v1"
	"github.com/qkitzero/auth/internal/domain/user"
	mocksAuthUsecase "github.com/qkitzero/auth/mocks/application/auth"
	mocksToken "github.com/qkitzero/auth/mocks/domain/token"
	mocksUser "github.com/qkitzero/auth/mocks/domain/user"
)

func TestLogin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                    string
		success                 bool
		code                    string
		exchangeCodeForTokenErr error
		verifyTokenErr          error
	}{
		{"success login", true, "code", nil, nil},
		{"failure exchange code for token error", false, "code", fmt.Errorf("exchange code for token error"), nil},
		{"failure verify token error", false, "code", nil, fmt.Errorf("verify token error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthUsecase := mocksAuthUsecase.NewMockAuthUsecase(ctrl)
			mockToken := mocksToken.NewMockToken(ctrl)
			mockUser := mocksUser.NewMockUser(ctrl)
			mockAuthUsecase.EXPECT().ExchangeCodeForToken(tt.code).Return(mockToken, tt.exchangeCodeForTokenErr).AnyTimes()
			mockAuthUsecase.EXPECT().VerifyToken("accessToken").Return(mockUser, tt.verifyTokenErr).AnyTimes()
			mockUserID, _ := user.NewUserID("fe8c2263-bbac-4bb9-a41d-b04f5afc4425")
			mockUser.EXPECT().ID().Return(mockUserID).AnyTimes()
			mockToken.EXPECT().AccessToken().Return("accessToken").AnyTimes()
			mockToken.EXPECT().RefreshToken().Return("refreshToken").AnyTimes()

			authHandler := NewAuthHandler(mockAuthUsecase)

			ctx := context.Background()
			req := &authv1.LoginRequest{
				Code: tt.code,
			}

			_, err := authHandler.Login(ctx, req)
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
		verifyTokenErr error
	}{
		{"success verify token", true, "accessToken", nil},
		{"failure verify token error", false, "accessToken", fmt.Errorf("verify token error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthUsecase := mocksAuthUsecase.NewMockAuthUsecase(ctrl)
			mockUser := mocksUser.NewMockUser(ctrl)
			mockAuthUsecase.EXPECT().VerifyToken(tt.accessToken).Return(mockUser, tt.verifyTokenErr).AnyTimes()
			mockUserID, _ := user.NewUserID("fe8c2263-bbac-4bb9-a41d-b04f5afc4425")
			mockUser.EXPECT().ID().Return(mockUserID).AnyTimes()

			authHandler := NewAuthHandler(mockAuthUsecase)

			ctx := context.Background()
			req := &authv1.VerifyTokenRequest{
				AccessToken: tt.accessToken,
			}

			_, err := authHandler.VerifyToken(ctx, req)
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
		{"failure refresh token", false, "refreshToken", fmt.Errorf("refresh token error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthUsecase := mocksAuthUsecase.NewMockAuthUsecase(ctrl)
			mockToken := mocksToken.NewMockToken(ctrl)
			mockAuthUsecase.EXPECT().RefreshToken(tt.refreshToken).Return(mockToken, tt.refreshTokenErr).AnyTimes()
			mockToken.EXPECT().AccessToken().Return("accessToken").AnyTimes()
			mockToken.EXPECT().RefreshToken().Return("refreshToken").AnyTimes()

			authHandler := NewAuthHandler(mockAuthUsecase)

			ctx := context.Background()
			req := &authv1.RefreshTokenRequest{
				RefreshToken: tt.refreshToken,
			}

			_, err := authHandler.RefreshToken(ctx, req)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error but got nil")
			}
		})
	}
}

func TestLogout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		success        bool
		accessToken    string
		refreshToken   string
		verifyTokenErr error
		revokeTokenErr error
	}{
		{"success logout", true, "accessToken", "refreshToken", nil, nil},
		{"failure verify token", false, "accessToken", "refreshToken", fmt.Errorf("refresh token error"), nil},
		{"failure revoke token", false, "accessToken", "refreshToken", nil, fmt.Errorf("revoke token error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthUsecase := mocksAuthUsecase.NewMockAuthUsecase(ctrl)
			mockUser := mocksUser.NewMockUser(ctrl)
			mockAuthUsecase.EXPECT().VerifyToken(tt.accessToken).Return(mockUser, tt.verifyTokenErr).AnyTimes()
			mockAuthUsecase.EXPECT().RevokeToken(tt.refreshToken).Return(tt.revokeTokenErr).AnyTimes()
			mockUserID, _ := user.NewUserID("fe8c2263-bbac-4bb9-a41d-b04f5afc4425")
			mockUser.EXPECT().ID().Return(mockUserID).AnyTimes()

			authHandler := NewAuthHandler(mockAuthUsecase)

			ctx := context.Background()
			req := &authv1.LogoutRequest{
				AccessToken:  tt.accessToken,
				RefreshToken: tt.refreshToken,
			}

			_, err := authHandler.Logout(ctx, req)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error but got nil")
			}
		})
	}
}
