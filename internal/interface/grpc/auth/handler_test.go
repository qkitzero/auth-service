package auth

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/metadata"

	authv1 "github.com/qkitzero/auth-service/gen/go/auth/v1"
	"github.com/qkitzero/auth-service/internal/domain/user"
	mocksappauth "github.com/qkitzero/auth-service/mocks/application/auth"
	mockstoken "github.com/qkitzero/auth-service/mocks/domain/token"
	mocksuser "github.com/qkitzero/auth-service/mocks/domain/user"
)

func TestLogin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		success     bool
		ctx         context.Context
		redirectURI string
		loginErr    error
	}{
		{
			name:        "success login",
			success:     true,
			ctx:         context.Background(),
			redirectURI: "http://localhost:3000/callback",
			loginErr:    nil,
		},
		{
			name:        "failure login error",
			success:     false,
			ctx:         context.Background(),
			redirectURI: "http://localhost:3000/callback",
			loginErr:    errors.New("login error"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockAuthUsecase.EXPECT().Login(tt.redirectURI).Return("login url", tt.loginErr).AnyTimes()

			authHandler := NewAuthHandler(mockAuthUsecase)

			req := &authv1.LoginRequest{
				RedirectUri: tt.redirectURI,
			}

			_, err := authHandler.Login(tt.ctx, req)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
		})
	}
}

func TestExchangeCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                    string
		success                 bool
		ctx                     context.Context
		code                    string
		redirectURI             string
		exchangeCodeForTokenErr error
		verifyTokenErr          error
	}{
		{
			name:                    "success exchange code",
			success:                 true,
			ctx:                     context.Background(),
			code:                    "code",
			redirectURI:             "http://localhost:3000/callback",
			exchangeCodeForTokenErr: nil,
			verifyTokenErr:          nil,
		},
		{
			name:                    "failure exchange code error",
			success:                 false,
			ctx:                     context.Background(),
			code:                    "code",
			redirectURI:             "http://localhost:3000/callback",
			exchangeCodeForTokenErr: errors.New("exchange code error"),
			verifyTokenErr:          nil,
		},
		{
			name:                    "failure verify token error",
			success:                 false,
			ctx:                     context.Background(),
			code:                    "code",
			redirectURI:             "http://localhost:3000/callback",
			exchangeCodeForTokenErr: nil,
			verifyTokenErr:          errors.New("verify token error"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockToken := mockstoken.NewMockToken(ctrl)
			mockUser := mocksuser.NewMockUser(ctrl)
			mockAuthUsecase.EXPECT().ExchangeCode(tt.code, tt.redirectURI).Return(mockToken, tt.exchangeCodeForTokenErr).AnyTimes()
			mockAuthUsecase.EXPECT().VerifyToken("accessToken").Return(mockUser, tt.verifyTokenErr).AnyTimes()
			mockUser.EXPECT().ID().Return(user.UserID("fe8c2263-bbac-4bb9-a41d-b04f5afc4425")).AnyTimes()
			mockToken.EXPECT().AccessToken().Return("accessToken").AnyTimes()
			mockToken.EXPECT().RefreshToken().Return("refreshToken").AnyTimes()

			authHandler := NewAuthHandler(mockAuthUsecase)

			req := &authv1.ExchangeCodeRequest{
				Code:        tt.code,
				RedirectUri: tt.redirectURI,
			}

			_, err := authHandler.ExchangeCode(tt.ctx, req)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
		})
	}
}

func TestVerifyToken(t *testing.T) {
	t.Parallel()
	accessToken := "accessToken"
	tests := []struct {
		name           string
		success        bool
		ctx            context.Context
		accessToken    string
		verifyTokenErr error
	}{
		{
			name:           "success verify token",
			success:        true,
			ctx:            metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+accessToken)),
			accessToken:    accessToken,
			verifyTokenErr: nil,
		},
		{
			name:           "failure missing metadata",
			success:        false,
			ctx:            context.Background(),
			accessToken:    accessToken,
			verifyTokenErr: nil,
		},
		{
			name:           "failure missing authorization",
			success:        false,
			ctx:            metadata.NewIncomingContext(context.Background(), metadata.Pairs()),
			accessToken:    accessToken,
			verifyTokenErr: nil,
		},
		{
			name:           "failure missing bearer",
			success:        false,
			ctx:            metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", accessToken)),
			accessToken:    accessToken,
			verifyTokenErr: nil,
		},
		{
			name:           "failure verify token error",
			success:        false,
			ctx:            metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+accessToken)),
			accessToken:    accessToken,
			verifyTokenErr: errors.New("verify token error"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockUser := mocksuser.NewMockUser(ctrl)
			mockAuthUsecase.EXPECT().VerifyToken(tt.accessToken).Return(mockUser, tt.verifyTokenErr).AnyTimes()
			mockUser.EXPECT().ID().Return(user.UserID("fe8c2263-bbac-4bb9-a41d-b04f5afc4425")).AnyTimes()

			authHandler := NewAuthHandler(mockAuthUsecase)

			req := &authv1.VerifyTokenRequest{}

			_, err := authHandler.VerifyToken(tt.ctx, req)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
		})
	}
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()
	refreshToken := "refreshToken"
	tests := []struct {
		name            string
		success         bool
		ctx             context.Context
		refreshToken    string
		refreshTokenErr error
	}{
		{
			name:            "success refresh token",
			success:         true,
			ctx:             metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)),
			refreshToken:    refreshToken,
			refreshTokenErr: nil,
		},
		{
			name:            "failure missing metadata",
			success:         false,
			ctx:             context.Background(),
			refreshToken:    refreshToken,
			refreshTokenErr: nil,
		},
		{
			name:            "failure missing refresh token",
			success:         false,
			ctx:             metadata.NewIncomingContext(context.Background(), metadata.Pairs()),
			refreshToken:    refreshToken,
			refreshTokenErr: nil,
		},
		{
			name:            "failure refresh token",
			success:         false,
			ctx:             metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)),
			refreshToken:    refreshToken,
			refreshTokenErr: errors.New("refresh token error"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockToken := mockstoken.NewMockToken(ctrl)
			mockAuthUsecase.EXPECT().RefreshToken(tt.refreshToken).Return(mockToken, tt.refreshTokenErr).AnyTimes()
			mockToken.EXPECT().AccessToken().Return("accessToken").AnyTimes()
			mockToken.EXPECT().RefreshToken().Return("refreshToken").AnyTimes()

			authHandler := NewAuthHandler(mockAuthUsecase)

			req := &authv1.RefreshTokenRequest{}

			_, err := authHandler.RefreshToken(tt.ctx, req)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
		})
	}
}

func TestRevokeToken(t *testing.T) {
	t.Parallel()
	refreshToken := "refreshToken"
	tests := []struct {
		name           string
		success        bool
		ctx            context.Context
		refreshToken   string
		revokeTokenErr error
	}{
		{
			name:           "success revoke token",
			success:        true,
			ctx:            metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)),
			refreshToken:   refreshToken,
			revokeTokenErr: nil,
		},
		{
			name:           "failure missing metadata",
			success:        false,
			ctx:            context.Background(),
			refreshToken:   refreshToken,
			revokeTokenErr: nil,
		},
		{
			name:           "failure missing refresh token",
			success:        false,
			ctx:            metadata.NewIncomingContext(context.Background(), metadata.Pairs()),
			refreshToken:   refreshToken,
			revokeTokenErr: nil,
		},
		{
			name:           "failure revoke token",
			ctx:            metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)),
			success:        false,
			refreshToken:   refreshToken,
			revokeTokenErr: errors.New("revoke token error"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockUser := mocksuser.NewMockUser(ctrl)
			mockAuthUsecase.EXPECT().RevokeToken(tt.refreshToken).Return(tt.revokeTokenErr).AnyTimes()
			mockUser.EXPECT().ID().Return(user.UserID("fe8c2263-bbac-4bb9-a41d-b04f5afc4425")).AnyTimes()

			authHandler := NewAuthHandler(mockAuthUsecase)

			req := &authv1.RevokeTokenRequest{}

			_, err := authHandler.RevokeToken(tt.ctx, req)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
		})
	}
}

func TestLogout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		success   bool
		ctx       context.Context
		returnTo  string
		logoutErr error
	}{
		{
			name:      "success logout",
			success:   true,
			ctx:       context.Background(),
			returnTo:  "http://localhost:3000/",
			logoutErr: nil,
		},
		{
			name:      "failure logout error",
			success:   false,
			ctx:       context.Background(),
			returnTo:  "http://localhost:3000/",
			logoutErr: errors.New("logout error"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockAuthUsecase.EXPECT().Logout(tt.returnTo).Return("logout url", tt.logoutErr).AnyTimes()

			authHandler := NewAuthHandler(mockAuthUsecase)

			req := &authv1.LogoutRequest{
				ReturnTo: tt.returnTo,
			}

			_, err := authHandler.Logout(tt.ctx, req)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
		})
	}
}
