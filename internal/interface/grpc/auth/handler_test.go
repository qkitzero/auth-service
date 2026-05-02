package auth

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/qkitzero/auth-service/gen/go/auth/v1"
	"github.com/qkitzero/auth-service/internal/domain/token"
	"github.com/qkitzero/auth-service/internal/domain/user"
	mocksappauth "github.com/qkitzero/auth-service/mocks/application/auth"
	mockstoken "github.com/qkitzero/auth-service/mocks/domain/token"
	mocksuser "github.com/qkitzero/auth-service/mocks/domain/user"
)

func TestLogin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		ctx         context.Context
		redirectURI string
		loginErr    error
		wantCode    codes.Code
	}{
		{"success login", context.Background(), "http://localhost:3000/callback", nil, codes.OK},
		{"failure login error", context.Background(), "http://localhost:3000/callback", errors.New("login error"), codes.Internal},
		{"failure status preserved", context.Background(), "http://localhost:3000/callback", status.Error(codes.Unauthenticated, "auth"), codes.Unauthenticated},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockUsecase.EXPECT().Login(tt.ctx, tt.redirectURI).Return("login url", tt.loginErr).Times(1)

			handler := NewAuthHandler(mockUsecase)

			_, err := handler.Login(tt.ctx, &authv1.LoginRequest{RedirectUri: tt.redirectURI})
			if got := status.Code(err); got != tt.wantCode {
				t.Errorf("expected code %v, got %v (err=%v)", tt.wantCode, got, err)
			}
		})
	}
}

func TestExchangeCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		ctx            context.Context
		code           string
		redirectURI    string
		exchangeErr    error
		callVerify     bool
		verifyTokenErr error
		wantCode       codes.Code
	}{
		{"success exchange code", context.Background(), "code", "http://localhost:3000/callback", nil, true, nil, codes.OK},
		{"failure exchange error", context.Background(), "code", "http://localhost:3000/callback", errors.New("exchange code error"), false, nil, codes.Internal},
		{"failure exchange invalid grant", context.Background(), "code", "http://localhost:3000/callback", token.ErrInvalidGrant, false, nil, codes.Unauthenticated},
		{"failure exchange status preserved", context.Background(), "code", "http://localhost:3000/callback", status.Error(codes.Unauthenticated, "auth"), false, nil, codes.Unauthenticated},
		{"failure verify token error", context.Background(), "code", "http://localhost:3000/callback", nil, true, errors.New("verify token error"), codes.Internal},
		{"failure verify token invalid token", context.Background(), "code", "http://localhost:3000/callback", nil, true, token.ErrInvalidToken, codes.Unauthenticated},
		{"failure verify token status preserved", context.Background(), "code", "http://localhost:3000/callback", nil, true, status.Error(codes.Unauthenticated, "auth"), codes.Unauthenticated},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockToken := mockstoken.NewMockToken(ctrl)
			mockUser := mocksuser.NewMockUser(ctrl)
			mockToken.EXPECT().AccessToken().Return("accessToken").AnyTimes()
			mockToken.EXPECT().RefreshToken().Return("refreshToken").AnyTimes()
			mockUser.EXPECT().ID().Return(user.UserID("fe8c2263-bbac-4bb9-a41d-b04f5afc4425")).AnyTimes()
			mockUsecase.EXPECT().ExchangeCode(tt.ctx, tt.code, tt.redirectURI).Return(mockToken, tt.exchangeErr).Times(1)
			if tt.callVerify {
				mockUsecase.EXPECT().VerifyToken(tt.ctx, "accessToken").Return(mockUser, tt.verifyTokenErr).Times(1)
			}

			handler := NewAuthHandler(mockUsecase)

			req := &authv1.ExchangeCodeRequest{Code: tt.code, RedirectUri: tt.redirectURI}
			_, err := handler.ExchangeCode(tt.ctx, req)
			if got := status.Code(err); got != tt.wantCode {
				t.Errorf("expected code %v, got %v (err=%v)", tt.wantCode, got, err)
			}
		})
	}
}

func TestVerifyToken(t *testing.T) {
	t.Parallel()
	accessToken := "accessToken"
	tests := []struct {
		name           string
		ctx            context.Context
		callUsecase    bool
		verifyTokenErr error
		wantCode       codes.Code
	}{
		{"success verify token", metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+accessToken)), true, nil, codes.OK},
		{"failure missing metadata", context.Background(), false, nil, codes.Unauthenticated},
		{"failure missing authorization", metadata.NewIncomingContext(context.Background(), metadata.Pairs()), false, nil, codes.Unauthenticated},
		{"failure missing bearer prefix", metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", accessToken)), false, nil, codes.Unauthenticated},
		{"failure verify token error", metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+accessToken)), true, errors.New("verify token error"), codes.Internal},
		{"failure invalid token", metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+accessToken)), true, token.ErrInvalidToken, codes.Unauthenticated},
		{"failure status preserved", metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+accessToken)), true, status.Error(codes.Unauthenticated, "rejected"), codes.Unauthenticated},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockUser := mocksuser.NewMockUser(ctrl)
			mockUser.EXPECT().ID().Return(user.UserID("fe8c2263-bbac-4bb9-a41d-b04f5afc4425")).AnyTimes()
			if tt.callUsecase {
				mockUsecase.EXPECT().VerifyToken(tt.ctx, accessToken).Return(mockUser, tt.verifyTokenErr).Times(1)
			}

			handler := NewAuthHandler(mockUsecase)

			_, err := handler.VerifyToken(tt.ctx, &authv1.VerifyTokenRequest{})
			if got := status.Code(err); got != tt.wantCode {
				t.Errorf("expected code %v, got %v (err=%v)", tt.wantCode, got, err)
			}
		})
	}
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()
	refreshToken := "refreshToken"
	tests := []struct {
		name            string
		ctx             context.Context
		callUsecase     bool
		refreshTokenErr error
		wantCode        codes.Code
	}{
		{"success refresh token", metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)), true, nil, codes.OK},
		{"failure missing metadata", context.Background(), false, nil, codes.Unauthenticated},
		{"failure missing refresh token", metadata.NewIncomingContext(context.Background(), metadata.Pairs()), false, nil, codes.Unauthenticated},
		{"failure refresh token error", metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)), true, errors.New("refresh token error"), codes.Internal},
		{"failure refresh invalid grant", metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)), true, token.ErrInvalidGrant, codes.Unauthenticated},
		{"failure status preserved", metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)), true, status.Error(codes.Unauthenticated, "auth"), codes.Unauthenticated},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockToken := mockstoken.NewMockToken(ctrl)
			mockToken.EXPECT().AccessToken().Return("accessToken").AnyTimes()
			mockToken.EXPECT().RefreshToken().Return("refreshToken").AnyTimes()
			if tt.callUsecase {
				mockUsecase.EXPECT().RefreshToken(tt.ctx, refreshToken).Return(mockToken, tt.refreshTokenErr).Times(1)
			}

			handler := NewAuthHandler(mockUsecase)

			_, err := handler.RefreshToken(tt.ctx, &authv1.RefreshTokenRequest{})
			if got := status.Code(err); got != tt.wantCode {
				t.Errorf("expected code %v, got %v (err=%v)", tt.wantCode, got, err)
			}
		})
	}
}

func TestRevokeToken(t *testing.T) {
	t.Parallel()
	refreshToken := "refreshToken"
	tests := []struct {
		name           string
		ctx            context.Context
		callUsecase    bool
		revokeTokenErr error
		wantCode       codes.Code
	}{
		{"success revoke token", metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)), true, nil, codes.OK},
		{"failure missing metadata", context.Background(), false, nil, codes.Unauthenticated},
		{"failure missing refresh token", metadata.NewIncomingContext(context.Background(), metadata.Pairs()), false, nil, codes.Unauthenticated},
		{"failure revoke token error", metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)), true, errors.New("revoke token error"), codes.Internal},
		{"failure revoke invalid grant", metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)), true, token.ErrInvalidGrant, codes.Unauthenticated},
		{"failure status preserved", metadata.NewIncomingContext(context.Background(), metadata.Pairs("refresh-token", refreshToken)), true, status.Error(codes.Unauthenticated, "auth"), codes.Unauthenticated},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			if tt.callUsecase {
				mockUsecase.EXPECT().RevokeToken(tt.ctx, refreshToken).Return(tt.revokeTokenErr).Times(1)
			}

			handler := NewAuthHandler(mockUsecase)

			_, err := handler.RevokeToken(tt.ctx, &authv1.RevokeTokenRequest{})
			if got := status.Code(err); got != tt.wantCode {
				t.Errorf("expected code %v, got %v (err=%v)", tt.wantCode, got, err)
			}
		})
	}
}

func TestLogout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		ctx       context.Context
		returnTo  string
		logoutErr error
		wantCode  codes.Code
	}{
		{"success logout", context.Background(), "http://localhost:3000/", nil, codes.OK},
		{"failure logout error", context.Background(), "http://localhost:3000/", errors.New("logout error"), codes.Internal},
		{"failure status preserved", context.Background(), "http://localhost:3000/", status.Error(codes.Unauthenticated, "auth"), codes.Unauthenticated},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockUsecase.EXPECT().Logout(tt.ctx, tt.returnTo).Return("logout url", tt.logoutErr).Times(1)

			handler := NewAuthHandler(mockUsecase)

			_, err := handler.Logout(tt.ctx, &authv1.LogoutRequest{ReturnTo: tt.returnTo})
			if got := status.Code(err); got != tt.wantCode {
				t.Errorf("expected code %v, got %v (err=%v)", tt.wantCode, got, err)
			}
		})
	}
}

func TestGetM2MToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		ctx            context.Context
		clientID       string
		clientSecret   string
		getM2MTokenErr error
		wantCode       codes.Code
	}{
		{"success get m2m token", context.Background(), "m2mClientID", "m2mClientSecret", nil, codes.OK},
		{"failure get m2m token error", context.Background(), "m2mClientID", "m2mClientSecret", errors.New("get m2m token error"), codes.Internal},
		{"failure get m2m invalid grant", context.Background(), "m2mClientID", "m2mClientSecret", token.ErrInvalidGrant, codes.Unauthenticated},
		{"failure status preserved", context.Background(), "m2mClientID", "m2mClientSecret", status.Error(codes.Unauthenticated, "auth"), codes.Unauthenticated},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockUsecase := mocksappauth.NewMockAuthUsecase(ctrl)
			mockM2MToken := mockstoken.NewMockM2MToken(ctrl)
			mockM2MToken.EXPECT().AccessToken().Return("m2mAccessToken").AnyTimes()
			mockUsecase.EXPECT().GetM2MToken(tt.ctx, tt.clientID, tt.clientSecret).Return(mockM2MToken, tt.getM2MTokenErr).Times(1)

			handler := NewAuthHandler(mockUsecase)

			req := &authv1.GetM2MTokenRequest{ClientId: tt.clientID, ClientSecret: tt.clientSecret}
			_, err := handler.GetM2MToken(tt.ctx, req)
			if got := status.Code(err); got != tt.wantCode {
				t.Errorf("expected code %v, got %v (err=%v)", tt.wantCode, got, err)
			}
		})
	}
}
