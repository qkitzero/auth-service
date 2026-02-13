package auth

import (
	"errors"
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/qkitzero/auth-service/internal/application/identity"
	mocks "github.com/qkitzero/auth-service/mocks/application/identity"
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
			loginErr:    errors.New("login error"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIdentityProvider := mocks.NewMockProvider(ctrl)
			mockIdentityProvider.EXPECT().Login(tt.redirectURI).Return("login url", tt.loginErr).AnyTimes()

			authUsecase := NewAuthUsecase(mockIdentityProvider)

			_, err := authUsecase.Login(tt.redirectURI)
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
		name            string
		success         bool
		code            string
		redirectURI     string
		tokenResult     *identity.TokenResult
		exchangeCodeErr error
	}{
		{
			name:            "success exchange code",
			success:         true,
			code:            "code",
			redirectURI:     "http://localhost:3000/callback",
			tokenResult:     &identity.TokenResult{AccessToken: "accessToken", RefreshToken: "refreshToken"},
			exchangeCodeErr: nil,
		},
		{
			name:            "failure exchange code error",
			success:         false,
			code:            "code",
			redirectURI:     "http://localhost:3000/callback",
			tokenResult:     nil,
			exchangeCodeErr: errors.New("exchange code error"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIdentityProvider := mocks.NewMockProvider(ctrl)
			mockIdentityProvider.EXPECT().ExchangeCode(tt.code, tt.redirectURI).Return(tt.tokenResult, tt.exchangeCodeErr).AnyTimes()

			authUsecase := NewAuthUsecase(mockIdentityProvider)

			_, err := authUsecase.ExchangeCode(tt.code, tt.redirectURI)
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
	tests := []struct {
		name           string
		success        bool
		accessToken    string
		verifyResult   *identity.VerifyResult
		verifyTokenErr error
	}{
		{
			name:           "success verify token",
			success:        true,
			accessToken:    "accessToken",
			verifyResult:   &identity.VerifyResult{Subject: "126ff835-d63f-4f44-a3aa-b5e530b98991"},
			verifyTokenErr: nil,
		},
		{
			name:           "failure verify token error",
			success:        false,
			accessToken:    "accessToken",
			verifyResult:   nil,
			verifyTokenErr: errors.New("verify token error"),
		},
		{
			name:           "failure empty subject",
			success:        false,
			accessToken:    "accessToken",
			verifyResult:   &identity.VerifyResult{Subject: ""},
			verifyTokenErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIdentityProvider := mocks.NewMockProvider(ctrl)
			mockIdentityProvider.EXPECT().VerifyToken(tt.accessToken).Return(tt.verifyResult, tt.verifyTokenErr).AnyTimes()

			authUsecase := NewAuthUsecase(mockIdentityProvider)

			_, err := authUsecase.VerifyToken(tt.accessToken)
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
	tests := []struct {
		name            string
		success         bool
		refreshToken    string
		tokenResult     *identity.TokenResult
		refreshTokenErr error
	}{
		{
			name:            "success refresh token",
			success:         true,
			refreshToken:    "refreshToken",
			tokenResult:     &identity.TokenResult{AccessToken: "accessToken", RefreshToken: "refreshToken"},
			refreshTokenErr: nil,
		},
		{
			name:            "failure refresh token error",
			success:         false,
			refreshToken:    "refreshToken",
			tokenResult:     nil,
			refreshTokenErr: errors.New("refresh token error"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIdentityProvider := mocks.NewMockProvider(ctrl)
			mockIdentityProvider.EXPECT().RefreshToken(tt.refreshToken).Return(tt.tokenResult, tt.refreshTokenErr).AnyTimes()

			authUsecase := NewAuthUsecase(mockIdentityProvider)

			_, err := authUsecase.RefreshToken(tt.refreshToken)
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIdentityProvider := mocks.NewMockProvider(ctrl)
			mockIdentityProvider.EXPECT().RevokeToken(tt.refreshToken).Return(tt.revokeTokenErr).AnyTimes()

			authUsecase := NewAuthUsecase(mockIdentityProvider)

			err := authUsecase.RevokeToken(tt.refreshToken)
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
		returnTo  string
		logoutErr error
	}{
		{
			name:      "success logout",
			success:   true,
			returnTo:  "http://localhost:3000/",
			logoutErr: nil,
		},
		{
			name:      "failure logout error",
			success:   false,
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

			mockIdentityProvider := mocks.NewMockProvider(ctrl)
			mockIdentityProvider.EXPECT().Logout(tt.returnTo).Return("logout url", tt.logoutErr).AnyTimes()

			authUsecase := NewAuthUsecase(mockIdentityProvider)

			_, err := authUsecase.Logout(tt.returnTo)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
		})
	}
}

func TestGetM2MToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		success        bool
		clientID       string
		clientSecret   string
		tokenResult    *identity.TokenResult
		getM2MTokenErr error
	}{
		{
			name:           "success get m2m token",
			success:        true,
			clientID:       "m2mClientID",
			clientSecret:   "m2mClientSecret",
			tokenResult:    &identity.TokenResult{AccessToken: "m2mAccessToken"},
			getM2MTokenErr: nil,
		},
		{
			name:           "failure get m2m token error",
			success:        false,
			clientID:       "m2mClientID",
			clientSecret:   "m2mClientSecret",
			tokenResult:    nil,
			getM2MTokenErr: errors.New("get m2m token error"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIdentityProvider := mocks.NewMockProvider(ctrl)
			mockIdentityProvider.EXPECT().GetM2MToken(tt.clientID, tt.clientSecret).Return(tt.tokenResult, tt.getM2MTokenErr).AnyTimes()

			authUsecase := NewAuthUsecase(mockIdentityProvider)

			_, err := authUsecase.GetM2MToken(tt.clientID, tt.clientSecret)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
		})
	}
}
