package auth

import (
	"context"

	authv1 "github.com/qkitzero/auth/gen/go/proto/auth/v1"
	"github.com/qkitzero/auth/internal/application/auth"
)

type AuthHandler struct {
	authv1.UnimplementedAuthServiceServer
	authUsecase auth.AuthUsecase
}

func NewAuthHandler(authUsecase auth.AuthUsecase) *AuthHandler {
	return &AuthHandler{authUsecase: authUsecase}
}

func (h *AuthHandler) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	token, err := h.authUsecase.ExchangeCodeForToken(req.GetCode())
	if err != nil {
		return nil, err
	}

	user, err := h.authUsecase.VerifyToken(token.AccessToken())
	if err != nil {
		return nil, err
	}

	return &authv1.LoginResponse{
		UserId:       user.ID().String(),
		AccessToken:  token.AccessToken(),
		RefreshToken: token.RefreshToken(),
	}, nil
}

func (h *AuthHandler) VerifyToken(ctx context.Context, req *authv1.VerifyTokenRequest) (*authv1.VerifyTokenResponse, error) {
	user, err := h.authUsecase.VerifyToken(req.GetAccessToken())
	if err != nil {
		return nil, err
	}

	return &authv1.VerifyTokenResponse{
		UserId: user.ID().String(),
	}, nil
}

func (h *AuthHandler) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	token, err := h.authUsecase.RefreshToken(req.GetRefreshToken())
	if err != nil {
		return nil, err
	}

	return &authv1.RefreshTokenResponse{
		AccessToken:  token.AccessToken(),
		RefreshToken: token.RefreshToken(),
	}, nil
}

func (h *AuthHandler) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	user, err := h.authUsecase.VerifyToken(req.GetAccessToken())
	if err != nil {
		return nil, err
	}

	if err := h.authUsecase.RevokeToken(req.GetRefreshToken()); err != nil {
		return nil, err
	}

	return &authv1.LogoutResponse{
		UserId: user.ID().String(),
	}, nil
}
