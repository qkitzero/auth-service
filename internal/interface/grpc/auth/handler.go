package auth

import (
	"context"

	"github.com/qkitzero/auth/internal/application/auth"
	"github.com/qkitzero/auth/internal/application/user"
	"github.com/qkitzero/auth/pb"
)

type AuthHandler struct {
	pb.UnimplementedAuthServiceServer
	authService auth.AuthService
	userService user.UserService
}

func NewAuthHandler(
	authService auth.AuthService,
	userService user.UserService,
) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		userService: userService,
	}
}

func (h *AuthHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	token, err := h.authService.ExchangeCodeForToken(req.GetCode())
	if err != nil {
		return nil, err
	}

	sub, err := h.authService.VerifyToken(token.AccessToken())
	if err != nil {
		return nil, err
	}

	user, err := h.userService.GetOrCreateUser(sub)
	if err != nil {
		return nil, err
	}

	return &pb.LoginResponse{
		UserId:       user.ID().String(),
		AccessToken:  token.AccessToken(),
		RefreshToken: token.RefreshToken(),
	}, nil
}

func (h *AuthHandler) VerifyToken(ctx context.Context, req *pb.VerifyTokenRequest) (*pb.VerifyTokenResponse, error) {
	sub, err := h.authService.VerifyToken(req.GetAccessToken())
	if err != nil {
		return nil, err
	}

	user, err := h.userService.GetUser(sub)
	if err != nil {
		return nil, err
	}

	return &pb.VerifyTokenResponse{
		UserId: user.ID().String(),
	}, nil
}

func (h *AuthHandler) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	token, err := h.authService.RefreshToken(req.GetRefreshToken())
	if err != nil {
		return nil, err
	}

	return &pb.RefreshTokenResponse{
		AccessToken:  token.AccessToken(),
		RefreshToken: token.RefreshToken(),
	}, nil
}

func (h *AuthHandler) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	sub, err := h.authService.VerifyToken(req.GetAccessToken())
	if err != nil {
		return nil, err
	}

	user, err := h.userService.GetUser(sub)
	if err != nil {
		return nil, err
	}

	if err := h.authService.RevokeToken(req.GetRefreshToken()); err != nil {
		return nil, err
	}

	return &pb.LogoutResponse{
		UserId: user.ID().String(),
	}, nil
}
