package auth

import (
	"context"
	"token/internal/application/auth"
	"token/internal/application/token"
	"token/pb"
)

type AuthHandler struct {
	pb.UnimplementedAuthServiceServer
	authService  auth.AuthService
	tokenService token.TokenService
}

func NewAuthHandler(authService auth.AuthService, tokenService token.TokenService) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		tokenService: tokenService,
	}
}

func (h *AuthHandler) GetAccessToken(ctx context.Context, req *pb.GetAccessTokenRequest) (*pb.GetAccessTokenResponse, error) {
	tokenResponse, err := h.authService.Tokne(req.GetCode())
	if err != nil {
		return nil, err
	}

	_, err = h.tokenService.CreateTokne()
	if err != nil {
		return nil, err
	}

	return &pb.GetAccessTokenResponse{
		AccessToken: tokenResponse.AccessToken,
	}, nil
}
