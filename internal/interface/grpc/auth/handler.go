package auth

import (
	"context"
	"token/internal/application/token"
	"token/pb"
)

type AuthHandler struct {
	pb.UnimplementedAuthServiceServer
	tokenService token.TokenService
}

func NewAuthHandler(tokenService token.TokenService) *AuthHandler {
	return &AuthHandler{
		tokenService: tokenService,
	}
}

func (h *AuthHandler) GetAccessToken(ctx context.Context, req *pb.GetAccessTokenRequest) (*pb.GetAccessTokenResponse, error) {
	_, err := h.tokenService.CreateTokne()
	if err != nil {
		return nil, err
	}
	return &pb.GetAccessTokenResponse{
		AccessToken: "access token",
	}, nil
}
