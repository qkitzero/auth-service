package token

import (
	"context"
	"token/internal/application/token"
	"token/pb"
)

type TokenHandler struct {
	pb.UnimplementedTokenServiceServer
	tokenService token.TokenService
}

func NewTokenHandler(tokenService token.TokenService) *TokenHandler {
	return &TokenHandler{
		tokenService: tokenService,
	}
}

func (h *TokenHandler) GetAccessToken(ctx context.Context, req *pb.GetAccessTokenRequest) (*pb.GetAccessTokenResponse, error) {
	_, err := h.tokenService.CreateTokne()
	if err != nil {
		return nil, err
	}
	return &pb.GetAccessTokenResponse{
		AccessToken: "access token",
	}, nil
}
