package auth

import (
	"context"
	"fmt"
	"strings"
	"token/internal/application/auth"
	"token/internal/application/token"
	"token/pb"

	"google.golang.org/grpc/metadata"
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

func (h *AuthHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	tokenResponse, err := h.authService.GetTokne(req.GetCode())
	if err != nil {
		return nil, err
	}

	user, err := h.authService.ValidateToken(tokenResponse.AccessToken)
	if err != nil {
		return nil, err
	}

	token, err := h.tokenService.CreateOrUpdateToken(tokenResponse.AccessToken, tokenResponse.RefreshToken, user.ID())
	if err != nil {
		return nil, err
	}

	return &pb.LoginResponse{
		AccessToken: token.AccessToken(),
	}, nil
}

func (h *AuthHandler) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to get metadata")
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return nil, fmt.Errorf("failed to get authorization header")
	}

	accessToken := strings.TrimPrefix(authHeader[0], "Bearer ")
	if accessToken == "" {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	user, err := h.authService.ValidateToken(accessToken)
	if err != nil {
		return nil, err
	}

	return &pb.ValidateTokenResponse{
		UserId: user.ID().String(),
	}, nil
}
