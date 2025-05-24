package auth

import (
	"context"
	"errors"
	"strings"

	authv1 "github.com/qkitzero/auth/gen/go/auth/v1"
	"github.com/qkitzero/auth/internal/application/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
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

	grpc.SendHeader(ctx, metadata.Pairs("refresh-token", token.RefreshToken()))

	return &authv1.LoginResponse{
		UserId:      user.ID().String(),
		AccessToken: token.AccessToken(),
	}, nil
}

func (h *AuthHandler) VerifyToken(ctx context.Context, req *authv1.VerifyTokenRequest) (*authv1.VerifyTokenResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("metadata is missing")
	}

	authorizations := md.Get("authorization")
	if len(authorizations) == 0 {
		return nil, errors.New("authorization is missing")
	}

	token := authorizations[0]
	if !strings.HasPrefix(token, "Bearer ") {
		return nil, errors.New("authorization header must start with 'Bearer '")
	}

	accessToken := strings.TrimPrefix(token, "Bearer ")

	user, err := h.authUsecase.VerifyToken(accessToken)
	if err != nil {
		return nil, err
	}

	return &authv1.VerifyTokenResponse{
		UserId: user.ID().String(),
	}, nil
}

func (h *AuthHandler) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("metadata is missing")
	}

	refreshTokens := md.Get("refresh-token")
	if len(refreshTokens) == 0 {
		return nil, errors.New("refresh token is missing")
	}

	refreshToken := refreshTokens[0]

	token, err := h.authUsecase.RefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	grpc.SendHeader(ctx, metadata.Pairs("refresh-token", token.RefreshToken()))

	return &authv1.RefreshTokenResponse{
		AccessToken: token.AccessToken(),
	}, nil
}

func (h *AuthHandler) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("metadata is missing")
	}

	refreshTokens := md.Get("refresh-token")
	if len(refreshTokens) == 0 {
		return nil, errors.New("refresh token is missing")
	}

	refreshToken := refreshTokens[0]

	if err := h.authUsecase.RevokeToken(refreshToken); err != nil {
		return nil, err
	}

	return &authv1.LogoutResponse{}, nil
}
