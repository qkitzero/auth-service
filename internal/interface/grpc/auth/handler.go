package auth

import (
	"context"
	"log"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/qkitzero/auth-service/gen/go/auth/v1"
	"github.com/qkitzero/auth-service/internal/application/auth"
)

type AuthHandler struct {
	authv1.UnimplementedAuthServiceServer
	authUsecase auth.AuthUsecase
}

func NewAuthHandler(authUsecase auth.AuthUsecase) *AuthHandler {
	return &AuthHandler{authUsecase: authUsecase}
}

func (h *AuthHandler) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	url, err := h.authUsecase.Login(ctx, req.GetRedirectUri())
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		log.Printf("Login: internal error: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &authv1.LoginResponse{
		LoginUrl: url,
	}, nil
}

func (h *AuthHandler) ExchangeCode(ctx context.Context, req *authv1.ExchangeCodeRequest) (*authv1.ExchangeCodeResponse, error) {
	token, err := h.authUsecase.ExchangeCode(ctx, req.GetCode(), req.GetRedirectUri())
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		log.Printf("ExchangeCode: internal error: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	user, err := h.authUsecase.VerifyToken(ctx, token.AccessToken())
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		log.Printf("ExchangeCode: internal error: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	if err := grpc.SendHeader(ctx, metadata.Pairs("refresh-token", token.RefreshToken())); err != nil {
		log.Printf("failed to send refresh-token header: %v", err)
	}

	return &authv1.ExchangeCodeResponse{
		UserId:      user.ID().String(),
		AccessToken: token.AccessToken(),
	}, nil
}

func (h *AuthHandler) VerifyToken(ctx context.Context, req *authv1.VerifyTokenRequest) (*authv1.VerifyTokenResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is missing")
	}

	authorizations := md.Get("authorization")
	if len(authorizations) == 0 {
		return nil, status.Error(codes.Unauthenticated, "authorization is missing")
	}

	token := authorizations[0]
	if !strings.HasPrefix(token, "Bearer ") {
		return nil, status.Error(codes.Unauthenticated, "authorization header must start with 'Bearer '")
	}

	accessToken := strings.TrimPrefix(token, "Bearer ")

	user, err := h.authUsecase.VerifyToken(ctx, accessToken)
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		log.Printf("VerifyToken: internal error: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &authv1.VerifyTokenResponse{
		UserId: user.ID().String(),
	}, nil
}

func (h *AuthHandler) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is missing")
	}

	refreshTokens := md.Get("refresh-token")
	if len(refreshTokens) == 0 {
		return nil, status.Error(codes.Unauthenticated, "refresh token is missing")
	}

	refreshToken := refreshTokens[0]

	token, err := h.authUsecase.RefreshToken(ctx, refreshToken)
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		log.Printf("RefreshToken: internal error: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	if err := grpc.SendHeader(ctx, metadata.Pairs("refresh-token", token.RefreshToken())); err != nil {
		log.Printf("failed to send refresh-token header: %v", err)
	}

	return &authv1.RefreshTokenResponse{
		AccessToken: token.AccessToken(),
	}, nil
}

func (h *AuthHandler) RevokeToken(ctx context.Context, req *authv1.RevokeTokenRequest) (*authv1.RevokeTokenResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is missing")
	}

	refreshTokens := md.Get("refresh-token")
	if len(refreshTokens) == 0 {
		return nil, status.Error(codes.Unauthenticated, "refresh token is missing")
	}

	refreshToken := refreshTokens[0]

	if err := h.authUsecase.RevokeToken(ctx, refreshToken); err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		log.Printf("RevokeToken: internal error: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &authv1.RevokeTokenResponse{}, nil
}

func (h *AuthHandler) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	url, err := h.authUsecase.Logout(ctx, req.GetReturnTo())
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		log.Printf("Logout: internal error: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &authv1.LogoutResponse{
		LogoutUrl: url,
	}, nil
}

func (h *AuthHandler) GetM2MToken(ctx context.Context, req *authv1.GetM2MTokenRequest) (*authv1.GetM2MTokenResponse, error) {
	m2mToken, err := h.authUsecase.GetM2MToken(ctx, req.GetClientId(), req.GetClientSecret())
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		log.Printf("GetM2MToken: internal error: %v", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &authv1.GetM2MTokenResponse{
		AccessToken: m2mToken.AccessToken(),
	}, nil
}
