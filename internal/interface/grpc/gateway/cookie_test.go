package gateway

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestSetRefreshTokenCookie(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		success bool
		ctx     context.Context
	}{
		{
			name:    "success set refresh token in cookie",
			success: true,
			ctx: runtime.NewServerMetadataContext(
				context.Background(),
				runtime.ServerMetadata{
					HeaderMD: metadata.Pairs("refresh-token", "refreshToken"),
				},
			),
		},
		{
			name:    "success no metadata in context",
			success: true,
			ctx:     context.Background(),
		},
		{
			name:    "success no refresh token in metadata",
			success: true,
			ctx: runtime.NewServerMetadataContext(
				context.Background(),
				runtime.ServerMetadata{
					HeaderMD: metadata.Pairs(),
				},
			),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			resp := &emptypb.Empty{}

			err := SetRefreshTokenCookie(tt.ctx, w, resp)
			if tt.success && err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
			if !tt.success && err == nil {
				t.Errorf("expected error, but got nil")
			}
		})
	}
}
