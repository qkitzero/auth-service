package gateway

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestCustomMetadataAnnotator(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		success    bool
		req        *http.Request
		expectedMD metadata.MD
	}{
		{
			name:    "success with refresh token cookie",
			success: true,
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.AddCookie(&http.Cookie{
					Name:  "refresh_token",
					Value: "refreshToken",
				})
				return req
			}(),
			expectedMD: metadata.MD{
				"refresh-token": []string{"refreshToken"},
			},
		},
		{
			name:    "success without refresh token cookie",
			success: true,
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				return req
			}(),
			expectedMD: metadata.MD{},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			md := CustomMetadataAnnotator(context.Background(), tt.req)
			if !reflect.DeepEqual(md, tt.expectedMD) {
				t.Errorf("expected %v, but got %v", tt.expectedMD, md)
			}
		})
	}
}
