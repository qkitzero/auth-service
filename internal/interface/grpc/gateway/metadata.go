package gateway

import (
	"context"
	"net/http"

	"google.golang.org/grpc/metadata"
)

func CustomMetadataAnnotator(ctx context.Context, req *http.Request) metadata.MD {
	md := metadata.MD{}

	cookie, err := req.Cookie("refresh_token")
	if err == nil {
		md.Append("refresh-token", cookie.Value)
	}

	return md
}
