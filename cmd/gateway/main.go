package main

import (
	"context"
	"log"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"

	authv1 "github.com/qkitzero/auth-service/gen/go/auth/v1"
	"github.com/qkitzero/auth-service/internal/interface/grpc/gateway"
	"github.com/qkitzero/auth-service/util"
)

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	endpoint := util.GetEnv("SERVER_HOST", "") + ":" + util.GetEnv("SERVER_PORT", "")

	var opts grpc.DialOption
	switch util.GetEnv("ENV", "development") {
	case "production":
		opts = grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))
	default:
		opts = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	conn, err := grpc.NewClient(endpoint, opts)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)

	mux := runtime.NewServeMux(
		runtime.WithHealthzEndpoint(healthClient),
		runtime.WithForwardResponseOption(gateway.SetRefreshTokenCookie),
		runtime.WithMetadata(gateway.CustomMetadataAnnotator),
	)

	if err := authv1.RegisterAuthServiceHandlerFromEndpoint(ctx, mux, endpoint, []grpc.DialOption{opts}); err != nil {
		log.Fatal(err)
	}

	if err := http.ListenAndServe(":"+util.GetEnv("PORT", ""), mux); err != nil {
		log.Fatal(err)
	}
}
