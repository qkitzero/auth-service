package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"

	authv1 "github.com/qkitzero/auth-service/gen/go/auth/v1"
	"github.com/qkitzero/auth-service/internal/interface/grpc/gateway"
	"github.com/qkitzero/auth-service/util"
)

const shutdownTimeout = 15 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	srv := &http.Server{
		Addr:    ":" + util.GetEnv("PORT", ""),
		Handler: mux,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Printf("HTTP gateway listening on %s", srv.Addr)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP gateway failed: %v", err)
		}
	case <-ctx.Done():
		log.Println("shutdown signal received, starting HTTP gateway shutdown")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP gateway shutdown error: %v", err)
			return
		}
		log.Println("HTTP gateway stopped gracefully")
	}
}
