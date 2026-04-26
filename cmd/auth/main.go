package main

import (
	"context"
	"log"
	"net"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	authv1 "github.com/qkitzero/auth-service/gen/go/auth/v1"
	appauth "github.com/qkitzero/auth-service/internal/application/auth"
	"github.com/qkitzero/auth-service/internal/infrastructure/api/auth0"
	infraauth "github.com/qkitzero/auth-service/internal/interface/grpc/auth"
	"github.com/qkitzero/auth-service/util"
)

const shutdownTimeout = 15 * time.Second

func main() {
	listener, err := net.Listen("tcp", ":"+util.GetEnv("PORT", ""))
	if err != nil {
		log.Fatal(err)
	}

	server := grpc.NewServer()

	auth0Client := auth0.NewClient(
		util.GetEnv("AUTH0_BASE_URL", ""),
		util.GetEnv("AUTH0_CLIENT_ID", ""),
		util.GetEnv("AUTH0_CLIENT_SECRET", ""),
		util.GetEnv("AUTH0_AUDIENCE", ""),
		10*time.Second,
	)

	authUsecase := appauth.NewAuthUsecase(auth0Client)

	healthServer := health.NewServer()
	tokenHandler := infraauth.NewAuthHandler(authUsecase)

	grpc_health_v1.RegisterHealthServer(server, healthServer)
	authv1.RegisterAuthServiceServer(server, tokenHandler)

	healthServer.SetServingStatus("auth", grpc_health_v1.HealthCheckResponse_SERVING)

	if util.GetEnv("ENV", "development") == "development" {
		reflection.Register(server)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		log.Printf("gRPC server listening on %s", listener.Addr().String())
		serveErr <- server.Serve(listener)
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			log.Fatalf("gRPC server failed: %v", err)
		}
	case <-ctx.Done():
		log.Println("shutdown signal received, starting graceful stop")
		healthServer.Shutdown()

		stopped := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
			log.Println("gRPC server stopped gracefully")
		case <-time.After(shutdownTimeout):
			log.Printf("graceful stop timed out after %s, forcing stop", shutdownTimeout)
			server.Stop()
			<-stopped
		}
	}
}
