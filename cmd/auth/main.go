package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
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
)

const (
	shutdownTimeout    = 15 * time.Second
	auth0ClientTimeout = 10 * time.Second
)

type config struct {
	Env               string
	Port              string
	Auth0BaseURL      string
	Auth0ClientID     string
	Auth0ClientSecret string
	Auth0Audience     string
}

func loadConfig() (config, error) {
	env := os.Getenv("ENV")
	if env == "" {
		env = "development"
	}
	cfg := config{Env: env}
	required := []struct {
		key string
		dst *string
	}{
		{"PORT", &cfg.Port},
		{"AUTH0_BASE_URL", &cfg.Auth0BaseURL},
		{"AUTH0_CLIENT_ID", &cfg.Auth0ClientID},
		{"AUTH0_CLIENT_SECRET", &cfg.Auth0ClientSecret},
		{"AUTH0_AUDIENCE", &cfg.Auth0Audience},
	}
	var missing []string
	for _, r := range required {
		v := os.Getenv(r.key)
		if v == "" {
			missing = append(missing, r.key)
			continue
		}
		*r.dst = v
	}
	if len(missing) > 0 {
		return cfg, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("auth-service: %v", err)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	auth0Client := auth0.NewClient(
		cfg.Auth0BaseURL,
		cfg.Auth0ClientID,
		cfg.Auth0ClientSecret,
		cfg.Auth0Audience,
		auth0ClientTimeout,
	)

	authUsecase := appauth.NewAuthUsecase(auth0Client)

	server := grpc.NewServer()

	healthServer := health.NewServer()
	tokenHandler := infraauth.NewAuthHandler(authUsecase)

	grpc_health_v1.RegisterHealthServer(server, healthServer)
	authv1.RegisterAuthServiceServer(server, tokenHandler)

	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("auth", grpc_health_v1.HealthCheckResponse_SERVING)

	if cfg.Env == "development" {
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
			return fmt.Errorf("grpc serve: %w", err)
		}
		return nil
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
		return nil
	}
}
