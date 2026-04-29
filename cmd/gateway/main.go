package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"

	authv1 "github.com/qkitzero/auth-service/gen/go/auth/v1"
	"github.com/qkitzero/auth-service/internal/interface/grpc/gateway"
)

const (
	shutdownTimeout   = 15 * time.Second
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 120 * time.Second
)

type config struct {
	Env        string
	Port       string
	ServerHost string
	ServerPort string
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
		{"SERVER_HOST", &cfg.ServerHost},
		{"SERVER_PORT", &cfg.ServerPort},
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
		log.Fatalf("gateway: %v", err)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	endpoint := cfg.ServerHost + ":" + cfg.ServerPort

	var dialOpt grpc.DialOption
	switch cfg.Env {
	case "production":
		dialOpt = grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))
	default:
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	conn, err := grpc.NewClient(endpoint, dialOpt)
	if err != nil {
		return fmt.Errorf("grpc client: %w", err)
	}
	defer func() { _ = conn.Close() }()

	healthClient := grpc_health_v1.NewHealthClient(conn)

	mux := runtime.NewServeMux(
		runtime.WithHealthzEndpoint(healthClient),
		runtime.WithForwardResponseOption(gateway.SetRefreshTokenCookie),
		runtime.WithMetadata(gateway.CustomMetadataAnnotator),
	)

	if err := authv1.RegisterAuthServiceHandler(ctx, mux, conn); err != nil {
		return fmt.Errorf("register auth handler: %w", err)
	}

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Printf("HTTP gateway listening on %s", srv.Addr)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		log.Println("shutdown signal received, starting HTTP gateway shutdown")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("http shutdown: %w", err)
		}
		log.Println("HTTP gateway stopped gracefully")
		return nil
	}
}
