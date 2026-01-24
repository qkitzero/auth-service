package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	authv1 "github.com/qkitzero/auth-service/gen/go/auth/v1"
	appauth "github.com/qkitzero/auth-service/internal/application/auth"
	"github.com/qkitzero/auth-service/internal/infrastructure/api/auth0"
	grpcauth "github.com/qkitzero/auth-service/internal/interface/grpc/auth"
	"github.com/qkitzero/auth-service/util"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// keycloakClient := keycloak.NewClient(
	// 	util.GetEnv("KEYCLOAK_SERVER_BASE_URL", ""),
	// 	util.GetEnv("KEYCLOAK_CLIENT_ID", ""),
	// 	util.GetEnv("KEYCLOAK_CLIENT_SECRET", ""),
	// 	util.GetEnv("KEYCLOAK_REALM", ""),
	// 	10*time.Second,
	// )

	auth0Client := auth0.NewClient(
		util.GetEnv("AUTH0_BASE_URL", ""),
		util.GetEnv("AUTH0_CLIENT_ID", ""),
		util.GetEnv("AUTH0_CLIENT_SECRET", ""),
		util.GetEnv("AUTH0_AUDIENCE", ""),
		10*time.Second,
	)

	authHandler := newDependencies(auth0Client)

	grpcPort := util.GetEnv("GRPC_PORT", "50051")
	grpcServer := newGRPCServer(authHandler)

	go startGRPCServer(grpcServer, grpcPort)

	httpPort := util.GetEnv("HTTP_PORT", "8080")
	startHTTPServer(ctx, grpcPort, httpPort)
}

func newDependencies(auth0Client auth0.Client) *grpcauth.AuthHandler {
	authUsecase := appauth.NewAuthUsecase(nil, auth0Client)

	authHandler := grpcauth.NewAuthHandler(authUsecase)

	return authHandler
}

func newGRPCServer(authHandler *grpcauth.AuthHandler) *grpc.Server {
	healthServer := health.NewServer()
	healthServer.SetServingStatus("auth", grpc_health_v1.HealthCheckResponse_SERVING)

	server := grpc.NewServer()

	grpc_health_v1.RegisterHealthServer(server, healthServer)
	authv1.RegisterAuthServiceServer(server, authHandler)

	if util.GetEnv("ENV", "development") == "development" {
		reflection.Register(server)
	}

	return server
}

func startGRPCServer(server *grpc.Server, port string) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("starting gRPC server on port %s", port)

	if err := server.Serve(listener); err != nil {
		log.Fatal(err)
	}
}

func startHTTPServer(ctx context.Context, grpcPort, httpPort string) {
	grpcEndpoint := "localhost:" + grpcPort

	authConn, err := grpc.NewClient(grpcEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer authConn.Close()

	mux := runtime.NewServeMux(
		runtime.WithHealthzEndpoint(grpc_health_v1.NewHealthClient(authConn)),
	)

	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if err := authv1.RegisterAuthServiceHandlerFromEndpoint(ctx, mux, grpcEndpoint, opts); err != nil {
		log.Fatal(err)
	}

	log.Printf("starting http server on port %s", httpPort)

	if err := http.ListenAndServe(":"+httpPort, mux); err != nil {
		log.Fatal(err)
	}
}
