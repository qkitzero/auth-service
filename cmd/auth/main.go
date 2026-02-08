package main

import (
	"log"
	"net"
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

func main() {
	listener, err := net.Listen("tcp", ":"+util.GetEnv("PORT", ""))
	if err != nil {
		log.Fatal(err)
	}

	server := grpc.NewServer()

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

	authUsecase := appauth.NewAuthUsecase(nil, auth0Client)

	healthServer := health.NewServer()
	tokenHandler := infraauth.NewAuthHandler(authUsecase)

	grpc_health_v1.RegisterHealthServer(server, healthServer)
	authv1.RegisterAuthServiceServer(server, tokenHandler)

	healthServer.SetServingStatus("auth", grpc_health_v1.HealthCheckResponse_SERVING)

	if util.GetEnv("ENV", "development") == "development" {
		reflection.Register(server)
	}

	if err = server.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
