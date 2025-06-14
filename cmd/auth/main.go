package main

import (
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	authv1 "github.com/qkitzero/auth/gen/go/auth/v1"
	application_auth "github.com/qkitzero/auth/internal/application/auth"
	"github.com/qkitzero/auth/internal/infrastructure/api/auth0"
	"github.com/qkitzero/auth/internal/infrastructure/api/keycloak"
	interface_auth "github.com/qkitzero/auth/internal/interface/grpc/auth"
	"github.com/qkitzero/auth/util"
)

func main() {
	listener, err := net.Listen("tcp", ":"+util.GetEnv("PORT", ""))
	if err != nil {
		log.Fatal(err)
	}

	server := grpc.NewServer()

	keycloakClient := keycloak.NewClient(
		util.GetEnv("KEYCLOAK_SERVER_BASE_URL", ""),
		util.GetEnv("KEYCLOAK_CLIENT_ID", ""),
		util.GetEnv("KEYCLOAK_CLIENT_SECRET", ""),
		util.GetEnv("KEYCLOAK_REALM", ""),
	)

	auth0Client := auth0.NewClient(
		util.GetEnv("AUTH0_DOMAIN", ""),
		util.GetEnv("AUTH0_CLIENT_ID", ""),
		util.GetEnv("AUTH0_CLIENT_SECRET", ""),
		util.GetEnv("AUTH0_AUDIENCE", ""),
	)

	authUsecase := application_auth.NewAuthUsecase(keycloakClient, auth0Client)

	healthServer := health.NewServer()
	tokenHandler := interface_auth.NewAuthHandler(authUsecase)

	grpc_health_v1.RegisterHealthServer(server, healthServer)
	authv1.RegisterAuthServiceServer(server, tokenHandler)

	healthServer.SetServingStatus("auth", grpc_health_v1.HealthCheckResponse_SERVING)

	reflection.Register(server) // dev

	if err = server.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
