package main

import (
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	authv1 "github.com/qkitzero/auth/gen/go/auth/v1"
	application_auth "github.com/qkitzero/auth/internal/application/auth"
	"github.com/qkitzero/auth/internal/infrastructure/api"
	interface_auth "github.com/qkitzero/auth/internal/interface/grpc/auth"
	"github.com/qkitzero/auth/util"
)

func main() {
	listener, err := net.Listen("tcp", ":"+util.GetEnv("PORT", ""))
	if err != nil {
		log.Fatal(err)
	}

	server := grpc.NewServer()

	keycloakClient := api.NewKeycloakClient(
		util.GetEnv("KEYCLOAK_SERVER_BASE_URL", ""),
		util.GetEnv("KEYCLOAK_CLIENT_ID", ""),
		util.GetEnv("KEYCLOAK_CLIENT_SECRET", ""),
		util.GetEnv("KEYCLOAK_CLIENT_REDIRECT_URI", ""),
		util.GetEnv("KEYCLOAK_REALM", ""),
	)

	authUsecase := application_auth.NewAuthUsecase(keycloakClient)

	healthServer := health.NewServer()
	tokenHandler := interface_auth.NewAuthHandler(authUsecase)

	grpc_health_v1.RegisterHealthServer(server, healthServer)
	authv1.RegisterAuthServiceServer(server, tokenHandler)

	healthServer.SetServingStatus("auth", grpc_health_v1.HealthCheckResponse_SERVING)

	if err = server.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
