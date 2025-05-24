package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	authv1 "github.com/qkitzero/auth/gen/go/auth/v1"
	application_auth "github.com/qkitzero/auth/internal/application/auth"
	"github.com/qkitzero/auth/internal/infrastructure/api"
	interface_auth "github.com/qkitzero/auth/internal/interface/grpc/auth"
)

func main() {
	listener, err := net.Listen("tcp", ":"+getEnv("PORT"))
	if err != nil {
		log.Fatal(err)
	}

	server := grpc.NewServer()

	keycloakClient := api.NewKeycloakClient(
		getEnv("KEYCLOAK_SERVER_BASE_URL"),
		getEnv("KEYCLOAK_CLIENT_ID"),
		getEnv("KEYCLOAK_CLIENT_SECRET"),
		getEnv("KEYCLOAK_CLIENT_REDIRECT_URI"),
		getEnv("KEYCLOAK_REALM"),
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

func getEnv(key string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		log.Fatal(fmt.Sprintf("missing required environment variable: %s", key))
	}
	return value
}
