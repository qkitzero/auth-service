package main

import (
	"fmt"
	"log"
	"net"
	"os"

	application_auth "github.com/qkitzero/auth/internal/application/auth"
	"github.com/qkitzero/auth/internal/infrastructure/api"
	interface_auth "github.com/qkitzero/auth/internal/interface/grpc/auth"
	auth_pb "github.com/qkitzero/auth/pb"
	"google.golang.org/grpc"
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

	authService := application_auth.NewAuthService(keycloakClient)

	tokenHandler := interface_auth.NewAuthHandler(authService)

	auth_pb.RegisterAuthServiceServer(server, tokenHandler)

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
