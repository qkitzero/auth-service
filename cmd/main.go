package main

import (
	"fmt"
	"log"
	"net"
	"os"

	application_auth "github.com/qkitzero/auth/internal/application/auth"
	application_user "github.com/qkitzero/auth/internal/application/user"
	"github.com/qkitzero/auth/internal/infrastructure/api"
	"github.com/qkitzero/auth/internal/infrastructure/db"
	infrastructure_user "github.com/qkitzero/auth/internal/infrastructure/persistence/user"
	interface_auth "github.com/qkitzero/auth/internal/interface/grpc/auth"
	"github.com/qkitzero/auth/pb"
	"google.golang.org/grpc"
)

func main() {
	db, err := db.Init(
		getEnv("DB_USER"),
		getEnv("DB_PASSWORD"),
		getEnv("DB_HOST"),
		getEnv("DB_PORT"),
		getEnv("DB_NAME"),
	)
	if err != nil {
		log.Fatal(err)
	}

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
	userRepository := infrastructure_user.NewUserRepository(db)

	authService := application_auth.NewTokenService(keycloakClient)
	userService := application_user.NewUserService(userRepository)

	tokenHandler := interface_auth.NewAuthHandler(authService, userService)

	pb.RegisterAuthServiceServer(server, tokenHandler)

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
