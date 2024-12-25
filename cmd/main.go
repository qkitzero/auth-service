package main

import (
	"fmt"
	"log"
	"net"
	"os"

	application_token "token/internal/application/token"
	"token/internal/infrastructure/db"
	infrastructure_token "token/internal/infrastructure/persistence/token"
	interface_auth "token/internal/interface/grpc/auth"
	"token/pb"

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

	tokenRepository := infrastructure_token.NewTokenRepository(db)

	tokenService := application_token.NewTokenService(tokenRepository)

	tokenHandler := interface_auth.NewAuthHandler(*tokenService)

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
