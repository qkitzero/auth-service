package util

import (
	"log"
	"os"
)

func GetEnv(key string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		log.Fatalf("missing required environment variable: %s", key)
	}
	return value
}
