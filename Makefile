MOCKGEN_CMD=go run go.uber.org/mock/mockgen@v0.5.0

mockgen:
	$(MOCKGEN_CMD) -source=internal/domain/user/user.go -destination=mocks/domain/user/mock_user.go -package=mocks
	$(MOCKGEN_CMD) -source=internal/domain/token/token.go -destination=mocks/domain/token/mock_token.go -package=mocks
	$(MOCKGEN_CMD) -source=internal/application/auth/usecase.go -destination=mocks/application/auth/mock_usecase.go -package=mocks
	$(MOCKGEN_CMD) -source=internal/infrastructure/api/keycloak_client.go -destination=mocks/infrastructure/api/mock_keycloak_client.go -package=mocks

test:
	mkdir -p tmp
	go test -cover ./internal/... -coverprofile=./tmp/cover.out
	go tool cover -func=./tmp/cover.out | tail -n 1
	go tool cover -html=./tmp/cover.out -o ./tmp/cover.html
	open ./tmp/cover.html