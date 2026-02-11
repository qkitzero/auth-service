proto-format:
	buf format -w

proto-lint:
	buf lint

proto-gen:
	buf generate

MOCK_GEN=go run go.uber.org/mock/mockgen@v0.6.0

mock-gen:
	$(MOCK_GEN) -source=internal/domain/user/user.go -destination=mocks/domain/user/mock_user.go -package=mocks
	$(MOCK_GEN) -source=internal/domain/token/token.go -destination=mocks/domain/token/mock_token.go -package=mocks
	$(MOCK_GEN) -source=internal/domain/token/m2m_token.go -destination=mocks/domain/token/mock_m2m_token.go -package=mocks
	$(MOCK_GEN) -source=internal/application/auth/usecase.go -destination=mocks/application/auth/mock_usecase.go -package=mocks
	$(MOCK_GEN) -source=internal/infrastructure/api/keycloak/client.go -destination=mocks/infrastructure/api/keycloak/mock_client.go -package=mocks
	$(MOCK_GEN) -source=internal/infrastructure/api/auth0/client.go -destination=mocks/infrastructure/api/auth0/mock_client.go -package=mocks

test:
	mkdir -p tmp
	go test -cover ./internal/... -coverprofile=./tmp/cover.out
	go tool cover -func=./tmp/cover.out | tail -n 1
	go tool cover -html=./tmp/cover.out -o ./tmp/cover.html
	open ./tmp/cover.html