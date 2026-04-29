.PHONY: test lint lint-fix \
	proto-format proto-lint proto-gen \
	mock-gen

test:
	mkdir -p tmp
	go test -cover ./internal/... -coverprofile=./tmp/cover.out
	go tool cover -func=./tmp/cover.out | tail -n 1
	go tool cover -html=./tmp/cover.out -o ./tmp/cover.html
	open ./tmp/cover.html

lint:
	go tool golangci-lint run ./...

lint-fix:
	go tool golangci-lint run --fix ./...

proto-format:
	buf format -w

proto-lint:
	buf lint

proto-gen:
	buf generate

mock-gen:
	go tool mockgen -source=internal/domain/user/user.go -destination=mocks/domain/user/mock_user.go -package=mocks
	go tool mockgen -source=internal/domain/token/token.go -destination=mocks/domain/token/mock_token.go -package=mocks
	go tool mockgen -source=internal/domain/token/m2m_token.go -destination=mocks/domain/token/mock_m2m_token.go -package=mocks
	go tool mockgen -source=internal/application/auth/usecase.go -destination=mocks/application/auth/mock_usecase.go -package=mocks
	go tool mockgen -source=internal/application/identity/provider.go -destination=mocks/application/identity/mock_provider.go -package=mocks
