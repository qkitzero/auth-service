test:
	mkdir -p tmp
	go test -cover ./internal/domain/... -coverprofile=./tmp/cover.out
	go tool cover -html=./tmp/cover.out -o ./tmp/cover.html
	open ./tmp/cover.html