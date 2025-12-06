FROM golang:1.25.5-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -v -o /usr/local/bin/app ./cmd/gateway

FROM alpine:latest
WORKDIR /app
COPY --from=builder /usr/local/bin/app .
CMD ["./app"]