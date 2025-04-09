FROM golang:1.24
WORKDIR /work
RUN apt-get update && apt-get install -y wget unzip && \
    wget https://github.com/protocolbuffers/protobuf/releases/download/v27.1/protoc-27.1-linux-x86_64.zip && \
    unzip protoc-27.1-linux-x86_64.zip -d /usr/local && \
    rm protoc-27.1-linux-x86_64.zip
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1