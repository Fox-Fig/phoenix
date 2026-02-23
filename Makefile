
.PHONY: all fmt test build clean speedtest integration_test

all: fmt test build

fmt:
	go fmt ./...

test:
	go test ./...

build:
	mkdir -p bin
	go build -o bin/server cmd/server/main.go
	go build -o bin/client cmd/client/main.go
	go build -o bin/speedtest cmd/speedtest/main.go

speedtest: build
	./bin/speedtest

integration_test: build
	go run cmd/integration_test/main.go

clean:
	rm -rf bin
