
.PHONY: all fmt test build clean speedtest android-client

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

android-client:
	mkdir -p android/app/src/main/assets
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o android/app/src/main/assets/phoenix-client ./cmd/android-client/

clean:
	rm -rf bin
