.PHONY: all fmt test build clean speedtest integration_test gen-examples

all: fmt test build

fmt:
	go fmt ./...

test: build
	@echo "Running modular test suite..."
	go test -v ./pkg/testutils/... ./pkg/transport/... | ./bin/test-parser

gen-examples: build
	@echo "Generating Auto-Documented Example Configurations..."
	go run cmd/gen-config/main.go

build:
	mkdir -p bin
	go build -o bin/server cmd/server/main.go
	go build -o bin/client cmd/client/main.go
	go build -o bin/gen-config cmd/gen-config/main.go
	go build -o bin/speedtest-parser cmd/speedtest-parser/main.go
	go build -o bin/test-parser cmd/test-parser/main.go

speedtest: build
	@echo "Running Modular Benchmark Suite..."
	go test -v -bench . ./pkg/transport/h2/... | ./bin/speedtest-parser

integration_test: build
	go run cmd/integration_test/main.go

clean:
	rm -rf bin
