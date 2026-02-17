.PHONY: build test lint fmt validate clean install

# Version from git tag (strip leading 'v')
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "dev")
LDFLAGS := -X github.com/emphereio/ovrse/pkg/mcp.Version=$(VERSION)

# Build the ovrse binary with version injection
build:
	go build -v -ldflags "$(LDFLAGS)" -o bin/ovrse ./cmd/ovrse

# Run all tests with race detection and coverage
test:
	go test -v -race -cover ./...

# Run tests with coverage report
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run linter
lint:
	golangci-lint run

# Format code
fmt:
	gofmt -w ./cmd ./pkg

# Validate examples
validate: build
	./bin/ovrse validate --templates examples/templates --kb examples/kb

# Clean build artifacts
clean:
	rm -rf bin/ coverage.out coverage.html

# Install to GOPATH/bin
install:
	go install -ldflags "$(LDFLAGS)" ./cmd/ovrse

# Run MCP server (for development)
mcp: build
	./bin/ovrse mcp

# Quick build and test cycle
check: fmt lint test
