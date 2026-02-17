# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies for CGO (required by sqlite3)
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with CGO enabled for sqlite3 support
RUN CGO_ENABLED=1 go build -o ovrse ./cmd/ovrse

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates sqlite-libs

# Copy binary from builder
COPY --from=builder /app/ovrse /usr/local/bin/

# Create non-root user
RUN adduser -D -u 1000 ovrse
USER ovrse

# Set working directory
WORKDIR /workspace

ENTRYPOINT ["ovrse"]
CMD ["--help"]
