# Build stage
FROM rust:1.84-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock* ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (this layer will be cached)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src

# Build the actual application
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM alpine:3.21

# Install runtime dependencies (CA certificates for HTTPS)
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -S ldap && adduser -S ldap -G ldap

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/ldap-auth-proxy /app/ldap-auth-proxy

# Copy default config
COPY config.toml /app/config.toml

# Change ownership
RUN chown -R ldap:ldap /app

USER ldap

# Expose LDAP port
EXPOSE 3890

# Run the binary
CMD ["/app/ldap-auth-proxy"]
