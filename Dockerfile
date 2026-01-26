FROM clux/muslrust:stable AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src src
COPY templates templates
COPY static static
COPY config.json config.json

# Build a statically linked binary to avoid runtime glibc mismatches.
RUN rustup target add x86_64-unknown-linux-musl && \
	cargo build --release --target x86_64-unknown-linux-musl

FROM gcr.io/distroless/cc
WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/status /usr/local/bin/status
COPY templates templates
COPY static static
COPY config.json config.json

ENV RUST_LOG=info
# Polling configuration (used in daemon mode)
ENV POLL_TIMEOUT_SECS=30
ENV POLL_BACKOFF_SECS=5
ENV POLL_MAX_BACKOFF_SECS=60
ENV DASHBOARD_URL=""
ENV DEPLOYMENT_HASH=""

# Expose API/UI port
EXPOSE 5000

# MODE options:
#   "serve-ui"  - API server with web UI (default)
#   "serve"     - API server without UI  
#   "daemon"    - Background polling agent
#   "both"      - API server + polling loop
ENV MODE="serve-ui"

# Use shell form to allow ENV variable expansion
# Note: distroless/cc doesn't have shell, so we use a wrapper script approach
# For simple cases, override CMD at runtime:
#   docker run ... status serve --port 5000 --with-ui
#   docker run ... status (daemon mode with polling)
# CMD ["/usr/local/bin/status", "serve", "--port", "5000", "--with-ui"]

ENTRYPOINT ["/usr/local/bin/status"]
CMD ["serve", "--port", "5000", "--with-ui"]