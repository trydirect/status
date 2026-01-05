FROM clux/muslrust:1.83.0 AS builder

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
# Expose API/UI port
EXPOSE 5000
CMD ["/usr/local/bin/status", "serve", "--port", "5000", "--with-ui"]
