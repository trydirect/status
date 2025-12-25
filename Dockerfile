FROM rust:1.83 AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src src
COPY templates templates
COPY static static
COPY config.json config.json
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/status /usr/local/bin/status
COPY templates templates
COPY static static
COPY config.json config.json
ENV RUST_LOG=info
# Expose API/UI port
EXPOSE 8080
CMD ["/usr/local/bin/status", "serve", "--port", "8080", "--with-ui"]
