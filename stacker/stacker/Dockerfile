# syntax=docker/dockerfile:1.4
FROM rust:bookworm AS builder

RUN apt-get update && apt-get install --no-install-recommends -y protobuf-compiler libprotobuf-dev && rm -rf /var/lib/apt/lists/*

RUN cargo install sqlx-cli

WORKDIR /app
COPY --from=shared_fixtures / /shared-fixtures
# copy manifests
COPY ./Cargo.toml .
COPY ./Cargo.lock .
COPY ./build.rs .
COPY ./rustfmt.toml .
COPY ./Makefile .
COPY ./docker/local/.env .
COPY ./docker/local/configuration.yaml .
COPY .sqlx .sqlx/
COPY ./proto ./proto
COPY ./tests/bdd.rs ./tests/bdd.rs

# build this project to cache dependencies
#RUN sqlx database create && sqlx migrate run

# build skeleton and remove src after
#RUN cargo build --release; \
#    rm src/*.rs


COPY ./src ./src
COPY ./crates ./crates

# for ls output use BUILDKIT_PROGRESS=plain docker build .
#RUN ls -la /app/ >&2
#RUN sqlx migrate run
#RUN cargo sqlx prepare -- --bin stacker
ENV SQLX_OFFLINE=true

RUN apt-get update && apt-get install --no-install-recommends -y libssl-dev; \
    cargo build --release --bin server; \
    cargo build --release --bin console --features explain

#RUN ls -la /app/target/release/ >&2

# deploy production
FROM debian:bookworm-slim AS production

RUN apt-get update && apt-get install --no-install-recommends -y libssl-dev ca-certificates;
# create app directory
WORKDIR /app
RUN mkdir ./files && chmod 0777 ./files

# copy binary and configuration files
COPY --from=builder /app/target/release/server .
COPY --from=builder /app/target/release/console .
COPY --from=builder /app/.env .
COPY --from=builder /app/configuration.yaml .
COPY --from=builder /usr/local/cargo/bin/sqlx /usr/local/bin/sqlx
COPY ./access_control.conf.dist ./access_control.conf

EXPOSE 8000

# run the binary
ENTRYPOINT ["/app/server"]
