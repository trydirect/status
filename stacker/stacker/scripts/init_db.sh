#!/usr/bin/env bash

set -x
set -eo pipefail

if ! [ -x "$(command -v psql)" ]; then
  echo >&2 "Error: 'psql' is not installed."
  exit 1
fi
if ! [ -x "$(command -v sqlx)" ]; then
  echo >&2 "Error: 'sqlx' is not installed."
  exit 1
fi

DB_USER=${POSTGRES_USER:=postgres}
DB_PASSWORD=${POSTGRES_PASSWORD:=postgres}
DB_NAME=${POSTGRES_DB:=stacker}
DB_PORT=${POSTGRES_PORT:=5432}

docker run \
  -e POSTGRES_USER=${DB_USER} \
  -e POSTGRES_PASSWORD=${DB_PASSWORD} \
  -e POSTGRES_DB=${DB_NAME} \
  -p "${DB_PORT}":5432 \
  -d postgres \
  postgres -N 1000

# Keep pinging Postgres until the server is ready to accept commands
export PGPASSWORD="${DB_PASSWORD}"
until psql -h "localhost" -U "${DB_USER}" -p "${DB_PORT}" -c '\q'; do
  >&2 echo "Postgres is still unavailable - sleeping"
  sleep 1
done

>&2 echo "Postgres is up and running on port ${DB_PORT} - executing command"

export DATABASE_URL=postgres://${DB_USER}:${DB_PASSWORD}@localhost:${DB_PORT}/${DB_NAME}
sqlx database create
sqlx migrate run

>&2 echo "Postgres has been migrated, ready to go!"

