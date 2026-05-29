#!/usr/bin/env bash
set -euo pipefail

# ─── Config ───────────────────────────────────────────────────────────────────
CONTAINER="stackerdb"
DB_USER="postgres"
DB_NAME="stacker"
# Docker Compose prefixes volumes with project name (directory name)
PROJECT_NAME="$(basename "$(pwd)")"
VOLUME="${PROJECT_NAME}_stackerdb"
COMPOSE_FILE="docker-compose.yml"
DUMP_FILE="stacker_$(date +%Y%m%d_%H%M%S).sql"

# ─── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ─── Step 1: Dump ─────────────────────────────────────────────────────────────
info "Dumping '$DB_NAME' from running container '$CONTAINER'..."
docker exec "$CONTAINER" pg_dump -U "$DB_USER" "$DB_NAME" > "$DUMP_FILE"

DUMP_SIZE=$(wc -c < "$DUMP_FILE")
if [ "$DUMP_SIZE" -lt 1000 ]; then
  error "Dump file is too small (${DUMP_SIZE} bytes) — aborting. Check container is running and DB exists."
fi
info "Dump saved to $DUMP_FILE (${DUMP_SIZE} bytes)"

# ─── Step 2: Stop containers ──────────────────────────────────────────────────
info "Stopping containers..."
docker compose -f "$COMPOSE_FILE" stop stackerdb

# ─── Step 3: Remove old volume ────────────────────────────────────────────────
warn "Removing old volume '$VOLUME'..."
docker volume rm "$VOLUME"

# ─── Step 4: Start fresh PG18 container ──────────────────────────────────────
info "Starting fresh stackerdb (PG18)..."
docker compose -f "$COMPOSE_FILE" up -d stackerdb

# ─── Step 5: Wait for healthy ─────────────────────────────────────────────────
info "Waiting for stackerdb to be ready..."
RETRIES=20
until docker exec "$CONTAINER" pg_isready -U "$DB_USER" -q; do
  RETRIES=$((RETRIES - 1))
  if [ "$RETRIES" -le 0 ]; then
    error "stackerdb did not become ready in time."
  fi
  sleep 3
done
info "stackerdb is ready."

# ─── Step 6: Create database if missing ───────────────────────────────────────
DB_EXISTS=$(docker exec "$CONTAINER" psql -U "$DB_USER" -tAc \
  "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'")
if [ "$DB_EXISTS" != "1" ]; then
  info "Creating database '$DB_NAME'..."
  docker exec "$CONTAINER" psql -U "$DB_USER" -c "CREATE DATABASE ${DB_NAME};"
else
  info "Database '$DB_NAME' already exists."
fi

# ─── Step 7: Restore ──────────────────────────────────────────────────────────
info "Restoring from $DUMP_FILE..."
cat "$DUMP_FILE" | docker exec -i "$CONTAINER" psql -U "$DB_USER" "$DB_NAME"

# ─── Step 8: Verify ───────────────────────────────────────────────────────────
info "Verifying restored tables..."
docker exec "$CONTAINER" psql -U "$DB_USER" "$DB_NAME" -c "\dt"

info "Migration complete! Dump kept at: $DUMP_FILE"
