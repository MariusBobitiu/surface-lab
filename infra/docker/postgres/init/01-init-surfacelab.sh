#!/bin/sh
set -eu

db_name="${POSTGRES_DB:?POSTGRES_DB is required}"
migrate_password="${POSTGRES_MIGRATE_PASSWORD:?POSTGRES_MIGRATE_PASSWORD is required}"
scanner_password="${POSTGRES_SCANNER_PASSWORD:?POSTGRES_SCANNER_PASSWORD is required}"
orchestrator_password="${POSTGRES_ORCHESTRATOR_PASSWORD:?POSTGRES_ORCHESTRATOR_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db_name" -f /surfacelab-init/000001_init.up.sql
psql \
  -v ON_ERROR_STOP=1 \
  -v migrate_password="$migrate_password" \
  -v scanner_password="$scanner_password" \
  -v orchestrator_password="$orchestrator_password" \
  --username "$POSTGRES_USER" \
  --dbname "$db_name" \
  -f /surfacelab-init/roles.sql
