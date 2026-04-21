#!/usr/bin/env bash

set -euo pipefail

APP_NAME="surfacelab"
INSTALL_DIR="${APP_NAME}"
REPO_OWNER="mariusbobitiu"
REPO_NAME="surface-lab"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main"
DEFAULT_PUBLIC_IP="127.0.0.1"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"
DEFAULT_GHCR_OWNER="${REPO_OWNER}"
DEFAULT_IMAGE_REGISTRY="ghcr.io"
DEFAULT_IMAGE_TAG="latest"
COMPOSE_FILE="docker-compose.server.yml"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1"
    exit 1
  }
}

need_cmd docker
need_cmd curl
need_cmd openssl

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose plugin is required."
  exit 1
fi

detect_public_ip() {
  local ip=""
  local url

  for url in \
    "https://icanhazip.com" \
    "https://api.ipify.org" \
    "https://ifconfig.me"
  do
    ip="$(curl -fsSL --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      printf '%s\n' "$ip"
      return 0
    fi
  done

  hostname -I 2>/dev/null | awk '{print $1}' || true
}

GHCR_OWNER="${GHCR_OWNER:-$REPO_OWNER}"
IMAGE_REGISTRY="${IMAGE_REGISTRY:-$DEFAULT_IMAGE_REGISTRY}"
IMAGE_NAMESPACE="${IMAGE_NAMESPACE:-$GHCR_OWNER}"
IMAGE_TAG="${IMAGE_TAG:-$DEFAULT_IMAGE_TAG}"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [ -f ".env" ]; then
  echo "Existing install detected at $(pwd)/.env"
  echo "Refusing to overwrite generated secrets. Remove the directory or edit the files manually."
  exit 1
fi

POSTGRES_DB="${POSTGRES_DB:-surfacelab}"
POSTGRES_SUPERUSER="${POSTGRES_SUPERUSER:-postgres}"
POSTGRES_SUPERUSER_PASSWORD="$(openssl rand -base64 24 | tr -d '\n' | tr '/+' 'ab' | cut -c1-24)"
POSTGRES_MIGRATE_PASSWORD="$(openssl rand -base64 24 | tr -d '\n' | tr '/+' 'ab' | cut -c1-24)"
POSTGRES_SCANNER_PASSWORD="$(openssl rand -base64 24 | tr -d '\n' | tr '/+' 'ab' | cut -c1-24)"
POSTGRES_ORCHESTRATOR_PASSWORD="$(openssl rand -base64 24 | tr -d '\n' | tr '/+' 'ab' | cut -c1-24)"
ORCHESTRATOR_API_KEY="$(openssl rand -hex 32)"
SCANNER_SERVICE_TOKEN="$(openssl rand -hex 32)"
SERVER_IP="$(detect_public_ip | tr -d '[:space:]')"
if [ -z "${SERVER_IP:-}" ]; then
  SERVER_IP="$DEFAULT_PUBLIC_IP"
fi

APP_BASE_URL="http://${SERVER_IP}:${FRONTEND_PORT}"
ORCHESTRATOR_ALLOWED_ORIGINS="${APP_BASE_URL}"
ORCHESTRATOR_TRUSTED_HOSTS="localhost,127.0.0.1,[::1],frontend,orchestrator,${SERVER_IP}"

mkdir -p postgres-init postgres-bootstrap

curl -fsSL "${RAW_BASE}/infra/compose/docker-compose.server.yml" -o "${COMPOSE_FILE}"
curl -fsSL "${RAW_BASE}/infra/docker/postgres/init/01-init-surfacelab.sh" -o "postgres-init/01-init-surfacelab.sh"
curl -fsSL "${RAW_BASE}/services/scanner/db/roles/001_runtime_roles.sql" -o "postgres-bootstrap/roles.sql"
curl -fsSL "${RAW_BASE}/services/scanner/db/migrations/000001_init.up.sql" -o "postgres-bootstrap/000001_init.up.sql"

chmod +x postgres-init/01-init-surfacelab.sh

cat > .env <<EOF
APP_NAME=${APP_NAME}
IMAGE_REGISTRY=${IMAGE_REGISTRY}
IMAGE_NAMESPACE=${IMAGE_NAMESPACE}
IMAGE_TAG=${IMAGE_TAG}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_SUPERUSER=${POSTGRES_SUPERUSER}
POSTGRES_SUPERUSER_PASSWORD=${POSTGRES_SUPERUSER_PASSWORD}
POSTGRES_MIGRATE_PASSWORD=${POSTGRES_MIGRATE_PASSWORD}
POSTGRES_SCANNER_PASSWORD=${POSTGRES_SCANNER_PASSWORD}
POSTGRES_ORCHESTRATOR_PASSWORD=${POSTGRES_ORCHESTRATOR_PASSWORD}
ORCHESTRATOR_API_KEY=${ORCHESTRATOR_API_KEY}
SCANNER_SERVICE_TOKEN=${SCANNER_SERVICE_TOKEN}
ORCHESTRATOR_REQUEST_TIMEOUT_MS=10000
ORCHESTRATOR_REQUIRE_API_KEY=true
ORCHESTRATOR_RATE_LIMIT_ENABLED=true
ORCHESTRATOR_RATE_LIMIT_RPM=60
ORCHESTRATOR_RATE_LIMIT_BURST=20
ORCHESTRATOR_ALLOWED_ORIGINS=${ORCHESTRATOR_ALLOWED_ORIGINS}
ORCHESTRATOR_TRUSTED_HOSTS=${ORCHESTRATOR_TRUSTED_HOSTS}
ORCHESTRATOR_SECURITY_HEADERS_ENABLED=true
ORCHESTRATOR_BODY_LIMIT_BYTES=1048576
ORCHESTRATOR_WORKERS=2
SCANNER_APP_ENV=production
SCANNER_GRPC_AUTH_MODE=bearer
SCANNER_GRPC_TLS_ENABLED=false
SCANNER_RATE_LIMIT_RPS=5
SCANNER_RATE_LIMIT_BURST=10
SCANNER_MAX_CONCURRENT_REQUESTS=4
SCANNER_REQUEST_TIMEOUT_SECONDS=30
FRONTEND_HOST_PORT=${FRONTEND_PORT}
REDIS_ENABLED=true
NVD_CACHE_TTL_SECONDS=86400
NVD_API_KEY=
NVD_ENABLED=false
NVD_MIN_INTERVAL_SECONDS=6
NVD_TIMEOUT_SECONDS=10
OLLAMA_ENABLED=false
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=gemma3
OLLAMA_TIMEOUT_SECONDS=30
EOF

docker compose -p "${APP_NAME}" -f "${COMPOSE_FILE}" pull
docker compose -p "${APP_NAME}" -f "${COMPOSE_FILE}" up -d

echo "SurfaceLab installed."
echo "Frontend: ${APP_BASE_URL}"
echo "Install directory: $(pwd)"
echo "Compose file: $(pwd)/${COMPOSE_FILE}"
echo "Environment file: $(pwd)/.env"
echo "To inspect logs: docker compose -p ${APP_NAME} -f ${COMPOSE_FILE} logs -f"
