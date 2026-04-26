# SurfaceLab Containerization

This repo now includes production-leaning container assets for:

- `apps/frontend` as a standalone Next.js production image
- `apps/orchestrator` as a FastAPI image served by `uvicorn`
- `services/scanner` as a compiled Go gRPC image
- `infra/compose/docker-compose.yml` with Postgres and Redis
- GitHub Actions image packaging to GHCR and Docker Hub

## Local Compose

1. Copy the compose example file:

   ```bash
   cp infra/compose/.env.example .env
   ```

2. Adjust the secrets and optional integration values in `.env`.

3. Start the stack:

   ```bash
   docker compose --env-file .env -f infra/compose/docker-compose.yml up --build
   ```

4. Open the frontend at `http://localhost:3000`.

### What gets exposed

- `frontend` is published on `localhost:${FRONTEND_PORT}`
- `orchestrator` stays internal on the Compose network
- `scanner` stays internal on the Compose network
- `laravel-stack`, `php-stack`, and `ecommerce-stack` stay internal on the Compose network
- `postgres` and `redis` stay internal on the Compose network

If you need direct orchestrator access during local debugging, expose port `8000` temporarily in `infra/compose/docker-compose.yml` rather than changing the service contract.

### Specialist Runtime Verification

After Compose is up, validate specialist connectivity from inside the orchestrator container:

```bash
docker compose --env-file .env -f infra/compose/docker-compose.yml exec orchestrator sh -lc 'nc -z laravel-stack 50063 && nc -z php-stack 50064 && nc -z ecommerce-stack 50065'
```

If this passes, the orchestrator service discovery matches compose DNS and gRPC ports.

### Database initialization

On the first `postgres` boot, Compose runs:

- `services/scanner/db/migrations/000001_init.up.sql`
- `services/scanner/db/roles/001_runtime_roles.sql`

This creates the base schema plus the separate runtime roles used by the scanner and orchestrator.

If you change the init SQL after the volume already exists, recreate the Postgres volume:

```bash
docker compose down -v
docker compose up --build
```

## Environment Expectations

### Frontend

- `ORCHESTRATOR_BASE_URL`
  For Compose this is `http://orchestrator:8000`.
- `ORCHESTRATOR_API_KEY`
  Must match the orchestrator API key.
- `ORCHESTRATOR_REQUEST_TIMEOUT_MS`
  Server-side fetch timeout in milliseconds.

### Orchestrator

- `DATABASE_URL`
  Uses the read-only runtime role in Compose.
- `SCANNER_GRPC_ADDRESS`
  `scanner:50051` in Compose.
- `SCANNER_SERVICE_TOKEN`
  Must match the scanner token.
- `SCANNER_GRPC_AUTH_MODE`
  `bearer` or `x-service-token`.
- `SCANNER_GRPC_TLS_ENABLED`
  Leave `false` for the default local stack unless you mount certs.
- `REDIS_URL`
  `redis://redis:6379/0` in Compose.
- `NVD_API_KEY`
  Optional.
- `NVD_ENABLED`
  Usually `false` unless an API key is configured.
- `OLLAMA_*`
  Optional local LLM integration, routed to `host.docker.internal` by default.

### Specialist Contract Naming

SurfaceLab specialist contracts now use `*.verify_stack` as the preferred naming convention to reflect safe external verification behavior.

Legacy compatibility aliases remain enabled during transition:

- `wordpress.v1.run_stack` -> `wordpress.v1.verify_stack`
- `nextjs.v1.run_stack` -> `nextjs.v1.verify_stack`

Both IDs are accepted. Execution de-duplicates aliases so the same specialist is not run twice when both IDs are selected.

### Scanner

- `DATABASE_URL`
  Uses the scanner runtime role in Compose.
- `SCANNER_SERVICE_TOKEN`
  Must match the orchestrator token.
- `SCANNER_GRPC_TLS_ENABLED`
  Leave `false` by default.
- `SCANNER_GRPC_TLS_CERT_FILE`
- `SCANNER_GRPC_TLS_KEY_FILE`
- `SCANNER_GRPC_TLS_CA_FILE`
  Required only when TLS is enabled.

## GitHub Actions Image Publishing

Workflow file: `.github/workflows/images.yml`

Docker asset locations:

- `infra/docker/frontend/Dockerfile`
- `infra/docker/orchestrator/Dockerfile`
- `infra/docker/scanner/Dockerfile`
- `infra/docker/postgres/init/01-init-surfacelab.sh`

### Pull requests

- Builds all three images
- Uses Buildx cache
- Does not push to any registry

### Pushes to `main`

- Builds all three images
- Pushes to GHCR and Docker Hub
- Publishes `latest`
- Publishes a short SHA tag like `sha-abc1234`

### Version tags like `v1.2.3`

- Builds all three images
- Pushes the Git tag
- Pushes semver tags like `1.2.3` and `1.2`
- Also pushes the SHA tag

## Registry Naming

GHCR images:

- `ghcr.io/<repo-owner>/surfacelab-frontend`
- `ghcr.io/<repo-owner>/surfacelab-orchestrator`
- `ghcr.io/<repo-owner>/surfacelab-scanner`

Docker Hub images:

- `<dockerhub-username>/surfacelab-frontend`
- `<dockerhub-username>/surfacelab-orchestrator`
- `<dockerhub-username>/surfacelab-scanner`

`<repo-owner>` comes from GitHub automatically. Docker Hub uses the repository variable `DOCKERHUB_USERNAME`.

## Required GitHub Configuration

Repository variable:

- `DOCKERHUB_USERNAME`

Repository secrets:

- `DOCKERHUB_TOKEN`

`GITHUB_TOKEN` is provided automatically for GHCR publishing.
