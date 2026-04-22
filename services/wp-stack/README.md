# wp-stack

`wp-stack` is the first real specialist Go gRPC service in the SurfaceLab monorepo. It performs safe, deterministic WordPress-oriented HTTP checks and returns normalized findings for later orchestration and reporting.

It follows the existing SurfaceLab monorepo conventions:
- shared contracts live in `proto/v1`
- shared generation lives in `scripts/proto-gen.sh`
- generated Go stubs live in `services/wp-stack/transport/grpc`
- Dockerfiles live under `infra/docker/<service-name>/Dockerfile`

## Structure

- `config/`: environment loading and validation
- `models/`: normalized internal response models
- `tools/`: WordPress-specific stack checks
- `transport/grpc/`: generated stubs, handlers, interceptors, and server wiring
- `utils/`: structured logger setup

There is no `db/` folder because this service is a network-facing specialist worker, not a persistence layer.

## Regenerate protobuf code

From the repo root:

```bash
./scripts/proto-gen.sh wp-stack
```

To regenerate scanner, baseline, and wp-stack contracts:

```bash
./scripts/proto-gen.sh all
```

## Run locally

From the repo root:

```bash
cp services/wp-stack/.env.example services/wp-stack/.env
cd services/wp-stack
go mod tidy
go run .
```

Call the `RunStack` RPC on `WordPressStackService` with the configured `SERVICE_TOKEN` in either:
- `authorization: Bearer <token>`
- `x-service-token: <token>`

Reflection is enabled only when `APP_ENV=development`.

## Included v1 checks

- homepage fetch for `wp-content`, `wp-includes`, and `/wp-json/` indicators
- WordPress generator meta tag detection
- plugin and theme asset hint extraction from HTML
- `/wp-login.php` exposure check
- `/xmlrpc.php` enabled check
- `/readme.html` exposure check

## Build the Docker image

From the repo root:

```bash
docker build -f infra/docker/wp-stack/Dockerfile -t surfacelab/wp-stack:local .
```
