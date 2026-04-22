# service-baseline

`service-baseline` is a reusable Go gRPC service template for future stack-specific services such as `wp-stack`, `nextjs-stack`, or `generic-http-stack`.

It follows the existing SurfaceLab monorepo conventions:
- shared contracts live in `proto/v1`
- shared generation lives in `scripts/proto-gen.sh`
- generated Go stubs live in `services/service-baseline/transport/grpc`
- Dockerfiles live under `infra/docker/<service-name>/Dockerfile`

## Structure

- `config/`: environment loading and validation
- `models/`: normalized internal response models
- `tools/`: placeholder service logic
- `transport/grpc/`: generated stubs, handlers, interceptors, and server wiring
- `utils/`: structured logger setup

There is no `db/` folder because this baseline is for reusable service infrastructure, not persistence.

## Regenerate protobuf code

From the repo root:

```bash
./scripts/proto-gen.sh service-baseline
```

To regenerate both scanner and baseline contracts:

```bash
./scripts/proto-gen.sh all
```

## Run locally

From the repo root:

```bash
cp services/service-baseline/.env.example services/service-baseline/.env
cd services/service-baseline
go mod tidy
go run .
```

Call the placeholder RPC with a gRPC client using the configured `SERVICE_TOKEN` in either:
- `authorization: Bearer <token>`
- `x-service-token: <token>`

Reflection is enabled only when `APP_ENV=development`.

## Build the Docker image

From the repo root:

```bash
docker build -f infra/docker/service-baseline/Dockerfile -t surfacelab/service-baseline:local .
```

## Turning this into a real service

To create a new service such as `wp-stack`:

1. Copy `services/service-baseline` to `services/wp-stack`.
2. Rename the Go module, binary name, and log/service labels.
3. Replace `proto/v1/baseline.proto` with a real shared contract such as `proto/v1/wp_stack.proto`.
4. Update `option go_package` in the shared proto to point at the new service’s `transport/grpc` folder.
5. Extend `scripts/proto-gen.sh` so it can generate the new shared contract into the new service folder.
6. Replace the placeholder handler and `tools/execute` logic with real stack-specific logic.
7. Add a new Dockerfile under `infra/docker/wp-stack/Dockerfile`.
8. Update `.env.example` defaults for the new service.
