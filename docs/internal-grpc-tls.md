# Internal gRPC TLS

SurfaceLab keeps the existing scanner service-token auth and adds TLS on top for encrypted orchestrator-to-scanner traffic.

## Shared Certificate Folder

Local development certificates live under the repo root `certificate/` directory so the scanner and orchestrator can share the same files easily.

The generated certificate files are ignored by git.

## Env Vars

Scanner:

- `SCANNER_GRPC_TLS_ENABLED`
- `SCANNER_GRPC_TLS_CERT_FILE`
- `SCANNER_GRPC_TLS_KEY_FILE`
- `SCANNER_GRPC_TLS_CA_FILE`

Orchestrator:

- `SCANNER_GRPC_TLS_ENABLED`
- `SCANNER_GRPC_TLS_CA_FILE`
- `SCANNER_GRPC_TLS_SERVER_NAME`

## Generate Local Certs

macos:

```bash
cd path/to/surface-lab
bash scripts/generate-dev-grpc-tls.sh
```

windows (powershell):

```powershell
cd path/to/surface-lab
bash scripts/generate-dev-grpc-tls.sh
```

linux:

```bash
cd path/to/surface-lab
bash scripts/generate-dev-grpc-tls.sh
```

That creates:

- `certificate/scanner.crt`
- `certificate/scanner.key`
- `certificate/scanner-ca.crt`

For local development, the CA file is the same self-signed certificate.

## Start Scanner With TLS

macos:

```bash
cd path/to/surface-lab/services/scanner
export DATABASE_URL='postgresql://surfacelab_scanner:change-me-scanner@localhost:5432/surfacelab?sslmode=disable'
export APP_ENV=development
export SCANNER_SERVICE_TOKEN='dev-scanner-token'
export SCANNER_GRPC_TLS_ENABLED='true'
export SCANNER_GRPC_TLS_CERT_FILE='path/to/surface-lab/certificate/scanner.crt'
export SCANNER_GRPC_TLS_KEY_FILE='path/to/surface-lab/certificate/scanner.key'
go run .
```

windows (powershell):

```powershell
cd path/to/surface-lab/services/scanner
$env:DATABASE_URL='postgresql://surfacelab_scanner:change-me-scanner@localhost:5432/surfacelab?sslmode=disable'
$env:APP_ENV='development'
$env:SCANNER_SERVICE_TOKEN='dev-scanner-token'
$env:SCANNER_GRPC_TLS_ENABLED='true'
$env:SCANNER_GRPC_TLS_CERT_FILE='path/to/surface-lab/certificate/scanner.crt'
$env:SCANNER_GRPC_TLS_KEY_FILE='path/to/surface-lab/certificate/scanner.key'
go run .
```

linux:

```bash
cd path/to/surface-lab/services/scanner
export DATABASE_URL='postgresql://surfacelab_scanner:change-me-scanner@localhost:5432/surfacelab?sslmode=disable'
export APP_ENV=development
export SCANNER_SERVICE_TOKEN='dev-scanner-token'
export SCANNER_GRPC_TLS_ENABLED='true'
export SCANNER_GRPC_TLS_CERT_FILE='path/to/surface-lab/certificate/scanner.crt'
export SCANNER_GRPC_TLS_KEY_FILE='path/to/surface-lab/certificate/scanner.key'
go run .
```

## Start Orchestrator With TLS

The orchestrator uses FastAPI, with uvicorn under the hood, so we can set env vars and start it with TLS support.
You can use the fastapi server, just by swapping `uvicorn main:app --reload` with `fastapi dev` if you prefer.

macos:

```bash
cd path/to/surface-lab/apps/orchestrator
export DATABASE_URL='postgresql://surfacelab_orchestrator:change-me-orchestrator@localhost:5432/surfacelab?sslmode=disable'
export SCANNER_GRPC_ADDRESS='localhost:50051'
export SCANNER_SERVICE_TOKEN='dev-scanner-token'
export SCANNER_GRPC_AUTH_MODE='bearer'
export SCANNER_GRPC_TLS_ENABLED='true'
export SCANNER_GRPC_TLS_CA_FILE='path/to/surface-lab/certificate/scanner-ca.crt'
export SCANNER_GRPC_TLS_SERVER_NAME='localhost'
uvicorn main:app --reload
```

windows (powershell):

```powershell
cd path/to/surface-lab/apps/orchestrator
$env:DATABASE_URL='postgresql://surfacelab_orchestrator:change-me-orchestrator@localhost:5432/surfacelab?sslmode=disable'
$env:SCANNER_GRPC_ADDRESS='localhost:50051'
$env:SCANNER_SERVICE_TOKEN='dev-scanner-token'
$env:SCANNER_GRPC_AUTH_MODE='bearer'
$env:SCANNER_GRPC_TLS_ENABLED='true'
$env:SCANNER_GRPC_TLS_CA_FILE='path/to/surface-lab/certificate/scanner-ca.crt'
$env:SCANNER_GRPC_TLS_SERVER_NAME='localhost'
uvicorn main:app --reload
```

linux:

```bash
cd path/to/surface-lab/apps/orchestrator
export DATABASE_URL='postgresql://surfacelab_orchestrator:change-me-orchestrator@localhost:5432/surfacelab?sslmode=disable'
export SCANNER_GRPC_ADDRESS='localhost:50051'
export SCANNER_SERVICE_TOKEN='dev-scanner-token'
export SCANNER_GRPC_AUTH_MODE='bearer'
export SCANNER_GRPC_TLS_ENABLED='true'
export SCANNER_GRPC_TLS_CA_FILE='path/to/surface-lab/certificate/scanner-ca.crt'
export SCANNER_GRPC_TLS_SERVER_NAME='localhost'
uvicorn main:app --reload
```

## Test

macos:

```bash
curl -X POST http://127.0.0.1:8000/scans \
  -H 'content-type: application/json' \
  -d '{"target":"https://example.com"}'
```

windows (powershell):

```powershell
curl -X POST http://127.0.0.1:8000/scans `
  -H 'content-type: application/json' `
  -d '{"target":"https://example.com"}'
```

linux:

```bash
curl -X POST http://127.0.0.1:8000/scans \
  -H 'content-type: application/json' \
  -d '{"target":"https://example.com"}'
```

## Wiring
  
- The scanner loads the configured certificate and private key and enables gRPC TLS credentials.
- The orchestrator uses the configured CA file to create a secure gRPC channel.
- The existing service-token metadata auth remains in place on every RPC.
