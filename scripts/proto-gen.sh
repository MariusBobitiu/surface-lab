#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROTO_DIR="$ROOT_DIR/proto/v1"
GO_OUT_DIR="$ROOT_DIR/services/scanner/transport/grpc"
PYTHON_OUT_DIR="$ROOT_DIR/apps/orchestrator/grpc_clients/v1"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/apps/orchestrator/.venv/bin/python}"

PROTO_FILES=(
  "$PROTO_DIR/tool.proto"
)

echo "Generating protobuf files..."

if ! command -v protoc >/dev/null 2>&1; then
  echo "protoc not installed"
  exit 1
fi

if ! command -v protoc-gen-go >/dev/null 2>&1; then
  echo "protoc-gen-go not installed"
  echo "Install with:"
  echo "go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
  exit 1
fi

if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
  echo "protoc-gen-go-grpc not installed"
  echo "Install with:"
  echo "go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
  exit 1
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "python interpreter for grpc_tools not found at $PYTHON_BIN"
  echo "Set PYTHON_BIN or create the orchestrator virtualenv first"
  exit 1
fi

if ! "$PYTHON_BIN" -m grpc_tools.protoc --version >/dev/null 2>&1; then
  echo "python grpc_tools not installed"
  echo "Install with:"
  echo "cd apps/orchestrator && ./.venv/bin/pip install -r requirements.txt"
  exit 1
fi

mkdir -p "$GO_OUT_DIR" "$PYTHON_OUT_DIR"

echo "Generating Go stubs..."
protoc \
  -I "$PROTO_DIR" \
  --go_out="$GO_OUT_DIR" \
  --go_opt=paths=source_relative \
  --go-grpc_out="$GO_OUT_DIR" \
  --go-grpc_opt=paths=source_relative \
  "${PROTO_FILES[@]}"

echo "Generating Python stubs..."
"$PYTHON_BIN" -m grpc_tools.protoc \
  -I "$PROTO_DIR" \
  --python_out="$PYTHON_OUT_DIR" \
  --grpc_python_out="$PYTHON_OUT_DIR" \
  "${PROTO_FILES[@]}"

# grpc_tools generates absolute imports by default. Rewrite them to package-relative
# imports so the checked-in stubs work when imported via grpc_clients.v1.
sed -i.bak 's/^import tool_pb2 as tool__pb2$/from . import tool_pb2 as tool__pb2/' "$PYTHON_OUT_DIR/tool_pb2_grpc.py"
rm -f "$PYTHON_OUT_DIR/tool_pb2_grpc.py.bak"

echo "Protobuf generation complete"
