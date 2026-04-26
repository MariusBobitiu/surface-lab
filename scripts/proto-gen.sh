#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROTO_DIR="$ROOT_DIR/proto/v1"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/apps/orchestrator/.venv/bin/python}"
TARGET="${1:-all}"

SCANNER_GO_OUT_DIR="$ROOT_DIR/services/scanner/transport/grpc"
BASELINE_GO_OUT_DIR="$ROOT_DIR/services/service-baseline/transport/grpc"
WP_STACK_GO_OUT_DIR="$ROOT_DIR/services/wp-stack/transport/grpc"
NEXTJS_STACK_GO_OUT_DIR="$ROOT_DIR/services/nextjs-stack/transport/grpc"
LARAVEL_STACK_GO_OUT_DIR="$ROOT_DIR/services/laravel-stack/transport/grpc"
PHP_STACK_GO_OUT_DIR="$ROOT_DIR/services/php-stack/transport/grpc"
SHOPIFY_STACK_GO_OUT_DIR="$ROOT_DIR/services/ecommerce-stack/transport/grpc"
PYTHON_OUT_DIR="$ROOT_DIR/apps/orchestrator/grpc_clients/v1"

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

generate_go() {
  local proto_file="$1"
  local out_dir="$2"

  mkdir -p "$out_dir"
  protoc \
    -I "$PROTO_DIR" \
    --go_out="$out_dir" \
    --go_opt=paths=source_relative \
    --go-grpc_out="$out_dir" \
    --go-grpc_opt=paths=source_relative \
    "$proto_file"
}

generate_python_stubs() {
  local proto_file="$1"
  local module_name="$2"

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

  mkdir -p "$PYTHON_OUT_DIR"

  echo "Generating Python stubs for $module_name..."
  "$PYTHON_BIN" -m grpc_tools.protoc \
    -I "$PROTO_DIR" \
    --python_out="$PYTHON_OUT_DIR" \
    --grpc_python_out="$PYTHON_OUT_DIR" \
    "$proto_file"

  # grpc_tools generates absolute imports by default. Rewrite them to package-relative
  # imports so the checked-in stubs work when imported via grpc_clients.v1.
  sed -E -i.bak "s/^import (${module_name}_pb2) as (.*)$/from . import \\1 as \\2/" "$PYTHON_OUT_DIR/${module_name}_pb2_grpc.py"
  rm -f "$PYTHON_OUT_DIR/${module_name}_pb2_grpc.py.bak"
}

case "$TARGET" in
  all)
    echo "Generating Go stubs for scanner..."
    generate_go "$PROTO_DIR/tool.proto" "$SCANNER_GO_OUT_DIR"
    echo "Generating Go stubs for service-baseline..."
    generate_go "$PROTO_DIR/baseline.proto" "$BASELINE_GO_OUT_DIR"
    echo "Generating Go stubs for wp-stack..."
    generate_go "$PROTO_DIR/wp_stack.proto" "$WP_STACK_GO_OUT_DIR"
    echo "Generating Go stubs for nextjs-stack..."
    generate_go "$PROTO_DIR/nextjs_stack.proto" "$NEXTJS_STACK_GO_OUT_DIR"
    echo "Generating Go stubs for laravel-stack..."
    generate_go "$PROTO_DIR/laravel_stack.proto" "$LARAVEL_STACK_GO_OUT_DIR"
    echo "Generating Go stubs for php-stack..."
    generate_go "$PROTO_DIR/php_stack.proto" "$PHP_STACK_GO_OUT_DIR"
    echo "Generating Go stubs for shopify-stack..."
    generate_go "$PROTO_DIR/shopify_stack.proto" "$SHOPIFY_STACK_GO_OUT_DIR"
    generate_python_stubs "$PROTO_DIR/tool.proto" "tool"
    generate_python_stubs "$PROTO_DIR/wp_stack.proto" "wp_stack"
    generate_python_stubs "$PROTO_DIR/nextjs_stack.proto" "nextjs_stack"
    generate_python_stubs "$PROTO_DIR/laravel_stack.proto" "laravel_stack"
    generate_python_stubs "$PROTO_DIR/php_stack.proto" "php_stack"
    generate_python_stubs "$PROTO_DIR/shopify_stack.proto" "shopify_stack"
    ;;
  scanner)
    echo "Generating Go stubs for scanner..."
    generate_go "$PROTO_DIR/tool.proto" "$SCANNER_GO_OUT_DIR"
    generate_python_stubs "$PROTO_DIR/tool.proto" "tool"
    ;;
  service-baseline)
    echo "Generating Go stubs for service-baseline..."
    generate_go "$PROTO_DIR/baseline.proto" "$BASELINE_GO_OUT_DIR"
    ;;
  wp-stack)
    echo "Generating Go stubs for wp-stack..."
    generate_go "$PROTO_DIR/wp_stack.proto" "$WP_STACK_GO_OUT_DIR"
    generate_python_stubs "$PROTO_DIR/wp_stack.proto" "wp_stack"
    ;;
  nextjs-stack)
    echo "Generating Go stubs for nextjs-stack..."
    generate_go "$PROTO_DIR/nextjs_stack.proto" "$NEXTJS_STACK_GO_OUT_DIR"
    generate_python_stubs "$PROTO_DIR/nextjs_stack.proto" "nextjs_stack"
    ;;
  laravel-stack)
    echo "Generating Go stubs for laravel-stack..."
    generate_go "$PROTO_DIR/laravel_stack.proto" "$LARAVEL_STACK_GO_OUT_DIR"
    generate_python_stubs "$PROTO_DIR/laravel_stack.proto" "laravel_stack"
    ;;
  php-stack)
    echo "Generating Go stubs for php-stack..."
    generate_go "$PROTO_DIR/php_stack.proto" "$PHP_STACK_GO_OUT_DIR"
    generate_python_stubs "$PROTO_DIR/php_stack.proto" "php_stack"
    ;;
  shopify-stack)
    echo "Generating Go stubs for shopify-stack..."
    generate_go "$PROTO_DIR/shopify_stack.proto" "$SHOPIFY_STACK_GO_OUT_DIR"
    generate_python_stubs "$PROTO_DIR/shopify_stack.proto" "shopify_stack"
    ;;
  *)
    echo "Unknown target: $TARGET"
    echo "Usage: scripts/proto-gen.sh [all|scanner|service-baseline|wp-stack|nextjs-stack|laravel-stack|php-stack|shopify-stack]"
    exit 1
    ;;
esac

echo "Protobuf generation complete"
