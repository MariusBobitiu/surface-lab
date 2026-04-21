#!/usr/bin/env bash

set -euo pipefail

OUTPUT_DIR="${1:-certificate}"
mkdir -p "${OUTPUT_DIR}"

openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout "${OUTPUT_DIR}/scanner.key" \
  -out "${OUTPUT_DIR}/scanner.crt" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

cp "${OUTPUT_DIR}/scanner.crt" "${OUTPUT_DIR}/scanner-ca.crt"

echo "Generated:"
echo "  ${OUTPUT_DIR}/scanner.crt"
echo "  ${OUTPUT_DIR}/scanner.key"
echo "  ${OUTPUT_DIR}/scanner-ca.crt"
