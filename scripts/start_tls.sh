#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_BIN="${BUILD_BIN:-$PROJECT_ROOT/build/my_siplite}"
TLS_PORT="${SIPLITE_TLS_PORT:-5061}"
TLS_CERT_FILE="${SIPLITE_TLS_CERT_FILE:-$PROJECT_ROOT/certs/server.crt}"
TLS_KEY_FILE="${SIPLITE_TLS_KEY_FILE:-$PROJECT_ROOT/certs/server.key}"

if [[ ! -x "$BUILD_BIN" ]]; then
  echo "Missing executable: $BUILD_BIN" >&2
  echo "Build the server first with: make all" >&2
  exit 1
fi

if [[ ! -f "$TLS_CERT_FILE" ]]; then
  echo "Missing TLS certificate: $TLS_CERT_FILE" >&2
  exit 1
fi

if [[ ! -f "$TLS_KEY_FILE" ]]; then
  echo "Missing TLS private key: $TLS_KEY_FILE" >&2
  exit 1
fi

export SIPLITE_TLS_ENABLE=1
export SIPLITE_TLS_PORT="$TLS_PORT"
export SIPLITE_TLS_CERT_FILE="$TLS_CERT_FILE"
export SIPLITE_TLS_KEY_FILE="$TLS_KEY_FILE"

echo "Starting SIPLite with TLS"
echo "  binary: $BUILD_BIN"
echo "  tls port: $SIPLITE_TLS_PORT"
echo "  cert: $SIPLITE_TLS_CERT_FILE"
echo "  key: $SIPLITE_TLS_KEY_FILE"

exec "$BUILD_BIN"
