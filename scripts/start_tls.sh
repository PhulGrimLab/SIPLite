#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_BIN="${BUILD_BIN:-$PROJECT_ROOT/build/my_siplite}"
TLS_PORT="${SIPLITE_TLS_PORT:-5061}"
TLS_CERT_FILE="${SIPLITE_TLS_CERT_FILE:-$PROJECT_ROOT/certs/server.crt}"
TLS_KEY_FILE="${SIPLITE_TLS_KEY_FILE:-$PROJECT_ROOT/certs/server.key}"
TLS_CA_FILE="${SIPLITE_TLS_CA_FILE:-}"
TLS_VERIFY_PEER="${SIPLITE_TLS_VERIFY_PEER:-0}"
TLS_REQUIRE_CLIENT_CERT="${SIPLITE_TLS_REQUIRE_CLIENT_CERT:-0}"
TLS_CERT_CN="${SIPLITE_TLS_CERT_CN:-127.0.0.1}"
TLS_CERT_SAN_IP="${SIPLITE_TLS_CERT_SAN_IP:-127.0.0.1}"
TLS_CERT_SAN_DNS="${SIPLITE_TLS_CERT_SAN_DNS:-localhost}"

if [[ ! -x "$BUILD_BIN" ]]; then
  echo "Missing executable: $BUILD_BIN" >&2
  echo "Build the server first with: make all" >&2
  exit 1
fi

export SIPLITE_TLS_CERT_FILE="$TLS_CERT_FILE"
export SIPLITE_TLS_KEY_FILE="$TLS_KEY_FILE"
export SIPLITE_TLS_CERT_CN="$TLS_CERT_CN"
export SIPLITE_TLS_CERT_SAN_IP="$TLS_CERT_SAN_IP"
export SIPLITE_TLS_CERT_SAN_DNS="$TLS_CERT_SAN_DNS"

"$PROJECT_ROOT/scripts/ensure_tls_certs.sh"

export SIPLITE_TLS_ENABLE=1
export SIPLITE_TLS_PORT="$TLS_PORT"
export SIPLITE_TLS_VERIFY_PEER="$TLS_VERIFY_PEER"
export SIPLITE_TLS_REQUIRE_CLIENT_CERT="$TLS_REQUIRE_CLIENT_CERT"
if [[ -n "$TLS_CA_FILE" ]]; then
  export SIPLITE_TLS_CA_FILE="$TLS_CA_FILE"
fi

echo "Starting SIPLite with TLS"
echo "  binary: $BUILD_BIN"
echo "  tls port: $SIPLITE_TLS_PORT"
echo "  cert: $SIPLITE_TLS_CERT_FILE"
echo "  key: $SIPLITE_TLS_KEY_FILE"
echo "  cert CN: $SIPLITE_TLS_CERT_CN"
echo "  cert SAN IP: $SIPLITE_TLS_CERT_SAN_IP"
echo "  cert SAN DNS: $SIPLITE_TLS_CERT_SAN_DNS"
echo "  verify peer: $SIPLITE_TLS_VERIFY_PEER"
echo "  require client cert: $SIPLITE_TLS_REQUIRE_CLIENT_CERT"
if [[ -n "${SIPLITE_TLS_CA_FILE:-}" ]]; then
  echo "  ca file: $SIPLITE_TLS_CA_FILE"
fi

exec "$BUILD_BIN"
