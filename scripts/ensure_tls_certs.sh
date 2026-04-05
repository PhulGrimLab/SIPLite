#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${SIPLITE_TLS_CERT_DIR:-$PROJECT_ROOT/certs}"
TLS_CERT_FILE="${SIPLITE_TLS_CERT_FILE:-$CERT_DIR/server.crt}"
TLS_KEY_FILE="${SIPLITE_TLS_KEY_FILE:-$CERT_DIR/server.key}"
OPENSSL_CONFIG="${SIPLITE_TLS_OPENSSL_CONFIG:-$CERT_DIR/openssl-san.cnf}"
TLS_CERT_DAYS="${SIPLITE_TLS_CERT_DAYS:-365}"
TLS_CERT_CN="${SIPLITE_TLS_CERT_CN:-127.0.0.1}"
TLS_CERT_SAN_IP="${SIPLITE_TLS_CERT_SAN_IP:-127.0.0.1}"
TLS_CERT_SAN_DNS="${SIPLITE_TLS_CERT_SAN_DNS:-localhost}"

if [[ -f "$TLS_CERT_FILE" && -f "$TLS_KEY_FILE" ]]; then
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl command not found; cannot generate TLS certificate automatically." >&2
  exit 1
fi

mkdir -p "$CERT_DIR"

tmp_config="$(mktemp)"
cleanup() {
  rm -f "$tmp_config"
}
trap cleanup EXIT

if [[ -f "$OPENSSL_CONFIG" ]]; then
  sed \
    -e "s/^CN = .*/CN = $TLS_CERT_CN/" \
    -e "s/^IP\\.1 = .*/IP.1 = $TLS_CERT_SAN_IP/" \
    -e "s/^DNS\\.1 = .*/DNS.1 = $TLS_CERT_SAN_DNS/" \
    "$OPENSSL_CONFIG" >"$tmp_config"
else
  cat >"$tmp_config" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn

[dn]
C = KR
ST = Seoul
L = Seoul
O = SIPLite
OU = Dev
CN = $TLS_CERT_CN

[v3_req]
subjectAltName = @alt_names

[alt_names]
IP.1 = $TLS_CERT_SAN_IP
DNS.1 = $TLS_CERT_SAN_DNS
EOF
fi

echo "Generating self-signed TLS certificate"
echo "  cert: $TLS_CERT_FILE"
echo "  key: $TLS_KEY_FILE"
echo "  CN: $TLS_CERT_CN"
echo "  SAN IP: $TLS_CERT_SAN_IP"
echo "  SAN DNS: $TLS_CERT_SAN_DNS"

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$TLS_KEY_FILE" \
  -out "$TLS_CERT_FILE" \
  -days "$TLS_CERT_DAYS" \
  -config "$tmp_config" \
  -extensions v3_req
