#!/bin/bash
# Generate ephemeral self-signed TLS material for the kerbside CI lane.
#
# Usage: generate-tls.sh TLSDIR
#
# Produces in TLSDIR:
#   ca-key.pem      CA private key
#   ca-cert.pem     Self-signed CA certificate (CN=kerbside-ci-ca, 30 days)
#   proxy-key.pem   Kerbside proxy private key
#   proxy-cert.pem  Proxy certificate signed by the CA (CN=kerbside-ci, 30 days)
#
# Always regenerates; never reuses existing material.
# Part of docs/plans/PLAN-test-harness-phase-05-direct-qemu-ci.md step 5b.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 TLSDIR" >&2
    exit 1
fi

TLSDIR="$1"
mkdir -p "${TLSDIR}"

echo "[generate-tls] Writing TLS material to ${TLSDIR}"

# --- CA key and self-signed cert ---
openssl genrsa -out "${TLSDIR}/ca-key.pem" 2048 2>/dev/null

openssl req \
    -new \
    -x509 \
    -days 30 \
    -key "${TLSDIR}/ca-key.pem" \
    -out "${TLSDIR}/ca-cert.pem" \
    -subj '/CN=kerbside-ci-ca'

echo "[generate-tls] CA cert: ${TLSDIR}/ca-cert.pem"

# --- Proxy key and CSR ---
openssl genrsa -out "${TLSDIR}/proxy-key.pem" 2048 2>/dev/null

openssl req \
    -new \
    -key "${TLSDIR}/proxy-key.pem" \
    -out "${TLSDIR}/proxy.csr" \
    -subj '/C=US/O=Kerbside CI/CN=kerbside-ci'

# --- Sign the proxy cert with our CA ---
openssl x509 \
    -req \
    -days 30 \
    -in "${TLSDIR}/proxy.csr" \
    -CA "${TLSDIR}/ca-cert.pem" \
    -CAkey "${TLSDIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${TLSDIR}/proxy-cert.pem" \
    2>/dev/null

rm -f "${TLSDIR}/proxy.csr" "${TLSDIR}/ca-cert.srl"

echo "[generate-tls] Proxy cert: ${TLSDIR}/proxy-cert.pem"

# --- Lock down key files ---
chmod 600 "${TLSDIR}/ca-key.pem" "${TLSDIR}/proxy-key.pem"

echo "[generate-tls] TLS material generated successfully"
