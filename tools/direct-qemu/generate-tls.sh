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
#   qemu-x509/      SPICE server material for a TLS-enabled qemu backend, laid
#                   out with the fixed filenames qemu's -spice x509-dir=
#                   expects: ca-cert.pem (copy of the CA above),
#                   server-cert.pem (subject C=US,O=Kerbside CI,CN=qemu-hv,
#                   deliberately NO SAN entries -- real SPICE server certs
#                   typically lack them, and host_subject pinning is what
#                   identifies the server), server-key.pem.
#
# Always regenerates; never reuses existing material.
# Part of docs/plans/PLAN-test-harness-phase-05-direct-qemu-ci.md step 5b and
# docs/plans/PLAN-host-subject-phase-02-kerbside-adoption.md step 2b.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 TLSDIR" >&2
    exit 1
fi

TLSDIR="$1"
mkdir -p "${TLSDIR}"

echo "[generate-tls] Writing TLS material to ${TLSDIR}"

# --- CA key and self-signed cert ---
#
# Emit X.509 v3 explicitly via -addext.  `openssl req -x509` in
# 3.x defaults to v3, but older toolchains (and `openssl x509
# -req` further down) silently produce v1 when no extensions are
# present, and rustls/webpki rejects v1 with UnsupportedCertVersion.
openssl genrsa -out "${TLSDIR}/ca-key.pem" 2048 2>/dev/null

openssl req \
    -new \
    -x509 \
    -days 30 \
    -key "${TLSDIR}/ca-key.pem" \
    -out "${TLSDIR}/ca-cert.pem" \
    -subj '/CN=kerbside-ci-ca' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign'

echo "[generate-tls] CA cert: ${TLSDIR}/ca-cert.pem"

# --- Proxy key and CSR ---
openssl genrsa -out "${TLSDIR}/proxy-key.pem" 2048 2>/dev/null

openssl req \
    -new \
    -key "${TLSDIR}/proxy-key.pem" \
    -out "${TLSDIR}/proxy.csr" \
    -subj '/C=US/O=Kerbside CI/CN=kerbside-ci'

# --- Sign the proxy cert with our CA ---
#
# Add server-cert extensions via -extfile.  Without these,
# `openssl x509 -req` emits a v1 certificate (no extensions ⇒ v1),
# which rustls's webpki verifier rejects outright with
# UnsupportedCertVersion.  Including a SAN covering the loopback
# address keeps modern TLS clients happy even though ryll's
# SpiceCaVerifier currently tolerates hostname mismatches.
cat > "${TLSDIR}/proxy-ext.cnf" << 'EOF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1, DNS:localhost
EOF

openssl x509 \
    -req \
    -days 30 \
    -in "${TLSDIR}/proxy.csr" \
    -CA "${TLSDIR}/ca-cert.pem" \
    -CAkey "${TLSDIR}/ca-key.pem" \
    -CAcreateserial \
    -extfile "${TLSDIR}/proxy-ext.cnf" \
    -out "${TLSDIR}/proxy-cert.pem" \
    2>/dev/null

rm -f "${TLSDIR}/proxy.csr" "${TLSDIR}/ca-cert.srl" "${TLSDIR}/proxy-ext.cnf"

echo "[generate-tls] Proxy cert: ${TLSDIR}/proxy-cert.pem"

# --- QEMU SPICE server key and cert (the backend the proxy connects to) ---
#
# Signed by the same CA, subject C=US,O=Kerbside CI,CN=qemu-hv, and
# deliberately NO subjectAltName: real SPICE server certificates typically
# lack SANs (which is why the proxy's backend verifier relaxes hostname
# checking), and the console's host_subject pin is what identifies the
# server. Extensions are still required so the cert is X.509 v3 -- webpki
# rejects v1 with UnsupportedCertVersion (same reason as the proxy cert).
# Laid out in qemu-x509/ with the fixed filenames -spice x509-dir= expects.
QEMU_X509_DIR="${TLSDIR}/qemu-x509"
mkdir -p "${QEMU_X509_DIR}"

openssl genrsa -out "${QEMU_X509_DIR}/server-key.pem" 2048 2>/dev/null

openssl req \
    -new \
    -key "${QEMU_X509_DIR}/server-key.pem" \
    -out "${QEMU_X509_DIR}/server.csr" \
    -subj '/C=US/O=Kerbside CI/CN=qemu-hv'

cat > "${QEMU_X509_DIR}/server-ext.cnf" << 'EOF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

openssl x509 \
    -req \
    -days 30 \
    -in "${QEMU_X509_DIR}/server.csr" \
    -CA "${TLSDIR}/ca-cert.pem" \
    -CAkey "${TLSDIR}/ca-key.pem" \
    -CAcreateserial \
    -extfile "${QEMU_X509_DIR}/server-ext.cnf" \
    -out "${QEMU_X509_DIR}/server-cert.pem" \
    2>/dev/null

cp "${TLSDIR}/ca-cert.pem" "${QEMU_X509_DIR}/ca-cert.pem"
rm -f "${QEMU_X509_DIR}/server.csr" "${QEMU_X509_DIR}/server-ext.cnf" \
      "${TLSDIR}/ca-cert.srl"

echo "[generate-tls] QEMU SPICE server cert: ${QEMU_X509_DIR}/server-cert.pem"

# --- Lock down key files ---
chmod 600 "${TLSDIR}/ca-key.pem" "${TLSDIR}/proxy-key.pem" \
          "${QEMU_X509_DIR}/server-key.pem"

echo "[generate-tls] TLS material generated successfully"
