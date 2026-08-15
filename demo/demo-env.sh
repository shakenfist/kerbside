# shellcheck shell=bash
#
# Shared environment for the demo container. Sourced, not executed,
# which is why there is no shebang and why shellcheck needs telling
# which shell to assume.
#
# This exists because `docker compose exec` does not inherit anything
# the entrypoint exported: it starts a fresh process from the image's
# ENV plus the compose `environment:` block, so a second process in the
# container sees neither the generated signing seed nor the generated
# certificate paths. Without this, `kerbside demo token` run via exec
# falls back to the unconfigured sentinel and refuses to mint -- which
# is the guard working correctly, on a container that is in fact
# configured.
#
# The seed is read from the state volume rather than passed on a
# command line, so it never appears in `ps` or in `docker inspect`, and
# never in a file committed to this repository.
#
# Both entrypoint.sh and the kerbside-demo-env wrapper source this. The
# entrypoint generates the material first; the wrapper assumes it is
# already there.

STATE_DIR="${KERBSIDE_DEMO_STATE_DIR:-/var/lib/kerbside-demo}"
TLS_DIR="${STATE_DIR}/tls"
SEED_FILE="${STATE_DIR}/auth-seed.txt"

export KERBSIDE_CACERT_PATH="${TLS_DIR}/ca-cert.pem"
export KERBSIDE_PROXY_HOST_CERT_PATH="${TLS_DIR}/proxy-cert.pem"
export KERBSIDE_PROXY_HOST_CERT_KEY_PATH="${TLS_DIR}/proxy-key.pem"

if [ ! -f "${SEED_FILE}" ]; then
    echo "ERROR: no signing seed at ${SEED_FILE}." >&2
    echo "  The kerbside container generates it at startup, so this" >&2
    echo "  means the stack has not come up yet. Try:" >&2
    echo "      docker compose up -d" >&2
    exit 1
fi

KERBSIDE_AUTH_SECRET_SEED="$(cat "${SEED_FILE}")"
export KERBSIDE_AUTH_SECRET_SEED
