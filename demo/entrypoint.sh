#!/bin/bash
# Entrypoint for the kerbside demo container.
#
# Brings up both kerbside processes in one container: the REST API
# under gunicorn, and the SPICE proxy daemon. That is NOT the shape a
# production deployment should copy -- see the note above the exec at
# the bottom of this file, and demo/README.md.
#
# Everything this generates (the CA, the proxy certificate, the JWT
# signing seed) goes in ${STATE_DIR}, which docker-compose.yml backs
# with a named volume. `docker compose down -v` removes it and the next
# `up` generates fresh material.

set -euo pipefail

STATE_DIR="${KERBSIDE_DEMO_STATE_DIR:-/var/lib/kerbside-demo}"
TLS_DIR="${STATE_DIR}/tls"
SEED_FILE="${STATE_DIR}/auth-seed.txt"

# The API port is a gunicorn argument, not a kerbside setting: there is
# no KERBSIDE_API_PORT and grepping config.py for one finds nothing.
# Every other value in this stack arrives as an environment variable,
# so this one is easy to look for in the wrong place.
API_PORT="${KERBSIDE_DEMO_API_PORT:-13002}"

mkdir -p "${STATE_DIR}"

# ── TLS material ─────────────────────────────────────────────────────
#
# generate-tls.sh always regenerates and never reuses, so the skip has
# to happen out here. Regenerating on every restart would invalidate
# the CA embedded in any .vv file already fetched.
#
# The certificates are issued for 30 days and the state volume outlives
# `compose restart`, `stop`/`start` and host reboots, so a stack left up
# long enough would go on serving an expired certificate and fail CA
# verification with no hint that `down -v` is the fix. -checkend gives
# the skip an expiry escape hatch: reuse only while the certificate has
# more than a day left.
if [ -f "${TLS_DIR}/proxy-cert.pem" ] \
        && openssl x509 -checkend 86400 -noout \
            -in "${TLS_DIR}/proxy-cert.pem" 2> /dev/null; then
    echo "[demo] Reusing TLS material in ${TLS_DIR}"
else
    if [ -f "${TLS_DIR}/proxy-cert.pem" ]; then
        echo "[demo] TLS material has expired or is about to; regenerating."
        echo "[demo] Any .vv file fetched earlier will stop working: run"
        echo "[demo] ./get-console.sh again to get one with the new CA."
    fi
    echo "[demo] Generating TLS material in ${TLS_DIR}"
    /usr/local/lib/kerbside-demo/generate-tls.sh "${TLS_DIR}"
fi

# ── JWT signing seed ─────────────────────────────────────────────────
#
# Generated per deployment, never baked in. Issue #131 is precisely the
# failure of shipping a known signing key: anyone who knows the seed can
# forge a token for any user. Persisting it across restarts is what lets
# a token minted at `up` still work afterwards.
#
# It is generated here rather than set in kerbside.ini so that no secret
# is ever written to a committed file. Environment beats INI, so it wins
# regardless of what the mounted file says.
if [ ! -f "${SEED_FILE}" ]; then
    echo "[demo] Generating a new JWT signing seed"
    openssl rand -hex 32 > "${SEED_FILE}"
    chmod 600 "${SEED_FILE}"
fi

# The certificate paths and the seed are exported by the shared module,
# which `docker compose exec ... kerbside-demo-env` also sources. One
# definition, so a process started by exec sees exactly what PID 1 sees.
# shellcheck source=demo/demo-env.sh
. /usr/local/lib/kerbside-demo/demo-env.sh

# ── Wait for the database ────────────────────────────────────────────
#
# The compose healthcheck covers most of this, but "mariadb-admin ping
# answers" and "the kerbside user can authenticate against the kerbside
# database" are not the same event, and `kerbside db upgrade` needs the
# second one.
echo "[demo] Waiting for the database..."
DEADLINE=$(( $(date +%s) + 60 ))
while true; do
    if python3 -c 'import sqlalchemy, os; \
sqlalchemy.create_engine(os.environ["KERBSIDE_SQL_URL"]).connect().close()' \
            2> /dev/null; then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: the database did not accept a connection within 60s" >&2
        echo "  one-shot attempt, with the error:" >&2
        python3 -c 'import sqlalchemy, os; \
sqlalchemy.create_engine(os.environ["KERBSIDE_SQL_URL"]).connect().close()' >&2
        exit 1
    fi
    sleep 1
done
echo "[demo] Database is accepting connections"

echo "[demo] Running kerbside db upgrade"
kerbside db upgrade

# ── REST API (gunicorn) ──────────────────────────────────────────────
#
# Logs to stdout rather than to files: this is a container, and the
# evaluator reads `docker compose logs`.
echo "[demo] Starting gunicorn on 0.0.0.0:${API_PORT}"
gunicorn \
    --bind "0.0.0.0:${API_PORT}" \
    --workers 2 \
    --access-logfile - \
    --error-logfile - \
    'kerbside.api:app' &

echo "[demo] Waiting for the API on port ${API_PORT}..."
DEADLINE=$(( $(date +%s) + 60 ))
while true; do
    if curl --max-time 1 --output /dev/null --silent --fail \
            "http://127.0.0.1:${API_PORT}/" \
            -H 'Accept: application/json' 2> /dev/null; then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: the kerbside API did not come up within 60s" >&2
        exit 1
    fi
    sleep 0.5
done
echo "[demo] REST API up on port ${API_PORT}"

# ── SPICE proxy daemon ───────────────────────────────────────────────
#
# exec, so the daemon becomes PID 1: if it dies, the container exits and
# compose reports it. Backgrounding both processes and waiting would
# hide exactly the failure that matters most.
#
# Two processes in one container is a demo convenience, not a pattern to
# copy. In a real deployment they are separate units or containers that
# share API_SOCKET_PATH -- the proxy must be co-located with the daemon
# to reach that unix socket, which docs/configuration.md records against
# the API_SOCKET_PATH setting.
echo "[demo] Starting kerbside daemon run"
exec kerbside daemon run
