#!/bin/bash
# Mint a demo token, find the console, and write a .vv file for it.
#
# Usage: ./get-console.sh [OUTPUT]     (default: ./demo-console.vv)
#
# Everything that talks to the API runs inside the kerbside container,
# so the only thing this needs on your machine is docker. No jq, no
# python, no curl.

set -euo pipefail

cd "$(dirname "$0")"

OUTPUT="${1:-./demo-console.vv}"
TOKEN_FILE='/var/lib/kerbside-demo/demo-token.txt'
API='http://127.0.0.1:13002'

if ! docker compose ps --status running --services 2> /dev/null \
        | grep -qx kerbside; then
    echo "ERROR: the kerbside container is not running." >&2
    echo "  Start the stack first:  docker compose up -d" >&2
    exit 1
fi

# ── Mint a bearer token ──────────────────────────────────────────────
#
# `kerbside demo token` is the only supported way to do this, and it is
# deliberate that there is no fallback here. If it refuses, the refusal
# is information: it declines unless every configured source is static,
# and it declines while AUTH_SECRET_SEED is still the unconfigured
# sentinel. Both hold for this stack, so a refusal means the seed
# generation in entrypoint.sh or the contents of sources.yaml are
# wrong, and hand-rolling a JWT around it would hide a real fault.
#
# --output rather than stdout: importing kerbside configures logging on
# stdout, so stdout is not a clean channel for a secret.
#
# This is a demonstration affordance standing in for authentication,
# not the intended user journey. Interactive login is Keystone-only
# today (issue #300) and the session JWT scheme has no revocation or
# issuance audit (issue #301).
echo '[demo] Minting a bearer token...'
docker compose exec -T kerbside kerbside-demo-env \
    kerbside demo token --subject demo-admin --output "${TOKEN_FILE}" \
    > /dev/null

# ── Find the console and fetch its .vv ───────────────────────────────
#
# The API is only published on loopback, but these run inside the
# container anyway so the published ports are not involved.
echo '[demo] Looking up the console...'
CONSOLE="$(docker compose exec -T kerbside bash -c "
    set -euo pipefail
    token=\$(cat '${TOKEN_FILE}')
    curl --silent --fail --show-error \
        -H \"Authorization: Bearer \${token}\" \
        -H 'Accept: application/json' \
        '${API}/console' \
    | python3 -c '
import json, sys
consoles = json.load(sys.stdin)
if not consoles:
    sys.exit(\"no consoles: is spice-target running?\")
c = consoles[0]
print(c[\"source\"], c[\"uuid\"], c[\"name\"])
'")"

read -r SOURCE UUID NAME <<< "${CONSOLE}"
echo "[demo] Console: ${NAME} (${SOURCE}/${UUID})"

echo '[demo] Fetching the .vv file...'
docker compose exec -T kerbside bash -c "
    set -euo pipefail
    token=\$(cat '${TOKEN_FILE}')
    curl --silent --fail --show-error \
        -H \"Authorization: Bearer \${token}\" \
        '${API}/console/proxy/${SOURCE}/${UUID}/console.vv'
" > "${OUTPUT}"

# ── Check the .vv is the TLS one ─────────────────────────────────────
#
# The quiet failure this demo most needs to avoid is working over the
# plaintext port while the TLS leg is broken: the console still appears,
# so it looks fine. These three fields are what make remote-viewer use
# TLS and verify the demo's self-signed CA without anything being
# installed in your trust store, so their absence is fatal rather than
# cosmetic.
MISSING=''
for field in 'tls-port=' 'host-subject=' 'ca=-----BEGIN CERTIFICATE-----'; do
    grep -qF "${field}" "${OUTPUT}" || MISSING="${MISSING} ${field}"
done
if [ -n "${MISSING}" ]; then
    echo "ERROR: ${OUTPUT} is missing:${MISSING}" >&2
    echo '  Without these the session would not use TLS, or would not' >&2
    echo '  verify the CA. Check KERBSIDE_CACERT_PATH and' >&2
    echo '  KERBSIDE_PROXY_HOST_SUBJECT in docker-compose.yml.' >&2
    exit 1
fi

echo "[demo] Wrote ${OUTPUT} (TLS, with the demo CA embedded)"
echo
echo 'Open it with:'
echo "    remote-viewer ${OUTPUT}"
echo
echo 'Expect a black screen with BIOS text: the demo VM has no disk, so'
echo 'SeaBIOS reports "No bootable device". That IS the SPICE session.'
