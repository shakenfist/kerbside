#!/bin/bash
# Mint a demo token, find the console, and write a .vv file for it.
#
# Usage: ./get-console.sh [OUTPUT]     (default: ./demo-console.vv)
#
# Everything that talks to the API runs inside the kerbside container,
# so the only thing this needs on your machine is docker. No jq, no
# python, no curl, no openssl.

set -euo pipefail

cd "$(dirname "$0")"

OUTPUT="${1:-./demo-console.vv}"
# Deliberately not on the state volume. `kerbside demo token --output`
# writes it safely (O_NOFOLLOW, 0600), but the state volume outlives
# the run and already holds the CA private key and the signing seed;
# there is no reason for a bearer token to sit there for the life of
# the volume when it is useful for one HTTP request. /tmp is per
# container and this script removes the file when it is done.
TOKEN_FILE="/tmp/demo-token.$$"
API='http://127.0.0.1:13002'

cleanup() {
    docker compose exec -T kerbside rm -f "${TOKEN_FILE}" 2> /dev/null || true
}
trap cleanup EXIT

# ── Wait for the stack to finish starting ────────────────────────────
#
# `docker compose up -d` returns once the containers are created, but
# the kerbside entrypoint then generates TLS material, waits for the
# database, runs `kerbside db upgrade`, starts gunicorn and only then
# execs the daemon -- and the console list stays empty until the daemon
# has enumerated sources. Checking merely that the container is
# "running" would pass immediately and then fail further down with a
# misleading diagnosis: a missing seed file, a bare curl error, or "no
# consoles" blaming spice-target for a stack that is simply still
# booting.
#
# This waits on the compose healthcheck, which covers the API. The
# console list needs a token, so that wait happens after minting.
echo '[demo] Waiting for the stack to finish starting...'
DEADLINE=$(( $(date +%s) + 180 ))
while true; do
    STATE="$(docker compose ps kerbside --format '{{.Health}}' 2> /dev/null || true)"
    if [ "${STATE}" = 'healthy' ]; then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: the kerbside container did not become healthy" >&2
        echo "  within 180s. Current health: ${STATE:-unknown}" >&2
        echo "  Look at:  docker compose logs kerbside" >&2
        exit 1
    fi
    sleep 2
done

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

# ── Wait for the console list ────────────────────────────────────────
#
# A healthy API is not the same as a populated console list: the
# daemon enumerates sources on its own cycle, and the window between
# the two is exactly when a naive script reports "no consoles" and
# blames spice-target for a stack that is merely still starting. The
# list needs the token, which is why this waits here rather than
# alongside the health check above.
echo '[demo] Waiting for the console list...'
DEADLINE=$(( $(date +%s) + 120 ))
while true; do
    if docker compose exec -T kerbside bash -c '
            token=$(cat "$1")
            curl -sf -H "Authorization: Bearer ${token}" \
                -H "Accept: application/json" "$2/console" \
            | grep -q "\"uuid\""' _ "${TOKEN_FILE}" "${API}" 2> /dev/null; then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: no consoles appeared within 120s." >&2
        echo "  The API is up, so this is the daemon not enumerating" >&2
        echo "  demo/sources.yaml. Look at: docker compose logs kerbside" >&2
        exit 1
    fi
    sleep 2
done

# ── Find the console and fetch its .vv ───────────────────────────────
#
# Values that came from the API are passed to the remote shell as
# positional arguments, never spliced into the script text. As shipped
# the only input is demo/sources.yaml, which you wrote, so nothing here
# is attacker-controlled -- but this is the file in the repository most
# likely to be copied as the starting point for a real one, where the
# console list would come from a cloud. The argument form is also
# easier to read than the escaping it replaces.
echo '[demo] Looking up the console...'
CONSOLE="$(docker compose exec -T kerbside bash -c '
    set -euo pipefail
    token=$(cat "$1")
    curl --silent --fail --show-error \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/json" \
        "$2/console" \
    | python3 -c "
import json, sys
consoles = json.load(sys.stdin)
if not consoles:
    sys.exit(\"the console list is empty\")
c = consoles[0]
print(c[\"source\"], c[\"uuid\"], c[\"name\"])
"' _ "${TOKEN_FILE}" "${API}")"

read -r SOURCE UUID NAME <<< "${CONSOLE}"
echo "[demo] Console: ${NAME} (${SOURCE}/${UUID})"

echo '[demo] Fetching the .vv file...'
docker compose exec -T kerbside bash -c '
    set -euo pipefail
    token=$(cat "$1")
    curl --silent --fail --show-error \
        -H "Authorization: Bearer ${token}" \
        "$2/console/proxy/$3/$4/console.vv"
' _ "${TOKEN_FILE}" "${API}" "${SOURCE}" "${UUID}" > "${OUTPUT}"

# ── Prove the TLS leg actually works ─────────────────────────────────
#
# The quiet failure this demo most needs to avoid is a session running
# over the plaintext port while the TLS leg is broken: the console
# still appears, so it looks fine.
#
# Checking that the .vv merely *contains* tls-port= and ca= would not
# catch that. kerbside emits both unconditionally (api.py:481,483), so
# they are present whether or not the TLS listener works and whatever
# port the client ends up using. This connects to the port the .vv
# advertises and verifies the certificate against the CA embedded in
# that same .vv, then checks the presented subject is the one the .vv
# tells the client to expect -- which is what remote-viewer will do.
#
# check_hostname is off deliberately: SPICE identifies the server by
# host-subject rather than by SAN, which is why ryll's verifier relaxes
# hostname checking too. CA verification stays on.
echo '[demo] Verifying the TLS leg...'
docker compose exec -T kerbside python3 -c '
import re, socket, ssl, sys

vv = sys.stdin.read()

def field(name):
    m = re.search(r"^%s=(.*)$" % re.escape(name), vv, re.M)
    if not m:
        sys.exit("the .vv has no %s= field" % name)
    return m.group(1)

ca = field("ca").replace("\\n", "\n")
port = int(field("tls-port"))
want = field("host-subject")

ctx = ssl.create_default_context(cadata=ca)
ctx.check_hostname = False

try:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with ctx.wrap_socket(raw) as tls:
            peer = tls.getpeercert()
            version = tls.version()
except ssl.SSLError as e:
    sys.exit("TLS verification against the CA in the .vv failed: %s" % e)
except OSError as e:
    sys.exit("could not connect to the TLS port %d: %s" % (port, e))

short = {"countryName": "C", "organizationName": "O", "commonName": "CN",
         "stateOrProvinceName": "ST", "localityName": "L",
         "organizationalUnitName": "OU"}
got = {}
for rdn in peer.get("subject", ()):
    for key, value in rdn:
        got[short.get(key, key)] = value

for part in want.split(","):
    key, _, value = part.partition("=")
    if got.get(key.strip()) != value.strip():
        sys.exit("the certificate subject is %r, but the .vv says to "
                 "expect %r" % (got, want))

print("    %s, certificate verified against the CA in the .vv" % version)
print("    subject matches host-subject=%s" % want)
' < "${OUTPUT}"

echo "[demo] Wrote ${OUTPUT}"
echo
echo 'Open it with:'
echo "    remote-viewer ${OUTPUT}"
echo
echo 'Expect a black screen with BIOS text: the demo VM has no disk, so'
echo 'SeaBIOS reports "No bootable device". That IS the SPICE session.'
