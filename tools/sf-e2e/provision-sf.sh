#!/bin/bash
# Provision the Kerbside integration in a single-node Shaken Fist cluster.
#
# Runs ON the SF primary node. Sets the cluster-wide KERBSIDE_URL and
# KERBSIDE_TOKEN_DURATION, ensures a VDI-token signing key exists, and
# restarts sf-api so the process-cached KERBSIDE_URL takes effect (SF reads
# it into config at process start).
#
# Usage: provision-sf.sh KERBSIDE_URL TOKEN_DURATION
#
# KERBSIDE_URL is BOTH the exchange-URL base and the token audience; it must
# equal kerbside's SF_CONSOLE_TOKEN_AUDIENCE byte-for-byte.
#
# SECURITY: prints the active signing kid and key count for diagnostics, but
# never any key material.

set -euo pipefail

KERBSIDE_URL="${1:?Usage: $0 KERBSIDE_URL TOKEN_DURATION}"
TOKEN_DURATION="${2:?Usage: $0 KERBSIDE_URL TOKEN_DURATION}"

SF_BIN='/srv/shakenfist/venv/bin'
SF_API='http://localhost:13000'

echo "[sf-e2e] Sourcing /etc/sf/sfrc"
# shellcheck disable=SC1091
. /etc/sf/sfrc

echo "[sf-e2e] Setting KERBSIDE_URL=${KERBSIDE_URL}"
"${SF_BIN}/sf-ctl" set-config KERBSIDE_URL "${KERBSIDE_URL}"

echo "[sf-e2e] Setting KERBSIDE_TOKEN_DURATION=${TOKEN_DURATION}"
"${SF_BIN}/sf-ctl" set-config KERBSIDE_TOKEN_DURATION "${TOKEN_DURATION}"

echo "[sf-e2e] Ensuring a Kerbside VDI-token signing key exists"
"${SF_BIN}/sf-ctl" ensure-kerbside-signing-key

# Report the active kid + key count without ever printing key material. The
# published key set is safe to read (it is public), so pull it from the
# admin endpoint via the system client and summarise.
echo "[sf-e2e] Published signing-key summary (no key material):"
"${SF_BIN}/python3" - << 'PYEOF'
from shakenfist_client import apiclient

# Client() with no explicit args reads SHAKENFIST_API_URL / _NAMESPACE / _KEY
# from the environment, which /etc/sf/sfrc has exported (namespace: system).
client = apiclient.Client(async_strategy=apiclient.ASYNC_BLOCK)
material = client.get_vdi_token_public_keys()
kids = [k.get('kid') for k in material.get('keys', [])]
print('[sf-e2e]   active_kid=%s' % material.get('active_kid'))
print('[sf-e2e]   key_count=%d' % len(kids))
print('[sf-e2e]   kids=%s' % ', '.join(str(k) for k in kids))
PYEOF

echo "[sf-e2e] Restarting sf-api so KERBSIDE_URL takes effect"
sudo systemctl restart sf-api

echo "[sf-e2e] Waiting for the SF API on ${SF_API}..."
DEADLINE=$(( $(date +%s) + 120 ))
while true; do
    if curl --max-time 2 --silent --output /dev/null --fail "${SF_API}/"; then
        break
    fi
    if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
        echo "ERROR: SF API did not answer on ${SF_API} within 120s" >&2
        sudo systemctl status sf-api --no-pager >&2 || true
        exit 1
    fi
    sleep 2
done

echo "[sf-e2e] SF provisioning complete; API is up on ${SF_API}"
