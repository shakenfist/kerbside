#!/bin/bash
# Import the Uncalibrated Sextant assertion-oracle image into Shaken Fist and
# boot it as a UEFI + SPICE instance in a fresh test namespace.
#
# Runs ON the SF primary. Uploads tests/fixtures/uncalibrated-sextant.qcow2 as
# a shared system artifact (so any namespace can boot from it), creates the
# vdie2e namespace with a generated key, and creates a UEFI, SPICE-console
# instance from the image, awaiting 'created'. Emits the instance uuid,
# namespace, and namespace key to /tmp/sf-e2e/instance.env.
#
# Sextant is a UEFI guest whose assertion oracle needs a working SPICE
# console, so the instance MUST enable UEFI and a SPICE video device.

set -euo pipefail

export no_proxy="${no_proxy:-}127.0.0.1,localhost"

SF_E2E_ROOT='/tmp/sf-e2e'
INSTANCE_ENV="${SF_E2E_ROOT}/instance.env"
NAMESPACE='vdie2e'
ARTIFACT_NAME='uncalibrated-sextant'
SF_BIN='/srv/shakenfist/venv/bin'

mkdir -p "${SF_E2E_ROOT}"

# The kerbside checkout (with the fixture) was copied to the primary by the
# deploy action; kerbside.env records where.
# shellcheck disable=SC1090,SC1091
. "${SF_E2E_ROOT}/kerbside.env"
QCOW2="${KERBSIDE_SRC}/tests/fixtures/uncalibrated-sextant.qcow2"

if [ ! -f "${QCOW2}" ]; then
    echo "ERROR: Sextant fixture not found at ${QCOW2}" >&2
    exit 1
fi

echo "[sf-e2e] Sourcing /etc/sf/sfrc"
# shellcheck disable=SC1091
. /etc/sf/sfrc

# ── Step 1: Upload the Sextant image as a shared system artifact ─────────────
#
# Mirrors build-smoke-cluster's `sf-client artifact upload <name> <path>
# --shared --no-checksum`. Uploaded under the system namespace (from sfrc),
# it is referenced by instances as sf://upload/system/<name>.

echo "[sf-e2e] Uploading ${ARTIFACT_NAME} from ${QCOW2}"
"${SF_BIN}/sf-client" artifact upload \
    "${ARTIFACT_NAME}" "${QCOW2}" --shared --no-checksum

# ── Step 2: Create the test namespace with a generated key ───────────────────

NAMESPACE_KEY="$(openssl rand -hex 16)"
export NAMESPACE NAMESPACE_KEY ARTIFACT_NAME INSTANCE_ENV

echo "[sf-e2e] Creating namespace ${NAMESPACE} and booting the Sextant instance"
"${SF_BIN}/python3" - << 'PYEOF'
import json
import os
import sys
import time

from shakenfist_client import apiclient

namespace = os.environ['NAMESPACE']
namespace_key = os.environ['NAMESPACE_KEY']
artifact_name = os.environ['ARTIFACT_NAME']
instance_env = os.environ['INSTANCE_ENV']
sf_url = os.environ.get('SHAKENFIST_API_URL', 'http://localhost:13000')

system = apiclient.Client(async_strategy=apiclient.ASYNC_BLOCK)

# Fresh namespace with a single generated key.
if namespace in system.get_namespaces():
    system.delete_namespace(namespace)
system.create_namespace(namespace)
system.add_namespace_key(namespace, 'e2e', namespace_key)

client = apiclient.Client(
    base_url=sf_url, namespace=namespace, key=namespace_key,
    async_strategy=apiclient.ASYNC_BLOCK)

# A UEFI, SPICE-console instance booting from the shared uploaded image. The
# server defaults an unspecified vdi to 'spice', but we set it explicitly so
# the kerbside shakenfist source (which filters on video['vdi'] startswith
# 'spice') reliably scrapes this console. secure_boot is left off: the
# Sextant fixture boots plain UEFI, matching the direct-qemu lane's OVMF.
disk = [{
    'size': 1,
    'base': 'sf://upload/system/%s' % artifact_name,
    'type': 'disk',
}]
video = {'model': 'cirrus', 'memory': 16384, 'vdi': 'spice'}

inst = client.create_instance(
    'sextant-%d' % int(time.time()), 1, 512,
    None, disk, None, None,
    namespace=namespace, video=video, uefi=True)
uuid = inst['uuid']
print('[sf-e2e] created instance %s (state=%s)' % (uuid, inst['state']))

# Await 'created'. create_instance already blocks past initial/creating, but
# confirm we reached created rather than error, with a generous ceiling.
deadline = time.time() + 300
state = inst['state']
while state not in ('created', 'error') and time.time() < deadline:
    time.sleep(3)
    inst = client.get_instance(uuid)
    state = inst['state']

if state != 'created':
    sys.stderr.write(
        '[sf-e2e] ERROR: instance %s did not reach created (state=%s)\n'
        % (uuid, state))
    sys.stderr.write(json.dumps(inst, indent=4, sort_keys=True) + '\n')
    sys.exit(1)

print('[sf-e2e] instance %s is created' % uuid)

with open(instance_env, 'w') as f:
    f.write('INSTANCE_UUID=%s\n' % uuid)
    f.write('SF_NAMESPACE=%s\n' % namespace)
    f.write('SF_NAMESPACE_KEY=%s\n' % namespace_key)
    f.write('SF_URL=%s\n' % sf_url)
print('[sf-e2e] wrote %s' % instance_env)
PYEOF

echo "[sf-e2e] Sextant instance import complete"
