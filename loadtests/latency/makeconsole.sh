#!/bin/bash
set -euo pipefail

test_image="uefi-latency-guest"
test_flavor="vdi-tiny"
test_identifier=$$

# Test if we need an image. Note the image requires UEFI.
echo "Determine if we already have a target image..."
image_id=$(openstack image show "${test_image}" -f json | jq -e -r ".id")
if [ -z "${image_id}" ]; then
    echo "Image is missing, downloading one."
    wget -O "/tmp/${test_image}.qcow2" \
        "https://images.shakenfist.com/testimages/${test_image}.qcow2"
    image_id=$(openstack image create --public --disk-format qcow2 \
        --container-format bare \
        --file "/tmp/${test_image}.qcow2" \
        "${test_image}" -f json | jq -e -r ".id")
    echo "Image ID is now ${image_id}"

    openstack image set --property hw_video_ram=64 "${image_id}"
    openstack image set --property hw_firmware_type=uefi "${image_id}"
fi

if [ -z "${image_id}" ]; then
    echo "Still no image! Abort."
    exit 1
fi

# Test if we have a flavor, the flavor however does not require UEFI
echo "Determine if we already have a target flavor..."
flavor_id=$(openstack flavor show "${test_flavor}" -f json | jq -e -r ".id")
if [ -z "${flavor_id}" ]; then
    echo "Flavor is missing, creating."
    openstack flavor create ${test_flavor} --ram 512 --disk 2 --vcpus 1 \
        --property hw_video:ram_max_mb=64

    flavor_id=$(openstack flavor show "${test_flavor}" -f json | jq -e -r ".id")
    echo "Flavor ID is now ${flavor_id}"
fi

if [ -z "${flavor_id}" ]; then
    echo "Still no flavor! Abort."
    exit 1
fi

# Start a target instance
echo
echo "Using image ${image_id} and flavor ${flavor_id}"
echo "Launch a target..."
instance_id=$(openstack server create --flavor "${flavor_id}" --image "${image_id}" \
    --network public1 "test-${test_identifier}" -f json | jq -e -r ".id")
if [ -z "${instance_id}" ]; then
    echo "Instance is missing, abort."
    exit 1
fi

echo
echo "Instance ID is ${instance_id}"

# Wait for instance to be active
instance_status="unknown"
while [ "${instance_status}" != "ACTIVE" ]; do
    sleep 2
    instance_status=$(openstack server show "${instance_id}" -f json | jq -e -r ".status")
    echo "    ... status is ${instance_status}"
done

# Request a console
console_url=$(openstack console url show "${instance_id}" --spice-direct -f json | \
    jq -e -r ".url")
if [ -z "${console_url}" ]; then
    echo "Instance console URL missing, abort."
    exit 1
fi
echo "Instance console URL is ${console_url}"

echo
echo "Connecting..."
mkdir -p /tmp/results

RYLL_SOCK=/tmp/ryll.sock
rm -f "${RYLL_SOCK}"

# Start ryll in headless mode with the control socket, then run the
# Python orchestrator against it.  The trap ensures ryll is killed
# on any exit path (normal, signal, or error).
ryll --headless --url "${console_url}" --control-socket "${RYLL_SOCK}" &
RYLL_PID=$!

cleanup_ryll() {
    if kill -0 "${RYLL_PID}" 2>/dev/null; then
        kill -TERM "${RYLL_PID}" 2>/dev/null || true
        wait "${RYLL_PID}" 2>/dev/null || true
    fi
}
trap cleanup_ryll EXIT

# Wait up to 30 s for the control socket to appear.
for _ in $(seq 1 60); do
    if [ -S "${RYLL_SOCK}" ]; then
        break
    fi
    sleep 0.5
done
if [ ! -S "${RYLL_SOCK}" ]; then
    echo "ryll control socket did not appear within 30s" >&2
    exit 1
fi

set +e
python3 /srv/orchestrator.py \
    --socket "${RYLL_SOCK}" \
    --output "/tmp/results/latency-${test_identifier}.csv"
ORCH_EXIT=$?
set -e

cleanup_ryll
trap - EXIT
exit ${ORCH_EXIT}
