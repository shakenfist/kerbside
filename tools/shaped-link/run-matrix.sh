#!/bin/bash
# Shaped-link keypress-to-draw measurement for kerbside-proxy.
#
# Runs a matrix of (link profile x screen activity x proxy socket
# settings) cases and writes one results directory per case. The
# procedure, the host it was last run on and the results are in
# docs/performance/proxy-backpressure.md; read that first.
#
# Topology, all unprivileged. The script re-executes itself under
# `unshare -rn` (a user plus network namespace, "server side"), where it
# runs qemu (the keydraw guest), mock-grpc-server.py and kerbside-proxy
# on 10.77.0.1. ryll runs in a nested network namespace ("client side",
# 10.77.0.2) joined to the server side by a veth pair. Only that veth
# pair is shaped, in both directions, with netem delay plus rate; the
# proxy's backend leg to qemu stays on the unshaped loopback.
#
#   ryll --(veth, shaped)--> kerbside-proxy --(loopback)--> qemu
#
# Usage: run-matrix.sh
#
# Inputs (environment):
#   WORKDIR        results and scratch (default ./shaped-link-results)
#   PROXY_BIN      kerbside-proxy binary (default: release build in-tree)
#   RYLL_BIN       ryll built by build-ryll.sh (required)
#   GUEST_DIR      vmlinuz + initrd.gz from build-guest.sh (required
#                  unless DISPLAYS names a guest per display)
#   MOCK_PYTHON    python with grpcio and kerbside importable
#                  (default: .tox/py3/bin/python)
#   PROFILES       "rtt_ms:rate_mbit ..." (default "20:50 80:10"; a
#                  rate of 0 leaves the veth unshaped, e.g. "0:0")
#   ACTIVITIES     "name:fps:noise_bits ..." (fps 0 = idle;
#                  default "idle:0:0 busy:30:3")
#   CONFIGS        "name:notsent_lowat:backend_rcvbuf ..." (0 disables;
#                  default "stock:0:0 tuned:131072:262144")
#   DISPLAYS       "name:qemu_bin:streaming_video:guest_dir ..." -- the
#                  display side of each case, interleaved with CONFIGS.
#                  streaming_video is off, all, filter or "default"
#                  (qemu's own default, which is off); guest_dir holds
#                  a build-guest.sh output, so a guest with a patched
#                  drm_kms_helper.ko (build-guest.sh KMS_HELPER=) can be
#                  compared with a stock one. Default: one display,
#                  qemu-system-x86_64 from PATH, qemu's default
#                  streaming, GUEST_DIR. Case names gain a "<name>-"
#                  prefix only when DISPLAYS is set.
#   REPEATS        passes over the matrix (default 2); configs are
#                  interleaved inside each pass to spread drift evenly
#   SAMPLES        key presses per case (default 40)
#   ACTIVITY_DELAY seconds after guest boot before the activity starts
#                  (default 0). Set it when a display streams, because
#                  spice-server 0.15.2 segfaults when a client connects
#                  while streams exist; about 8 s puts the start after
#                  ryll has connected
#   WARMUP         seconds between ryll connecting and the first key
#                  press (default 5); keep it past ACTIVITY_DELAY
#   BUFFER_BDP     bottleneck queue per direction in BDPs (default 1)
#   RYLL_ARGS      extra ryll arguments, e.g. -v to log display
#                  traffic for upstream/qemu/rig/tools/ryllana.py in
#                  kerbside-patches (default none; -v costs client CPU)
#   CC             congestion control for the server namespace, which
#                  is the sender of display traffic on the shaped leg
#                  (default: the kernel's; "bbr" needs the tcp_bbr
#                  module loaded on the host first, as root)
#
# Each case writes WORKDIR/<profile>/<activity>/<config>-r<N>/ with
# keydraw.csv/.json (latency samples and draw counts), metrics-{0,1}.txt
# (proxy /metrics before and after), ss.txt (`ss -tinm` every 0.5 s on
# the server side) and logs. summarise.py turns WORKDIR into tables.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DQ="${REPO_ROOT}/tools/direct-qemu"

WORKDIR="$(realpath -m "${WORKDIR:-./shaped-link-results}")"
PROXY_BIN="${PROXY_BIN:-${REPO_ROOT}/rust/kerbside-proxy/target/release/kerbside-proxy}"
RYLL_BIN="${RYLL_BIN:?set RYLL_BIN to a ryll built by build-ryll.sh}"
if [ -z "${DISPLAYS:-}" ]; then
    GUEST_DIR="${GUEST_DIR:?set GUEST_DIR to build-guest.sh output, or set DISPLAYS}"
fi
MOCK_PYTHON="${MOCK_PYTHON:-${REPO_ROOT}/.tox/py3/bin/python}"
PROFILES="${PROFILES:-20:50 80:10}"
ACTIVITIES="${ACTIVITIES:-idle:0:0 busy:30:3}"
CONFIGS="${CONFIGS:-stock:0:0 tuned:131072:262144}"
DISPLAYS_SET="${DISPLAYS:+1}"
DISPLAYS="${DISPLAYS:-default:qemu-system-x86_64:default:${GUEST_DIR}}"
REPEATS="${REPEATS:-2}"
SAMPLES="${SAMPLES:-40}"
ACTIVITY_DELAY="${ACTIVITY_DELAY:-0}"
WARMUP="${WARMUP:-5}"
BUFFER_BDP="${BUFFER_BDP:-1}"
CC="${CC:-}"
read -r -a RYLL_EXTRA <<< "${RYLL_ARGS:-}"
TC=/usr/sbin/tc
ETHTOOL=/usr/sbin/ethtool

SERVER_IP=10.77.0.1
CLIENT_IP=10.77.0.2
SPICE_PORT=5910
PROXY_SECURE_PORT=5900
PROXY_INSECURE_PORT=5901
PROM_PORT=13030
TICKET='shaped-link-ticket'
# Unix socket paths must stay under ~108 bytes, so they do not live in
# WORKDIR.
SOCK_DIR="$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/sl.XXXXXX")"

log() { echo "[shaped-link] $*" >&2; }

# ── Re-exec inside a user + network namespace ────────────────────────────────

if [ -z "${SHAPED_LINK_INNER:-}" ]; then
    for f in "${PROXY_BIN}" "${RYLL_BIN}" "${MOCK_PYTHON}"; do
        if [ ! -e "${f}" ]; then
            echo "ERROR: ${f} not found" >&2
            exit 1
        fi
    done
    for display in ${DISPLAYS}; do
        IFS=: read -r _ dqemu dstream dguest <<< "${display}"
        case "${dstream}" in
            default|off|all|filter) ;;
            *) echo "ERROR: streaming_video ${dstream} is not off, all, filter or default" >&2
               exit 1 ;;
        esac
        command -v "${dqemu}" >/dev/null || { echo "ERROR: ${dqemu} not found" >&2; exit 1; }
        for f in "${dguest}/vmlinuz" "${dguest}/initrd.gz"; do
            [ -e "${f}" ] || { echo "ERROR: ${f} not found" >&2; exit 1; }
        done
    done
    mkdir -p "${WORKDIR}"
    rmdir "${SOCK_DIR}"
    SHAPED_LINK_INNER=1 exec unshare --user --map-root-user --net \
        env SHAPED_LINK_INNER=1 WORKDIR="${WORKDIR}" "$0" "$@"
fi

# ── Server-side namespace setup ──────────────────────────────────────────────

PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "${pid}" 2>/dev/null || true
    done
    rm -rf "${SOCK_DIR}"
}
trap cleanup EXIT

ip link set lo up
if [ -n "${CC}" ]; then
    echo "${CC}" > /proc/sys/net/ipv4/tcp_congestion_control
fi

# The client namespace is held open by a sleeper; everything client side
# runs through nsenter into it.
unshare --net sleep infinity &
CLIENT_NS_PID=$!
PIDS+=("${CLIENT_NS_PID}")
sleep 0.5
in_client() { nsenter --target "${CLIENT_NS_PID}" --net -- "$@"; }

ip link add sl0 type veth peer name sl1
ip link set sl1 netns "${CLIENT_NS_PID}"
ip addr add "${SERVER_IP}/24" dev sl0
ip link set sl0 up
in_client ip link set lo up
in_client ip addr add "${CLIENT_IP}/24" dev sl1
in_client ip link set sl1 up
# netem's queue limit counts packets, so it must see MTU-sized packets,
# not 64k GSO super-packets. Turning the offloads off is not enough: TCP
# always builds GSO packets and the device segments them after the
# qdisc. Capping the device's GSO size is what makes TCP send one MSS
# per skb.
for dev in sl0 sl1; do
    ns=()
    [ "${dev}" = sl1 ] && ns=(nsenter --target "${CLIENT_NS_PID}" --net --)
    "${ns[@]}" ip link set "${dev}" gso_max_size 1500 gso_max_segs 1
    "${ns[@]}" "${ETHTOOL}" -K "${dev}" tso off gso off gro off >/dev/null
done

{
    echo "kernel: $(uname -r)"
    for s in net/ipv4/tcp_wmem net/ipv4/tcp_rmem net/core/rmem_max \
            net/core/wmem_max net/ipv4/tcp_notsent_lowat \
            net/ipv4/tcp_congestion_control; do
        echo "${s}: $(tr '\t' ' ' < "/proc/sys/${s}")"
    done
    for display in ${DISPLAYS}; do
        IFS=: read -r dname dqemu dstream dguest <<< "${display}"
        echo "display ${dname}: $("${dqemu}" --version | head -1)," \
            "streaming-video ${dstream}, guest ${dguest}"
    done
    echo "ryll: ${RYLL_BIN}"
    echo "proxy: ${PROXY_BIN}"
    if [ -w /dev/kvm ]; then echo 'accel: kvm'; else echo 'accel: tcg'; fi
} > "${WORKDIR}/host.txt"
cat "${WORKDIR}/host.txt" >&2

# One-way netem on each veth end: half the RTT as delay, the full rate,
# and a queue of BUFFER_BDP bandwidth-delay products on top of the
# packets that are sitting in the delay line.
shape() {
    local rtt_ms="$1" rate_mbit="$2"
    local limit
    if [ "${rate_mbit}" = '0' ]; then
        "${TC}" qdisc del dev sl0 root 2>/dev/null || true
        in_client "${TC}" qdisc del dev sl1 root 2>/dev/null || true
        log 'unshaped (veth only)'
        return
    fi
    limit=$(( (rate_mbit * 1000 * (rtt_ms / 2 + BUFFER_BDP * rtt_ms)) / (8 * 1500) + 10 ))
    local qdisc=(netem delay "$(( rtt_ms / 2 ))ms" rate "${rate_mbit}mbit" limit "${limit}")
    "${TC}" qdisc replace dev sl0 root "${qdisc[@]}"
    in_client "${TC}" qdisc replace dev sl1 root "${qdisc[@]}"
    log "shaped: rtt ${rtt_ms}ms rate ${rate_mbit}mbit limit ${limit} pkts per direction"
}

# ── Long-lived pieces: TLS material and the mock control plane ───────────────

"${DQ}/generate-tls.sh" "${WORKDIR}/tls" >/dev/null
GRPC_SOCKET="${SOCK_DIR}/grpc.sock"
PYTHONPATH="${REPO_ROOT}" "${MOCK_PYTHON}" "${DQ}/mock-grpc-server.py" \
    --socket "${GRPC_SOCKET}" --hypervisor-ip 127.0.0.1 \
    --insecure-port "${SPICE_PORT}" --secure-port 0 --ticket "${TICKET}" \
    > "${WORKDIR}/mock-grpc.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 60); do
    [ -S "${GRPC_SOCKET}" ] && break
    sleep 0.25
done
[ -S "${GRPC_SOCKET}" ] || { echo 'ERROR: mock gRPC server did not start' >&2; exit 1; }

PROXY_SUBJECT='C=US,O=Kerbside CI,CN=kerbside-ci'
CA_ESCAPED="$(sed ':a;N;$!ba;s/\n/\\n/g' "${WORKDIR}/tls/ca-cert.pem")"
CONSOLE_VV="${WORKDIR}/console.vv"
cat > "${CONSOLE_VV}" << EOF
[virt-viewer]
type=spice
host=${SERVER_IP}
port=${PROXY_INSECURE_PORT}
tls-port=${PROXY_SECURE_PORT}
password=shaped-link-any-token-works
delete-this-file=0
tls-ciphers=DEFAULT
ca=${CA_ESCAPED}
host-subject=${PROXY_SUBJECT}
EOF

wait_port() {
    local port="$1"
    for _ in $(seq 60); do
        if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

stop_pid() {
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}

# ── One case ─────────────────────────────────────────────────────────────────

run_case() {
    local out="$1" fps="$2" noise="$3" lowat="$4" rcvbuf="$5"
    local qemu="$6" streaming="$7" guest="$8"
    mkdir -p "${out}"
    log "case ${out#"${WORKDIR}"/}"

    local spice="port=${SPICE_PORT},addr=127.0.0.1,password-secret=spice-ticket"
    if [ "${streaming}" != 'default' ]; then
        spice="${spice},streaming-video=${streaming}"
    fi
    "${qemu}" -machine accel=kvm:tcg -m 512 -smp 2 \
        -kernel "${guest}/vmlinuz" -initrd "${guest}/initrd.gz" \
        -append "console=ttyS0 loglevel=4 rdinit=/init kd.fps=${fps} kd.noise=${noise} kd.delay=${ACTIVITY_DELAY}" \
        -vga none -device virtio-vga \
        -object "secret,id=spice-ticket,data=${TICKET}" \
        -spice "${spice}" \
        -serial "file:${out}/serial.log" -display none \
        > "${out}/qemu.log" 2>&1 &
    local qemu_pid=$!
    wait_port "${SPICE_PORT}" || { log 'qemu SPICE port never opened'; return 1; }

    "${DQ}/start-rust-proxy.sh" --tls-dir "${WORKDIR}/tls" \
        --api-socket "${GRPC_SOCKET}" --pid-file "${out}/proxy.pid" \
        --log-path "${out}/proxy.log" --binary "${PROXY_BIN}" \
        --secure-port "${PROXY_SECURE_PORT}" \
        --insecure-port "${PROXY_INSECURE_PORT}" \
        --prometheus-port "${PROM_PORT}" --host-subject "${PROXY_SUBJECT}" \
        -- --client-notsent-lowat-bytes "${lowat}" \
        --backend-rcvbuf-bytes "${rcvbuf}" > "${out}/start-proxy.log" 2>&1
    local proxy_pid
    proxy_pid="$(cat "${out}/proxy.pid")"

    # Give the guest time to boot and start drawing before connecting.
    sleep 3
    local ryll_sock="${SOCK_DIR}/ryll.sock"
    rm -f "${ryll_sock}"
    in_client "${RYLL_BIN}" --headless --file "${CONSOLE_VV}" \
        --control-socket "${ryll_sock}" "${RYLL_EXTRA[@]}" > "${out}/ryll.out" 2> "${out}/ryll.err" &
    local ryll_pid=$!
    for _ in $(seq 80); do
        [ -S "${ryll_sock}" ] && break
        sleep 0.25
    done

    (
        while true; do
            echo "@ $(date +%s.%N)"
            ss -tinmH state established
            sleep 0.5
        done
    ) > "${out}/ss.txt" 2>/dev/null &
    local ss_pid=$!

    curl -s "http://127.0.0.1:${PROM_PORT}/metrics" > "${out}/metrics-0.txt" || true
    date +%s.%N > "${out}/t0"
    local rc=0
    python3 "${SCRIPT_DIR}/keydraw-latency.py" --socket "${ryll_sock}" \
        --output-prefix "${out}/keydraw" --samples "${SAMPLES}" \
        --warmup "${WARMUP}" \
        > "${out}/keydraw.log" 2>&1 || rc=$?
    date +%s.%N > "${out}/t1"
    {
        "${TC}" -s qdisc show dev sl0
        in_client "${TC}" -s qdisc show dev sl1
    } > "${out}/tc.txt" 2>&1
    curl -s "http://127.0.0.1:${PROM_PORT}/metrics" > "${out}/metrics-1.txt" || true

    if ! kill -0 "${qemu_pid}" 2>/dev/null; then
        log "qemu exited during the case; see ${out}/qemu.log"
        echo 'qemu exited during the case' > "${out}/qemu-died"
    fi
    stop_pid "${ss_pid}"
    stop_pid "${ryll_pid}"
    stop_pid "${proxy_pid}"
    stop_pid "${qemu_pid}"
    if [ "${rc}" -ne 0 ]; then
        log "keydraw-latency.py failed (rc ${rc}); see ${out}/keydraw.log"
    fi
    sleep 1
}

# ── The matrix ───────────────────────────────────────────────────────────────

for rep in $(seq "${REPEATS}"); do
    for profile in ${PROFILES}; do
        rtt="${profile%%:*}"
        rate="${profile##*:}"
        shape "${rtt}" "${rate}"
        for activity in ${ACTIVITIES}; do
            IFS=: read -r aname fps noise <<< "${activity}"
            for display in ${DISPLAYS}; do
                IFS=: read -r dname dqemu dstream dguest <<< "${display}"
                for config in ${CONFIGS}; do
                    IFS=: read -r cname lowat rcvbuf <<< "${config}"
                    case_name="${cname}"
                    [ -n "${DISPLAYS_SET}" ] && case_name="${dname}-${cname}"
                    run_case "${WORKDIR}/${rtt}ms-${rate}mbit/${aname}/${case_name}-r${rep}" \
                        "${fps}" "${noise}" "${lowat}" "${rcvbuf}" \
                        "${dqemu}" "${dstream}" "${dguest}" || true
                done
            done
        done
    done
done
log "done; summarise with: ${SCRIPT_DIR}/summarise.py ${WORKDIR}"
