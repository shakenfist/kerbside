#!/bin/bash
# Transport bench over a shaped link: per-channel TCP against one QUIC
# connection with a stream per channel.
#
# The question, the results and the host they were taken on are in
# docs/performance/quic-transport-bench.md; read that first.
#
# Topology, all unprivileged. The script re-executes itself under
# `unshare -rn` (a user plus network namespace, "server side"), where it runs
# the bench's server on 10.78.0.1. The client runs in a nested network
# namespace ("client side", 10.78.0.2) joined to the server side by a veth
# pair. Only that veth pair is shaped, in both directions:
#
#   quic-bench client --(veth, shaped)--> quic-bench server
#
# The shaping is the same qdisc tools/shaped-link/run-matrix.sh builds -- the
# same delay, rate and packet-counted queue limit from the bandwidth-delay
# product, the same optional loss term, and the same GSO capping and offload
# disabling on each veth end. This script replicates it rather than calling it
# because run-matrix.sh brings a guest, a mock control plane and a SPICE
# client with it, and all of that is variance this measurement does not want.
#
# Usage: run-bench.sh
#
# Inputs (environment):
#   WORKDIR     results and scratch (default ./quic-bench-results)
#   BENCH_BIN   quic-bench binary (default: release build in-tree)
#   PROFILES    "rtt_ms:rate_mbit ..." (default "80:10 150:2")
#   LOSSES      "pct ..." applied per direction (default "0 1 2"). 0 means no
#               loss term at all, so the 0% cells are shaped by a qdisc line
#               identical to the one the rig built before it knew about loss
#   CCS         congestion controllers to pin both arms to (default
#               "cubic bbr"). The first is the headline; the rest are
#               sensitivity arms. Each must appear in
#               /proc/sys/net/ipv4/tcp_available_congestion_control, and the
#               bench must know it too (cubic, bbr, reno)
#   REPEATS     runs per cell per arm (default 5)
#   DURATION    measurement window in seconds (default 40)
#   WARMUP      seconds of that window discarded (default 5)
#   CHANNELS    channels per session (default 5: one saturating, one
#               interactive, three open and quiet, which is what a SPICE
#               session's main, display, inputs, cursor and playback do)
#   INTERVAL_MS gap between one interactive response and the next request
#               (default 20)
#   GSO_CONTROL set to 0 to skip the deliberately-wrong GSO run that proves
#               the queue-accounting check can detect segmentation offload
#   QUIC_FLAGS  extra flags for both ends of the QUIC arm, space separated.
#               --priority-interactive runs the sensitivity arm that gives the
#               interactive stream a send priority above the saturating one;
#               the headline arm leaves it unset
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)/quic-bench-results}"
DQ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_BIN="${BENCH_BIN:-${DQ}/target/release/quic-bench}"
PROFILES="${PROFILES:-80:10 150:2}"
LOSSES="${LOSSES:-0 1 2}"
CCS="${CCS:-cubic bbr}"
REPEATS="${REPEATS:-5}"
DURATION="${DURATION:-40}"
WARMUP="${WARMUP:-5}"
CHANNELS="${CHANNELS:-5}"
INTERVAL_MS="${INTERVAL_MS:-20}"
GSO_CONTROL="${GSO_CONTROL:-1}"
QUIC_FLAGS="${QUIC_FLAGS:-}"

# Same as the rig: one bandwidth-delay product of queue on top of the packets
# sitting in the delay line.
BUFFER_BDP="${BUFFER_BDP:-1}"

TC=/usr/sbin/tc
ETHTOOL=/usr/sbin/ethtool
SS=/usr/bin/ss
SERVER_IP=10.78.0.1
CLIENT_IP=10.78.0.2
TCP_PORT=5801
QUIC_PORT=5802

log() { echo "[$(date -u +%H:%M:%S)] $*" >&2; }

# ── Outer half: check the inputs, then re-execute in a namespace ─────────────

if [ -z "${QUIC_BENCH_INNER:-}" ]; then
    [ -x "${BENCH_BIN}" ] || {
        echo "ERROR: ${BENCH_BIN} not found. Run 'make release' in $(dirname "${BENCH_BIN}" | xargs dirname)." >&2
        exit 1
    }
    for tool in "${TC}" "${ETHTOOL}" "${SS}" /usr/bin/openssl; do
        [ -x "${tool}" ] || { echo "ERROR: ${tool} not found" >&2; exit 1; }
    done
    available="$(cat /proc/sys/net/ipv4/tcp_available_congestion_control)"
    for cc in ${CCS}; do
        case " ${available} " in
            *" ${cc} "*) ;;
            *)
                echo "ERROR: the kernel does not offer tcp congestion control '${cc}'." >&2
                echo "       available: ${available}" >&2
                echo "       'modprobe tcp_bbr' as root makes bbr available; it is not persisted." >&2
                exit 1
                ;;
        esac
    done
    mkdir -p "${WORKDIR}"
    export QUIC_BENCH_INNER=1 WORKDIR BENCH_BIN PROFILES LOSSES CCS REPEATS \
        DURATION WARMUP CHANNELS INTERVAL_MS GSO_CONTROL BUFFER_BDP QUIC_FLAGS
    exec unshare --user --map-root-user --net -- "${BASH_SOURCE[0]}" "$@"
fi

# ── Inner half: the shaped link ─────────────────────────────────────────────

PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "${pid}" 2>/dev/null || true
    done
}
trap cleanup EXIT

ip link set lo up

# The client namespace is held open by a sleeper; everything client side runs
# through nsenter into it.
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

# netem's queue limit counts packets, so it must see MTU-sized packets, not
# 64k GSO super-packets. Turning the offloads off is not enough for TCP, which
# always builds GSO packets and lets the device segment them after the qdisc;
# capping the device's GSO size is what makes TCP put one MSS in each skb.
#
# None of it works for UDP. A UDP sender that sets UDP_SEGMENT hands netem one
# super-packet per write whatever the device's GSO limits say, and a loss term
# then drops whole writes rather than single datagrams. That is why the QUIC
# arm declines segmentation offload in the bench itself, and why every QUIC
# run here is checked against the queue's bytes per slot before its numbers
# are believed. `tc -s qdisc show`'s packet counter cannot see the problem,
# because it counts segments either way.
for dev in sl0 sl1; do
    ns=()
    [ "${dev}" = sl1 ] && ns=(nsenter --target "${CLIENT_NS_PID}" --net --)
    "${ns[@]}" ip link set "${dev}" gso_max_size 1500 gso_max_segs 1
    "${ns[@]}" "${ETHTOOL}" -K "${dev}" tso off gso off gro off >/dev/null
done

# ── Host state worth recording ──────────────────────────────────────────────

{
    echo "kernel: $(uname -r)"
    echo "tc: $("${TC}" -V)"
    echo "bench: ${BENCH_BIN}"
    echo "tcp_available_congestion_control: $(cat /proc/sys/net/ipv4/tcp_available_congestion_control)"
    for s in net/ipv4/tcp_wmem net/ipv4/tcp_rmem net/core/rmem_max net/core/wmem_max \
            net/ipv4/tcp_notsent_lowat net/ipv4/tcp_congestion_control; do
        echo "server ns ${s}: $(tr '\t' ' ' < "/proc/sys/${s}")"
    done
    echo "client ns net/ipv4/tcp_congestion_control: $(in_client cat /proc/sys/net/ipv4/tcp_congestion_control)"
    echo "profiles: ${PROFILES}"
    echo "losses: ${LOSSES}"
    echo "congestion controllers: ${CCS}"
    echo "repeats: ${REPEATS} duration: ${DURATION}s warmup: ${WARMUP}s"
    echo "channels: ${CHANNELS} interactive interval: ${INTERVAL_MS}ms"
    echo "quic extra flags: ${QUIC_FLAGS:-none}"
} > "${WORKDIR}/host.txt"
cat "${WORKDIR}/host.txt" >&2

# ── TLS material for the QUIC arm ───────────────────────────────────────────
#
# Self-signed, generated per run, and handed to the client as its only trust
# root. The TCP arm is plain, which is deliberate: this bench is about loss
# recovery and congestion control, and TLS records add neither. The asymmetry
# favours TCP slightly on CPU, which at these rates is not the bottleneck.

# A CA and a leaf signed by it, not one self-signed certificate: webpki
# refuses to use a CA certificate as the end entity. Extensions are set
# explicitly because `openssl x509 -req` emits a v1 certificate when a
# certificate carries none, and webpki rejects v1 outright.

TLS_DIR="${WORKDIR}/tls"
mkdir -p "${TLS_DIR}"
if [ ! -s "${TLS_DIR}/server-cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
        -keyout "${TLS_DIR}/ca-key.pem" -out "${TLS_DIR}/ca-cert.pem" \
        -subj '/CN=quic-bench-ca' \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "${TLS_DIR}/server-key.pem" -out "${TLS_DIR}/server.csr" \
        -subj '/CN=quic-bench' >/dev/null 2>&1
    cat > "${TLS_DIR}/server-ext.cnf" << EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:quic-bench, IP:${SERVER_IP}
EOF
    openssl x509 -req -days 2 -in "${TLS_DIR}/server.csr" \
        -CA "${TLS_DIR}/ca-cert.pem" -CAkey "${TLS_DIR}/ca-key.pem" -CAcreateserial \
        -extfile "${TLS_DIR}/server-ext.cnf" -out "${TLS_DIR}/server-cert.pem" \
        >/dev/null 2>&1
    rm -f "${TLS_DIR}/server.csr" "${TLS_DIR}/server-ext.cnf" "${TLS_DIR}/ca-cert.srl"
    chmod 600 "${TLS_DIR}/ca-key.pem" "${TLS_DIR}/server-key.pem"
fi

# ── The shaped link ─────────────────────────────────────────────────────────
#
# One-way netem on each veth end: half the RTT as delay, the full rate, a
# queue of BUFFER_BDP bandwidth-delay products on top of the packets sitting
# in the delay line, and the loss percentage when the cell asked for one. Both
# ends drop at the same percentage and independently of each other, which is
# netem's default uncorrelated per-packet model. A cell at 0% loss builds the
# qdisc with no loss term at all, so it is the same line the rig has always
# built and the control is a control.

shape() {
    local rtt_ms="$1" rate_mbit="$2" loss_pct="$3"
    local limit
    local loss=()
    [ "${loss_pct}" != '0' ] && loss=(loss "${loss_pct}%")
    limit=$(( (rate_mbit * 1000 * (rtt_ms / 2 + BUFFER_BDP * rtt_ms)) / (8 * 1500) + 10 ))
    local qdisc=(netem delay "$(( rtt_ms / 2 ))ms" rate "${rate_mbit}mbit" limit "${limit}" "${loss[@]}")
    "${TC}" qdisc replace dev sl0 root "${qdisc[@]}"
    in_client "${TC}" qdisc replace dev sl1 root "${qdisc[@]}"
    log "shaped: rtt ${rtt_ms}ms rate ${rate_mbit}mbit limit ${limit} pkts per direction${loss[0]:+ loss ${loss_pct}%}"
}

set_tcp_cc() {
    local cc="$1"
    echo "${cc}" > /proc/sys/net/ipv4/tcp_congestion_control
    in_client sh -c "echo ${cc} > /proc/sys/net/ipv4/tcp_congestion_control"
}

# Sample the server-side egress queue. This is where the saturating flow
# queues, so it is where a segmentation-offloaded write would show up as a
# queue slot holding ten datagrams' worth of bytes.
sample_backlog() {
    local out="$1"
    while :; do
        printf '%s %s\n' "$(date +%s.%N)" "$("${TC}" -s -j qdisc show dev sl0 | tr -d '\n')" >> "${out}"
        sleep 0.2
    done
}

wait_for_server() {
    local logfile="$1" pid="$2"
    for _ in $(seq 100); do
        grep -q ' server on ' "${logfile}" 2>/dev/null && return 0
        kill -0 "${pid}" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

# run_arm <arm> <casedir> <cc> <label> [extra server/client flags...]
run_arm() {
    local arm="$1" casedir="$2" cc="$3" label="$4"
    shift 4
    local extra=("$@")
    if [ "${arm}" = quic ] && [ -n "${QUIC_FLAGS}" ]; then
        # shellcheck disable=SC2206  # a flag list carries no whitespace
        extra+=(${QUIC_FLAGS})
    fi
    local slog="${casedir}/${arm}-server.log"
    local clog="${casedir}/${arm}-client.log"
    local server_pid sampler_pid rc=0

    case "${arm}" in
        tcp)
            "${BENCH_BIN}" server --transport tcp --listen "${SERVER_IP}:${TCP_PORT}" \
                > "${slog}" 2>&1 &
            ;;
        quic)
            "${BENCH_BIN}" server --transport quic --listen "${SERVER_IP}:${QUIC_PORT}" \
                --cert "${TLS_DIR}/server-cert.pem" --key "${TLS_DIR}/server-key.pem" \
                --cc "${cc}" --channels "${CHANNELS}" "${extra[@]}" > "${slog}" 2>&1 &
            ;;
        *) echo "ERROR: unknown arm ${arm}" >&2; return 1 ;;
    esac
    server_pid=$!
    PIDS+=("${server_pid}")
    if ! wait_for_server "${slog}" "${server_pid}"; then
        echo "ERROR: ${arm} server did not come up; see ${slog}" >&2
        kill "${server_pid}" 2>/dev/null || true
        return 1
    fi

    sample_backlog "${casedir}/${arm}-backlog.jsonl" &
    sampler_pid=$!
    PIDS+=("${sampler_pid}")

    if [ "${arm}" = tcp ]; then
        # Witness the controller the kernel actually chose for these sockets,
        # rather than trusting that writing the sysctl was enough.
        (
            sleep $(( WARMUP + 5 ))
            "${SS}" -tim 2>/dev/null > "${casedir}/tcp-ss-server.txt" || true
            in_client "${SS}" -tim 2>/dev/null > "${casedir}/tcp-ss-client.txt" || true
        ) &
        PIDS+=("$!")
    fi

    local port="${TCP_PORT}"
    local certflag=()
    if [ "${arm}" = quic ]; then
        port="${QUIC_PORT}"
        certflag=(--cert "${TLS_DIR}/ca-cert.pem")
    fi
    in_client timeout $(( DURATION + 120 )) \
        "${BENCH_BIN}" client --transport "${arm}" \
            --connect "${SERVER_IP}:${port}" "${certflag[@]}" --cc "${cc}" \
            --channels "${CHANNELS}" --duration-secs "${DURATION}" --warmup-secs "${WARMUP}" \
            --interval-ms "${INTERVAL_MS}" --label "${label}" \
            --out "${casedir}/${arm}.json" "${extra[@]}" > "${clog}" 2>&1 || rc=$?

    kill "${sampler_pid}" 2>/dev/null || true
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
    if [ "${rc}" -ne 0 ]; then
        echo "ERROR: ${arm} client failed (${rc}); see ${clog}" >&2
        return 1
    fi
    return 0
}

# ── The matrix ──────────────────────────────────────────────────────────────

: > "${WORKDIR}/cells.txt"
for profile in ${PROFILES}; do
    IFS=: read -r rtt rate <<< "${profile}"
    for loss in ${LOSSES}; do
        for cc in ${CCS}; do
            cell="${rtt}ms-${rate}mbit-${loss}pct-${cc}"
            echo "${cell}" >> "${WORKDIR}/cells.txt"
            for rep in $(seq 1 "${REPEATS}"); do
                casedir="${WORKDIR}/${cell}/rep${rep}"
                mkdir -p "${casedir}"
                shape "${rtt}" "${rate}" "${loss}"
                set_tcp_cc "${cc}"
                "${TC}" -s -j qdisc show dev sl0 > "${casedir}/qdisc-sl0.json"
                in_client "${TC}" -s -j qdisc show dev sl1 > "${casedir}/qdisc-sl1.json"
                echo "${cc}" > "${casedir}/tcp-cc-requested.txt"
                cat /proc/sys/net/ipv4/tcp_congestion_control > "${casedir}/tcp-cc-server.txt"
                in_client cat /proc/sys/net/ipv4/tcp_congestion_control > "${casedir}/tcp-cc-client.txt"
                for arm in tcp quic; do
                    log "${cell} rep${rep} ${arm}"
                    run_arm "${arm}" "${casedir}" "${cc}" "${cell}/rep${rep}" || true
                done
            done
        done
    done
done

# ── The deliberately-wrong run ──────────────────────────────────────────────
#
# A check that only ever passes proves nothing, so run the QUIC arm once with
# quinn's segmentation offload left on. Its queue should hold many datagrams
# per slot where every measured run holds one. This is a diagnostic: its
# latency and throughput figures describe a link nobody has.

if [ "${GSO_CONTROL}" = '1' ]; then
    first_profile="${PROFILES%% *}"
    IFS=: read -r rtt rate <<< "${first_profile}"
    casedir="${WORKDIR}/gso-control-${rtt}ms-${rate}mbit-0pct"
    mkdir -p "${casedir}"
    shape "${rtt}" "${rate}" 0
    set_tcp_cc "${CCS%% *}"
    log "gso control (segmentation offload deliberately left on)"
    run_arm quic "${casedir}" "${CCS%% *}" 'gso-control' --allow-gso || true
fi

log "done: ${WORKDIR}"
