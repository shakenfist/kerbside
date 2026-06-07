#!/bin/bash
# Tear down the kerbside direct-qemu CI lane (best-effort, never errors).
#
# Kills ryll, kerbside (daemon + gunicorn), and QEMU by their pidfiles,
# then removes the workdir.
#
# Part of docs/plans/PLAN-test-harness-phase-05-direct-qemu-ci.md step 5b.

WORKDIR="${WORKDIR:-/tmp/kerbside-ci}"

_kill_pid_file() {
    local label="$1"
    local pidfile="$2"

    if [ ! -f "${pidfile}" ]; then
        return 0
    fi

    local pid
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [ -z "${pid}" ]; then
        return 0
    fi

    if kill -0 "${pid}" 2>/dev/null; then
        echo "[lane-down] sending SIGTERM to ${label} (pid ${pid})"
        kill -TERM "${pid}" 2>/dev/null || true
        sleep 2
        if kill -0 "${pid}" 2>/dev/null; then
            echo "[lane-down] sending SIGKILL to ${label} (pid ${pid})"
            kill -KILL "${pid}" 2>/dev/null || true
        fi
    else
        echo "[lane-down] ${label} (pid ${pid}) already gone"
    fi
}

# ── Kill processes in reverse startup order ───────────────────────────────────

_kill_pid_file 'ryll'               "${WORKDIR}/ryll.pid"
_kill_pid_file 'kerbside-daemon'    "${WORKDIR}/kerbside.pid"
_kill_pid_file 'kerbside-gunicorn'  "${WORKDIR}/kerbside-gunicorn.pid"
_kill_pid_file 'qemu'               "${WORKDIR}/qemu.pid"

# ── Remove workdir ────────────────────────────────────────────────────────────

if [ -d "${WORKDIR}" ]; then
    echo "[lane-down] removing ${WORKDIR}"
    rm -rf "${WORKDIR}" || true
fi

echo "lane down"
exit 0
