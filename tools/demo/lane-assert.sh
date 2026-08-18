#!/bin/bash
# Assert the compose demo actually works, for the CI lane.
#
# Runs after tools/demo/lane-up.sh. Four groups of assertions:
#
#   1. get-console.sh produces a .vv, and it carries the three fields a
#      client needs to reach the proxy over TLS.
#   2. ryll opens a real SPICE session over the TLS port.
#   3. The backend disappearing produces a bounded failure, not a hang.
#   4. `kerbside demo token` refuses a non-static source list.
#
# 3 and 4 are what make this more than a smoke test. A proxy that hangs
# when its backend vanishes is a real defect, and this is the cheapest
# lane positioned to catch it; the mint guard is unit-tested against
# fixtures in phase 1, but here it runs against a real deployment, which
# is where it has to hold.
#
# Note what this does NOT reimplement: demo/get-console.sh already
# proves the TLS leg, by connecting to the port the .vv advertises and
# verifying the presented certificate against the CA embedded in that
# same .vv. Asserting the fields here and letting ryll cover the SPICE
# handshake avoids writing a third TLS verifier.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEMO_DIR="${REPO_ROOT}/demo"

WORKDIR="${WORKDIR:-/tmp/kerbside-demo-lane}"
VV="${WORKDIR}/demo-console.vv"
RYLL_SOCK="${WORKDIR}/ryll-demo.sock"
RYLL_LOG="${WORKDIR}/ryll-demo.log"

# Unix socket paths are capped at ~108 bytes by the kernel, and ryll's
# control socket lives under WORKDIR. Overrun that and the bind fails
# silently: this script then reports "ryll never created its control
# socket" for a session that in fact connected perfectly, which is a
# genuinely misleading half hour. The CI default is short; an override
# under a long scratch path is how you get here.
if [ "${#RYLL_SOCK}" -gt 100 ]; then
    echo "ERROR: WORKDIR is too long: ${RYLL_SOCK} is ${#RYLL_SOCK} bytes," >&2
    echo "  and a Unix socket path cannot exceed about 108. ryll would" >&2
    echo "  fail to bind its control socket and this script would blame" >&2
    echo "  the session. Use a shorter WORKDIR." >&2
    exit 1
fi

# How long a console request may take once the backend is gone before we
# call it a hang. The proxy's own backend connection attempt failed in
# about 9 seconds when this was measured by hand during phase 3, so 60
# is generous while still being decisively shorter than a hang.
BACKEND_FAIL_TIMEOUT="${BACKEND_FAIL_TIMEOUT:-60}"

mkdir -p "${WORKDIR}"
cd "${DEMO_DIR}"

PASS=0
FAILURES=()

ok() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

bad() {
    echo "  FAIL: $1" >&2
    FAILURES+=("$1")
}

# Counts matching lines in the proxy's log so far. Used in before/after
# pairs rather than as an absolute count, because `docker compose logs`
# returns the whole history of the container: an absolute count passes on
# a line left over from an earlier session, which makes the assertion
# about the stack's past rather than about the thing just done. A fresh
# CI stack hides that, and re-running this script by hand exposes it.
# `|| true` because grep -c exits 1 on no matches, and under pipefail
# that would kill the assignment and the script with it.
count_proxy_log() {
    docker compose logs --no-color kerbside 2>&1 | grep -c "$1" || true
}

# demo/sources.yaml is edited in place by assertion 4. Restoring it from
# a trap rather than at the end of that block means a failure anywhere
# after the edit still leaves the tree clean -- otherwise a mid-run
# failure leaves a dummy oVirt source committed-looking in the working
# copy, and the next thing to read it is a confused human.
SOURCES_BACKUP="${WORKDIR}/sources.yaml.orig"
cp sources.yaml "${SOURCES_BACKUP}"

cleanup() {
    cp "${SOURCES_BACKUP}" "${DEMO_DIR}/sources.yaml"
    if [ -f "${WORKDIR}/ryll.pid" ]; then
        kill "$(cat "${WORKDIR}/ryll.pid")" 2> /dev/null || true
    fi
}
trap cleanup EXIT

# ── 1. Fetch a .vv and check its fields ──────────────────────────────

echo "[lane-assert] Fetching a console .vv"
./get-console.sh "${VV}" || {
    echo "ERROR: get-console.sh failed; it prints its own diagnosis above" >&2
    exit 1
}

echo "[lane-assert] Checking the .vv fields"
# These three are what a client needs and what a silent regression would
# drop. The TLS port and the CA are how remote-viewer reaches the proxy
# without anything being added to a system trust store; host-subject is
# what it checks the certificate against, since SPICE identifies a
# server by subject rather than by SAN.
if grep -q '^tls-port=' "${VV}"; then
    ok 'the .vv carries tls-port='
else
    bad 'the .vv has no tls-port=, so no client can use the TLS leg'
fi

if grep -q '^host-subject=' "${VV}"; then
    ok 'the .vv carries host-subject='
else
    bad 'the .vv has no host-subject=, so a client cannot verify the proxy identity'
fi

# An escaped PEM, not merely a non-empty field: kerbside writes the CA
# with literal \n escapes, and a ca= line holding anything else would
# pass a presence check and fail in the client.
if grep -q '^ca=.*BEGIN CERTIFICATE' "${VV}"; then
    ok 'the .vv carries a ca= field holding an escaped PEM'
else
    bad 'the .vv has no ca= field with a certificate in it'
fi

# ── 2. Drive a real SPICE session with ryll ──────────────────────────
#
# ryll is built without --features digest-decode: this lane asserts that
# a session is established, not what it renders, which is the same
# choice the oVirt lane makes (functional-tests.yml:629). The
# direct-qemu lane DOES build with digest-decode because it asserts on
# pixels; do not copy that one here.

echo "[lane-assert] Opening a SPICE session with ryll"
if ! command -v ryll > /dev/null 2>&1; then
    bad 'ryll is not on PATH; the workflow should have built it'
else
    rm -f "${RYLL_SOCK}"
    RELAYED_BEFORE="$(count_proxy_log 'hypervisor connection successful')"
    # --file rather than a positional argument, and --verbose because the
    # headless event loop otherwise swallows connect_channel errors as
    # "Connection task completed" -- with a TLS leg under test that is
    # the one diagnostic worth having. Both learned from
    # tools/direct-qemu/lane-up.sh, which carries the same notes.
    ryll --verbose --headless --file "${VV}" \
        --control-socket "${RYLL_SOCK}" \
        > "${RYLL_LOG}" 2>&1 &
    echo $! > "${WORKDIR}/ryll.pid"

    # Wait for the control socket rather than sleeping: ryll creates it
    # once it is ready to be driven.
    for _ in $(seq 1 60); do
        [ -S "${RYLL_SOCK}" ] && break
        sleep 0.5
    done

    if [ ! -S "${RYLL_SOCK}" ]; then
        # "ryll never came up" is a symptom, and on its own it sends the
        # reader to the wrong place. Whenever the proxy has recorded a
        # reason -- a refused or misdirected backend port is the common
        # one -- surface that alongside, because it names the actual
        # fault.
        bad 'ryll never created its control socket'
        # `|| true` is load-bearing, for the same reason as the `|| RC=$?`
        # below. Under `set -o pipefail` a grep that matches nothing makes
        # the whole pipeline exit 1, the assignment fails, and `set -e`
        # kills the script -- which meant that when the proxy had NO
        # matching reason to report, this diagnostic block died instead of
        # falling through to print the ryll log. That is exactly the case
        # where the ryll log is the only evidence there is.
        PROXY_REASON="$(docker compose logs --no-color kerbside 2>&1 \
            | grep -E 'hypervisor connection failed|connection refused' \
            | tail -3 || true)"
        if [ -n "${PROXY_REASON}" ]; then
            echo "--- the proxy's reason ---" >&2
            echo "${PROXY_REASON}" >&2
        fi
        echo "--- ryll log ---" >&2
        cat "${RYLL_LOG}" >&2 || true
    else
        # smoke-client.py is the existing driver for exactly this
        # assertion in the direct-qemu lane. Reused rather than
        # reimplemented so there is one definition of "the session
        # opened".
        if python3 "${REPO_ROOT}/tools/direct-qemu/smoke-client.py" \
                "${RYLL_SOCK}" 2>&1 | tee -a "${RYLL_LOG}"; then
            ok 'ryll established a SPICE session'
        else
            bad 'ryll could not establish a SPICE session'
        fi

        # Which port the session actually crossed. This is the failure
        # the whole demo is arranged to make visible: a session that
        # quietly ran over the plaintext port with the TLS leg broken
        # looks identical to a working one from the client's side.
        #
        # An earlier version of this greped the proxy log for `secure
        # SPICE listener bound` and proved nothing. That line is emitted
        # once at bind time by rust/kerbside-proxy/src/listen.rs, and its
        # `insecure SPICE listener bound` sibling fires identically for
        # the plaintext port, so the check passed whenever the proxy had
        # merely started -- including runs where ryll never connected.
        # Confirmed against a real lane artifact: both lines appear at
        # startup, twice, because the daemon restarted the proxy.
        #
        # Both ports are published on loopback, so the honest oracle is
        # the host's own socket table while the session is still live.
        # Zero established sockets on the plaintext port is the property
        # under test; a non-zero count on the TLS port is the
        # corroborating positive. Ports come from the .vv rather than
        # being hardcoded, so this cannot drift from what the client was
        # actually told to use.
        TLS_PORT="$(sed -n 's/^tls-port=//p' "${VV}" | tr -d '\r')"
        PLAIN_PORT="$(sed -n 's/^port=//p' "${VV}" | tr -d '\r')"

        if ! command -v ss > /dev/null 2>&1; then
            # Not skipped quietly: a check that cannot run is a check
            # that is not protecting anything, and saying so is the
            # difference between a gap and a false sense of coverage.
            bad 'ss is unavailable, so the session port could not be checked'
        elif [ -z "${TLS_PORT}" ] || [ -z "${PLAIN_PORT}" ]; then
            bad 'the .vv did not carry both port and tls-port, so the session port could not be checked'
        else
            established_on_port() {
                ss -tn state established 2> /dev/null \
                    | awk -v p=":$1\$" '$3 ~ p || $4 ~ p' \
                    | wc -l
            }
            TLS_SOCKETS="$(established_on_port "${TLS_PORT}")"
            PLAIN_SOCKETS="$(established_on_port "${PLAIN_PORT}")"
            echo "  established sockets: ${TLS_PORT}=${TLS_SOCKETS}," \
                "${PLAIN_PORT}=${PLAIN_SOCKETS}"

            if [ "${PLAIN_SOCKETS}" -eq 0 ]; then
                ok "no session crossed the plaintext port ${PLAIN_PORT}"
            else
                bad "${PLAIN_SOCKETS} established sockets on the plaintext port ${PLAIN_PORT}; the session did not stay on the TLS leg"
            fi

            if [ "${TLS_SOCKETS}" -ge 1 ]; then
                ok "the session crossed the TLS port ${TLS_PORT}"
            else
                bad "no established sockets on the TLS port ${TLS_PORT} while the session was open"
            fi
        fi

        # A per-connection line, not a bind-time one: this is the proxy
        # saying it relayed channels to the hypervisor. Counted as a
        # delta across this session, so a line from an earlier session
        # cannot satisfy it.
        RELAYED_AFTER="$(count_proxy_log 'hypervisor connection successful')"
        RELAYED_NEW=$(( RELAYED_AFTER - RELAYED_BEFORE ))
        if [ "${RELAYED_NEW}" -ge 1 ]; then
            ok "the proxy relayed ${RELAYED_NEW} channel(s) for this session"
        else
            bad 'the proxy did not report relaying any channel for this session'
        fi
    fi

    kill "$(cat "${WORKDIR}/ryll.pid")" 2> /dev/null || true
    rm -f "${WORKDIR}/ryll.pid"
fi

# ── 3. The backend disappearing must fail, not hang ──────────────────
#
# This has to drive a real client, and that is not obvious: fetching a
# .vv does NOT touch the backend. get-console.sh mints a token, reads the
# console list and verifies the TLS leg to the *proxy*, all of which keep
# working perfectly with the SPICE target stopped, because the proxy only
# dials the hypervisor once a client opens a session. An earlier draft of
# this script asserted on get-console.sh here and passed a stopped
# backend as success.
#
# Phase 3 verified this case with remote-viewer, and recorded both halves
# of the evidence: the client exited in about 9 seconds, and the proxy
# logged `hypervisor connection failed ... error=failed to lookup address
# information`. Both are asserted here; the log line is the half that
# names the cause.

echo "[lane-assert] Stopping the SPICE target; a session must fail promptly"
# stderr kept, and the failure routed through `bad` rather than left to
# `set -e`: discarding both streams here meant a failed stop killed the
# script with docker's exit status and no output at all.
docker compose stop spice-target > /dev/null \
    || bad 'could not stop spice-target, so the backend-failure case did not run'

if ! command -v ryll > /dev/null 2>&1; then
    bad 'ryll is not on PATH, so the backend-failure case could not be driven'
else
    # A fresh .vv: the token in the previous one is single-use in spirit
    # and the session id is stale.
    ./get-console.sh "${WORKDIR}/backend-gone.vv" \
        > "${WORKDIR}/backend-gone-fetch.log" 2>&1 || true

    rm -f "${WORKDIR}/ryll-fail.sock"
    FAILLOG_BEFORE="$(count_proxy_log 'hypervisor connection failed')"
    START="$(date +%s)"
    # `|| RC=$?`, not a bare invocation followed by `RC=$?`. This script
    # runs under `set -e`, so a bare non-zero exit here kills it before
    # the next line ever runs -- which made the timeout branch below
    # dead code and silently skipped every assertion after it. The two
    # interesting outcomes are both non-zero (124 for the hang this
    # exists to catch, and whatever ryll returns on a failed connect),
    # so the failure has to be captured rather than fatal.
    RC=0
    timeout "${BACKEND_FAIL_TIMEOUT}" \
        ryll --verbose --headless --file "${WORKDIR}/backend-gone.vv" \
            --control-socket "${WORKDIR}/ryll-fail.sock" \
            > "${WORKDIR}/ryll-backend-gone.log" 2>&1 || RC=$?
    ELAPSED=$(( $(date +%s) - START ))

    if [ "${RC}" -eq 124 ]; then
        bad "a session hung for ${BACKEND_FAIL_TIMEOUT}s with the backend stopped, rather than failing"
    else
        ok "a session attempt ended in ${ELAPSED}s with the backend stopped"
    fi

    # The proxy must say why. A client that merely gives up tells an
    # operator nothing; this is the line that does. A delta again, so an
    # earlier run's failure cannot stand in for this one's.
    FAILLOG_AFTER="$(count_proxy_log 'hypervisor connection failed')"
    if [ "$(( FAILLOG_AFTER - FAILLOG_BEFORE ))" -ge 1 ]; then
        ok 'the proxy logged the backend connection failure'
    else
        bad 'the proxy did not log a hypervisor connection failure for this attempt'
    fi
fi

echo "[lane-assert] Restarting the SPICE target"
docker compose start spice-target > /dev/null \
    || bad 'could not restart spice-target'

# And wait for it, rather than assuming. Assertion 4 below runs against
# the live stack, so a half-dead backend here would surface as a mint
# failure and be attributed to the mint guard -- the same
# wrong-attribution shape as findings 13 and 14.
for _ in $(seq 1 60); do
    if docker compose ps --status running --services 2> /dev/null \
            | grep -qx 'spice-target'; then
        break
    fi
    sleep 1
done
if docker compose ps --status running --services 2> /dev/null \
        | grep -qx 'spice-target'; then
    ok 'spice-target came back after the restart'
else
    bad 'spice-target did not come back after the restart'
fi

# ── 4. The mint guard must refuse a non-static source ────────────────

echo "[lane-assert] Adding a non-static source; kerbside demo token must refuse"
# A new top-level SOURCE, at zero indentation. demo/sources.yaml is a
# list of sources, each with `source:`, `type:` and `consoles:`, so an
# indented entry lands inside the demo source's `consoles:` list
# instead, which is malformed enough to crash the daemon at startup --
# the container then never comes back, `exec` fails, and the refusal
# this is trying to observe never happens. An earlier draft of this
# script did exactly that and reported the crash as a missing refusal.
cat >> sources.yaml <<'EOF'

- source: pretend-ovirt
  type: ovirt
  url: https://ovirt.example.com/ovirt-engine/api
  username: admin@internal
  password: not-a-real-password
  consoles: []
EOF

# The guard is evaluated when the command runs, against the source list
# the daemon has loaded, so the daemon has to see the edited file first.
docker compose restart kerbside > /dev/null 2>&1
if ! timeout 180 bash -c '
        until docker compose ps kerbside --format "{{.Health}}" \
                | grep -q healthy; do
            sleep 2
        done'; then
    # Distinguish "the guard refused" from "the daemon died reading the
    # file we just edited". Both make the mint command fail, and only one
    # of them is the thing under test.
    bad 'kerbside did not come back healthy after the sources.yaml edit, so the mint guard was never reached'
    docker compose logs --no-color kerbside 2>&1 | tail -30 >&2
fi

MINT_OUT="${WORKDIR}/mint-refusal.log"
if docker compose exec -T kerbside kerbside-demo-env \
        kerbside demo token --subject lane-check --output /tmp/lane-token \
        > "${MINT_OUT}" 2>&1; then
    bad 'kerbside demo token minted a token despite a non-static source being configured'
else
    # The refusal has to name the offending source. A generic "refusing
    # to mint" would send the reader looking in the wrong place, and the
    # message is the whole value of the guard.
    if grep -q 'pretend-ovirt' "${MINT_OUT}"; then
        ok 'kerbside demo token refused and named the offending source'
    else
        bad 'kerbside demo token refused but did not name the offending source'
        cat "${MINT_OUT}" >&2
    fi
fi

# ── Verdict ──────────────────────────────────────────────────────────

echo ""
echo "[lane-assert] ${PASS} assertions passed"
if [ "${#FAILURES[@]}" -ne 0 ]; then
    echo "[lane-assert] ${#FAILURES[@]} FAILED:" >&2
    for f in "${FAILURES[@]}"; do
        echo "  - ${f}" >&2
    done
    exit 1
fi
echo "[lane-assert] complete"
