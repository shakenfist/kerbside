#!/usr/bin/env python3
"""Drive an oVirt -> kerbside -> proxied SPICE session.

Runs ON the CI runner, with the kerbside venv's python (so ``kerbside``
imports), after ``tools/ovirt-e2e/deploy-kerbside.sh`` has deployed kerbside
and registered a ``type: ovirt`` source against a live oVirt 4.5 engine. It:

  1. polls kerbside's DB until the oVirt scrape discovers the lane's test VM
     (the console whose name starts with ``smoke-test-``), and logs the
     scraped ``hypervisor_ip``, ``insecure_port``, ``secure_port`` and
     ``host_subject``;
  2. asserts ``secure_port`` and ``host_subject`` are both populated -- the
     whole point of this lane is the backend TLS leg with certificate-subject
     pinning, and without those two values the run would prove less than it
     appears to;
  3. mints an API JWT from the auth seed, fetches
     ``/console/proxy/<source>/<uuid>/console.vv`` and launches
     ``ryll --headless`` against it IMMEDIATELY (oVirt graphics-console
     tickets are minted per request and expire in ~120s);
  4. reuses ``../direct-qemu/smoke-client.py`` (surfaces + PNG screenshot over
     the control socket) to assert real SPICE relayed through the proxy --
     guest-agnostic, which matters here because the guest is a Debian 12 GNOME
     image rather than Uncalibrated Sextant;
  5. asserts an audit row and an active session exist for the console;
  6. terminates the console via kerbside's REST API and asserts the session is
     removed and a termination audit event was appended.

Configuration comes from ``${WORKDIR}/kerbside.env``, written by
``deploy-kerbside.sh``. WORKDIR defaults to ``/tmp/kerbside-ovirt-ci`` and may
be overridden by the ``WORKDIR`` environment variable or ``--workdir``
(the argument wins).

SECURITY: the API JWT, the oVirt graphics-console ticket, the auth seed, and
the ``.vv`` body are NEVER printed or logged. The on-timeout diagnostic dump
deliberately omits the ``.vv`` contents, unlike the direct-qemu lane's
lane-up.sh, because the proxied ``.vv`` carries a kerbside proxy token.
Exits non-zero on any failure.

Part of docs/plans/PLAN-two-tier-ci-phase-01-ovirt-kerbside.md.
"""

import argparse
import os
import subprocess
import sys
import time
import uuid as uuidlib


DEFAULT_WORKDIR = '/tmp/kerbside-ovirt-ci'

# The lane's test VM is created by shakenfist/actions'
# tools/start-test-target.py, which names it smoke-test-<something>.
# tools/test-ovirt-console.py matches on the same prefix.
CONSOLE_NAME_PREFIX = 'smoke-test-'


def _load_env_file(path):
    """Load a KEY=VALUE env file into os.environ (skipping blanks)."""
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            os.environ[key] = value


def _log(msg):
    print('[ovirt-e2e] %s' % msg, file=sys.stderr)


def _tail(path, lines):
    """Return the last `lines` lines of a file, or a note if unreadable."""
    try:
        with open(path, 'r', errors='replace') as f:
            return ''.join(f.readlines()[-lines:])
    except OSError as exc:
        return '(could not read %s: %s)\n' % (path, exc)


def _discover_console(db, source, timeout=180):
    """Poll kerbside's DB until the oVirt scrape yields the test console.

    Unlike the sf-e2e lane, nothing tells us the VM uuid up front -- the
    oVirt scrape discovers it -- so we list the consoles for the source and
    match on the name prefix the lane's test VM is given.
    """
    _log('waiting for the oVirt scrape to discover a %s* console in source %s'
         % (CONSOLE_NAME_PREFIX, source))
    deadline = time.time() + timeout
    while time.time() < deadline:
        for console in db.get_consoles(include_audit=False):
            if console.get('source') != source:
                continue
            if not (console.get('name') or '').startswith(
                    CONSOLE_NAME_PREFIX):
                continue
            return console
        time.sleep(5)
    raise SystemExit(
        'the oVirt scrape never produced a %s* console for source %s '
        'within %ds' % (CONSOLE_NAME_PREFIX, source, timeout))


def _mint_auth_jwt(seed_path):
    """Mint an HS256 API JWT from the auth seed (never printed).

    Mirrors lane-up.sh: the kerbside verify_token decorator only checks the
    signature and expiry, so any string identity is fine.
    """
    import jwt as pyjwt

    with open(seed_path) as f:
        seed = f.read().strip()
    now = int(time.time())
    payload = {
        'fresh': False,
        'iat': now,
        'nbf': now,
        'jti': uuidlib.uuid4().hex,
        'type': 'access',
        'sub': 'ovirt-e2e-driver',
        'exp': now + 3600,
    }
    token = pyjwt.encode(payload, seed, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token


def _dump_ryll_diagnostics(proc, run_dir, log_path):
    """Dump what lane-up.sh dumps at its step 8, minus the .vv.

    ryll exits its event loop the moment the SPICE connection task finishes,
    which also unlinks the control socket, so a missing socket may mean
    "never connected" or "connected and died". The logs disambiguate.

    Deliberate difference from lane-up.sh: the .vv contents are NOT printed
    here, because the proxied .vv carries a kerbside proxy token.
    """
    if proc.poll() is None:
        _log('  ryll process %d is still running' % proc.pid)
    else:
        _log('  ryll process %d has exited (code %s)'
             % (proc.pid, proc.returncode))
    _log('  ryll stdout:\n%s'
         % _tail(os.path.join(run_dir, 'ryll-ovirt.stdout'), 40))
    _log('  ryll stderr:\n%s'
         % _tail(os.path.join(run_dir, 'ryll-ovirt.stderr'), 40))
    _log('  kerbside daemon (proxy) log:\n%s' % _tail(log_path, 60))
    _log('  gunicorn access log:\n%s'
         % _tail('%s.gunicorn-access' % log_path, 20))


def _launch_ryll(ryll_bin, vv_path, sock_path, run_dir, log_path):
    """Launch ryll headless and wait for its control socket.

    No --enable-paste-as-keystrokes: nothing pastes in this lane. No
    digest-decode expectations either -- CI builds ryll without that feature
    and the guest is a Debian 12 GNOME image, not Uncalibrated Sextant.
    """
    stdout = open(os.path.join(run_dir, 'ryll-ovirt.stdout'), 'wb')
    stderr = open(os.path.join(run_dir, 'ryll-ovirt.stderr'), 'wb')
    _log('launching ryll headless')
    proc = subprocess.Popen(
        [ryll_bin, '--verbose', '--headless', '--file', vv_path,
         '--control-socket', sock_path],
        stdout=stdout, stderr=stderr)

    deadline = time.time() + 30
    while time.time() < deadline:
        if os.path.exists(sock_path):
            _log('ryll control socket is ready')
            return proc
        if proc.poll() is not None:
            _dump_ryll_diagnostics(proc, run_dir, log_path)
            raise SystemExit(
                'ryll exited (code %s) before its control socket appeared'
                % proc.returncode)
        time.sleep(0.5)

    _dump_ryll_diagnostics(proc, run_dir, log_path)
    proc.terminate()
    raise SystemExit('ryll control socket did not appear within 30s')


def _run_smoke_client(smoke_client, sock_path, log_file):
    """Reuse the direct-qemu smoke client to assert a live proxied surface."""
    _log('running smoke-client.py (surfaces + screenshot)')
    result = subprocess.run(
        [sys.executable, smoke_client, sock_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    with open(log_file, 'w') as f:
        f.write(result.stdout or '')
    if result.returncode != 0:
        _log('  smoke-client.py output:\n%s' % (result.stdout or ''))
        raise SystemExit(
            'smoke-client.py failed (exit %d)' % result.returncode)
    _log('smoke-client.py passed (output in %s)' % log_file)


def _session_present(db, source, console_uuid):
    """True if kerbside has an active session for the console."""
    for entry in db.get_sessions().values():
        if entry.get('source') == source and entry.get('uuid') == console_uuid:
            return True
    return False


def main():
    parser = argparse.ArgumentParser(
        description='Drive an oVirt console through kerbside\'s proxy.')
    parser.add_argument(
        '--workdir', default=None,
        help='the deploy-kerbside.sh work directory (default: $WORKDIR, or '
             '%s)' % DEFAULT_WORKDIR)
    args = parser.parse_args()

    workdir = args.workdir or os.environ.get('WORKDIR') or DEFAULT_WORKDIR
    _load_env_file(os.path.join(workdir, 'kerbside.env'))

    # The runner's squid proxy 503s loopback traffic, so exempt it before any
    # requests call is made.
    os.environ['no_proxy'] = '127.0.0.1,localhost,' + os.environ.get(
        'no_proxy', '')

    source = os.environ['KERBSIDE_SOURCE_NAME']
    run_dir = os.environ.get('KERBSIDE_WORKDIR', workdir)
    api_port = os.environ['KERBSIDE_API_PORT']
    seed_path = os.environ['KERBSIDE_SEED_FILE']
    log_path = os.environ['KERBSIDE_LOG_PATH']
    kerbside_src = os.environ['KERBSIDE_SRC']
    ryll_bin = os.environ['RYLL_BIN']

    # KERBSIDE_SQL_URL is already in the env file; kerbside.config reads it at
    # import, so it must be set before importing kerbside.db (it is).
    from kerbside import db

    import requests

    smoke_client = os.path.join(
        kerbside_src, 'tools', 'direct-qemu', 'smoke-client.py')
    vv_path = os.path.join(run_dir, 'console.vv')
    sock_path = os.path.join(run_dir, 'ryll-ovirt.sock')
    smoke_log = os.path.join(run_dir, 'smoke-client.log')

    # 1. Wait for the oVirt scrape to discover the test VM.
    console = _discover_console(db, source)
    console_uuid = console['uuid']
    hypervisor_ip = console.get('hypervisor_ip')
    insecure_port = console.get('insecure_port')
    secure_port = console.get('secure_port')
    host_subject = console.get('host_subject')
    _log('discovered console %s (name %s): hypervisor_ip=%s insecure_port=%s '
         'secure_port=%s host_subject=%s'
         % (console_uuid, console.get('name'), hypervisor_ip, insecure_port,
            secure_port, host_subject))

    # 2. Assert the values the backend TLS leg depends on.
    if not secure_port:
        raise SystemExit(
            'console %s has no secure_port; this lane exists to prove the '
            'backend TLS leg and cannot without one' % console_uuid)
    if not host_subject:
        raise SystemExit(
            'console %s has no host_subject; certificate-subject pinning '
            'cannot be exercised without one' % console_uuid)

    # 3. Mint an API JWT (never printed).
    jwt_token = _mint_auth_jwt(seed_path)
    headers = {'Authorization': 'Bearer %s' % jwt_token,
               'Accept': 'application/json'}

    # 4. Fetch the .vv and connect IMMEDIATELY.
    #
    # ConsolesProxyVirtViewer (kerbside/api.py:465-473) acquires a FRESH oVirt
    # graphics-console ticket from the engine on every request and stores it
    # on the console row. oVirt tickets expire in about 120 seconds by
    # default, so any sleep, retry loop, or extra work between this fetch and
    # the ryll launch below risks a flaky lane. Do not insert anything here.
    vv_url = 'http://127.0.0.1:%s/console/proxy/%s/%s/console.vv' % (
        api_port, source, console_uuid)
    _log('fetching the proxied .vv for %s/%s' % (source, console_uuid))
    resp = requests.get(vv_url, headers=headers, timeout=30)
    if resp.status_code != 200:
        first_line = (resp.text or '').splitlines()
        raise SystemExit(
            '.vv fetch returned HTTP %d (expected 200); first line of the '
            'response body: %s'
            % (resp.status_code, first_line[0] if first_line else '(empty)'))
    fd = os.open(vv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(resp.text)
    ryll = _launch_ryll(ryll_bin, vv_path, sock_path, run_dir, log_path)

    try:
        # 5. Assert real SPICE was relayed through the proxy.
        _run_smoke_client(smoke_client, sock_path, smoke_log)

        # 6. Assert kerbside's bookkeeping.
        audit_count = db.count_audit_events(source, console_uuid)
        if audit_count < 1:
            raise SystemExit(
                'expected an audit row for %s/%s, found none'
                % (source, console_uuid))
        if not _session_present(db, source, console_uuid):
            raise SystemExit(
                'expected an active kerbside session for the console')
        _log('audit rows present (%d) and session is active' % audit_count)
    finally:
        # 7. Stop ryll before driving termination through the API.
        ryll.terminate()
        try:
            ryll.wait(timeout=10)
        except subprocess.TimeoutExpired:
            ryll.kill()

    # 7 (continued). Terminate via the live REST API and assert teardown.
    _log('terminating the console via the kerbside REST API')
    url = 'http://127.0.0.1:%s/console/%s/%s/terminate' % (
        api_port, source, console_uuid)
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code != 200:
        raise SystemExit(
            'terminate returned HTTP %d (expected 200)' % resp.status_code)

    if _session_present(db, source, console_uuid):
        raise SystemExit('session still active after terminate')

    events = db.get_audit_events(source, console_uuid, limit=50)
    if not any('terminated' in (e.get('message') or '').lower()
               for e in events):
        raise SystemExit('no termination audit event found after terminate')
    _log('session removed and termination audit event recorded')

    _log('oVirt proxied console path passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
