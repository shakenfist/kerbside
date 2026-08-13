#!/usr/bin/env python3
"""Drive the happy-path SF -> kerbside -> proxied SPICE session.

Runs ON the SF primary, with the kerbside venv's python (so both
``shakenfist_client`` and ``kerbside`` import). It:

  1. waits for kerbside's shakenfist scrape to pick up the Sextant console;
  2. calls ``client.get_vdi_console_proxy_file()`` -- one call that mints an
     SF token AND exchanges it at kerbside for the ``.vv``;
  3. launches ``ryll --headless`` against kerbside's proxy over localhost
     (mirroring the direct-qemu lane's lane-up.sh steps 7-8);
  4. reuses ``../direct-qemu/smoke-client.py`` (surfaces + screenshot over the
     control socket) and ``../direct-qemu/wait-for-banner.sh`` (the Sextant
     boot banner, fed from SF console data) to assert a live proxied session;
  5. asserts a session audit row exists in kerbside's DB;
  6. terminates the console via kerbside's REST API and asserts the session
     is removed and a termination audit event was appended.

SECURITY: the raw ``.vv`` text, the SF JWT, the terminate JWT, the auth
seed, and any key material are NEVER printed. Exits non-zero on any failure.
"""

import os
import subprocess
import sys
import threading
import time
import uuid as uuidlib


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
    print('[sf-e2e] %s' % msg, file=sys.stderr)


def _wait_for_console(db, source, instance_uuid, timeout=180):
    """Poll kerbside's DB until the shakenfist scrape yields the console."""
    _log('waiting for kerbside to scrape console %s (source %s)...'
         % (instance_uuid, source))
    deadline = time.time() + timeout
    while time.time() < deadline:
        console = db.get_console(source, instance_uuid)
        if console is not None and console.get('source') == source:
            _log('console %s is present in kerbside' % instance_uuid)
            return
        time.sleep(3)
    raise SystemExit(
        'console %s never appeared in kerbside within %ds'
        % (instance_uuid, timeout))


def _launch_ryll(ryll_bin, vv_path, sock_path, run_dir):
    """Launch ryll headless and wait for its control socket."""
    stdout = open(os.path.join(run_dir, 'ryll.stdout'), 'wb')
    stderr = open(os.path.join(run_dir, 'ryll.stderr'), 'wb')
    _log('launching ryll headless')
    proc = subprocess.Popen(
        [ryll_bin, '--verbose', '--headless', '--file', vv_path,
         '--control-socket', sock_path, '--enable-paste-as-keystrokes'],
        stdout=stdout, stderr=stderr)

    deadline = time.time() + 30
    while time.time() < deadline:
        if os.path.exists(sock_path):
            _log('ryll control socket is ready')
            return proc
        if proc.poll() is not None:
            raise SystemExit(
                'ryll exited (code %s) before its control socket appeared'
                % proc.returncode)
        time.sleep(0.5)
    proc.terminate()
    raise SystemExit('ryll control socket did not appear within 30s')


def _run_smoke_client(smoke_client, sock_path):
    """Reuse the direct-qemu smoke client to assert a live proxied surface."""
    _log('running smoke-client.py (surfaces + screenshot)')
    result = subprocess.run(
        [sys.executable, smoke_client, sock_path])
    if result.returncode != 0:
        raise SystemExit(
            'smoke-client.py failed (exit %d)' % result.returncode)
    _log('smoke-client.py passed')


class _ConsoleDataPump(threading.Thread):
    """Continuously mirror SF console data into a serial-log file.

    wait-for-banner.sh polls a serial log for the Sextant boot banner; the
    nested SF guest has no host-side qemu serial log, so we source it from
    the SF API's console data instead and reuse the script unchanged.
    """

    def __init__(self, client, instance_uuid, serial_log):
        super().__init__(daemon=True)
        self._client = client
        self._uuid = instance_uuid
        self._serial_log = serial_log
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                data = self._client.get_console_data(
                    self._uuid, 200000, decode=None)
                if isinstance(data, str):
                    data = data.encode('utf-8', 'replace')
                with open(self._serial_log, 'wb') as f:
                    f.write(data or b'')
            except Exception as exc:  # noqa: BLE001 - diagnostic only
                _log('console-data pump hiccup (ignored): %s' % exc)
            self._stop.wait(2)

    def stop(self):
        self._stop.set()


def _assert_banner(wait_for_banner, serial_log):
    """Reuse wait-for-banner.sh to assert the Sextant boot banner."""
    _log('waiting for the Sextant boot banner via SF console data')
    result = subprocess.run([wait_for_banner, serial_log, '90'])
    if result.returncode != 0:
        raise SystemExit('Sextant boot banner not seen')
    _log('Sextant boot banner seen')


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
        'sub': 'sf-e2e-driver',
        'exp': now + 3600,
    }
    token = pyjwt.encode(payload, seed, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token


def _session_present(db, source, instance_uuid):
    """True if kerbside has an active session for the console."""
    for entry in db.get_sessions().values():
        if entry.get('source') == source and entry.get('uuid') == instance_uuid:
            return True
    return False


def main():
    root = '/tmp/sf-e2e'
    _load_env_file(os.path.join(root, 'kerbside.env'))
    _load_env_file(os.path.join(root, 'instance.env'))

    os.environ['no_proxy'] = '127.0.0.1,localhost,' + os.environ.get(
        'no_proxy', '')

    source = os.environ['KERBSIDE_SOURCE_NAME']
    instance_uuid = os.environ['INSTANCE_UUID']
    sf_url = os.environ['SF_URL']
    namespace = os.environ['SF_NAMESPACE']
    namespace_key = os.environ['SF_NAMESPACE_KEY']
    run_dir = os.environ['KERBSIDE_RUN_DIR']
    api_port = os.environ['KERBSIDE_API_PORT']
    seed_path = os.environ['KERBSIDE_SEED_FILE']
    kerbside_src = os.environ['KERBSIDE_SRC']
    ryll_bin = os.environ['RYLL_BIN']

    # KERBSIDE_SQL_URL is already in the env file; kerbside.config reads it at
    # import, so it must be set before importing kerbside.db (it is).
    from kerbside import db

    from shakenfist_client import apiclient
    import requests

    client = apiclient.Client(
        base_url=sf_url, namespace=namespace, key=namespace_key,
        async_strategy=apiclient.ASYNC_BLOCK)

    smoke_client = os.path.join(
        kerbside_src, 'tools', 'direct-qemu', 'smoke-client.py')
    wait_for_banner = os.path.join(
        kerbside_src, 'tools', 'direct-qemu', 'wait-for-banner.sh')
    vv_path = os.path.join(run_dir, 'console.vv')
    sock_path = os.path.join(run_dir, 'ryll-e2e.sock')
    serial_log = os.path.join(run_dir, 'sextant-serial.log')

    # 1. Wait for the scrape, then mint + exchange in one client call.
    _wait_for_console(db, source, instance_uuid)

    _log('minting + exchanging the SF token for a .vv')
    vv_text = client.get_vdi_console_proxy_file(instance_uuid)
    if '/sf-console.vv?token=' in vv_text:
        # Defensive: the .vv must never carry the exchange JWT.
        raise SystemExit('.vv unexpectedly contains a token URL')
    with open(vv_path, 'w') as f:
        f.write(vv_text)
    _log('wrote %s (%d bytes)' % (vv_path, len(vv_text)))

    # 2. Drive a proxied SPICE session.
    ryll = _launch_ryll(ryll_bin, vv_path, sock_path, run_dir)
    pump = _ConsoleDataPump(client, instance_uuid, serial_log)
    pump.start()
    try:
        _run_smoke_client(smoke_client, sock_path)
        _assert_banner(wait_for_banner, serial_log)

        # 3. Assert a session audit row exists.
        audit_count = db.count_audit_events(source, instance_uuid)
        if audit_count < 1:
            raise SystemExit(
                'expected an audit row for %s/%s, found none'
                % (source, instance_uuid))
        if not _session_present(db, source, instance_uuid):
            raise SystemExit(
                'expected an active kerbside session for the console')
        _log('audit rows present (%d) and session is active' % audit_count)
    finally:
        pump.stop()
        ryll.terminate()
        try:
            ryll.wait(timeout=10)
        except subprocess.TimeoutExpired:
            ryll.kill()

    # 4. Terminate the console via the live REST API and assert teardown.
    _log('terminating the console via the kerbside REST API')
    jwt_token = _mint_auth_jwt(seed_path)
    url = 'http://127.0.0.1:%s/console/%s/%s/terminate' % (
        api_port, source, instance_uuid)
    resp = requests.get(
        url, headers={'Authorization': 'Bearer %s' % jwt_token,
                      'Accept': 'application/json'}, timeout=15)
    if resp.status_code != 200:
        raise SystemExit(
            'terminate returned HTTP %d (expected 200)' % resp.status_code)

    if _session_present(db, source, instance_uuid):
        raise SystemExit('session still active after terminate')

    events = db.get_audit_events(source, instance_uuid, limit=50)
    if not any('terminated' in (e.get('message') or '').lower()
               for e in events):
        raise SystemExit('no termination audit event found after terminate')
    _log('session removed and termination audit event recorded')

    _log('happy path passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
