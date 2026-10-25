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
     ``ryll --headless`` against it promptly. The .vv carries a kerbside
     token valid for ``CONSOLE_TOKEN_DURATION`` (a minute by default); the
     oVirt graphics-console ticket is minted when the session's first
     channel connects, for the token's remaining lifetime plus 30 s, and
     kept on the session's token row. The driver waits for that mint and
     reads the ticket once, before the daemon's maintenance loop clears it;
  4. reuses ``../direct-qemu/smoke-client.py`` (surfaces + PNG screenshot over
     the control socket) to assert real SPICE relayed through the proxy --
     guest-agnostic, which matters here because the guest is a Debian 12 GNOME
     image rather than Uncalibrated Sextant;
  5. asserts the proxy log shows the backend leg escalated to TLS with a
     non-empty certificate-subject pin on every escalation line, and that
     pinning did not visibly reject -- pinning fails silently in the passing
     direction, so the escalation line's ``host_subject`` field is the only
     oracle that the values asserted in step 2 were actually used;
  6. asserts an audit row and an active session exist for the console;
  7. asserts how the ticket was handled: the console row holds none, the
     token row recorded an expiry of about the token's expiry plus 30 s,
     and the session minted exactly once (one ``Minted backend console
     ticket`` audit event, and no failed mint) although it opened several
     channels. It then holds the session until 30 s past the ticket's
     expiry, re-runs the smoke client, asserts ryll and its channels are
     still up, and waits for the maintenance loop to clear the expired
     ticket from the token row;
  8. terminates the console via kerbside's REST API while ryll is still
     connected, and asserts the proxy dropped the in-flight session (the
     relay.rs oracle, as tools/direct-qemu/verify-terminate-live.sh does),
     the session is removed, and a termination audit event was appended;
  9. asserts the ticket appears in none of the files the lane uploads as
     artifacts, nor in the console's audit messages.

Configuration comes from ``${WORKDIR}/kerbside.env``, written by
``deploy-kerbside.sh``. WORKDIR defaults to ``/tmp/kerbside-ovirt-ci`` and may
be overridden by the ``WORKDIR`` environment variable or ``--workdir``
(the argument wins).

SECURITY: the API JWT, the oVirt graphics-console ticket, the auth seed, and
the ``.vv`` body are NEVER printed or logged. The ticket is read from the
database once, held in memory to search the collected logs for it, and only
its length is reported. The on-timeout diagnostic dump
deliberately omits the ``.vv`` contents, unlike the direct-qemu lane's
lane-up.sh, because the proxied ``.vv`` carries a kerbside proxy token.
Exits non-zero on any failure.
"""

import argparse
import os
import re
import subprocess
import sys
import time
import uuid as uuidlib


DEFAULT_WORKDIR = '/tmp/kerbside-ovirt-ci'

# The lane's test VM is created by shakenfist/actions'
# tools/start-test-target.py, which names it smoke-test-<something>.
# tools/test-ovirt-console.py matches on the same prefix.
CONSOLE_NAME_PREFIX = 'smoke-test-'

# The VM tools/create-ovirt-vnc-vm.py leaves running with a VNC display
# and no SPICE console. Kerbside must skip it during discovery, so it
# must never appear as a console. Keep in step with that script's
# --name default.
NO_SPICE_VM_NAME = 'no-spice-test'

# Proxy log oracles, asserted against the kerbside daemon log (which
# carries the Rust proxy's tracing output). These are load-bearing
# assertions, not diagnostics. The first two must stay in step with the
# message text at the CI-ORACLE-marked info! sites in
# rust/kerbside-proxy/src/backend.rs and relay.rs. The rejection needle
# is different: that message is produced by the ryll
# shakenfist-spice-protocol crate's verifier (rev-pinned via
# rust/kerbside-proxy/Cargo.toml), not by this repo, so nothing here
# flags a reword and a stale needle fails in the unsafe direction
# (silently passing). Match on the same short, stable fragment
# tools/direct-qemu/verify-rust-proxy.sh uses rather than the full
# message.
TLS_ESCALATION_ORACLE = ('hypervisor requires TLS; retrying backend '
                         'connection over the secure port')
PINNED_SUBJECT_REJECTION = 'pinned host_subject'
TERMINATE_ORACLE = 'session terminated by control plane'

# Audit event oracles, which must stay in step with the messages
# AuthorizeConnection writes in kerbside/rpc/servicer.py. A stale mint or
# channel needle fails closed (the counts asserted below come out wrong);
# a stale failure needle would hide a failed mint, but a failed mint also
# denies its channel, so the session would not have got this far.
MINT_AUDIT_PREFIX = 'Minted backend console ticket'
MINT_FAILED_AUDIT_PREFIX = 'Backend console ticket mint failed'
CHANNEL_CREATED_AUDIT = 'Channel created'

# How far past the backend ticket's expiry the session is held, to show
# that an established SPICE session outlives the ticket it linked with.
HOLD_PAST_TICKET_EXPIRY = 30

# The hold is computed from the ticket's expiry, which follows
# CONSOLE_TOKEN_DURATION. deploy-kerbside.sh leaves that at its default of
# a minute, making the hold about two minutes; refuse to sleep for much
# longer than that, since it means the deployment is not the one this
# driver expects and the drive step's timeout would cut the run short.
MAX_HOLD = 300

# How long to wait, once the hold is over, for the daemon's maintenance
# loop to clear the expired ticket from the token row. The loop runs about
# once every 60 s, and each pass also rescrapes the sources.
TICKET_CLEAR_GRACE = 75

# A ticket shorter than this would make the search for it in the logs
# match by chance. oVirt's are far longer.
MIN_SEARCHABLE_TICKET = 8

# tracing renders a structured field as `<esc>[3mname<esc>[0m<esc>[2m=`,
# so the literal `name=` a naive search looks for is not in the line at
# all when colour is on -- which is how #272 turned a correctly pinned
# TLS leg into an "empty host_subject" security failure. The proxy now
# disables ANSI unless its stdout is a terminal
# (rust/kerbside-proxy/src/main.rs), but a log captured from an older
# build, or from a terminal-attached run, still carries escapes, so
# strip them on read rather than trusting the writer.
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _strip_ansi(text):
    """Remove SGR escape sequences from captured tracing output."""
    return _ANSI_RE.sub('', text)


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


def _assert_no_spice_vm_skipped(db, source):
    """Assert the VNC-only VM was skipped rather than brokered or fatal.

    tools/create-ovirt-vnc-vm.py leaves a running VM with no SPICE
    console in the engine. Discovery must skip it and keep going. The
    two ways that can go wrong fail differently and both are caught:

    * Skipping it fatally (the missing `continue` in sources/ovirt.py)
      errors the whole source, so deploy-kerbside.sh's wait for a
      non-errored source fails before this ever runs, and if it somehow
      got past that, _discover_console() would time out.
    * Not skipping it at all -- brokering a console kerbside cannot
      actually connect to -- shows up here as a console row that should
      not exist.

    Only the second needs asserting, but say so out loud either way: a
    guard that can only pass is worse than no guard.
    """
    names = sorted(
        c.get('name') or ''
        for c in db.get_consoles(include_audit=False)
        if c.get('source') == source)
    if NO_SPICE_VM_NAME in names:
        raise SystemExit(
            '%s has no SPICE console, so kerbside must not have brokered '
            'it, but it is in the console list for source %s (consoles: '
            '%s). Discovery is yielding VMs it cannot connect to.'
            % (NO_SPICE_VM_NAME, source, ', '.join(names)))
    _log('confirmed %s was skipped; source %s brokered: %s'
         % (NO_SPICE_VM_NAME, source, ', '.join(names)))


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


def _log_contains(log_path, needle):
    """True if the daemon/proxy log currently contains `needle`."""
    try:
        with open(log_path, 'r', errors='replace') as f:
            return needle in _strip_ansi(f.read())
    except OSError:
        return False


def _escalation_pins(log_path):
    """(pins, unparseable) from the TLS escalation log lines.

    The escalation info! in rust/kerbside-proxy/src/backend.rs logs the
    pin it is about to apply as a trailing ``host_subject=`` field (the
    subject may contain spaces, so take everything to end of line). Only
    the text after the message is searched, so a tracing format change
    that stopped rendering the field last cannot silently match
    something else.

    ``pins`` holds one value per escalation line that carried a
    parseable field -- '' when the field was present but empty, which is
    a real unpinned escalation. Lines that carry the oracle but no
    parseable ``host_subject=`` at all are counted in ``unparseable``
    instead, and are the caller's cue that this check has gone blind.
    Folding them into ``pins`` as '' (as this did until #272) reports a
    harness failure as a proxy security failure, which is the most
    misleading outcome available.
    """
    pins = []
    unparseable = 0
    with open(log_path, 'r', errors='replace') as f:
        for line in f:
            line = _strip_ansi(line)
            offset = line.find(TLS_ESCALATION_ORACLE)
            if offset == -1:
                continue
            match = re.search(r'host_subject=(.*)$', line[offset:])
            if match is None:
                unparseable += 1
                continue
            pins.append(match.group(1).strip())
    return pins, unparseable


def _session_present(db, source, console_uuid):
    """True if kerbside has an active session for the console."""
    for entry in db.get_sessions().values():
        if entry.get('source') == source and entry.get('uuid') == console_uuid:
            return True
    return False


def _session_audit_messages(db, source, console_uuid, session_id):
    """The audit messages recorded for one session of the console."""
    return [e.get('message') or ''
            for e in db.get_audit_events(source, console_uuid, limit=500)
            if e.get('session_id') == session_id]


def _open_channel_count(db, session_id):
    """How many proxy channels kerbside holds open for a session."""
    return len(db.get_sessions().get(session_id, {}).get('channels', []))


def _capture_backend_ticket(db, source, console_uuid, timeout=30):
    """Wait for the session's backend ticket to be minted, and read it once.

    Returns (token, ticket): the session's token row without its secret,
    and the ticket itself, which the caller must never print. Only one .vv
    has been fetched, so the console has exactly one token. The ticket is
    read through the ORM because no db function hands it out except
    session_ticket(), which would mint.
    """
    deadline = time.time() + timeout
    token = None
    while time.time() < deadline:
        tokens = db.get_tokens_by_console(source, console_uuid)
        if len(tokens) > 1:
            raise SystemExit(
                'expected one console token for %s/%s, as one .vv was '
                'fetched, but found %d' % (source, console_uuid, len(tokens)))
        if tokens and tokens[0].get('backend_ticket_expires'):
            token = tokens[0]
            break
        time.sleep(1)

    if token is None:
        failures = [m for m in (e.get('message') or '' for e in
                                db.get_audit_events(source, console_uuid,
                                                    limit=500))
                    if m.startswith(MINT_FAILED_AUDIT_PREFIX)]
        raise SystemExit(
            'the session\'s token row recorded no backend ticket expiry '
            'within %ds of ryll starting; failed mints audited for the '
            'console: %s' % (timeout, '; '.join(failures) or 'none'))

    with db.Session(db.ENGINE) as session:
        row = session.query(db.ConsoleToken).\
            filter(db.ConsoleToken.session_id == token['session_id']).\
            one_or_none()
        ticket = row.backend_ticket if row is not None else None
    if not ticket:
        raise SystemExit(
            'the token row for session %s records a backend ticket expiry '
            'but no ticket' % token['session_id'])
    if len(ticket) < MIN_SEARCHABLE_TICKET:
        raise SystemExit(
            'the backend ticket is only %d characters, too short to search '
            'the logs for meaningfully' % len(ticket))
    _log('session %s minted a backend ticket (%d characters) expiring %ds '
         'after its token'
         % (token['session_id'], len(ticket),
            token['backend_ticket_expires'] - token['expires']))
    return token, ticket


def _hold_session(ryll, hold_until, run_dir, log_path):
    """Sleep until hold_until, failing at once if ryll's session ends.

    hold_until is an epoch second written by the daemon on this host, so
    this host's clock is the one to compare it with.
    """
    while time.time() < hold_until:
        if ryll.poll() is not None:
            _dump_ryll_diagnostics(ryll, run_dir, log_path)
            raise SystemExit(
                'ryll exited (code %s) %ds before the hold ended; the '
                'session did not survive its backend ticket'
                % (ryll.returncode, hold_until - time.time()))
        time.sleep(min(5, max(hold_until - time.time(), 0)))


def _files_containing(paths, secret):
    """(found, searched): which of paths contain secret, and how many were read.

    found holds base names only. The text is searched both as written and
    with ANSI escapes removed, so a colourised log line cannot split the
    value. Missing files are skipped and not counted in searched.
    """
    found = []
    searched = 0
    for path in paths:
        try:
            with open(path, 'r', errors='replace') as f:
                text = f.read()
        except OSError:
            continue
        searched += 1
        if secret in text or secret in _strip_ansi(text):
            found.append(os.path.basename(path))
    return found, searched


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
    from kerbside.rpc.servicer import TICKET_SLACK
    from kerbside.sources.minting import MINT_DEADLINE

    import requests

    smoke_client = os.path.join(
        kerbside_src, 'tools', 'direct-qemu', 'smoke-client.py')
    vv_path = os.path.join(run_dir, 'console.vv')
    sock_path = os.path.join(run_dir, 'ryll-ovirt.sock')
    smoke_log = os.path.join(run_dir, 'smoke-client.log')
    held_smoke_log = os.path.join(run_dir, 'smoke-client-held.log')

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

    # 1b. Assert the VM with no SPICE console was skipped, not brokered.
    _assert_no_spice_vm_skipped(db, source)

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

    # 4. Fetch the .vv and connect promptly.
    #
    # The .vv carries a kerbside token valid for CONSOLE_TOKEN_DURATION
    # minutes from this fetch (one, as deploy-kerbside.sh leaves the
    # default), and no channel is authorized once it has expired, so work
    # inserted between the fetch and the ryll launch below eats into the
    # window ryll has to connect. No oVirt ticket is minted here:
    # AuthorizeConnection mints one when the session's first channel
    # connects, for the token's remaining lifetime plus TICKET_SLACK, and
    # the session's later channels reuse it.
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
        # 4b. Wait for the first channel to mint the session's backend
        # ticket, and read it once. The daemon's maintenance loop clears
        # the ticket and its expiry from the token row once the token has
        # expired, so this is done before anything else can use up the
        # token's minute. The ticket is a live hypervisor password: it is
        # held in this variable only, used solely to check that no
        # collected log carries it (step 10), and only its length is
        # ever printed.
        token, backend_ticket = _capture_backend_ticket(
            db, source, console_uuid)
        session_id = token['session_id']

        # 5. Assert real SPICE was relayed through the proxy.
        _run_smoke_client(smoke_client, sock_path, smoke_log)

        # The log oracles from here on read the daemon log directly. A
        # missing file is a lane misconfiguration (KERBSIDE_LOG_PATH is
        # wrong, or the daemon never started), not a proxy behaviour --
        # fail as that, rather than letting _log_contains report the
        # unreadable log as 'oracle absent' and blaming the proxy.
        if not os.path.exists(log_path):
            raise SystemExit(
                'kerbside daemon log %s does not exist; KERBSIDE_LOG_PATH '
                'is wrong or the daemon never started' % log_path)

        # 5b. Assert the backend TLS escalation actually happened, and
        # that every escalation carried a non-empty certificate-subject
        # pin. Step 2 proved the scrape *populated* secure_port and
        # host_subject; neither proves the proxy used them. If the proxy
        # relayed happily over the plaintext port the escalation line
        # would be absent; if host_subject were dropped before
        # build_config (an empty subject maps to None, which disables
        # verification) the TLS handshake would still succeed unpinned,
        # so the positive oracle is the host_subject= field the
        # escalation line logs at the point of use.
        pins, unparseable = _escalation_pins(log_path)
        if unparseable:
            _log('  kerbside daemon (proxy) log:\n%s' % _tail(log_path, 60))
            raise SystemExit(
                '%d backend TLS escalation line(s) carried no parseable '
                'host_subject= field; the proxy log format has changed and '
                'this check can no longer tell whether pinning happened. '
                'This is a harness failure, not a proxy failure -- fix the '
                'parser before reading anything into it.' % unparseable)
        if not pins:
            _log('  kerbside daemon (proxy) log:\n%s' % _tail(log_path, 60))
            raise SystemExit(
                'the proxy never logged %r; the backend leg did not '
                'escalate to TLS' % TLS_ESCALATION_ORACLE)
        if not all(pins):
            _log('  kerbside daemon (proxy) log:\n%s' % _tail(log_path, 60))
            raise SystemExit(
                'a backend TLS escalation logged an empty host_subject; '
                'the secure leg ran without certificate-subject pinning')

        # Belt and braces only: a pinning rejection would have failed
        # the smoke client above first (the rejected channel never
        # relays), so this check is close to unreachable. It is kept
        # because it is cheap and its failure mode (a rejection line
        # with a somehow-working relay) would be genuinely alarming.
        if _log_contains(log_path, PINNED_SUBJECT_REJECTION):
            _log('  kerbside daemon (proxy) log:\n%s' % _tail(log_path, 60))
            raise SystemExit(
                'the proxy logged a %r rejection; certificate-subject '
                'pinning rejected the hypervisor' % PINNED_SUBJECT_REJECTION)
        _log('backend TLS escalation confirmed with a non-empty subject '
             'pin on all %d escalation(s)' % len(pins))

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

        # 6b. Assert the oVirt ticket belongs to the session. The console
        # row keeps no ticket for a source which mints them; the only
        # ticket is the session's, minted once for all of its channels.
        console_row = db.get_console(
            source, console_uuid, include_secrets=True) or {}
        row_ticket = console_row.get('ticket') or ''
        if row_ticket:
            raise SystemExit(
                'console %s holds a %d character ticket on its console row; '
                'an oVirt console\'s ticket belongs to its session, so the '
                'row should hold none' % (console_uuid, len(row_ticket)))

        # The lifetime asked for is the token's remaining life plus
        # TICKET_SLACK, measured just before the mint starts; the expiry
        # is the mint's start plus what the engine granted, and the mint
        # finishes within MINT_DEADLINE.
        ticket_expires = token['backend_ticket_expires']
        expected = token['expires'] + TICKET_SLACK
        if not expected - 2 <= ticket_expires <= expected + MINT_DEADLINE:
            raise SystemExit(
                'the backend ticket expires %ds after the token; expected '
                'about %ds' % (ticket_expires - token['expires'],
                               TICKET_SLACK))

        messages = _session_audit_messages(
            db, source, console_uuid, session_id)
        mints = [m for m in messages if m.startswith(MINT_AUDIT_PREFIX)]
        failures = [m for m in messages
                    if m.startswith(MINT_FAILED_AUDIT_PREFIX)]
        channels_created = messages.count(CHANNEL_CREATED_AUDIT)
        open_channels = _open_channel_count(db, session_id)
        _log('session %s: %d channel(s) created, %d open, %d ticket '
             'mint(s), %d failed mint(s)'
             % (session_id, channels_created, open_channels, len(mints),
                len(failures)))
        if failures:
            raise SystemExit(
                'the session audited failed mints: %s' % '; '.join(failures))
        if channels_created < 2:
            raise SystemExit(
                'the session created %d channel(s); a single mint only '
                'shows the ticket is shared if there are several'
                % channels_created)
        if len(mints) != 1:
            raise SystemExit(
                'expected exactly one backend ticket mint for the session\'s '
                '%d channels, found %d' % (channels_created, len(mints)))

        # Hold the session past the ticket's expiry. An established SPICE
        # session does not present its ticket again, so it must outlive
        # it; the hold proves that against a real engine and qemu.
        hold_until = ticket_expires + HOLD_PAST_TICKET_EXPIRY
        hold = hold_until - time.time()
        if hold > MAX_HOLD:
            raise SystemExit(
                'holding until %ds past the backend ticket\'s expiry would '
                'take %ds, over the %ds this driver allows; is '
                'CONSOLE_TOKEN_DURATION longer than deploy-kerbside.sh '
                'leaves it?' % (HOLD_PAST_TICKET_EXPIRY, hold, MAX_HOLD))
        _log('holding the session for %ds, until %ds past its backend '
             'ticket\'s expiry' % (max(hold, 0), HOLD_PAST_TICKET_EXPIRY))
        _hold_session(ryll, hold_until, run_dir, log_path)

        _run_smoke_client(smoke_client, sock_path, held_smoke_log)
        open_channels = _open_channel_count(db, session_id)
        if open_channels < 1:
            raise SystemExit(
                'kerbside holds no open channels for session %s after the '
                'hold' % session_id)
        mints = [m for m in _session_audit_messages(
                     db, source, console_uuid, session_id)
                 if m.startswith(MINT_AUDIT_PREFIX)]
        if len(mints) != 1:
            raise SystemExit(
                'the session minted %d backend tickets by the end of the '
                'hold; expected still one' % len(mints))
        _log('session outlived its backend ticket with %d channel(s) open'
             % open_channels)

        # The token expired at least a minute ago, so the maintenance loop
        # has had its chance to clear the ticket from the token row; allow
        # it one more pass.
        deadline = time.time() + TICKET_CLEAR_GRACE
        while True:
            row = db.get_token_by_session_id(session_id)
            if row is None:
                raise SystemExit(
                    'the token row for session %s vanished while the '
                    'session was open' % session_id)
            if row.get('backend_ticket_expires') is None:
                break
            if time.time() >= deadline:
                raise SystemExit(
                    'the maintenance loop had not cleared the expired '
                    'backend ticket from the token row %ds after the hold'
                    % TICKET_CLEAR_GRACE)
            time.sleep(2)
        _log('maintenance loop cleared the expired backend ticket')

        # 7. Terminate via the live REST API while ryll is still
        # connected, so this asserts an in-flight drop rather than the
        # bookkeeping of a session that had already ended.
        _log('terminating the console via the kerbside REST API')
        url = 'http://127.0.0.1:%s/console/%s/%s/terminate' % (
            api_port, source, console_uuid)
        resp = requests.post(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            raise SystemExit(
                'terminate returned HTTP %d (expected 200)'
                % resp.status_code)

        # The daemon polls session_terminations every ~2s, so allow a
        # bounded window for the relay to drop (the same oracle and
        # reasoning as tools/direct-qemu/verify-terminate-live.sh).
        deadline = time.time() + 30
        while not _log_contains(log_path, TERMINATE_ORACLE):
            if time.time() >= deadline:
                _log('  kerbside daemon (proxy) log:\n%s'
                     % _tail(log_path, 60))
                raise SystemExit(
                    'the proxy never logged %r within 30s of the '
                    'terminate call; the in-flight session was not '
                    'dropped' % TERMINATE_ORACLE)
            time.sleep(1)
        _log('proxy dropped the in-flight session')

        # Secondary, non-fatal confirmation (as in
        # verify-terminate-live.sh): headless ryll exits its event loop
        # when its channels close.
        try:
            ryll.wait(timeout=15)
            _log('ryll exited as its channels closed (code %s)'
                 % ryll.returncode)
        except subprocess.TimeoutExpired:
            _log('ryll still running 15s after the drop; proceeding on '
                 'the log oracle alone')
    finally:
        # 8. Belt and braces: on the happy path ryll has already exited
        # via the termination above, and terminate() on an exited
        # process is a no-op. This only matters on the failure paths.
        ryll.terminate()
        try:
            ryll.wait(timeout=10)
        except subprocess.TimeoutExpired:
            ryll.kill()

    # 9. Post-drop bookkeeping. _session_present() is a weak oracle at
    # this point -- terminate deletes the ConsoleToken row that
    # get_sessions() keys on, so it cannot return True once the API call
    # returned 200. The in-flight assertion above is the real gate; this
    # records what an operator listing sessions would now see.
    if _session_present(db, source, console_uuid):
        raise SystemExit('session still active after terminate')

    events = db.get_audit_events(source, console_uuid, limit=50)
    if not any('terminated' in (e.get('message') or '').lower()
               for e in events):
        raise SystemExit('no termination audit event found after terminate')
    _log('session removed and termination audit event recorded')

    # 10. Assert the backend ticket leaked into nothing the lane uploads as
    # an artifact (the list in functional-tests.yml), nor into the audit
    # trail. Only file names and counts are reported.
    collected = [
        log_path,
        '%s.gunicorn-access' % log_path,
        '%s.gunicorn-error' % log_path,
        os.path.join(workdir, 'kerbside.env'),
        os.path.join(run_dir, 'ryll-ovirt.stdout'),
        os.path.join(run_dir, 'ryll-ovirt.stderr'),
        smoke_log,
        held_smoke_log,
    ]
    leaked, searched = _files_containing(collected, backend_ticket)
    if leaked:
        raise SystemExit(
            'the backend ticket appears in %s' % ', '.join(leaked))
    if any(backend_ticket in (e.get('message') or '')
           for e in db.get_audit_events(source, console_uuid, limit=500)):
        raise SystemExit('the backend ticket appears in an audit message')
    _log('backend ticket found in none of %d collected files nor the audit '
         'trail' % searched)

    _log('oVirt proxied console path passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
