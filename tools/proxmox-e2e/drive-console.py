#!/usr/bin/env python3

"""Drive a Proxmox VE -> kerbside -> proxied SPICE session.

Runs ON the CI runner, with the kerbside venv's python (so kerbside
imports), after tools/proxmox-e2e/deploy-kerbside.sh has deployed kerbside
and registered a "type: proxmox" source against the lane's PVE node. It:

  1. waits for the scrape, and asserts that the console list for the source
     is exactly the smoke guest: its uuid is <vmid>-<SMBIOS UUID>, the UUID
     read from the guest's configuration with the action's token rather
     than kerbside's; its hypervisor is the node name; and its host subject
     is the one PVE gives the node's certificate. None of the guests
     prepare-node.sh made for discovery to skip is listed, and the daemon
     log names the guest with no SMBIOS UUID at info level;
  2. asks for a direct .vv as an administrator, and asserts the 409 and its
     audit event;
  3. fetches a proxied .vv and launches ryll --headless against it, polls
     the session's token row until its backend ticket appears, asserts
     real SPICE with tools/direct-qemu/smoke-client.py, waits for the
     session's channels to settle, and asserts from the proxy log that every
     backend leg was tunnelled, over TLS, and checked against a non-empty
     pinned subject equal to the console's;
  4. holds the session until 30 seconds past both the backend ticket's 30
     seconds and the .vv token's CONSOLE_TOKEN_DURATION, and asserts it
     still passes frames;
  5. opens a second session while the first is held, and asserts the first
     still passes frames after the second has minted: the second mint
     replaced the guest's SPICE password, which must not disconnect a
     client already linked;
  6. terminates the first session over the REST API, and asserts that the
     proxy dropped its channels and not the second session's;
  7. scans every file the lane uploads for each token secret, the auth seed,
     each session's backend ticket, the password in each proxied .vv (kerbside's
     own console token), each API JWT and the literal "pvespiceproxy:", and
     removes any file that holds one.

At each checkpoint it counts mints in PVE's own access log, rather than
trusting kerbside's account of them:

    after the first scrape                                0
    after the refused direct .vv (409, audited)           0
    after the first session's channels have connected     1
    after holding the first session                       1
    after the second session's channels have connected    2
    at the end, after the terminate                       2

PVE'S ACCESS LOG. pveproxy and spiceproxy both write
/var/log/pveproxy/access.log, through pve-http-server's
PVE::APIServer::AnyEvent::log_request (src/PVE/APIServer/AnyEvent.pm, read
at commit 5c9e4ea773364bdb7ae0e2faec5750fe58129a47), which writes each
request once, when its response is sent, as

    my $msg = "$realip - $userid [$timestr] \"$requestline\" $code $content_length\n";

with $timestr = strftime("%d/%m/%Y:%H:%M:%S %z", localtime()), so a mint
looks like this, on one line:

    10.0.2.1 - kerbside-lane@pve!console [29/10/2026:11:02:03 +0100]
        "POST /api2/json/nodes/pve/qemu/100/spiceproxy HTTP/1.1" 200 1234

$userid is the user the auth handler returned, which for an API token is
the whole token ID (pve-manager's PVE::HTTPServer::auth_handler, and
pve-access-control's PVE::AccessControl::verify_token). So mints are
counted for the documented token's ID exactly: the action's token,
kerbside@pve!console, and the single-privilege tokens check-privileges.py
uses are other users. $code is the response's status, and a mint is a
POST to spiceproxy answered 200. pvedaemon, which pveproxy hands the
request to, keeps no access log, so a mint is logged once.

spiceproxy logs its CONNECTs to the same file, with $userid "-" and the
connect host, a live credential, in the request line. So the log is
filtered on the node to the documented token's lines before anything
leaves it, and no line read from it is ever printed.

TWO KINDS OF FAILURE. Every check here reports a harness fault apart from a
defect, as docs/testing.md's "Log-derived oracles" asks: a log line which
would not parse, or a needle which is no longer there, means this script
can no longer see, while a field which parsed and was empty or wrong is a
real finding. The mint count has a third kind. A session's channels reuse
its ticket while at least REUSE_MARGIN of the ticket's TICKET_LIFETIME
remain, and a channel connecting after that legitimately mints again; a
count which is too high only because a channel connected that late is a
timing fault in the harness, typically a slow runner or a guest under
TCG, not a regression. That is judged from the proxy log's timestamps of
each channel's backend connection. All three fail the run.

Configuration comes from ${WORKDIR}/kerbside.env, written by
deploy-kerbside.sh. WORKDIR defaults to /tmp/kerbside-proxmox-ci and may be
overridden by the WORKDIR environment variable or --workdir (the argument
wins).

With --scan-only it does nothing but step 7, without the backend tickets,
.vv passwords and API JWTs, which it cannot know. Run that before uploading
artifacts on every run, so that a drive which was cut short is scanned too.
A drive killed by its step timeout may not reach its own scan, and then
those three are searched for by neither: the artifacts are scanned only for
the file-backed secrets and the literal. The backend tickets expire within
TICKET_LIFETIME, and the .vv tokens within CONSOLE_TOKEN_DURATION, but the
API JWTs stay valid for JWT_LIFETIME after they were minted.

With --redact it copies its standard input to its standard output with
every value the scan looks for, and every connect host, replaced by
REDACTED, so that a shell script can print a log tail; see redact().

SECURITY: the token secrets, the auth seed, the API JWTs, the .vv bodies,
the backend tickets and the connect hosts are NEVER printed or logged.
Anything read from a file or another process for printing, such as a log
tail for diagnosis, goes through _redacted() first, as does every verdict.
Each backend ticket is read from the database as soon as it is minted,
and only its length is reported. It, each .vv's password and each API JWT
are held in memory to search the artifacts for them. The scan
reports file names and what was found in them, never the value.
Exits non-zero on any failure.
"""

import argparse
import collections
import datetime
import json
import os
import re
import shlex
import subprocess
import sys
import time
import uuid as uuidlib


DEFAULT_WORKDIR = '/tmp/kerbside-proxmox-ci'

# The files under WORKDIR the workflow uploads, and so the files the scan
# reads. Keep this in step with the workflow's upload step and
# tools/proxmox-e2e/README.md; a unit test checks each against it. Never add sources.yaml, a .vv file, the auth
# seed, a token file, PVE's access log or ryll's /tmp/ryll.log.
UPLOADED_FILES = (
    'kerbside.log',
    'kerbside.log.gunicorn-access',
    'kerbside.log.gunicorn-error',
    'kerbside.env',
    'ryll-proxmox-1.stdout',
    'ryll-proxmox-1.stderr',
    'ryll-proxmox-2.stdout',
    'ryll-proxmox-2.stderr',
    'smoke-client-1.log',
    'smoke-client-1-held.log',
    'smoke-client-2.log',
    'smoke-client-1-superseded.log',
    'smoke-client-2-after-terminate.log',
)

# The kinds of verdict an oracle gives. Only OK passes.
OK = 'ok'
HARNESS = 'harness fault'
TIMING = 'timing fault'
DEFECT = 'defect'

# PVE's access log; see the module docstring for its layout.
ACCESS_LOG = '/var/log/pveproxy/access.log'
_ACCESS_LINE = re.compile(
    r'^(?P<client>\S+) - (?P<user>\S+) \[(?P<time>[^\]]*)\] '
    r'"(?P<method>[A-Z]+) (?P<target>\S+) HTTP/\d+\.\d+" (?P<status>\d{3}) (?:\d+|-)$')
_SPICEPROXY_PATH = re.compile(r'^/api2/(?:json|extjs)/nodes/[^/]+/qemu/\d+/spiceproxy$')
# Every scrape starts with this request, so its presence shows the log is
# being read, and parsed, at all.
SCRAPE_PATH = '/api2/json/cluster/resources'

# What one read of the access log found, for the documented token: POSTs to
# spiceproxy answered 200 (mints) and otherwise (refused), every request
# (requests) and every scrape (scrapes), and lines which did not parse.
MintCount = collections.namedtuple('MintCount', 'mints refused requests scrapes unparseable')

# A token ID as PVE accepts one, user@realm!tokenid. It is put into a
# command run on the node, so nothing else is.
_TOKEN_ID = re.compile(r'^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$')

# Proxy log oracles, asserted against the kerbside daemon log, which carries
# the Rust proxy's tracing output. The first three must stay in step with
# the CI-ORACLE-marked info! sites in rust/kerbside-proxy/src/backend.rs and
# relay.rs. The connection line carries tunnelled=, session_id= and
# connection_ref= fields; a tunnelled leg never escalates, so the escalation
# line must be absent.
CONNECTED_ORACLE = 'hypervisor connection successful; handing off to relay'
TLS_ESCALATION_ORACLE = 'hypervisor requires TLS; retrying backend connection over the secure port'
TERMINATE_ORACLE = 'session terminated by control plane'

# The ryll protocol crate's client, which the proxy dials the backend with,
# logs these; deploy-kerbside.sh raises that module to debug so that it
# does. They are not this repository's text, and the crate is rev-pinned
# in rust/kerbside-proxy/Cargo.toml, so a reword arrives with a pin bump
# and nothing here flags it. Each is a positive oracle, so a stale needle
# fails closed, as a harness fault. A tunnelled target is named
# "(tunnelled, target redacted)", never by its connect host.
CRATE_CLIENT_TARGET = 'shakenfist_spice_protocol::client: '
_TLS_DIAL = re.compile(r'^Connecting to (?P<target>.*) \(TLS: (?P<tls>true|false)\)$')
TUNNEL_REDACTED = '(tunnelled, target redacted)'
PIN_MATCH_NEEDLE = 'TLS: certificate subject matches pinned host_subject'
PIN_REJECTION_NEEDLE = 'TLS: rejecting certificate: pinned host_subject'

# tracing's default format starts each line with an RFC 3339 UTC time.
_LINE_TIME = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?Z\s')
_FIELD = r'(?:^|\s){}=(\S+)'

# tracing renders a structured field with SGR escapes when colour is on.
# The proxy disables colour unless its stdout is a terminal, but strip them
# on read rather than trusting the writer (issue #272).
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

# The daemon log's info line for a guest skipped for having no SMBIOS UUID.
# Keep in step with ProxmoxSource.__call__ in kerbside/sources/proxmox.py.
NO_SMBIOS_SKIP_MESSAGE = 'Ignoring VM with no SMBIOS UUID'

# The subject PVE gives each node's pve-ssl.pem, in the form spiceproxy
# hands to clients and kerbside pins.
NODE_SUBJECT = 'OU=PVE Cluster Node,O=Proxmox Virtual Environment,CN=%s'

# How far before the end of the reuse window a channel's connection counts
# as late. A channel's time is when the proxy logged its backend connection,
# and the ticket was minted a little before the first channel's, during its
# authorization, so the window is measured from slightly too late a start;
# this takes that back, and errs towards calling a high count a timing fault.
CHANNEL_TIME_SLACK = 5

# A session's channels are taken to have all connected once there are at
# least this many, and no more have connected for SETTLE seconds.
MIN_CHANNELS = 2
SETTLE = 5

# A session's token row is polled for its backend ticket this often from
# the moment the session is known, so that the ticket is read within a poll
# of its mint, long before it expires and the daemon's maintenance loop,
# about once a minute, clears it. A channel's backend connection is logged
# after its authorization stored the ticket, so once the proxy has logged
# one for the session the ticket has TICKET_GRACE more seconds to be seen;
# with none logged, the poll gives up after TICKET_CHANNEL_TIMEOUT.
TICKET_POLL_INTERVAL = 0.25
TICKET_GRACE = 3
TICKET_CHANNEL_TIMEOUT = 60

# How far past the later of the backend ticket's and the .vv token's expiry
# the first session is held, and the longest hold allowed: with the default
# CONSOLE_TOKEN_DURATION the hold is about a minute and a half.
HOLD_PAST_EXPIRY = 30
MAX_HOLD = 300

# Values shorter than this would match the artifacts by chance.
MIN_NEEDLE = 8

# Each request to the PVE API is bounded, as kerbside bounds its own.
REQUEST_TIMEOUT = 5

# How long the API JWTs the drive mints are valid: the drive step's
# 30-minute timeout in .github/workflows/proxmox-functional.yml, plus five
# minutes, so that a killed drive's JWTs do not outlive it by much. A unit
# test holds it to the step's timeout.
JWT_LIFETIME = 35 * 60

# What redact() puts in place of each value it removes.
REDACTED = '[redacted]'
# A connect host, as spiceproxy hands it out and logs it: the whole
# whitespace-delimited run from the literal on.
CONNECT_LITERAL = 'pvespiceproxy:'
_CONNECT_HOST = re.compile(re.escape(CONNECT_LITERAL) + r'\S*')

# The audit messages the API and AuthorizeConnection write. Keep in step
# with kerbside/api.py and kerbside/rpc/servicer.py.
DIRECT_REFUSED_AUDIT_PREFIX = 'Refused direct console for a proxied-only source'
MINT_AUDIT_PREFIX = 'Minted backend console ticket'
MINT_FAILED_AUDIT_PREFIX = 'Backend console ticket mint failed'


def strip_ansi(text):
    """Remove SGR escape sequences from captured tracing output."""
    return _ANSI_RE.sub('', text)


def redact(text, needles):
    """text with each of needles, and each connect host, replaced by REDACTED.

    A connect host is the whole whitespace-delimited run from
    CONNECT_LITERAL. Longer needles are replaced first, so that one which
    holds another is replaced whole, and an empty needle is passed over.
    Like find_needles, it looks at the text as written and with ANSI
    escapes removed: if a needle or a connect host is still there once the
    escapes are removed, because they split it, the text is redacted with
    them removed.
    """
    ordered = sorted((n for n in needles if n), key=len, reverse=True)

    def replace(t):
        t = _CONNECT_HOST.sub(REDACTED, t)
        for needle in ordered:
            t = t.replace(needle, REDACTED)
        return t

    redacted = replace(text)
    stripped = strip_ansi(redacted)
    if CONNECT_LITERAL in stripped or any(needle in stripped for needle in ordered):
        return replace(strip_ansi(text))
    return redacted


def reuse_window(lifetime, margin):
    """How long after a session's first channel the others may connect and still share its ticket.

    A ticket of lifetime seconds is reused while at least margin of them
    remain, less CHANNEL_TIME_SLACK for the mint coming before the first
    channel's connection. Raises ValueError for a window of zero or less,
    under which every channel but the first would be judged late.
    """
    window = lifetime - margin - CHANNEL_TIME_SLACK
    if window <= 0:
        raise ValueError('a ticket lifetime of %ds with a reuse margin of %ds and %ds of slack leaves no reuse '
                         'window' % (lifetime, margin, CHANNEL_TIME_SLACK))
    return window


# ── PVE's access log ─────────────────────────────────────────────────────────


def parse_access_line(line):
    """Parse one access log line into a dict, or return None if it does not parse."""
    m = _ACCESS_LINE.match(line.rstrip('\r\n'))
    if not m:
        return None
    parsed = m.groupdict()
    parsed['status'] = int(parsed['status'])
    parsed['path'] = parsed['target'].split('?', 1)[0]
    return parsed


def count_mints(lines, token_id):
    """Count what token_id asked PVE for in access log lines.

    Lines of other users are ignored, but a line which does not parse at
    all cannot be said to be another user's, and is counted as unparseable.
    """
    mints = refused = requests = scrapes = unparseable = 0
    for line in lines:
        if not line.strip():
            continue
        parsed = parse_access_line(line)
        if parsed is None:
            unparseable += 1
            continue
        if parsed['user'] != token_id:
            continue
        requests += 1
        if parsed['method'] == 'GET' and parsed['path'] == SCRAPE_PATH:
            scrapes += 1
        if parsed['method'] == 'POST' and _SPICEPROXY_PATH.match(parsed['path']):
            if parsed['status'] == 200:
                mints += 1
            else:
                refused += 1
    return MintCount(mints, refused, requests, scrapes, unparseable)


def late_channels(sessions, window):
    """The channels which connected window seconds or more after their session's first.

    sessions maps a session ID to the times its channels connected. Returns
    (session ID, seconds after the first) for each late channel.
    """
    late = []
    for session_id, times in sorted(sessions.items()):
        if not times:
            continue
        first = min(times)
        late.extend((session_id, t - first) for t in sorted(times) if t - first >= window)
    return late


def mint_verdict(count, expected, sessions, window):
    """Judge a mint count against what a checkpoint expects.

    sessions maps each session open so far to its channels' connection
    times, and window is how long after a session's first channel the
    others may connect and still reuse its ticket. Each late channel may
    legitimately have minted once more, so a count above expected by no
    more than the number of late channels is a timing fault, and any other
    wrong count is a defect. Returns (kind, message).
    """
    if count.unparseable:
        return HARNESS, ('%d access log line(s) did not parse; the log format has changed and the mint count '
                         'cannot be trusted' % count.unparseable)
    if not count.scrapes:
        return HARNESS, ('the access log shows no scrape by the token since kerbside started (%d request(s) in '
                         'all), so it is not being read, or not parsed, correctly' % count.requests)
    if count.refused:
        return DEFECT, 'PVE refused %d spiceproxy request(s) by the token' % count.refused
    if count.mints == expected:
        return OK, 'PVE logged %d mint(s), as expected' % count.mints
    if count.mints < expected:
        return DEFECT, 'PVE logged %d mint(s), fewer than the %d expected' % (count.mints, expected)

    late = late_channels(sessions, window)
    if late and count.mints <= expected + len(late):
        return TIMING, ('PVE logged %d mint(s), not %d, but %d channel(s) connected %ds or more after their '
                        'session\'s first (%s), late enough to mint again; the harness was too slow to show '
                        'the ticket being shared'
                        % (count.mints, expected, len(late), window,
                           ', '.join('%s +%.1fs' % (s, t) for s, t in late)))
    return DEFECT, ('PVE logged %d mint(s), more than the %d expected, although %s'
                    % (count.mints, expected,
                       'only %d channel(s) connected late' % len(late) if late
                       else 'every channel connected within %ds of its session\'s first' % window))


def ticket_verdict(ticket, expires, minted, failures, first_channel, now, lifetime):
    """Judge what polling a session's token row for its backend ticket found.

    ticket and expires are what the row held when the poll stopped: the
    first ticket it saw, or None if it saw none. minted is how many mints
    kerbside audited for the session, and failures the messages of its
    audited failed mints. first_channel is when the proxy logged the
    session's first backend connection, or None if it logged none; now is
    when the poll stopped; and lifetime is the ticket's TICKET_LIFETIME.

    A ticket seen only once it had expired, or a minted ticket gone from
    the row late enough for the sweep of expired tickets to have cleared
    it, means the harness was too slow: a timing fault. A ticket gone from
    the row while it must still have been live, and channels which
    connected with no ticket ever minted, are defects. Returns (kind,
    message), and never names the ticket, only its length.
    """
    if ticket:
        if not expires:
            return DEFECT, 'the session\'s token row holds a backend ticket with no expiry'
        if expires <= now:
            return TIMING, ('the poll first saw the backend ticket %ds after it expired; the harness was too slow '
                            'to read it while it was live' % (now - expires))
        return OK, 'a backend ticket (%d characters) expiring in %ds' % (len(ticket), expires - now)
    if minted:
        if first_channel is None:
            return HARNESS, ('kerbside audited %d mint(s) for the session but the proxy logged no backend '
                             'connection for it, so the ticket\'s age cannot be judged' % minted)
        # The mint came a little before the first channel's connection, so
        # its expiry is judged with the same slack as the reuse window.
        age = now - first_channel
        if age >= lifetime - CHANNEL_TIME_SLACK:
            return TIMING, ('kerbside audited %d mint(s) for the session, but its token row held no ticket when '
                            'polled %.1fs after its first channel connected, late enough for the sweep of expired '
                            'tickets to have cleared it; the harness was too slow to read it' % (minted, age))
        return DEFECT, ('kerbside audited %d mint(s) for the session, but its token row held no ticket when polled '
                        '%.1fs after its first channel connected, while the ticket was still live' % (minted, age))
    if first_channel is not None:
        return DEFECT, ('the session\'s channels connected but no backend ticket was ever minted for it; failed '
                        'mints audited: %s' % ('; '.join(failures) or 'none'))
    return HARNESS, ('no channel of the session connected while its token row was polled, so no ticket could '
                     'have been minted')


# ── The proxy log ────────────────────────────────────────────────────────────


def _line_time(line):
    m = _LINE_TIME.match(line)
    if not m:
        return None
    stamp = datetime.datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
    return stamp.timestamp() + float(m.group(2) or 0)


def _field(name, text):
    m = re.search(_FIELD.format(re.escape(name)), text)
    return m.group(1) if m else None


def proxy_log_facts(text):
    """What the proxy log says about the backend leg.

    Returns a dict of:
      connections   one dict per backend connection the proxy relayed, with
                    its time, connection_ref, session_id and tunnelled;
      escalations   how many direct connections escalated to TLS;
      tls_dials     how many backend dials were over TLS through a tunnel;
      other_dials   how many were not;
      pins          the subject of each certificate check against a pin;
      rejections    how many certificates a pin rejected;
      terminated    the connection_ref of each relay the control plane ended;
      unparseable   a description of each line which carried a needle but not
                    the fields this needs.
    """
    facts = {'connections': [], 'escalations': 0, 'tls_dials': 0, 'other_dials': 0, 'pins': [],
             'rejections': 0, 'terminated': [], 'unparseable': []}
    for line in strip_ansi(text).splitlines():
        offset = line.find(CONNECTED_ORACLE)
        if offset != -1:
            # Only the text after the message is searched for fields, so
            # that a format change cannot match something else.
            fields = line[offset + len(CONNECTED_ORACLE):]
            connection = {
                'time': _line_time(line),
                'connection_ref': _field('connection_ref', fields),
                'session_id': _field('session_id', fields),
                'tunnelled': _field('tunnelled', fields),
            }
            if None in connection.values() or connection['tunnelled'] not in ('true', 'false'):
                facts['unparseable'].append('a backend connection line without a time, connection_ref, '
                                            'session_id or tunnelled')
                continue
            connection['tunnelled'] = connection['tunnelled'] == 'true'
            facts['connections'].append(connection)
            continue

        if TLS_ESCALATION_ORACLE in line:
            facts['escalations'] += 1
            continue

        offset = line.find(TERMINATE_ORACLE)
        if offset != -1:
            ref = _field('connection_ref', line[offset + len(TERMINATE_ORACLE):])
            if ref is None:
                facts['unparseable'].append('a terminated relay line without a connection_ref')
            else:
                facts['terminated'].append(ref)
            continue

        offset = line.find(CRATE_CLIENT_TARGET)
        if offset == -1:
            continue
        message = line[offset + len(CRATE_CLIENT_TARGET):].rstrip()
        if message.startswith('Connecting to '):
            m = _TLS_DIAL.match(message)
            if m is None:
                facts['unparseable'].append('a backend dial line without its TLS flag')
            elif m.group('tls') == 'true' and m.group('target').endswith(TUNNEL_REDACTED):
                facts['tls_dials'] += 1
            else:
                facts['other_dials'] += 1
        elif message.startswith(PIN_MATCH_NEEDLE):
            facts['pins'].append(message[len(PIN_MATCH_NEEDLE):].strip())
        elif message.startswith(PIN_REJECTION_NEEDLE):
            facts['rejections'] += 1
    return facts


def session_channel_times(facts, session_ids):
    """Map each of session_ids to the times its channels' backend connections were made."""
    return {s: [c['time'] for c in facts['connections'] if c['session_id'] == s] for s in session_ids}


def terminated_sessions(facts):
    """The sessions at least one of whose relays the control plane ended."""
    sessions = {c['connection_ref']: c['session_id'] for c in facts['connections']}
    return {sessions[ref] for ref in facts['terminated'] if ref in sessions}


def backend_leg_verdict(facts, session_ids, expected_subject):
    """Judge whether every backend leg was tunnelled, TLS and pinned to expected_subject.

    The crate's dial and pin lines carry no connection_ref, so they are
    counted for the whole log: there must be at least one of each for every
    connection the proxy relayed. Returns (kind, message).
    """
    if facts['unparseable']:
        return HARNESS, ('%d proxy log line(s) carried an oracle but not the fields it needs (%s); the log format '
                         'has changed and this check cannot see' % (len(facts['unparseable']),
                                                                    '; '.join(sorted(set(facts['unparseable'])))))
    connections = facts['connections']
    mine = [c for c in connections if c['session_id'] in session_ids]
    if not mine:
        return HARNESS, ('the proxy logged no %r line for session(s) %s, although SPICE was relayed; the '
                         'message has changed' % (CONNECTED_ORACLE, ', '.join(sorted(session_ids))))
    direct = [c for c in connections if not c['tunnelled']]
    if direct:
        return DEFECT, '%d backend connection(s) were not tunnelled' % len(direct)
    if facts['escalations']:
        return DEFECT, ('the proxy escalated %d direct connection(s) to TLS; a tunnelled leg is TLS from the '
                        'start and never escalates' % facts['escalations'])
    if facts['other_dials']:
        return DEFECT, '%d backend dial(s) were not TLS through a tunnel' % facts['other_dials']
    if not facts['tls_dials']:
        return HARNESS, ('the proxy log holds no backend dial line from %s; its debug logging is not on '
                         '(RUST_LOG, set by deploy-kerbside.sh) or its text has changed'
                         % CRATE_CLIENT_TARGET.rstrip(': '))
    if facts['rejections']:
        return DEFECT, 'a pinned subject rejected %d backend certificate(s)' % facts['rejections']
    if not facts['pins']:
        return HARNESS, ('the proxy log holds backend dial lines but no %r line, so this check cannot tell '
                         'whether pinning happened; the crate\'s text has changed' % PIN_MATCH_NEEDLE)
    if not all(facts['pins']):
        return DEFECT, 'a backend certificate check logged an empty pinned subject'
    wrong = sorted(set(p for p in facts['pins'] if p != expected_subject))
    if wrong:
        return DEFECT, 'a backend leg was pinned to %s, not %s' % (', '.join(wrong), expected_subject)
    if facts['tls_dials'] < len(connections) or len(facts['pins']) < len(connections):
        return DEFECT, ('the proxy relayed %d connection(s) but logged %d TLS dial(s) through a tunnel and %d '
                        'pinned certificate check(s)' % (len(connections), facts['tls_dials'], len(facts['pins'])))
    return OK, ('all %d backend connection(s) were tunnelled, over TLS, and pinned to %s'
                % (len(connections), expected_subject))


# ── The daemon log and the guest's configuration ─────────────────────────────


def logged_skip(text, vmid, message_prefix):
    """(found, records): whether an INFO record says it skipped vmid, and how many JSON records were read.

    The daemon writes JSON records, one per line, into the same file as the
    proxy's text lines; anything which is not a JSON object is passed over.
    """
    found = False
    records = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        records += 1
        if (record.get('level') == 'INFO' and str(record.get('vmid')) == str(vmid) and
                str(record.get('message') or '').startswith(message_prefix)):
            found = True
    return found, records


_SMBIOS_UUID = re.compile(r'(?:^|,)uuid=([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})(?:,|$)')


def smbios_uuid_of(config):
    """The SMBIOS UUID in a guest's configuration, lower cased, or None.

    Parsed here rather than with the driver's own parser, so that a defect
    in that parser cannot make the expected uuid agree with the scraped one.
    """
    m = _SMBIOS_UUID.search(str(config.get('smbios1') or ''))
    return m.group(1).lower() if m else None


def vv_password(text):
    """The password a .vv file carries, or None."""
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if sep and key.strip() == 'password' and value.strip():
            return value.strip()
    return None


# ── The artifact scan ────────────────────────────────────────────────────────


def find_needles(texts, needles):
    """Return (name, index) for each needle found in each text.

    texts maps a file name to its contents, and needles is a sequence of
    the values to look for; index is a needle's position in it, so that
    the caller can name what was found without this seeing the names. A
    text is searched as written and with ANSI escapes removed, so a
    colourised log line cannot split a value. Raises ValueError for a
    needle too short to search for meaningfully.
    """
    for index, needle in enumerate(needles):
        if len(needle or '') < MIN_NEEDLE:
            raise ValueError('needle %d is too short to search for' % index)
    found = []
    for name, text in sorted(texts.items()):
        stripped = strip_ansi(text)
        for index, needle in enumerate(needles):
            if needle in text or needle in stripped:
                found.append((name, index))
    return found


def scan_artifacts(paths, needles):
    """(found, searched): find_needles over the files at paths which exist.

    found names files by their base name. A file which cannot be read is
    not searched, and is not counted in searched.
    """
    texts = {}
    for path in paths:
        try:
            with open(path, 'r', errors='replace') as f:
                texts[os.path.basename(path)] = f.read()
        except OSError:
            continue
    return find_needles(texts, needles), sorted(texts)


# ── Running the lane ─────────────────────────────────────────────────────────


def _log(msg):
    print('[proxmox-e2e] %s' % msg, file=sys.stderr)


def _require(kind, message):
    """Fail the run unless kind is OK, naming which kind of failure it is.

    message is redacted, as it may carry text from a log or an audit event.
    """
    message = _redacted(message)
    if kind == OK:
        _log(message)
        return
    print('::error title=Proxmox lane %s::%s' % (kind, message))
    raise SystemExit('%s: %s' % (kind.upper(), message))


def _load_env_file(path):
    """Load a KEY=VALUE env file into os.environ (skipping blanks)."""
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            os.environ[key] = value


def _read_text(path):
    try:
        with open(path, 'r', errors='replace') as f:
            return f.read()
    except OSError:
        return ''


def _tail(path, lines):
    """Return the last `lines` lines of a file, redacted for printing, or a note if unreadable."""
    try:
        with open(path, 'r', errors='replace') as f:
            return _redacted(''.join(f.readlines()[-lines:]))
    except OSError as exc:
        return '(could not read %s: %s)\n' % (path, exc)


# The Lane being driven, whose held values _redacted() removes too.
_active_lane = None


def _redacted(text):
    """text, safe to print: redact() with every value the scan looks for.

    Those are _forbidden_values(), with the held values of the Lane being
    driven, if there is one.
    """
    lane = _active_lane
    _, needles = _forbidden_values(lane.needle_descriptions if lane else (), lane.needles if lane else (),
                                   report=False)
    return redact(text, needles)


def _forbidden_values(extra_descriptions=(), extra_needles=(), report=True):
    """(descriptions, needles): what the artifacts must not hold, read from the env file's paths.

    The two are parallel lists, sorted by description, so that a
    description is only ever found by its index and is never carried
    beside its value. A value which cannot be read, or is too short to
    search for, is left out and said so. extra_descriptions and
    extra_needles add, in the same parallel form, values held in memory,
    such as backend tickets, .vv passwords and API JWTs. With report
    false, nothing left out is said so.
    """
    paths = []
    path_descriptions = []
    lane_file = os.environ.get('PROXMOX_LANE_FILE')
    if lane_file:
        try:
            with open(lane_file) as f:
                listed = json.load(f)['tokens']
            for name in sorted(listed):
                path_descriptions.append('the %s token\'s secret' % name.replace('_', '-'))
                paths.append(listed[name]['secret_file'])
        except (OSError, ValueError, KeyError, TypeError):
            if report:
                _log('could not read the token list in %s; its tokens are not scanned for' % lane_file)
    if os.environ.get('PROXMOX_ACTION_TOKEN_FILE'):
        path_descriptions.append('the action\'s token\'s secret')
        paths.append(os.environ['PROXMOX_ACTION_TOKEN_FILE'])
    if os.environ.get('KERBSIDE_SEED_FILE'):
        path_descriptions.append('the auth seed')
        paths.append(os.environ['KERBSIDE_SEED_FILE'])

    descriptions = ['the literal %s' % CONNECT_LITERAL]
    needles = [CONNECT_LITERAL]
    for index, path in enumerate(paths):
        needle = _read_text(path).strip()
        if len(needle) < MIN_NEEDLE:
            if report:
                _log('%s could not be read from %s; it is not scanned for' % (path_descriptions[index], path))
            continue
        descriptions.append(path_descriptions[index])
        needles.append(needle)
    for index, needle in enumerate(extra_needles):
        if len(needle or '') >= MIN_NEEDLE:
            descriptions.append(extra_descriptions[index])
            needles.append(needle)
    order = sorted(range(len(descriptions)), key=lambda i: descriptions[i])
    return [descriptions[i] for i in order], [needles[i] for i in order]


def _scan(workdir, extra_descriptions=(), extra_needles=()):
    """Scan the uploaded files, removing any which holds a forbidden value. Returns True if one did."""
    paths = [os.path.join(workdir, name) for name in UPLOADED_FILES]
    descriptions, needles = _forbidden_values(extra_descriptions, extra_needles)
    found, searched = scan_artifacts(paths, needles)
    if not found:
        _log('none of %d secret(s) is in the %d uploaded file(s) present (%s)'
             % (len(descriptions), len(searched), ', '.join(searched) or 'none'))
        return False
    for name, index in found:
        print('::error title=Proxmox lane leak::%s holds %s; it has been removed so it is not uploaded'
              % (name, descriptions[index]))
    for name in sorted(set(name for name, _ in found)):
        try:
            os.remove(os.path.join(workdir, name))
        except OSError as e:
            print('::error title=Proxmox lane leak::could not remove %s: %s' % (name, e.__class__.__name__))
    return True


def _mint_auth_jwt(seed_path, admin=False):
    """Mint an HS256 API JWT from the auth seed (never printed).

    The kerbside verify_token decorator only checks the signature and
    expiry, so any identity is fine; kerbside_admin must be literally True
    for the direct console handler to get past its administrator check.
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
        'sub': 'proxmox-e2e-driver',
        'exp': now + JWT_LIFETIME,
    }
    if admin:
        payload['kerbside_admin'] = True
    token = pyjwt.encode(payload, seed, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token


def _ssh_opts():
    return ['-i', os.environ['PROXMOX_SSH_KEY'], '-o', 'StrictHostKeyChecking=no', '-o',
            'UserKnownHostsFile=/dev/null', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
            '-o', 'LogLevel=ERROR']


def _read_access_log(offset, token_id):
    """The documented token's access log lines written after offset, read on the node over ssh.

    Filtered on the node, so that spiceproxy's CONNECT lines, which carry
    connect hosts, never leave it. The size is read first, so that a log
    which was rotated, and shrank, is not read as one in which nothing
    happened. Never prints what it read.
    """
    if not _TOKEN_ID.match(token_id):
        _require(HARNESS, 'the documented token ID is not of the form user@realm!tokenid: %s' % token_id)
    inner = 'sudo -n stat -c %%s %s && sudo -n tail -c +%d %s | awk -v user=%s %s' % (
        ACCESS_LOG, offset + 1, ACCESS_LOG, shlex.quote(token_id), shlex.quote('$3 == user'))
    remote = 'bash -o pipefail -c %s' % shlex.quote(inner)
    target = '%s@%s' % (os.environ['PROXMOX_SSH_USER'], os.environ['PROXMOX_NODE_ADDRESS'])
    result = subprocess.run(['timeout', '60', 'ssh'] + _ssh_opts() + [target, remote],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        reason = (result.stderr or '').strip().splitlines()
        _require(HARNESS, 'could not read PVE\'s access log over ssh (exit %d: %s)'
                 % (result.returncode, reason[-1] if reason else 'no message'))
    size, _, rest = result.stdout.partition('\n')
    if not size.strip().isdigit():
        _require(HARNESS, 'the node did not report the size of PVE\'s access log')
    if int(size) < offset:
        _require(HARNESS, 'PVE\'s access log is %s bytes, shorter than the %d it was when kerbside started; it '
                 'was rotated, so mints before the rotation cannot be counted' % (size.strip(), offset))
    return rest.splitlines()


class Lane:
    """The lane's configuration, and the checks which need it."""

    def __init__(self, workdir):
        # Everything the drive writes goes in the work directory, which is
        # where the scan looks for the uploaded files.
        self.run_dir = workdir
        self.source = os.environ['KERBSIDE_SOURCE_NAME']
        self.console_uuid = None
        self.api = 'http://127.0.0.1:%s' % os.environ['KERBSIDE_API_PORT']
        self.seed_path = os.environ['KERBSIDE_SEED_FILE']
        self.log_path = os.environ['KERBSIDE_LOG_PATH']
        self.ryll_bin = os.environ['RYLL_BIN']
        self.smoke_client = os.path.join(os.environ['KERBSIDE_SRC'], 'tools', 'direct-qemu', 'smoke-client.py')
        self.node = os.environ['PROXMOX_NODE_NAME']
        self.fqdn = os.environ['PROXMOX_NODE_FQDN']
        self.vmid = int(os.environ['PROXMOX_VMID'])
        self.offset = int(os.environ['PROXMOX_ACCESS_LOG_OFFSET'])
        with open(os.environ['PROXMOX_LANE_FILE']) as f:
            lane = json.load(f)
        self.token_id = lane['tokens']['documented']['token_id']
        self.skipped = {rule: vmid for rule, vmid in lane['skipped_guests'].items() if vmid is not None}
        # The values the drive holds in memory that the scan must look for,
        # and in parallel what each is, so that the two are never held
        # together.
        self.needle_descriptions = []
        self.needles = []

    def remember(self, description, needle):
        """Hold a value the drive learned, so the scan searches for it. Never printed."""
        self.needle_descriptions.append(description)
        self.needles.append(needle)

    def checkpoint(self, name, expected, sessions=()):
        """Count mints in PVE's access log, and fail unless they are as expected."""
        from kerbside.rpc.servicer import REUSE_MARGIN
        from kerbside.sources.proxmox import TICKET_LIFETIME

        count = count_mints(_read_access_log(self.offset, self.token_id), self.token_id)
        times = session_channel_times(proxy_log_facts(_read_text(self.log_path)), sessions)
        try:
            window = reuse_window(TICKET_LIFETIME, REUSE_MARGIN)
        except ValueError as e:
            _require(HARNESS, str(e))
        _log('checkpoint "%s": %d mint(s), %d refused, %d request(s) and %d scrape(s) by %s since kerbside started'
             % (name, count.mints, count.refused, count.requests, count.scrapes, self.token_id))
        kind, message = mint_verdict(count, expected, times, window)
        _require(kind, 'checkpoint "%s": %s' % (name, message))
        return count


def _api_config(path):
    """GET a path of the PVE API with the action's token, for the lane's own setup reads."""
    import requests

    with open(os.environ['PROXMOX_ACTION_TOKEN_FILE']) as f:
        secret = f.read().strip()
    headers = {'Authorization': 'PVEAPIToken=%s=%s' % (os.environ['PROXMOX_ACTION_TOKEN_ID'], secret)}
    url = os.environ['PROXMOX_API_URL'].rstrip('/') + '/api2/json' + path
    try:
        r = requests.get(url, headers=headers, verify=os.environ['PROXMOX_CA_FILE'], timeout=REQUEST_TIMEOUT,
                         proxies={'http': None, 'https': None})
    except requests.exceptions.RequestException as e:
        _require(HARNESS, 'GET %s with the action\'s token failed: %s' % (path, e.__class__.__name__))
    if r.status_code != 200:
        _require(HARNESS, 'GET %s with the action\'s token returned %d %s' % (path, r.status_code, r.reason))
    return r.json().get('data') or {}


def _discover(db, lane, timeout=180):
    """Wait for the scrape, and assert the console list is exactly the smoke guest."""
    config = _api_config('/nodes/%s/qemu/%d/config' % (lane.node, lane.vmid))
    smbios = smbios_uuid_of(config)
    if not smbios:
        _require(HARNESS, 'the smoke guest %d has no SMBIOS UUID in its configuration' % lane.vmid)
    expected_uuid = '%d-%s' % (lane.vmid, smbios)
    expected_subject = NODE_SUBJECT % lane.fqdn

    _log('waiting for the scrape of source %s; expecting only console %s' % (lane.source, expected_uuid))
    deadline = time.time() + timeout
    consoles = []
    while time.time() < deadline:
        consoles = [c for c in db.get_consoles(include_audit=False) if c.get('source') == lane.source]
        if consoles:
            break
        time.sleep(5)
    uuids = sorted(c.get('uuid') or '' for c in consoles)
    _log('source %s lists: %s' % (lane.source, ', '.join(uuids) or 'nothing'))
    if not consoles:
        _require(DEFECT, 'the scrape listed no console for source %s within %ds' % (lane.source, timeout))

    for rule, vmid in sorted(lane.skipped.items()):
        if any(u.startswith('%d-' % vmid) for u in uuids):
            _require(DEFECT, 'guest %d (%s) is listed, but discovery must skip it' % (vmid, rule.replace('_', ' ')))
    if uuids != [expected_uuid]:
        _require(DEFECT, 'the console list for source %s is %s, not exactly %s'
                 % (lane.source, ', '.join(uuids), expected_uuid))

    console = consoles[0]
    if console.get('hypervisor') != lane.node:
        _require(DEFECT, 'console %s names hypervisor %s, not the node %s'
                 % (expected_uuid, console.get('hypervisor'), lane.node))
    if console.get('host_subject') != expected_subject:
        _require(DEFECT, 'console %s has host subject %s, not %s'
                 % (expected_uuid, console.get('host_subject'), expected_subject))
    _log('the console list is exactly %s, on hypervisor %s, with subject %s'
         % (expected_uuid, lane.node, expected_subject))

    no_smbios = lane.skipped.get('no_smbios_uuid')
    if no_smbios is not None:
        found, records = logged_skip(_read_text(lane.log_path), no_smbios, NO_SMBIOS_SKIP_MESSAGE)
        if not records:
            _require(HARNESS, 'the daemon log %s holds no JSON records, so it cannot show a skip' % lane.log_path)
        if not found:
            _require(DEFECT, 'the daemon log does not name guest %d at info level as %r'
                     % (no_smbios, NO_SMBIOS_SKIP_MESSAGE))
        _log('the daemon log names guest %d at info level as skipped for having no SMBIOS UUID' % no_smbios)
    return console, expected_subject


def _dump_ryll_diagnostics(proc, stdout_path, stderr_path, log_path):
    """Dump ryll's state and logs, minus the .vv, which carries a proxy token, each tail redacted."""
    if proc.poll() is None:
        _log('  ryll process %d is still running' % proc.pid)
    else:
        _log('  ryll process %d has exited (code %s)' % (proc.pid, proc.returncode))
    _log('  ryll stdout:\n%s' % _tail(stdout_path, 40))
    _log('  ryll stderr:\n%s' % _tail(stderr_path, 40))
    _log('  kerbside daemon (proxy) log:\n%s' % _tail(log_path, 60))


class Ryll:
    """One headless ryll, with its control socket and logs in the run directory."""

    def __init__(self, lane, n, vv_path):
        self.lane = lane
        self.n = n
        self.sock = os.path.join(lane.run_dir, 'ryll-proxmox-%d.sock' % n)
        self.stdout_path = os.path.join(lane.run_dir, 'ryll-proxmox-%d.stdout' % n)
        self.stderr_path = os.path.join(lane.run_dir, 'ryll-proxmox-%d.stderr' % n)
        _log('launching ryll %d headless' % n)
        # The child has its own copies of these descriptors. The parent's
        # are kept only to be closed once ryll is reaped or stopped.
        self._logs = [open(self.stdout_path, 'wb'), open(self.stderr_path, 'wb')]
        self.proc = subprocess.Popen(
            [lane.ryll_bin, '--verbose', '--headless', '--file', vv_path, '--control-socket', self.sock],
            stdout=self._logs[0], stderr=self._logs[1])

        deadline = time.time() + 30
        while time.time() < deadline:
            if os.path.exists(self.sock):
                _log('ryll %d control socket is ready' % n)
                return
            if self.proc.poll() is not None:
                self.diagnose()
                raise SystemExit('ryll %d exited (code %s) before its control socket appeared'
                                 % (n, self.proc.returncode))
            time.sleep(0.5)
        self.stop()
        self.diagnose()
        raise SystemExit('ryll %d control socket did not appear within 30s' % n)

    def _close_logs(self):
        for f in self._logs:
            f.close()

    def diagnose(self):
        self._close_logs()
        _dump_ryll_diagnostics(self.proc, self.stdout_path, self.stderr_path, self.lane.log_path)

    def smoke(self, name):
        """Assert, with smoke-client.py, that this ryll is relaying real SPICE."""
        if self.proc.poll() is not None:
            self.diagnose()
            raise SystemExit('ryll %d has exited (code %s), so its session is not passing frames'
                             % (self.n, self.proc.returncode))
        log_file = os.path.join(self.lane.run_dir, name)
        result = subprocess.run([sys.executable, self.lane.smoke_client, self.sock],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with open(log_file, 'w') as f:
            f.write(result.stdout or '')
        if result.returncode != 0:
            _log('  smoke-client.py output:\n%s' % _redacted(result.stdout or ''))
            raise SystemExit('smoke-client.py failed against ryll %d (exit %d)' % (self.n, result.returncode))
        _log('smoke-client.py passed against ryll %d (output in %s)' % (self.n, log_file))

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self._close_logs()


def _open_session(db, lane, headers, n, known_sessions):
    """Fetch a proxied .vv, launch ryll against it, and return (ryll, session ID)."""
    import requests

    # The .vv's token lasts CONSOLE_TOKEN_DURATION, and no channel is
    # authorized once it has expired, so ryll is launched straight after.
    url = '%s/console/proxy/%s/%s/console.vv' % (lane.api, lane.source, lane.console_uuid)
    _log('fetching proxied .vv %d for %s/%s' % (n, lane.source, lane.console_uuid))
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code != 200:
        raise SystemExit('.vv fetch %d returned HTTP %d (expected 200)' % (n, resp.status_code))
    # Not uploaded: it carries a live proxy token.
    vv_path = os.path.join(lane.run_dir, 'console-%d.vv' % n)
    fd = os.open(vv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(resp.text)
    password = vv_password(resp.text)
    if password is None:
        _log('.vv %d carries no password, so there is none to scan for' % n)
    else:
        lane.remember('the password in .vv %d' % n, password)
    ryll = Ryll(lane, n, vv_path)

    tokens = [t for t in db.get_tokens_by_console(lane.source, lane.console_uuid)
              if t.get('session_id') not in known_sessions]
    if len(tokens) != 1:
        ryll.stop()
        raise SystemExit('expected one new console token after .vv fetch %d, found %d' % (n, len(tokens)))
    return ryll, tokens[0]['session_id']


def _wait_for_channels(lane, session_id, timeout=60):
    """Wait until the session's channels have all connected, and return their connection times."""
    deadline = time.time() + timeout
    count = 0
    stable_since = time.time()
    while time.time() < deadline:
        facts = proxy_log_facts(_read_text(lane.log_path))
        times = session_channel_times(facts, [session_id])[session_id]
        if len(times) != count:
            count = len(times)
            stable_since = time.time()
        elif count >= MIN_CHANNELS and time.time() - stable_since >= SETTLE:
            _log('session %s connected %d channel(s), the last %.1fs after the first'
                 % (session_id, count, max(times) - min(times)))
            return times
        time.sleep(1)
    _require(HARNESS, 'session %s connected %d channel(s) within %ds; a single mint only shows the ticket is '
             'shared if there are at least %d' % (session_id, count, timeout, MIN_CHANNELS))


def _capture_ticket(db, lane, session_id, label):
    """Poll the session's token row until its backend ticket appears, hold it for the scan, and return its expiry.

    Called as soon as the session is known, so that the ticket is read
    within a poll of its mint. Never printed.
    """
    from kerbside.sources.proxmox import TICKET_LIFETIME

    started = time.time()
    first_channel = None
    noticed = None
    while True:
        now = time.time()
        with db.Session(db.ENGINE) as session:
            row = session.query(db.ConsoleToken).filter(db.ConsoleToken.session_id == session_id).one_or_none()
            ticket = row.backend_ticket if row is not None else None
            expires = row.backend_ticket_expires if row is not None else None
        if ticket:
            break
        if first_channel is None:
            times = session_channel_times(proxy_log_facts(_read_text(lane.log_path)), [session_id])[session_id]
            if times:
                first_channel = min(times)
                noticed = now
        if noticed is not None and now - noticed >= TICKET_GRACE:
            break
        if noticed is None and now - started >= TICKET_CHANNEL_TIMEOUT:
            break
        time.sleep(TICKET_POLL_INTERVAL)

    if ticket:
        # Held for the scan whatever the verdict.
        lane.remember(label, ticket)
        minted = 0
        failures = []
    else:
        events = [e for e in db.get_audit_events(lane.source, lane.console_uuid, limit=500)
                  if e.get('session_id') == session_id]
        minted = len([e for e in events if (e.get('message') or '').startswith(MINT_AUDIT_PREFIX)])
        failures = [e.get('message') or '' for e in events
                    if (e.get('message') or '').startswith(MINT_FAILED_AUDIT_PREFIX)]
    kind, message = ticket_verdict(ticket, expires, minted, failures, first_channel, now, TICKET_LIFETIME)
    _require(kind, 'session %s: %s' % (session_id, message))
    return expires


def _hold(ryll, hold_until):
    """Sleep until hold_until, failing at once if ryll's session ends."""
    while time.time() < hold_until:
        if ryll.proc.poll() is not None:
            ryll.diagnose()
            raise SystemExit('ryll %d exited (code %s) %ds before the hold ended'
                             % (ryll.n, ryll.proc.returncode, hold_until - time.time()))
        time.sleep(min(5, max(hold_until - time.time(), 0)))


def _drive(lane):
    # KERBSIDE_SQL_URL is in the env file, and kerbside.config reads it at
    # import, so kerbside.db is imported only now.
    from kerbside import db

    import requests

    # 1. Discovery.
    console, expected_subject = _discover(db, lane)
    lane.console_uuid = console['uuid']
    lane.checkpoint('after the first scrape', 0)

    jwt = _mint_auth_jwt(lane.seed_path)
    lane.remember('the API JWT', jwt)
    admin_jwt = _mint_auth_jwt(lane.seed_path, admin=True)
    lane.remember('the administrator API JWT', admin_jwt)
    headers = {'Authorization': 'Bearer %s' % jwt, 'Accept': 'application/json'}
    admin_headers = {'Authorization': 'Bearer %s' % admin_jwt, 'Accept': 'application/json'}

    # 2. The direct .vv, refused before anything is minted. The body is
    # never printed: had the request been accepted, it would hold a ticket.
    def refusals():
        return [e for e in db.get_audit_events(lane.source, lane.console_uuid, limit=500)
                if (e.get('message') or '').startswith(DIRECT_REFUSED_AUDIT_PREFIX)]

    before = len(refusals())
    resp = requests.get('%s/console/direct/%s/%s/console.vv' % (lane.api, lane.source, lane.console_uuid),
                        headers=admin_headers, timeout=30)
    _log('the direct .vv request was answered %d' % resp.status_code)
    lane.checkpoint('after the refused direct .vv', 0)
    if resp.status_code != 409:
        _require(DEFECT, 'the direct .vv request was answered %d, not 409' % resp.status_code)
    if len(refusals()) != before + 1:
        _require(DEFECT, 'the direct .vv refusal was not audited')
    _log('the direct .vv request was refused with 409 and audited')

    # 3. The first session.
    first, s1 = _open_session(db, lane, headers, 1, set())
    second = None
    try:
        ticket_expires = _capture_ticket(db, lane, s1, 'session 1\'s backend ticket')
        first.smoke('smoke-client-1.log')
        _wait_for_channels(lane, s1)
        lane.checkpoint('after the first session\'s channels have connected', 1, [s1])
        _require(*backend_leg_verdict(proxy_log_facts(_read_text(lane.log_path)), {s1}, expected_subject))

        # 4. Hold it past the ticket's and the token's expiry.
        token = db.get_token_by_session_id(s1)
        hold_until = max(ticket_expires, token['expires']) + HOLD_PAST_EXPIRY
        hold = hold_until - time.time()
        if hold > MAX_HOLD:
            _require(HARNESS, 'holding the session would take %ds, over the %ds allowed; is CONSOLE_TOKEN_DURATION '
                     'longer than deploy-kerbside.sh leaves it?' % (hold, MAX_HOLD))
        _log('holding session %s for %ds, until %ds past its ticket\'s and its token\'s expiry'
             % (s1, max(hold, 0), HOLD_PAST_EXPIRY))
        _hold(first, hold_until)
        first.smoke('smoke-client-1-held.log')
        lane.checkpoint('after holding the first session', 1, [s1])

        # 5. A second session, while the first is held. Its mint replaces
        # the guest's SPICE password; the first must not notice.
        second, s2 = _open_session(db, lane, headers, 2, {s1})
        _capture_ticket(db, lane, s2, 'session 2\'s backend ticket')
        second.smoke('smoke-client-2.log')
        _wait_for_channels(lane, s2)
        lane.checkpoint('after the second session\'s channels have connected', 2, [s1, s2])
        first.smoke('smoke-client-1-superseded.log')
        _log('session %s still passes frames after session %s minted' % (s1, s2))
        _require(*backend_leg_verdict(proxy_log_facts(_read_text(lane.log_path)), {s1, s2}, expected_subject))

        audited = [e for e in db.get_audit_events(lane.source, lane.console_uuid, limit=500)
                   if (e.get('message') or '').startswith(MINT_AUDIT_PREFIX)]
        if len(audited) != 2:
            _require(DEFECT, 'kerbside audited %d mints for the two sessions, where PVE logged 2' % len(audited))

        # 6. Terminate the first session while ryll is connected.
        _log('terminating session %s via the kerbside REST API' % s1)
        resp = requests.post('%s/session/%s/terminate' % (lane.api, s1), headers=headers, timeout=15)
        if resp.status_code != 200:
            _require(DEFECT, 'terminating session %s returned HTTP %d' % (s1, resp.status_code))
        # The daemon polls for terminations every ~2s.
        deadline = time.time() + 30
        while s1 not in terminated_sessions(proxy_log_facts(_read_text(lane.log_path))):
            if time.time() >= deadline:
                _log('  kerbside daemon (proxy) log:\n%s' % _tail(lane.log_path, 60))
                _require(DEFECT, 'the proxy did not log %r for session %s within 30s of the terminate'
                         % (TERMINATE_ORACLE, s1))
            time.sleep(1)
        if s2 in terminated_sessions(proxy_log_facts(_read_text(lane.log_path))):
            _require(DEFECT, 'terminating session %s also ended session %s' % (s1, s2))
        _log('the proxy dropped session %s and not session %s' % (s1, s2))
        try:
            first.proc.wait(timeout=15)
            _log('ryll 1 exited as its channels closed (code %s)' % first.proc.returncode)
        except subprocess.TimeoutExpired:
            _log('ryll 1 still running 15s after the drop; proceeding on the log oracle alone')
        second.smoke('smoke-client-2-after-terminate.log')
        if db.get_token_by_session_id(s1) is not None:
            _require(DEFECT, 'session %s still has a token after the terminate' % s1)

        lane.checkpoint('at the end', 2, [s1, s2])
    finally:
        first.stop()
        if second is not None:
            second.stop()

    _log('Proxmox proxied console path passed')


def main():
    parser = argparse.ArgumentParser(description='Drive a Proxmox VE console through kerbside\'s proxy.')
    parser.add_argument('--workdir', default=None,
                        help='the deploy-kerbside.sh work directory (default: $WORKDIR, or %s)' % DEFAULT_WORKDIR)
    parser.add_argument('--scan-only', action='store_true',
                        help='only scan the files the lane uploads for secrets, removing any which holds one; '
                        'it cannot know the backend tickets, .vv passwords and API JWTs a drive held in memory, '
                        'so after a drive killed by its step timeout those go unscanned, and its API JWTs stay '
                        'valid for %ds after they were minted' % JWT_LIFETIME)
    parser.add_argument('--redact', action='store_true',
                        help='copy standard input to standard output with every value the scan looks for, and '
                        'every connect host, replaced by %s' % REDACTED)
    args = parser.parse_args()

    workdir = args.workdir or os.environ.get('WORKDIR') or DEFAULT_WORKDIR
    env_file = os.path.join(workdir, 'kerbside.env')

    if args.scan_only:
        # A deploy which failed early may have written no env file, and then
        # nothing which could hold a token secret either.
        if os.path.exists(env_file):
            _load_env_file(env_file)
        else:
            _log('%s does not exist; scanning for the literal pvespiceproxy: only' % env_file)
        return 1 if _scan(workdir) else 0

    if args.redact:
        # As --scan-only, with no env file only connect hosts are known.
        if os.path.exists(env_file):
            _load_env_file(env_file)
        # Read whole and written only once redacted, so that a failure part
        # way prints nothing rather than the raw text.
        text = sys.stdin.buffer.read().decode('utf-8', errors='replace')
        sys.stdout.write(_redacted(text))
        return 0

    _load_env_file(env_file)
    # The runner's squid proxy 503s loopback traffic, so exempt it before any
    # requests call is made.
    os.environ['no_proxy'] = '127.0.0.1,localhost,' + os.environ.get('no_proxy', '')

    global _active_lane
    lane = Lane(workdir)
    _active_lane = lane
    leaked = False
    try:
        _drive(lane)
    finally:
        # Whether or not the drive passed, before anything is uploaded.
        leaked = _scan(workdir, lane.needle_descriptions, lane.needles)
    if leaked:
        raise SystemExit('a secret reached a file the lane uploads')
    return 0


if __name__ == '__main__':
    sys.exit(main())
