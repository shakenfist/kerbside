"""End-to-end scenario test driving the Uncalibrated Sextant guest.

This test consumes an already-running direct-qemu lane (see
``tools/direct-qemu/lane-up.sh``): a Sextant guest under qemu/KVM, fronted
by kerbside's SPICE proxy, with a headless ryll attached and its control
socket exposed at ``CONF.kerbside.control_socket_path``. The test drives
the full canonical sequence — Awaiting -> Booting -> locked-bootloader
Ignore -> paste -> Parked -> shutdown — over ryll's control socket and
asserts the run against both oracles:

- the live QR digest stream (``digest_updated`` events, available only
  when ryll is built with ``cargo build --features digest-decode``); and
- the post-mortem serial drain that Sextant writes just before its final
  ACPI shutdown (``CONF.kerbside.serial_log_path``).

The test provisions nothing and never touches a cloud: it inherits from
``tempest.test.BaseTestCase`` directly, declares no credentials, and skips
unless ``control_socket_path`` is configured (the OpenStack lane leaves it
unset). It is deliberately destructive — the final keypress shuts the
guest down, qemu exits, and ryll unlinks the control socket — so it must
run as the last step on a lane.

The expected on-screen geometry and event vocabulary are properties of the
committed Sextant qcow2 fixture; the constants below each point at the
Sextant source file they mirror.
"""

import os
import time

from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators
import tempest.test

from kerbside_tempest_plugin import ryll_client


CONF = config.CONF
LOG = logging.getLogger(__name__)


# AT-set-1 scancodes for the only two keys this scenario sends. Sextant
# consumes digits 0-6 as GOP mode-switch keys in every blink loop
# (uncalibrated-sextant/src/scene.rs::MODE_KEYS), so phase transitions
# use Enter and the bootloader choice uses the letter 'i'.
ENTER_SCANCODE = 28
KEY_I_SCANCODE = 23

# AT-set-1 encodes a key release as the make code with the high bit set.
KEY_RELEASE_BIT = 0x80

# The oldest control-socket protocol this scenario can run against, as a
# (major, minor) tuple. 1.1 is where digest_updated was added; the lane
# tracks ryll main, so anything newer in the same major is fine.
MIN_PROTOCOL_VERSION = (1, 1)

# The byte-exact payload the locked bootloader expects, hardcoded in
# uncalibrated-sextant/src/bootloader.rs::PASTE_TARGET. It is a property
# of the committed qcow2 fixture, not configuration.
PASTE_PAYLOAD = 'sextant{HELLO_OPERATOR}'

# Inter-character delay for the paste-as-keystrokes path. Generous
# relative to ryll's 10 ms default because the Sextant firmware polls
# keys at 50 ms (scene.rs::POLL_MS) and echoes each one to the screen.
PASTE_CHAR_DELAY_MS = 20

# The PRE boot script renders 19 lines on rows 0..18
# (scene.rs::BOOT_SCRIPT_PRE), the bootloader's telemetry preamble takes
# the next two rows, and the R/I/A prompt renders two rows below the
# bootloader's start row (bootloader.rs: prompt_row = start_row + 2).
BOOT_PRE_SCRIPT_LINES = 19
BOOTLOADER_PROMPT_ROW = BOOT_PRE_SCRIPT_LINES + 2

# The serial drain must show at least this many type=line records between
# the awaiting->booting transition and the bootloader decision. The real
# count is 19 PRE lines + 2 preamble + the prompt and blob-screen lines;
# 10 is a plausibility floor, not an exact count.
MIN_BOOT_LINE_RECORDS = 10


# ---------------------------------------------------------------------------
# Digest-event record helpers.
#
# A digest_updated event's data.events field is a serde passthrough of the
# digest crate's Event enum (shakenfist-visual-digest/src/events.rs),
# which derives Serialize with rename_all="snake_case". Each record is
# therefore an externally-tagged single-key object, e.g.:
#
#   {'scene_transition': {'from': 'awaiting', 'to': 'booting',
#                         'timestamp_ms': 9000}}
#   {'keypress': {'unicode': '\r', 'scancode': 0, 'timestamp_ms': 8950}}
#   {'line_rendered': {'row': 5, 'timestamp_ms': 10200}}
#   {'paste_received': {'len': 23, 'correct': True, 'timestamp_ms': 31000}}
#
# These helpers are deliberately dependency-free (no tempest imports) so
# they can grow unit tests later.
# ---------------------------------------------------------------------------

def press_key(client, scancode):
    """Type one key as an explicit down + up pair with the release bit set.

    Control-socket protocols before 1.2 wrote the supplied scancode
    verbatim into the SPICE KEY_UP message, so a ``send_key`` with state
    ``"press"`` (or an ``"up"`` without the release bit) injected the
    make code twice and the guest saw the key double-typed. Protocol 1.2
    sets the release bit server-side, but supplying it here stays
    correct: the server ORs the bit in, and ORing a bit that is already
    set is a no-op — an affordance the protocol document guarantees.
    Sending it explicitly is what lets this scenario run unchanged
    against either version.
    """
    client.send_key(scancode, state='down')
    client.send_key(scancode | KEY_RELEASE_BIT, state='up')


def iter_records(event):
    """Yield (kind, payload) tuples for each record in a digest_updated event.

    Tolerates the two shapes serde can emit for an enum variant: a
    single-key object (struct variants, the only kind the digest crate
    currently has) and a bare string (a hypothetical future unit variant).
    Anything unrecognised is skipped rather than raised on, per the
    protocol's forward-compatibility guidance.
    """
    for record in event.get('data', {}).get('events', []):
        if isinstance(record, dict) and len(record) == 1:
            kind, payload = next(iter(record.items()))
            yield kind, payload if isinstance(payload, dict) else {}
        elif isinstance(record, str):
            yield record, {}


def is_digest_event(event):
    """Predicate: the event is a digest_updated event (any content)."""
    return event.get('event') == 'digest_updated'


def digest_with_record(kind, fields=None):
    """Build a predicate matching digest_updated events carrying a record.

    ``kind`` is the snake_case record tag (e.g. ``scene_transition``);
    ``fields`` is an optional dict of payload fields that must all match
    by equality. Field values are compared against the decoded JSON, so
    booleans and integers are native Python types and the digest crate's
    Phase / BootloaderChoice enums are snake_case strings.
    """
    fields = fields or {}

    def predicate(event):
        if not is_digest_event(event):
            return False
        for record_kind, payload in iter_records(event):
            if record_kind != kind:
                continue
            if all(payload.get(key) == value for key, value in fields.items()):
                return True
        return False

    return predicate


def digest_with_line_at_or_past(row):
    """Build a predicate matching digests with a line_rendered at/past ``row``.

    Used to detect bootloader-prompt arrival: the prompt's own
    line_rendered record is the first one at BOOTLOADER_PROMPT_ROW, and
    because the bootloader then polls for input without further digest
    refreshes, the digest carrying it stays current until the test acts.
    """
    def predicate(event):
        if not is_digest_event(event):
            return False
        return any(record_kind == 'line_rendered' and payload.get('row', -1) >= row
                   for record_kind, payload in iter_records(event))

    return predicate


# ---------------------------------------------------------------------------
# Serial drain helpers.
#
# At shutdown Sextant drains its event ring buffer to serial, one
# CRLF-terminated line per event in the form 't=<ms> type=<tag> k=v ...',
# terminated by a 'type=refresh_stats ...' summary line (see
# uncalibrated-sextant/src/serial.rs::drain for the exact formats). The
# same serial log also carries the boot banner and the GOP mode dump;
# anything that does not tokenise as k=v pairs with a type= field is not
# a drain record and is skipped.
# ---------------------------------------------------------------------------

def parse_drain_line(line):
    """Parse one serial line into a field dict, or None if not a drain record.

    All values are kept as strings ('23', 'true', 'ignore', ...) — the
    drain is a textual oracle and exact-string comparison is the least
    surprising way to assert against it. The 't' field, when present, is
    the guest's monotonic millisecond clock.
    """
    line = line.strip()
    if not line or 'type=' not in line:
        return None
    fields = {}
    for token in line.split():
        if '=' not in token:
            return None
        key, value = token.split('=', 1)
        fields[key] = value
    if 'type' not in fields:
        return None
    return fields


def parse_drain(text):
    """Parse a whole serial log into an ordered list of drain record dicts."""
    records = []
    for line in text.splitlines():
        fields = parse_drain_line(line)
        if fields is not None:
            records.append(fields)
    return records


def find_ordered_subsequence(records, matchers):
    """Find ``matchers`` in ``records`` as an ordered (non-contiguous) subsequence.

    ``matchers`` is a list of (label, callable) pairs. Returns the list of
    matched indices. Raises ValueError naming the first matcher that could
    not be found beyond the previous match — the label is the diagnostic a
    red CI run gets, so they are written to read well in a failure message.
    """
    indices = []
    start = 0
    for label, matcher in matchers:
        for idx in range(start, len(records)):
            if matcher(records[idx]):
                indices.append(idx)
                start = idx + 1
                break
        else:
            raise ValueError(
                'serial drain is missing (in order) %r; matched %d of %d expected records '
                'before the miss' % (label, len(indices), len(matchers)))
    return indices


def drain_timestamps(records):
    """Return the integer t= values of every drain record that has one."""
    return [int(record['t']) for record in records if 't' in record]


class SextantScenarioTest(tempest.test.BaseTestCase):
    """Drive the canonical Sextant sequence over ryll's control socket.

    No credentials and no cloud clients: this class talks only to a local
    Unix-domain socket and a local serial log file, so the same tempest
    invocation runs on a runner with no cloud at all.
    """

    # Explicitly no credentials — tempest must never contact keystone for
    # this test.
    credentials = []

    @classmethod
    def skip_checks(cls):
        super(SextantScenarioTest, cls).skip_checks()
        if not CONF.kerbside.control_socket_path:
            raise cls.skipException(
                'CONF.kerbside.control_socket_path is not set; the Sextant '
                'scenario test only runs on a lane that exposes a ryll '
                'control socket')

    def setUp(self):
        super(SextantScenarioTest, self).setUp()
        # (label, frame_counter) for every digest event the test consumed,
        # in consumption order; asserted strictly increasing at the end.
        self._digest_frames = []

    # ── Lane interaction helpers ─────────────────────────────────────────

    def _artifact_path(self, name):
        """Return the artifact path for ``name``, or None when unconfigured."""
        artifact_dir = CONF.kerbside.scenario_artifact_dir
        if not artifact_dir:
            return None
        return os.path.join(artifact_dir, '%s.png' % name)

    def _screenshot(self, client, name):
        """Best-effort PNG of surface 0 into the artifact dir.

        Never raises: screenshots are diagnostics, and late in the scenario
        the socket may already be gone (ryll exits and unlinks the control
        socket when the SPICE session ends).
        """
        path = self._artifact_path(name)
        if path is None:
            return
        try:
            size = client.screenshot_to_file(0, path)
            LOG.info('saved screenshot %s (%d bytes)', path, size)
        except ryll_client.RyllError as exc:
            LOG.warning('screenshot %s failed (continuing): %s', name, exc)

    def _wait_digest(self, client, predicate, label):
        """Wait one beat-deadline for a digest event matching ``predicate``.

        On expiry, screenshots the live framebuffer (socket permitting) and
        re-raises the RyllTimeout, whose message carries the count and names
        of the events seen while waiting — the primary CI diagnostic.
        Matched events have their frame counter logged and recorded for the
        end-of-test monotonicity assertion.
        """
        deadline = time.monotonic() + CONF.kerbside.scenario_step_timeout
        try:
            event = client.wait_for_event(predicate, deadline)
        except ryll_client.RyllTimeout:
            LOG.error('beat %s: no matching digest event before the deadline', label)
            self._screenshot(client, 'failure-%s' % label)
            raise
        frame_counter = event.get('data', {}).get('frame_counter')
        LOG.debug('beat %s: consumed digest event frame_counter=%s records=%s',
                  label, frame_counter, list(iter_records(event)))
        self._digest_frames.append((label, frame_counter))
        return event

    def _await_serial_drain(self):
        """Poll the serial log until the drain terminator appears; return the log text.

        The guest writes the drain at ACPI-shutdown time, after the control
        socket is already useless, so this is a plain file poll. The
        'type=refresh_stats' summary is always the final drain line
        (serial.rs::drain), so its appearance means the drain is complete.
        """
        path = CONF.kerbside.serial_log_path
        self.assertTrue(
            path,
            'CONF.kerbside.serial_log_path is not set but control_socket_path '
            'is: the lane configuration is incomplete')
        deadline = time.monotonic() + CONF.kerbside.scenario_step_timeout
        while True:
            try:
                with open(path, 'rb') as handle:
                    text = handle.read().decode('utf-8', errors='replace')
            except FileNotFoundError:
                text = ''
            if any(line.strip().startswith('type=refresh_stats') for line in text.splitlines()):
                return text
            if time.monotonic() >= deadline:
                self.fail(
                    'serial drain terminator (type=refresh_stats) did not appear in %s '
                    'within %ds; log so far is %d bytes' % (
                        path, CONF.kerbside.scenario_step_timeout, len(text)))
            time.sleep(0.5)

    def _assert_drain(self, records):
        """Assert the canonical ordered subsequence over the parsed drain."""
        expected = [
            ('keypress (Awaiting Enter)',
             lambda r: r['type'] == 'keypress'),
            ('transition awaiting->booting',
             lambda r: r['type'] == 'transition' and r.get('from') == 'awaiting' and
             r.get('to') == 'booting'),
            ('bootloader_decision choice=ignore attempt=1',
             lambda r: r['type'] == 'bootloader_decision' and r.get('choice') == 'ignore' and
             r.get('attempt') == '1'),
            ('paste len=23 correct=true',
             lambda r: r['type'] == 'paste' and r.get('len') == str(len(PASTE_PAYLOAD)) and
             r.get('correct') == 'true'),
            ('transition booting->parked',
             lambda r: r['type'] == 'transition' and r.get('from') == 'booting' and
             r.get('to') == 'parked'),
            ('keypress (Parked Enter)',
             lambda r: r['type'] == 'keypress'),
            ('transition parked->parked',
             lambda r: r['type'] == 'transition' and r.get('from') == 'parked' and
             r.get('to') == 'parked'),
        ]
        try:
            indices = find_ordered_subsequence(records, expected)
        except ValueError as exc:
            self.fail('%s; full drain: %s' % (exc, records))

        # A plausible count of boot lines between the awaiting->booting
        # transition and the bootloader decision.
        transition_idx, decision_idx = indices[1], indices[2]
        line_count = sum(1 for record in records[transition_idx:decision_idx]
                         if record['type'] == 'line')
        self.assertGreaterEqual(
            line_count, MIN_BOOT_LINE_RECORDS,
            'expected at least %d type=line records between the awaiting->booting '
            'transition and the bootloader decision, found %d' % (
                MIN_BOOT_LINE_RECORDS, line_count))

        # Guest timestamps are monotonically non-decreasing across the drain.
        timestamps = drain_timestamps(records)
        self.assertEqual(
            timestamps, sorted(timestamps),
            'serial drain t= values are not monotonically non-decreasing')

        # The drain terminator is present.
        self.assertTrue(
            any(record['type'] == 'refresh_stats' for record in records),
            'serial drain is missing the type=refresh_stats summary line')

    # ── The scenario ─────────────────────────────────────────────────────

    @decorators.idempotent_id('2e879dd4-90ff-4190-b78b-7c1881b9f4a9')
    def test_sextant_scenario(self):
        client = ryll_client.RyllClient(CONF.kerbside.control_socket_path)
        client.connect()
        self.addCleanup(client.close)

        # Beat 1: hello. Protocol v1.1 or newer with the digest event
        # available. A missing digest_updated is a lane misconfiguration
        # (ryll built without the feature), never a skip.
        #
        # The version is compared as a tuple, not for equality: the
        # protocol's compatibility rule is that only the major component
        # must agree, and the lane builds ryll from main, so the minor
        # version moves whenever upstream adds a verb or an event.
        # MIN_PROTOCOL_VERSION is the floor this scenario needs
        # (digest_updated arrived in 1.1); what the test actually depends
        # on is asserted below, as capabilities.
        hello = client.hello(client_name='kerbside-sextant-scenario')
        LOG.info('hello: %s', hello)
        served = ryll_client.parse_protocol_version(
            hello.get('protocol_version'))
        self.assertEqual(MIN_PROTOCOL_VERSION[0], served[0],
                         'expected ryll to speak protocol major version %d, '
                         'got %r' % (MIN_PROTOCOL_VERSION[0],
                                     hello.get('protocol_version')))
        self.assertGreaterEqual(
            served, MIN_PROTOCOL_VERSION,
            'expected ryll to speak protocol %d.%d or newer, got %r' %
            (MIN_PROTOCOL_VERSION + (hello.get('protocol_version'),)))
        self.assertIn(
            'digest_updated', hello.get('supported_events', []),
            'ryll does not advertise digest_updated: the lane must build ryll '
            'with `cargo build --features digest-decode` (lane misconfiguration, '
            'not a skippable condition)')

        # Beat 2: subscribe. The server silently drops names it does not
        # recognise, so assert digest_updated actually took.
        subscribed = client.subscribe(['digest_updated', 'paste_completed', 'paste_failed'])
        LOG.info('subscribed: %s', subscribed)
        self.assertIn('digest_updated', subscribed,
                      'subscribe did not accept digest_updated; got %s' % subscribed)

        # Beat 3: the Awaiting screen's blinking cursor re-encodes the QR
        # about twice a second, so a digest event arriving at all proves the
        # whole pipeline (guest QR -> SPICE -> ryll decode) is live. Log the
        # raw event so a CI run records the actual serde wire shape.
        first = self._wait_digest(client, is_digest_event, '00-awaiting')
        LOG.info('raw sample digest_updated event: %s', first)
        self._screenshot(client, '00-awaiting')

        # Beat 4: Enter ends Awaiting. The digest's raw-record region is a
        # tiny sliding window (the most recent run of records that fits in
        # 44 bytes) over a busy stream, so wait for *a* digest carrying the
        # transition within the beat deadline rather than expecting any
        # particular event to carry it.
        press_key(client, ENTER_SCANCODE)
        self._wait_digest(
            client,
            digest_with_record('scene_transition', {'from': 'awaiting', 'to': 'booting'}),
            '01-booting')
        self._screenshot(client, '01-booting')

        # Beat 5: boot progress through the 19-line PRE script, the
        # bootloader telemetry preamble, and finally the R/I/A prompt. The
        # prompt's own line_rendered record is the first at or past
        # BOOTLOADER_PROMPT_ROW, and the bootloader fires no further digest
        # refreshes while polling for the choice, so the digest carrying it
        # remains the latest until the test responds.
        self._wait_digest(client, digest_with_line_at_or_past(BOOTLOADER_PROMPT_ROW),
                          '02-bootloader-prompt')
        self._screenshot(client, '02-bootloader-prompt')

        # Beat 6: take the Ignore path to the encoded-blob paste challenge.
        press_key(client, KEY_I_SCANCODE)

        # Beat 7: paste the decoded payload. The paste verb is async —
        # completion arrives as a paste_completed event correlated to the
        # request — and Sextant's capture_paste (bootloader.rs) submits on
        # Enter, so the terminating keypress is sent only after ryll reports
        # every payload character delivered (SPICE input is ordered, but the
        # explicit wait keeps the Enter from racing the paste queue).
        client.paste(PASTE_PAYLOAD, char_delay_ms=PASTE_CHAR_DELAY_MS)
        paste_deadline = time.monotonic() + CONF.kerbside.scenario_step_timeout
        outcome = client.wait_for_event(
            lambda e: e.get('event') in ('paste_completed', 'paste_failed'),
            paste_deadline)
        self.assertEqual('paste_completed', outcome.get('event'),
                         'paste did not complete: %s' % outcome)
        press_key(client, ENTER_SCANCODE)

        # Beat 8: the guest validates the paste byte-exactly against
        # PASTE_TARGET and records the verdict.
        accepted = self._wait_digest(
            client, digest_with_record('paste_received', {'correct': True}),
            '03-paste-accepted')
        for record_kind, payload in iter_records(accepted):
            if record_kind == 'paste_received' and payload.get('correct'):
                self.assertEqual(len(PASTE_PAYLOAD), payload.get('len'),
                                 'paste_received.len mismatch: %s' % payload)
        self._screenshot(client, '03-paste-accepted')

        # Beat 9: the boot script finishes and the scene parks. run_parked
        # pushes no further events until the final keypress, so every
        # blink-driven digest from here carries this transition — the most
        # stable wait in the scenario.
        self._wait_digest(
            client,
            digest_with_record('scene_transition', {'from': 'booting', 'to': 'parked'}),
            '04-parked')
        self._screenshot(client, '04-parked')

        # Beat 10: the final Enter. The guest drains its ring buffer to
        # serial and ACPI-shuts-down; qemu exits; ryll exits and unlinks the
        # control socket. EOF is success-shaped from here, and nothing more
        # is collected from the socket.
        try:
            press_key(client, ENTER_SCANCODE)
        except ryll_client.RyllConnectionClosed:
            LOG.info('control socket closed while sending the final keypress '
                     '(expected: the guest is shutting down)')
        client.close()

        # Beats 11+12: the serial drain is the authoritative post-mortem
        # oracle. Wait for its terminator, then assert the canonical ordered
        # subsequence with monotonic guest timestamps.
        drain_text = self._await_serial_drain()
        records = parse_drain(drain_text)
        LOG.info('parsed %d serial drain records', len(records))
        self._assert_drain(records)

        # Beat 13: frame counters must have strictly increased across every
        # digest event the test consumed (ryll dedups by frame counter, and
        # the guest's counter is monotonic per boot).
        LOG.info('digest frames consumed: %s', self._digest_frames)
        frames = [frame for _, frame in self._digest_frames]
        for earlier, later in zip(frames, frames[1:]):
            self.assertLess(
                earlier, later,
                'digest frame counters did not strictly increase: %s' % self._digest_frames)
