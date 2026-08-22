"""Stdlib-only NDJSON client for ryll's control socket (protocol v1.x).

This module is the tempest plugin's own implementation of the ryll
control-socket protocol. The protocol is specified end-to-end in
``ryll/docs/control-socket-protocol.md``; read that document before
touching this client. Two sibling implementations already live in the
kerbside tree (``loadtests/latency/orchestrator.py`` and
``tools/direct-qemu/smoke-client.py``); the framing and handshake here
are lifted from them rather than reinvented. They are not reused
directly because the tempest plugin is an installable package and
cannot import from ``loadtests/`` or ``tools/``. Consolidating the
three copies is future work.

Design notes:

- **Stdlib only.** This module imports nothing beyond ``socket``,
  ``json``, ``time``, ``os``, ``base64``, and ``collections`` so that it
  stays reusable outside tempest (no tempest, oslo, or third-party
  imports). A future shared client can lift this file unchanged.
- **Single-threaded demux.** There is exactly one buffered reader.
  Every received NDJSON line is a JSON object; a frame carrying ``id``
  resolves the matching pending request, and a frame carrying ``event``
  is appended to an internal ``collections.deque`` for later draining by
  :meth:`RyllClient.wait_for_event`. There are no background threads;
  the caller owns the read loop by calling ``call`` and ``wait_for_event``.
- **EOF is a distinct, catchable condition.** End-of-stream during any
  read raises :class:`RyllConnectionClosed`, a type separate from
  :class:`RyllTimeout` and :class:`RyllRpcError`. The Sextant scenario
  test treats EOF after the final keypress as expected (ryll exits and
  unlinks the socket once the guest shuts down), so it must be catchable
  specifically rather than blanket-caught alongside genuine failures.
- **Minor versions float.** This client requests
  :data:`CLIENT_PROTOCOL_VERSION` and speaks that feature set, but the
  protocol only requires the *major* components to agree: the spec's
  compatibility rule accepts a minor mismatch in either direction and
  says explicitly that clients must not compare the server's
  ``protocol_version`` for equality. The direct-qemu lane builds ryll
  from ``main``, so its minor version moves without warning. Callers
  that need to gate on a server feature parse the returned version with
  :func:`parse_protocol_version` and compare tuples.

All timeouts and deadlines in this module are measured against
``time.monotonic()`` so they are immune to wall-clock adjustments.
"""

import base64
import collections
import json
import os
import socket
import time


# The protocol version this client requests in its hello. It is the
# feature set the client implements, not a demand on the server: every
# verb and event used here exists in 1.1, and a newer server answers
# with its own (higher) minor version.
CLIENT_PROTOCOL_VERSION = '1.1'

# Standard PNG file signature; used to sanity-check screenshot bytes.
_PNG_MAGIC = b'\x89PNG\r\n\x1a\n'

# Default per-request response timeout, in seconds.
_DEFAULT_CALL_TIMEOUT = 10.0

# Per-read socket timeout used while draining for events. Kept short so
# wait_for_event can re-check its deadline frequently rather than blocking
# for the whole remaining budget inside a single recv().
_EVENT_READ_TIMEOUT = 0.25

# recv() chunk size. NDJSON lines are tiny except for screenshot
# responses, which arrive as one large line and are reassembled across
# however many chunks it takes.
_RECV_CHUNK = 65536


class RyllError(Exception):
    """Base class for every error this client raises."""


class RyllConnectionClosed(RyllError):
    """The server closed the socket (EOF) during a read.

    This is deliberately distinct from :class:`RyllTimeout` and
    :class:`RyllRpcError` so callers can catch it on its own. After the
    final keypress in the Sextant scenario the guest ACPI-shuts-down,
    qemu exits, and ryll unlinks the control socket: EOF there is
    expected and is caught specifically, never confused with a real RPC
    failure or a deadline expiry.
    """


class RyllTimeout(RyllError):
    """A request response or an awaited event did not arrive in time.

    For :meth:`RyllClient.wait_for_event` the message includes how many
    events were seen while waiting and a summary of their names. That
    detail is what makes a red CI run debuggable: it distinguishes "the
    stream was silent" from "the stream was busy but never matched the
    predicate".
    """


class RyllRpcError(RyllError):
    """The server returned an ``ok: false`` response.

    The protocol error ``code`` (a stable machine-readable string such as
    ``busy``, ``bad_params``, or ``agent_not_connected``) is carried on
    the ``code`` attribute so callers can branch on it without parsing
    the human-readable message.
    """

    def __init__(self, code, message, method=None):
        self.code = code
        self.error_message = message
        self.method = method
        prefix = '%s: ' % method if method else ''
        super().__init__('%s%s (%s)' % (prefix, message, code))


def parse_protocol_version(version):
    """Parse a dotted ``major.minor`` protocol version into an int tuple.

    The protocol specifies ``protocol_version`` as exactly two dotted
    parts, so anything else is a malformed frame rather than a version
    this client should try to interpret leniently.

    :raises ValueError: the value is not a two-part dotted integer pair.
    """
    parts = str(version).split('.')
    if len(parts) != 2:
        raise ValueError(
            'malformed protocol version %r: expected major.minor' % (version,))
    try:
        return (int(parts[0]), int(parts[1]))
    except ValueError:
        raise ValueError(
            'malformed protocol version %r: parts must be integers'
            % (version,))


class RyllClient:
    """A single-connection NDJSON client for ryll's control socket.

    The intended lifecycle is ``connect`` -> ``hello`` -> any mix of
    ``call`` / ``subscribe`` / ``send_key`` / ``paste`` /
    ``screenshot_to_file`` / ``wait_for_event`` -> ``close``. The client
    holds one Unix-domain stream socket and one receive buffer; it is not
    thread-safe and is meant to be driven from a single test thread.
    """

    def __init__(self, path=None):
        """Create a client. If ``path`` is given it is the default socket path.

        The socket is not opened until :meth:`connect` is called. Storing
        the path here lets a caller construct then connect in two steps,
        or pass the path straight to ``connect``.
        """
        self._path = path
        self._sock = None
        self._buf = bytearray()
        self._events = collections.deque()
        self._next_id = 0

    # ── Connection lifecycle ──────────────────────────────────────────────

    def connect(self, path=None, timeout=10.0):
        """Open the Unix-domain control socket.

        ``path`` overrides any path given to the constructor. ``timeout``
        bounds the ``connect()`` call itself, in seconds. After a
        successful connect the socket is left in blocking mode; per-read
        timeouts are applied on demand by the event-draining path.

        A ``busy`` server (a second client connecting while one is already
        attached) does not fail here: ryll accepts the connection, writes a
        single ``{"ok": false, "error": {"code": "busy", ...}}`` line with
        no ``id``, and closes. That surfaces from :meth:`hello` as a
        :class:`RyllRpcError` with code ``busy``.
        """
        if path is not None:
            self._path = path
        if self._path is None:
            raise RyllError('no socket path supplied to connect()')

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(self._path)
        except OSError as exc:
            sock.close()
            raise RyllError('could not connect to %s: %s' % (self._path, exc)) from exc
        # Blocking by default; the event path sets short timeouts as needed.
        sock.settimeout(None)
        self._sock = sock

    def close(self):
        """Close the socket. Idempotent — safe to call more than once."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ── Framing primitives ────────────────────────────────────────────────

    def _new_id(self):
        """Return a monotonically-increasing request id for this connection."""
        self._next_id += 1
        return self._next_id

    def _send(self, method, params):
        """Serialise and write one NDJSON request line; return its id."""
        if self._sock is None:
            raise RyllError('not connected')
        req_id = self._new_id()
        line = json.dumps({'id': req_id, 'method': method, 'params': params}) + '\n'
        try:
            self._sock.sendall(line.encode('utf-8'))
        except OSError as exc:
            raise RyllConnectionClosed('write failed: %s' % exc) from exc
        return req_id

    def _read_line(self):
        """Read and parse exactly one NDJSON object from the socket.

        Buffers across ``recv()`` boundaries: a single ``recv()`` may
        deliver a partial line, several lines, or part of a multi-chunk
        screenshot response, so the loop accumulates into ``self._buf``
        and only consumes up to the first newline. EOF (a zero-length
        ``recv``) raises :class:`RyllConnectionClosed`. A socket timeout
        propagates as ``socket.timeout`` for the caller's deadline logic
        to handle.
        """
        if self._sock is None:
            raise RyllConnectionClosed('not connected')
        while b'\n' not in self._buf:
            chunk = self._sock.recv(_RECV_CHUNK)
            if not chunk:
                raise RyllConnectionClosed('server closed the connection')
            self._buf.extend(chunk)
        nl = self._buf.index(b'\n')
        line = self._buf[:nl].decode('utf-8')
        del self._buf[:nl + 1]
        return json.loads(line)

    def _stash_event(self, msg):
        """Append an event frame to the internal deque."""
        self._events.append(msg)

    # ── Hello handshake ───────────────────────────────────────────────────

    def hello(self, client_name='kerbside-tempest', timeout=_DEFAULT_CALL_TIMEOUT):
        """Perform the mandatory ``hello`` handshake; return its result dict.

        Sends :data:`CLIENT_PROTOCOL_VERSION`. Returns the ``result``
        object (with ``server_name``, ``protocol_version``,
        ``supported_methods``, and ``supported_events``). The returned
        ``protocol_version`` is whatever minor version the server speaks
        and need not match what was requested; only a *major* mismatch is
        an error, and the server reports that as a
        ``protocol_version_mismatch`` :class:`RyllRpcError` before
        closing the connection. A ``busy`` server surfaces here as a
        :class:`RyllRpcError` with code ``busy``: the busy line has no
        ``id``, so :meth:`call` matches it as the response to this first
        request and raises accordingly.
        """
        return self.call('hello', {
            'client_name': client_name,
            'protocol_version': CLIENT_PROTOCOL_VERSION,
        }, timeout=timeout)

    # ── Request / response ────────────────────────────────────────────────

    def call(self, method, params=None, timeout=_DEFAULT_CALL_TIMEOUT):
        """Send a request and read until the matching response arrives.

        Event frames received while waiting are demuxed into the internal
        deque rather than discarded, so a ``call`` interleaved with a busy
        event stream does not lose events. The matching response is
        identified by its ``id``; a response with no ``id`` (the synthetic
        ``busy`` line, which arrives before any request is acknowledged) is
        also accepted as the answer to the in-flight request, since ryll
        only ever emits it as the first and only line on the connection.

        On ``ok: false`` this raises :class:`RyllRpcError` carrying the
        protocol error code. On ``ok: true`` it returns the ``result``
        dict (``{}`` if the verb has no payload). A deadline expiry raises
        :class:`RyllTimeout`; EOF raises :class:`RyllConnectionClosed`.
        """
        if params is None:
            params = {}
        req_id = self._send(method, params)
        deadline = time.monotonic() + timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RyllTimeout('no response to %s (id=%r) within %.1fs' % (method, req_id, timeout))
            self._sock.settimeout(remaining)
            try:
                msg = self._read_line()
            except socket.timeout:
                raise RyllTimeout('no response to %s (id=%r) within %.1fs' % (method, req_id, timeout))
            finally:
                self._sock.settimeout(None)

            if 'event' in msg:
                self._stash_event(msg)
                continue

            # A response: match by id, or accept the id-less synthetic
            # error (busy / pre-hello refusals are written without an id).
            if msg.get('id') == req_id or ('id' not in msg and 'ok' in msg):
                if not msg.get('ok'):
                    error = msg.get('error', {})
                    raise RyllRpcError(
                        error.get('code', 'unknown'),
                        error.get('message', ''),
                        method=method,
                    )
                return msg.get('result', {})

            # A stray response with a non-matching id (should not happen on a
            # single-in-flight client); demux it nowhere and keep reading.

    # ── Convenience verbs ─────────────────────────────────────────────────

    def subscribe(self, names, timeout=_DEFAULT_CALL_TIMEOUT):
        """Subscribe to the named events; return the accepted-names list.

        Thin wrapper over :meth:`call`. The server silently drops event
        names it does not recognise, so the returned ``subscribed`` list
        may be a subset of ``names`` — the caller should check it. An
        empty result for ``digest_updated`` means ryll was built without
        the ``digest-decode`` feature.
        """
        result = self.call('subscribe', {'events': list(names)}, timeout=timeout)
        return result.get('subscribed', [])

    def send_key(self, scancode, state='press', timeout=_DEFAULT_CALL_TIMEOUT):
        """Send one keyboard scancode event; return the (empty) result dict.

        ``state`` is one of ``"down"``, ``"up"``, or ``"press"``. Convenience
        wrapper over :meth:`call`.
        """
        return self.call('send_key', {'scancode': scancode, 'state': state}, timeout=timeout)

    def paste(self, text, char_delay_ms=None, timeout=_DEFAULT_CALL_TIMEOUT):
        """Queue a paste-as-keystrokes operation; return the (empty) result.

        This verb is asynchronous: the response returns when the paste is
        queued, not when typing finishes. Completion arrives later as a
        ``paste_completed`` (or ``paste_failed``) event, correlated by the
        ``request_id`` field — subscribe to those events and await one via
        :meth:`wait_for_event` if completion must be observed.
        """
        params = {'text': text}
        if char_delay_ms is not None:
            params['char_delay_ms'] = char_delay_ms
        return self.call('paste', params, timeout=timeout)

    # ── Event waiting ─────────────────────────────────────────────────────

    def wait_for_event(self, predicate, deadline):
        """Return the first event matching ``predicate`` before ``deadline``.

        ``deadline`` is an absolute ``time.monotonic()`` value (not a
        relative duration) — compute it as ``time.monotonic() + budget`` at
        the call site. The already-buffered deque is scanned first, in
        arrival order; matched events are removed and returned, non-matching
        events ahead of the match are left in place for later waits. If
        nothing in the deque matches, the socket is read with short
        per-read timeouts (so the deadline is re-checked frequently),
        demuxing responses-with-ids back into nowhere and appending fresh
        events to the deque as they arrive, until either ``predicate(event)``
        is truthy or the deadline passes.

        On expiry this raises :class:`RyllTimeout` whose message reports how
        many events were seen and a summary of their names — that diagnostic
        is the whole point of the explicit count, and it is what a CI triage
        reads first. EOF during a read raises :class:`RyllConnectionClosed`.
        """
        seen_names = []

        # 1. Drain anything already buffered, preserving arrival order. The
        #    deque is rebuilt so non-matching events stay queued for the next
        #    waiter rather than being silently dropped.
        remaining = collections.deque()
        match = None
        while self._events:
            event = self._events.popleft()
            if match is None and predicate(event):
                match = event
            else:
                if match is None:
                    seen_names.append(event.get('event', '?'))
                remaining.append(event)
        # Any events behind the match (and the unmatched ones ahead of it)
        # go back on the queue in order.
        self._events = remaining
        if match is not None:
            return match

        # 2. Read from the socket until the predicate matches or we time out.
        while True:
            now = time.monotonic()
            if now >= deadline:
                raise RyllTimeout(
                    'no matching event within deadline; saw %d event(s): %s' % (
                        len(seen_names), self._summarise_names(seen_names)))
            read_budget = min(_EVENT_READ_TIMEOUT, deadline - now)
            self._sock.settimeout(read_budget)
            try:
                msg = self._read_line()
            except socket.timeout:
                continue
            finally:
                if self._sock is not None:
                    self._sock.settimeout(None)

            if 'event' in msg:
                if predicate(msg):
                    return msg
                seen_names.append(msg.get('event', '?'))
                self._stash_event(msg)
            # Responses (frames with an id) that arrive here are unsolicited
            # from this method's point of view; drop them. wait_for_event is
            # only called after the relevant request/response exchanges.

    @staticmethod
    def _summarise_names(names):
        """Render a compact ``name xN`` summary of event names, in first-seen order.

        Used only to build the :class:`RyllTimeout` diagnostic message.
        """
        if not names:
            return '(none)'
        counts = collections.OrderedDict()
        for name in names:
            counts[name] = counts.get(name, 0) + 1
        return ', '.join('%s x%d' % (name, count) for name, count in counts.items())

    # ── Screenshot ────────────────────────────────────────────────────────

    def screenshot_to_file(self, surface_id, path, timeout=30.0):
        """Capture a PNG of ``surface_id``, write it to ``path``, return byte count.

        Calls the ``screenshot`` verb with ``format`` ``"png"``,
        base64-decodes the returned ``data_base64`` per the spec, verifies
        the PNG signature, writes the bytes to ``path`` (creating parent
        directories if needed), and returns the number of bytes written.
        Screenshot responses are large and slow; the default ``timeout`` is
        correspondingly generous.
        """
        params = {'format': 'png'}
        if surface_id is not None:
            params['surface_id'] = surface_id
        result = self.call('screenshot', params, timeout=timeout)

        b64_data = result.get('data_base64', '')
        if not b64_data:
            raise RyllError('screenshot returned empty data_base64')
        png_bytes = base64.b64decode(b64_data)
        if not png_bytes.startswith(_PNG_MAGIC):
            raise RyllError('screenshot data is not a PNG (got %r)' % (png_bytes[:8],))

        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, 'wb') as handle:
            handle.write(png_bytes)
        return len(png_bytes)
