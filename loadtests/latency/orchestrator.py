"""Latency loadtest orchestrator driving Ryll's control socket.

This script is the latency loadtest's SUT-side driver. See the kerbside
phase 4 plan at docs/plans/PLAN-test-harness-phase-04-port-latency.md
for context and the phase 6 plan at
docs/plans/PLAN-test-harness-phase-06-digest-decoding.md for the
metric switch-back recorded here.

Wire protocol: https://github.com/shakenfist/ryll/blob/main/docs/control-socket-protocol.md

The CSV column is **keypress-to-screen latency in seconds**: time
between the cadence thread sending a `send_key down` and the first
`surface_drawn` event received afterwards.  Phase 4 had to fall back
to SPICE PING/PONG round-trip latency because the v1.0 control socket
had no "a draw just happened" event; the v1.1 protocol added
`surface_drawn` for exactly this use case, and this orchestrator
hard-fails at startup against a v1.0 server that does not advertise it.
"""

import argparse
import collections
import json
import signal
import socket
import sys
import threading
import time


# ── Protocol helpers ──────────────────────────────────────────────────────────

_next_id = 0
_id_lock = threading.Lock()


def _new_id() -> int:
    """Return a monotonically-increasing request id (thread-safe)."""
    global _next_id
    with _id_lock:
        _next_id += 1
        return _next_id


def _send(sock: socket.socket, method: str, params: dict) -> int:
    """Serialise and write one NDJSON request; return the request id."""
    req_id = _new_id()
    line = json.dumps({'id': req_id, 'method': method, 'params': params}) + '\n'
    sock.sendall(line.encode('utf-8'))
    return req_id


def _recv_line(buf: bytearray, sock: socket.socket) -> dict:
    """Read bytes from sock until a newline arrives, then parse and return the JSON object."""
    while b'\n' not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError('server closed the connection')
        buf.extend(chunk)
    nl = buf.index(b'\n')
    line = buf[:nl].decode('utf-8')
    del buf[:nl + 1]
    return json.loads(line)


# ── Shutdown coordination ─────────────────────────────────────────────────────

_shutdown = threading.Event()


def _handle_signal(signum, frame):  # noqa: ARG001
    _shutdown.set()


# ── Cadence thread ────────────────────────────────────────────────────────────

class _CadenceThread(threading.Thread):
    """Background thread that sends periodic spacebar key events.

    Sends key-down, waits 0.1 s, sends key-up, waits cadence_seconds - 0.1 s.
    Uses a separate send lock so cadence sends don't race with the main
    thread's hello/subscribe sends (which happen before this thread starts).

    Pushes the wallclock timestamp (in microseconds since the Unix
    epoch) of every `send_key down` onto `pending_keypress` so the
    main reader can FIFO-pair it with the next `surface_drawn` event.
    """

    def __init__(self, sock: socket.socket, scancode: int, cadence_seconds: float,
                 send_lock: threading.Lock,
                 pending_keypress: 'collections.deque[int]'):
        super().__init__(daemon=True, name='cadence')
        self._sock = sock
        self._scancode = scancode
        self._cadence = cadence_seconds
        self._send_lock = send_lock
        self._pending = pending_keypress

    def run(self) -> None:
        while not _shutdown.is_set():
            try:
                # Capture wallclock as close as possible to the down
                # event going out; the corresponding `surface_drawn`
                # carries its own wallclock_us captured at the server
                # side of the same socket.
                keypress_us = int(time.time() * 1_000_000)
                with self._send_lock:
                    _send(self._sock, 'send_key',
                          {'scancode': self._scancode, 'state': 'down'})
                self._pending.append(keypress_us)
                _shutdown.wait(timeout=0.1)
                if _shutdown.is_set():
                    break
                with self._send_lock:
                    _send(self._sock, 'send_key',
                          {'scancode': self._scancode, 'state': 'up'})
                _shutdown.wait(timeout=max(0.0, self._cadence - 0.1))
            except OSError:
                # Socket closed; main thread will handle the resulting EOF.
                break


# ── Synchronous request helper (pre-cadence, main thread only) ────────────────

def _request(sock: socket.socket, buf: bytearray, method: str, params: dict,
             timeout: float = 10.0) -> dict:
    """Send a request and read responses until the matching one arrives.

    Events received while waiting are discarded; this helper is only used
    during the setup phase (hello, subscribe) before event collection starts.
    """
    req_id = _send(sock, method, params)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msg = _recv_line(buf, sock)
        if msg.get('id') == req_id:
            return msg
        # Non-matching id or pure event: discard during setup phase.
    raise TimeoutError(f'no response to request {req_id!r} within {timeout:.0f} s')


# ── Main ──────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Latency loadtest orchestrator for the Ryll control socket '
                    '(protocol v1.1 or newer; surface_drawn required).',
    )
    parser.add_argument(
        '--socket',
        default='/tmp/ryll.sock',
        metavar='PATH',
        help='Path to the ryll Unix-domain control socket (default: /tmp/ryll.sock)',
    )
    parser.add_argument(
        '--output',
        required=True,
        metavar='PATH',
        help='CSV output path; one latency float per line, in seconds',
    )
    parser.add_argument(
        '--sample-count',
        type=int,
        default=60,
        metavar='N',
        help='Exit after collecting this many latency samples (default: 60)',
    )
    parser.add_argument(
        '--cadence-seconds',
        type=float,
        default=2.0,
        metavar='F',
        help='Seconds between spacebar key presses (default: 2.0)',
    )
    parser.add_argument(
        '--max-seconds',
        type=float,
        default=600.0,
        metavar='F',
        help='Hard wall-clock cap on the run, in seconds (default: 600.0)',
    )
    parser.add_argument(
        '--scancode',
        default='0x39',
        metavar='HEX',
        help='AT-set-1 scancode to send as the cadence key (default: 0x39 = spacebar)',
    )
    args = parser.parse_args()

    # Accept hex (0x39), bare hex (39), or decimal (57) via int(s, 0).
    try:
        args.scancode = int(args.scancode, 0)
    except ValueError:
        parser.error(f'--scancode: cannot parse {args.scancode!r} as an integer')

    return args


def main() -> None:
    args = _parse_args()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # ── Connect ───────────────────────────────────────────────────────────────
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(args.socket)
    except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
        print(f'ERROR: could not connect to {args.socket}: {exc}', file=sys.stderr)
        sys.exit(1)

    buf: bytearray = bytearray()
    send_lock = threading.Lock()

    try:
        # ── Hello ─────────────────────────────────────────────────────────────
        # Hello at v1.1: the protocol-version negotiation is at the
        # major level (1.x); the server replies with whatever minor
        # it speaks, and we hard-fail downstream if `surface_drawn`
        # is missing from `supported_events`.
        resp = _request(sock, buf, 'hello', {
            'client_name': 'kerbside-latency-loadtest',
            'protocol_version': '1.1',
        })
        if not resp.get('ok'):
            print(f'ERROR: hello failed: {resp.get("error", resp)}', file=sys.stderr)
            sys.exit(1)
        result = resp.get('result', {})
        server_proto = result.get('protocol_version', '')
        if not server_proto.startswith('1.'):
            print(
                f'ERROR: server returned non-v1 protocol_version {server_proto!r}; '
                'orchestrator only speaks v1.x',
                file=sys.stderr,
            )
            sys.exit(1)
        supported_events = result.get('supported_events', [])
        if 'surface_drawn' not in supported_events:
            print(
                'ERROR: server does not advertise `surface_drawn` in '
                'supported_events; this orchestrator requires ryll v1.1+ '
                'because the CSV column is keypress-to-screen latency, '
                'not PING/PONG round-trip. Got: '
                f'{supported_events!r}',
                file=sys.stderr,
            )
            sys.exit(1)

        # ── Subscribe ─────────────────────────────────────────────────────────
        resp = _request(sock, buf, 'subscribe',
                        {'events': ['surface_drawn', 'dropped']})
        if not resp.get('ok'):
            print(f'ERROR: subscribe failed: {resp.get("error", resp)}', file=sys.stderr)
            sys.exit(1)
        subscribed = resp.get('result', {}).get('subscribed', [])
        if 'surface_drawn' not in subscribed:
            print(
                'ERROR: server did not accept `surface_drawn` subscription; '
                f'got {subscribed!r}',
                file=sys.stderr,
            )
            sys.exit(1)

        # ── Start cadence thread ──────────────────────────────────────────────
        # `pending_keypress` is the cross-thread FIFO of keypress
        # wallclock_us values waiting for their matching surface_drawn.
        # Use a `deque` -- thread-safe for append/popleft.
        pending_keypress: 'collections.deque[int]' = collections.deque()
        cadence = _CadenceThread(sock, args.scancode, args.cadence_seconds,
                                 send_lock, pending_keypress)
        cadence.start()

        # ── Collect latency samples ───────────────────────────────────────────
        sample_count = 0
        run_start = time.monotonic()

        # Line-buffered so partial runs leave usable data even on hard kill.
        with open(args.output, 'w', buffering=1) as csv_file:
            while not _shutdown.is_set():
                if sample_count >= args.sample_count:
                    break
                if time.monotonic() - run_start >= args.max_seconds:
                    break

                try:
                    msg = _recv_line(buf, sock)
                except EOFError:
                    print('ERROR: server closed the connection before sample count reached',
                          file=sys.stderr)
                    sys.exit(1)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    print(f'ERROR: failed to parse server message: {exc}', file=sys.stderr)
                    sys.exit(1)
                except OSError as exc:
                    if _shutdown.is_set():
                        # Socket closed by our own cleanup on signal; not an error.
                        break
                    print(f'ERROR: socket error during event collection: {exc}', file=sys.stderr)
                    sys.exit(1)

                event_name = msg.get('event')

                if event_name == 'surface_drawn':
                    # Pair the surface_drawn with the oldest pending
                    # keypress.  If the deque is empty, the server
                    # produced a draw that did not follow any keypress
                    # we sent (boot screen activity, vdagent ping, etc.)
                    # -- skip it rather than counting it as a sample.
                    try:
                        keypress_us = pending_keypress.popleft()
                    except IndexError:
                        continue
                    server_wallclock_us = msg.get('data', {}).get('wallclock_us')
                    if server_wallclock_us is None:
                        print('ERROR: surface_drawn event missing wallclock_us field: '
                              f'{msg}',
                              file=sys.stderr)
                        sys.exit(1)
                    latency_seconds = (
                        int(server_wallclock_us) - keypress_us) / 1_000_000.0
                    csv_file.write(f'{latency_seconds}\n')
                    sample_count += 1

                elif event_name == 'dropped':
                    count = msg.get('data', {}).get('count', '?')
                    print(f'dropped {count} events', file=sys.stderr)

                elif 'id' in msg:
                    # Response to a send_key from the cadence thread.
                    if not msg.get('ok'):
                        err = msg.get('error', {})
                        print(
                            f'WARNING: send_key error: {err.get("code", "?")} — '
                            f'{err.get("message", "")}',
                            file=sys.stderr,
                        )
                    # Non-error send_key responses are silently consumed.

                # All other events (agent_connected, paste_completed, etc.) are ignored.

    finally:
        _shutdown.set()
        # Closing the socket unblocks any recv() in _recv_line and also
        # causes the cadence thread's sendall() to raise OSError, ending it.
        sock.close()


if __name__ == '__main__':
    main()
