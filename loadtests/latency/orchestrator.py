"""Latency loadtest orchestrator driving Ryll's control socket.

This script is the latency loadtest's SUT-side driver. See the kerbside
phase 4 plan at docs/plans/PLAN-test-harness-phase-04-port-latency.md
for context and motivation.

Wire protocol: https://github.com/shakenfist/ryll/blob/main/docs/control-socket-protocol.md

Note: the latency CSV column changed semantics in phase 4. Legacy
runs measured keypress-to-screen end-to-end; this script measures
SPICE PING/PONG round-trip time (the v1 control-socket `latency`
event). Phase 6 will restore the keypress-to-screen metric once the
control socket grows a `surface_drawn` event.
"""

import argparse
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
    """

    def __init__(self, sock: socket.socket, scancode: int, cadence_seconds: float,
                 send_lock: threading.Lock):
        super().__init__(daemon=True, name='cadence')
        self._sock = sock
        self._scancode = scancode
        self._cadence = cadence_seconds
        self._send_lock = send_lock

    def run(self) -> None:
        while not _shutdown.is_set():
            try:
                with self._send_lock:
                    _send(self._sock, 'send_key', {'scancode': self._scancode, 'state': 'down'})
                _shutdown.wait(timeout=0.1)
                if _shutdown.is_set():
                    break
                with self._send_lock:
                    _send(self._sock, 'send_key', {'scancode': self._scancode, 'state': 'up'})
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
        description='Latency loadtest orchestrator for the Ryll control socket (protocol v1.0).',
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
        resp = _request(sock, buf, 'hello', {
            'client_name': 'kerbside-latency-loadtest',
            'protocol_version': '1.0',
        })
        if not resp.get('ok'):
            print(f'ERROR: hello failed: {resp.get("error", resp)}', file=sys.stderr)
            sys.exit(1)
        server_proto = resp.get('result', {}).get('protocol_version', '')
        if server_proto != '1.0':
            print(
                f'ERROR: server returned unexpected protocol_version {server_proto!r}; expected "1.0"',
                file=sys.stderr,
            )
            sys.exit(1)

        # ── Subscribe ─────────────────────────────────────────────────────────
        resp = _request(sock, buf, 'subscribe', {'events': ['latency', 'dropped']})
        if not resp.get('ok'):
            print(f'ERROR: subscribe failed: {resp.get("error", resp)}', file=sys.stderr)
            sys.exit(1)
        subscribed = resp.get('result', {}).get('subscribed', [])
        if 'latency' not in subscribed:
            print(
                f'ERROR: server did not accept "latency" subscription; got {subscribed!r}',
                file=sys.stderr,
            )
            sys.exit(1)

        # ── Start cadence thread ──────────────────────────────────────────────
        cadence = _CadenceThread(sock, args.scancode, args.cadence_seconds, send_lock)
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

                if event_name == 'latency':
                    data = msg.get('data', {})
                    sample_ms = data.get('sample_ms')
                    if sample_ms is None:
                        print(f'ERROR: latency event missing sample_ms field: {msg}',
                              file=sys.stderr)
                        sys.exit(1)
                    csv_file.write(f'{float(sample_ms) / 1000.0}\n')
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
