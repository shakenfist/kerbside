#!/usr/bin/env python3
"""Smoke-test client for the kerbside direct-qemu CI lane.

Connects to a ryll headless control socket, performs a minimal
hello / status / screenshot sequence, and asserts that:

  - The ryll server speaks protocol major version 1 (any minor).
  - `surfaces` is a non-empty list within 30 seconds.
  - A screenshot of surface 0 returns a valid (non-empty) PNG.

`agent_connected` is logged for diagnostics but is not asserted:
the Sextant fixture intentionally ships without a guest-side
vdagent (see uncalibrated-sextant/README.md and the dedicated
`spice-ryll.sh` recipe for testing without an agent), so the
field is expected to remain false in this lane.

Exits 0 on success, 1 on assertion failure, 2 on socket/RPC error.

References:
  - Protocol: ryll/docs/control-socket-protocol.md
  - Framing helpers lifted from loadtests/latency/orchestrator.py

Usage:
    python3 smoke-client.py /path/to/ryll-ci.sock
"""

import argparse
import base64
import json
import socket
import sys
import time
import threading


# ── Protocol framing (lifted from loadtests/latency/orchestrator.py) ─────────

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


def _request(sock: socket.socket, buf: bytearray, method: str, params: dict,
             timeout: float = 10.0) -> dict:
    """Send a request and read responses until the matching one arrives."""
    req_id = _send(sock, method, params)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msg = _recv_line(buf, sock)
        if msg.get('id') == req_id:
            return msg
    raise TimeoutError(f'no response to request {req_id!r} within {timeout:.0f}s')


# ── Smoke checks ──────────────────────────────────────────────────────────────

_PNG_MAGIC = b'\x89PNG\r\n\x1a\n'


def _check_hello(sock: socket.socket, buf: bytearray) -> None:
    """Assert hello succeeds and the server speaks protocol major version 1.

    The control-socket protocol negotiates at the major-version level:
    the server replies with its own version, and a v1.0 client remains
    valid against any v1.x server (ryll is at 1.1).
    Asserting the exact minor version here would break the lane on
    every compatible minor bump.
    """
    resp = _request(sock, buf, 'hello', {
        'client_name': 'kerbside-ci-smoke',
        'protocol_version': '1.0',
    })
    if not resp.get('ok'):
        print(f'[smoke] ERROR: hello failed: {resp.get("error", resp)}', file=sys.stderr)
        sys.exit(1)
    proto = resp.get('result', {}).get('protocol_version', '')
    if not proto.startswith('1.'):
        print(
            f'[smoke] ASSERT FAIL: expected protocol major version 1, got {proto!r}',
            file=sys.stderr,
        )
        sys.exit(1)
    print(f'[smoke] hello ok (server protocol {proto})', file=sys.stderr)


def _check_status(sock: socket.socket, buf: bytearray) -> None:
    """Poll status every 1s for up to 30s; assert non-empty surfaces.

    `agent_connected` is logged but not asserted -- the Sextant
    fixture has no guest-side vdagent, so the field never flips
    to true in this lane.
    """
    budget = 30.0
    deadline = time.monotonic() + budget
    while True:
        resp = _request(sock, buf, 'status', {}, timeout=5.0)
        if not resp.get('ok'):
            print(
                f'[smoke] ERROR: status RPC failed: {resp.get("error", resp)}',
                file=sys.stderr,
            )
            sys.exit(2)
        result = resp.get('result', {})
        agent_connected = result.get('agent_connected', False)
        surfaces = result.get('surfaces', [])
        print(
            f'[smoke] status: agent_connected={agent_connected}, surfaces={surfaces}',
            file=sys.stderr,
        )
        if surfaces:
            print('[smoke] surfaces populated — ok', file=sys.stderr)
            return
        if time.monotonic() >= deadline:
            print(
                f'[smoke] ASSERT FAIL: after {budget:.0f}s surfaces still empty',
                file=sys.stderr,
            )
            sys.exit(1)
        time.sleep(1.0)


def _check_screenshot(sock: socket.socket, buf: bytearray) -> None:
    """Take a screenshot of surface 0 and assert non-empty PNG."""
    resp = _request(sock, buf, 'screenshot', {'surface_id': 0, 'format': 'png'}, timeout=30.0)
    if not resp.get('ok'):
        print(
            f'[smoke] ERROR: screenshot RPC failed: {resp.get("error", resp)}',
            file=sys.stderr,
        )
        sys.exit(2)
    result = resp.get('result', {})
    b64_data = result.get('data_base64', '')
    if not b64_data:
        print('[smoke] ASSERT FAIL: screenshot returned empty data_base64', file=sys.stderr)
        sys.exit(1)
    png_bytes = base64.b64decode(b64_data)
    if len(png_bytes) == 0:
        print('[smoke] ASSERT FAIL: decoded screenshot is zero bytes', file=sys.stderr)
        sys.exit(1)
    if not png_bytes.startswith(_PNG_MAGIC):
        print(
            f'[smoke] ASSERT FAIL: screenshot does not start with PNG magic; '
            f'got {png_bytes[:8]!r}',
            file=sys.stderr,
        )
        sys.exit(1)
    print(f'[smoke] screenshot: {len(png_bytes)} bytes, PNG magic ok', file=sys.stderr)


# ── Entry point ───────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Smoke-test client for the kerbside direct-qemu CI lane.',
    )
    parser.add_argument(
        'socket_path',
        metavar='SOCKET',
        help='Path to the ryll Unix-domain control socket',
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(args.socket_path)
    except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
        print(f'[smoke] ERROR: could not connect to {args.socket_path}: {exc}', file=sys.stderr)
        sys.exit(2)

    buf: bytearray = bytearray()

    try:
        _check_hello(sock, buf)
        _check_status(sock, buf)
        _check_screenshot(sock, buf)
    except (EOFError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f'[smoke] ERROR: protocol error: {exc}', file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f'[smoke] ERROR: socket error: {exc}', file=sys.stderr)
        sys.exit(2)
    except TimeoutError as exc:
        print(f'[smoke] ERROR: timeout: {exc}', file=sys.stderr)
        sys.exit(2)
    finally:
        sock.close()

    print('[smoke] all checks passed', file=sys.stderr)
    sys.exit(0)


if __name__ == '__main__':
    main()
