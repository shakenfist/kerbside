#!/usr/bin/env python3
"""Drive a qemu QMP monitor socket for the kerbside direct-qemu CI lane.

Subcommands:

  set-spice-password --password-file FILE
      QMP set_password with protocol spice and the password read from
      FILE. No `connected` argument is sent, so qemu applies its
      default for clients already connected, which is to keep them.

  expire-spice-password --time TIME
      QMP expire_password with protocol spice. TIME is anything qemu
      accepts: 'now', 'never', '+SECONDS' or an absolute epoch time.

  spice-channels
      QMP query-spice, printing one line per SPICE channel qemu holds
      open, sorted: 'connection-id channel-type channel-id host:port'.
      The client-side host and port identify the TCP connection, so two
      snapshots that print the same lines describe the same connections.

A password is only ever read from a file and sent to qemu. It is never
printed, and neither is a request that carries one.

Exits 0 on success, 1 when qemu answers a command with an error, and 2
on a socket or protocol error.

References:
  - qemu/qapi/ui.json (set_password, expire_password, query-spice)
  - qemu/docs/interop/qmp-spec.rst (greeting, capabilities negotiation)

Usage:
    python3 qmp-client.py --socket /path/to/qmp.sock spice-channels
"""

import argparse
import json
import socket
import sys


class QMPError(Exception):
    """qemu answered a command with an error object."""


class QMPClient:
    """A minimal synchronous QMP client over a Unix socket."""

    def __init__(self, path: str, timeout: float = 10.0) -> None:
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(timeout)
        self._sock.connect(path)
        self._buf = bytearray()
        greeting = self._recv()
        if 'QMP' not in greeting:
            raise EOFError('expected a QMP greeting, got %s' % sorted(greeting))
        self.execute('qmp_capabilities')

    def close(self) -> None:
        self._sock.close()

    def _recv(self) -> dict:
        """Read one newline-terminated JSON message."""
        while b'\n' not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise EOFError('qemu closed the QMP connection')
            self._buf.extend(chunk)
        nl = self._buf.index(b'\n')
        line = self._buf[:nl].decode('utf-8')
        del self._buf[:nl + 1]
        return json.loads(line)

    def execute(self, command: str, arguments: dict = None):
        """Run one command and return its 'return' value.

        Asynchronous events qemu sends in the meantime are skipped. The
        request is never echoed, because set_password's carries the
        password.
        """
        request = {'execute': command}
        if arguments is not None:
            request['arguments'] = arguments
        self._sock.sendall(json.dumps(request).encode('utf-8') + b'\r\n')
        while True:
            reply = self._recv()
            if 'event' in reply:
                continue
            if 'error' in reply:
                err = reply['error']
                raise QMPError('%s: %s' % (err.get('class', '?'), err.get('desc', '?')))
            if 'return' in reply:
                return reply['return']
            raise EOFError('unexpected QMP reply with keys %s' % sorted(reply))


def _read_password(path: str) -> str:
    with open(path) as f:
        password = f.read().strip()
    if not password:
        raise ValueError('password file %s is empty' % path)
    return password


def set_spice_password(qmp: QMPClient, args: argparse.Namespace) -> None:
    password = _read_password(args.password_file)
    qmp.execute('set_password', {'protocol': 'spice', 'password': password})
    print('[qmp] set_password: spice password replaced (connected clients left to qemu\'s default)',
          file=sys.stderr)


def expire_spice_password(qmp: QMPClient, args: argparse.Namespace) -> None:
    qmp.execute('expire_password', {'protocol': 'spice', 'time': args.time})
    print('[qmp] expire_password: spice password expiry set to %s' % args.time, file=sys.stderr)


def format_channels(info: dict) -> list:
    """Render query-spice's channels as sorted, comparable lines."""
    lines = []
    for ch in info.get('channels', []):
        lines.append('%s %s %s %s:%s' % (
            ch.get('connection-id'), ch.get('channel-type'), ch.get('channel-id'),
            ch.get('host'), ch.get('port')))
    return sorted(lines)


def spice_channels(qmp: QMPClient, args: argparse.Namespace) -> None:
    for line in format_channels(qmp.execute('query-spice')):
        print(line)


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Drive a qemu QMP socket for the kerbside direct-qemu CI lane.')
    parser.add_argument('--socket', required=True, help='Path to the qemu QMP Unix socket')
    sub = parser.add_subparsers(dest='command', required=True)

    p = sub.add_parser('set-spice-password', help='Replace the SPICE password')
    p.add_argument('--password-file', required=True,
                   help='File holding the new password; it is read, never printed')
    p.set_defaults(func=set_spice_password)

    p = sub.add_parser('expire-spice-password', help='Set when the SPICE password expires')
    p.add_argument('--time', required=True, help="'now', 'never', '+SECONDS' or an epoch time")
    p.set_defaults(func=expire_spice_password)

    p = sub.add_parser('spice-channels', help='List the SPICE channels qemu holds open')
    p.set_defaults(func=spice_channels)

    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    try:
        qmp = QMPClient(args.socket)
    except (OSError, EOFError, ValueError) as exc:
        print('[qmp] ERROR: could not open QMP on %s: %s' % (args.socket, exc), file=sys.stderr)
        return 2

    try:
        args.func(qmp, args)
    except QMPError as exc:
        print('[qmp] ERROR: %s refused: %s' % (args.command, exc), file=sys.stderr)
        return 1
    except (OSError, EOFError, ValueError) as exc:
        print('[qmp] ERROR: %s failed: %s' % (args.command, exc), file=sys.stderr)
        return 2
    finally:
        qmp.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
