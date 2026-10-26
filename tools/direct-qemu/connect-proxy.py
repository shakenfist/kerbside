#!/usr/bin/env python3
"""A one-target HTTP CONNECT proxy for the kerbside direct-qemu lane.

It stands in for Proxmox's spiceproxy where kerbside can tell the
difference. A CONNECT is accepted only when both the request line's
authority and the Host: header are exactly `<connect host>:<port>`. PVE
reads the target from the Host: header and signs the port into the
connect host, so a client that sends only one of them, or names another
port, is refused there too. Everything else is answered `401`, as PVE
answers a bad ticket, and closed.

An accepted CONNECT is answered `HTTP/1.0 200 Connection established` and
relayed both ways to `<upstream host>:<port>`, which in the lane is qemu's
SPICE TLS listener. If that cannot be reached the client gets a `502`.

The connect host is a credential (PVE signs a ticket into it), so it is
read from a file rather than taken as an argument, which would put it in
`ps`, and nothing here ever prints it. Nothing is logged at all: the
counts of tunnels opened, requests refused and upstream failures are
written to the status file as `name=value` lines, rewritten whole on
every change. The status file is first written, with zero counts, once
the listener is bound, so its appearance means the proxy is ready.

Usage:
    python3 connect-proxy.py --listen-port 13128 --port 5911 \\
        --expected-host-file /tmp/kerbside-tunnel-checks-match/connect-host \\
        --status-file /tmp/kerbside-tunnel-checks-match/connect-proxy.status
"""

import argparse
import asyncio
import os
import sys


# The request header block must end within this many bytes and seconds.
MAX_HEADER_BYTES = 8192
HEADER_TIMEOUT = 10.0
RELAY_CHUNK = 65536

ACCEPTED_VERSIONS = ('HTTP/1.0', 'HTTP/1.1')

ESTABLISHED = b'HTTP/1.0 200 Connection established\r\n\r\n'
REFUSED = b'HTTP/1.0 401 invalid ticket\r\n\r\n'
UPSTREAM_FAILED = b'HTTP/1.0 502 Bad Gateway\r\n\r\n'

COUNTERS = ('tunnels', 'refused', 'upstream_failed')


def parse_connect_request(block):
    """Return (authority, host header) from a CONNECT request's header block.

    Returns None for anything that is not a well-formed CONNECT with exactly
    one Host: header.
    """
    try:
        text = block.decode('ascii')
    except UnicodeDecodeError:
        return None
    if not text.endswith('\r\n\r\n'):
        return None
    lines = text[:-4].split('\r\n')

    parts = lines[0].split(' ')
    if len(parts) != 3:
        return None
    method, authority, version = parts
    if method != 'CONNECT' or version not in ACCEPTED_VERSIONS:
        return None

    hosts = []
    for line in lines[1:]:
        name, sep, value = line.partition(':')
        if not sep:
            return None
        if name.lower() == 'host':
            hosts.append(value.strip(' \t'))
    if len(hosts) != 1:
        return None
    return authority, hosts[0]


def is_expected_request(block, expected_authority):
    """True only if both the request line and Host: name the expected target."""
    parsed = parse_connect_request(block)
    if parsed is None:
        return False
    authority, host = parsed
    return authority == expected_authority and host == expected_authority


class ConnectProxy:
    def __init__(self, expected_authority, upstream_host, port, status_file):
        self.expected_authority = expected_authority
        self.upstream_host = upstream_host
        self.port = port
        self.status_file = status_file
        self.counts = dict.fromkeys(COUNTERS, 0)

    def write_status(self):
        tmp = '%s.tmp' % self.status_file
        with open(tmp, 'w') as f:
            for name in COUNTERS:
                f.write('%s=%d\n' % (name, self.counts[name]))
        os.replace(tmp, self.status_file)

    def count(self, name):
        self.counts[name] += 1
        self.write_status()

    async def handle(self, reader, writer):
        try:
            await self._handle(reader, writer)
        finally:
            writer.close()

    async def _handle(self, reader, writer):
        try:
            block = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), HEADER_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, OSError):
            block = None

        if block is None or not is_expected_request(block, self.expected_authority):
            self.count('refused')
            await _send_and_forget(writer, REFUSED)
            return

        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(self.upstream_host, self.port)
        except OSError:
            self.count('upstream_failed')
            await _send_and_forget(writer, UPSTREAM_FAILED)
            return

        try:
            writer.write(ESTABLISHED)
            await writer.drain()
            self.count('tunnels')
            await asyncio.gather(
                _pipe(reader, upstream_writer),
                _pipe(upstream_reader, writer))
        except OSError:
            pass
        finally:
            upstream_writer.close()


async def _send_and_forget(writer, response):
    try:
        writer.write(response)
        await writer.drain()
    except OSError:
        pass


async def _pipe(reader, writer):
    """Copy reader to writer until EOF, then pass the EOF on."""
    try:
        while True:
            data = await reader.read(RELAY_CHUNK)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except OSError:
        pass


def _quiet_exception_handler(loop, context):
    # The default handler prints the exception's message, which is not
    # known to be free of the connect host. Its class name is.
    exception = context.get('exception')
    name = type(exception).__name__ if exception else 'no exception'
    sys.stderr.write('connect-proxy: unexpected %s\n' % name)


def _parse_args():
    parser = argparse.ArgumentParser(
        description='A one-target HTTP CONNECT proxy for the direct-qemu lane.')
    parser.add_argument('--listen-host', default='127.0.0.1', help='Address to listen on.')
    parser.add_argument('--listen-port', type=int, required=True, help='Port to listen on.')
    parser.add_argument(
        '--expected-host-file', required=True,
        help='A file holding the only connect host a CONNECT may name. It is never printed.')
    parser.add_argument(
        '--port', type=int, required=True,
        help='The only port a CONNECT may name, and the upstream port it is relayed to.')
    parser.add_argument(
        '--upstream-host', default='127.0.0.1', help='Where an accepted CONNECT is relayed to.')
    parser.add_argument('--status-file', required=True, help='Where to write the counts.')
    args = parser.parse_args()

    # Errors name the file, never what is in it.
    try:
        with open(args.expected_host_file) as f:
            expected_host = f.read()
    except OSError as e:
        parser.error('cannot read --expected-host-file %s: %s' % (args.expected_host_file, e.strerror))
    if expected_host.endswith('\n'):
        expected_host = expected_host[:-1]
    if not expected_host:
        parser.error('--expected-host-file %s is empty' % args.expected_host_file)
    args.expected_authority = '%s:%d' % (expected_host, args.port)
    return args


async def _serve(args):
    asyncio.get_running_loop().set_exception_handler(_quiet_exception_handler)
    proxy = ConnectProxy(args.expected_authority, args.upstream_host, args.port, args.status_file)
    server = await asyncio.start_server(
        proxy.handle, args.listen_host, args.listen_port, limit=MAX_HEADER_BYTES)
    proxy.write_status()
    async with server:
        await server.serve_forever()


def main():
    args = _parse_args()
    asyncio.run(_serve(args))


if __name__ == '__main__':
    main()
