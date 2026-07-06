#!/usr/bin/env python3
"""Mock KerbsideProxy gRPC service for standalone Rust-proxy verification.

Implements the same wire contract as kerbside/rpc/servicer.py
(KerbsideProxyServicer) against the generated stubs in kerbside/rpc/, but
with every RPC's answer canned instead of backed by a MariaDB database.
This lets tools/direct-qemu/verify-rust-proxy.sh exercise the built
kerbside-proxy Rust binary end to end -- gRPC authorization, channel
bookkeeping, and audit events -- without a running kerbside daemon or
database.

AuthorizeConnection authorizes ANY token unconditionally and always
answers with the same Target, built from this script's --hypervisor-ip /
--insecure-port / --secure-port / --ticket / --source / --uuid /
--session-id arguments (typically pointed at the qemu SPICE server the
verification harness also starts). RegisterChannel, RecordAuditEvent,
DeregisterChannel, and ClearNodeChannels all log their request and reply
with StatusReply(success=True). ProxyControl mirrors the real servicer:
it opens the stream, emits an immediate Heartbeat, then keeps emitting
heartbeats until the peer (the Rust proxy) disconnects.

Because this speaks the identical protobuf/gRPC contract as the real
servicer, the Rust proxy under test cannot distinguish this mock from the
production KerbsideProxy service -- it is a faithful stand-in, not a
special test mode.

Part of docs/plans/PLAN-rust-proxy-phase-03-proxy-skeleton.md step 3h.

Usage:
    mock-grpc-server.py --socket /tmp/kerbside-rust-proxy-verify/mock-grpc.sock \\
        --insecure-port 5910 --ticket ci-ticket-vm-1

Requires: grpcio (pinned to the same version kerbside uses, see
pyproject.toml) and the kerbside package importable (either `pip install
-e .` from the repo root into a venv, or PYTHONPATH pointing at the repo
root) so `from kerbside.rpc import kerbside_pb2, kerbside_pb2_grpc`
resolves to the checked-in generated stubs.
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time
from concurrent import futures

import grpc

from kerbside.rpc import kerbside_pb2
from kerbside.rpc import kerbside_pb2_grpc


LOG = logging.getLogger('mock-grpc-server')

# Interval between keepalive heartbeats on the ProxyControl stream. Mirrors
# kerbside/rpc/servicer.py's PROXY_CONTROL_HEARTBEAT_SECONDS; kept short here
# because verification runs are short-lived and we would rather see a couple
# of heartbeats in the log than wait 30s for the first one to confirm the
# stream is alive.
PROXY_CONTROL_HEARTBEAT_SECONDS = 5


class MockKerbsideProxyServicer(kerbside_pb2_grpc.KerbsideProxyServicer):
    """Canned-response implementation of the KerbsideProxy service.

    Every field the real servicer would normally resolve from MariaDB
    (kerbside/db.py) is instead a fixed value supplied on the command line,
    stashed on `self` at construction time.
    """

    def __init__(self, hypervisor, hypervisor_ip, insecure_port, secure_port,
                 ticket, ca_cert, host_subject, source, uuid, session_id):
        self.hypervisor = hypervisor
        self.hypervisor_ip = hypervisor_ip
        self.insecure_port = insecure_port
        self.secure_port = secure_port
        self.ticket = ticket
        self.ca_cert = ca_cert
        self.host_subject = host_subject
        self.source = source
        self.uuid = uuid
        self.session_id = session_id

    def AuthorizeConnection(self, request, context):
        LOG.info(
            'AuthorizeConnection: connection_ref=%s client=%s:%s connection_id=%s '
            'channel_type=%s channel_id=%s token=%s (authorizing unconditionally)',
            request.connection_ref, request.client_ip, request.client_port,
            request.connection_id, request.channel_type, request.channel_id,
            '<redacted, len=%d>' % len(request.token))

        target = kerbside_pb2.Target(
            hypervisor=self.hypervisor,
            hypervisor_ip=self.hypervisor_ip,
            insecure_port=self.insecure_port,
            secure_port=self.secure_port,
            ticket=self.ticket,
            ca_cert=self.ca_cert,
            host_subject=self.host_subject,
            source=self.source,
            uuid=self.uuid,
            session_id=self.session_id)
        return kerbside_pb2.AuthorizeConnectionReply(target=target)

    def RegisterChannel(self, request, context):
        LOG.info(
            'RegisterChannel: node=%s connection_ref=%s client=%s:%s connection_id=%s '
            'channel_type=%s channel_id=%s',
            request.node, request.connection_ref, request.client_ip, request.client_port,
            request.connection_id, request.channel_type, request.channel_id)
        return kerbside_pb2.StatusReply(success=True)

    def RecordAuditEvent(self, request, context):
        LOG.info(
            'RecordAuditEvent: source=%s uuid=%s session_id=%s channel=%s node=%s '
            'connection_ref=%s message=%r',
            request.source, request.uuid, request.session_id, request.channel,
            request.node, request.connection_ref, request.message)
        return kerbside_pb2.StatusReply(success=True)

    def DeregisterChannel(self, request, context):
        LOG.info(
            'DeregisterChannel: node=%s connection_ref=%s', request.node, request.connection_ref)
        return kerbside_pb2.StatusReply(success=True)

    def ClearNodeChannels(self, request, context):
        LOG.info('ClearNodeChannels: node=%s', request.node)
        return kerbside_pb2.StatusReply(success=True)

    def ProxyControl(self, request, context):
        """Server-streaming control channel; mirrors servicer.py's stub.

        Opens the stream, emits an immediate Heartbeat so the caller knows
        the stream is live, then keeps emitting heartbeats until the peer
        disconnects (context goes inactive). The Rust proxy's ProxyControl
        consumer this phase only logs events, so heartbeats are all this
        needs to send to be indistinguishable from the real service.
        """
        LOG.info('ProxyControl: stream opened for node=%s', request.node)
        try:
            yield kerbside_pb2.ProxyControlEvent(heartbeat=kerbside_pb2.Heartbeat())
            while context.is_active():
                time.sleep(PROXY_CONTROL_HEARTBEAT_SECONDS)
                if not context.is_active():
                    break
                yield kerbside_pb2.ProxyControlEvent(heartbeat=kerbside_pb2.Heartbeat())
        except Exception as e:
            LOG.error('ProxyControl stream failed: %s', e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('ProxyControl stream failed (see server logs)')
        LOG.info('ProxyControl: stream closed for node=%s', request.node)


def _parse_args():
    parser = argparse.ArgumentParser(
        description='Mock KerbsideProxy gRPC server for standalone rust-proxy verification.')
    parser.add_argument(
        '--socket', default=os.environ.get('MOCK_GRPC_SOCKET'),
        help='Unix domain socket path to bind (matches the proxy binary\'s --api-socket). '
             'May also be set via MOCK_GRPC_SOCKET. Required (via flag or env var).')
    parser.add_argument(
        '--hypervisor', default=os.environ.get('MOCK_GRPC_HYPERVISOR', 'mock-hypervisor'),
        help='Target.hypervisor value (display name only; the proxy prefers hypervisor_ip '
             'when set).')
    parser.add_argument(
        '--hypervisor-ip', default=os.environ.get('MOCK_GRPC_HYPERVISOR_IP', '127.0.0.1'),
        help='Target.hypervisor_ip -- the address of the qemu SPICE server.')
    parser.add_argument(
        '--insecure-port', type=int, default=_int_env('MOCK_GRPC_INSECURE_PORT'),
        help='Target.insecure_port -- the qemu SPICE server\'s plaintext port. Required '
             '(via flag or env var): the backend leg in this harness always connects to '
             'qemu in plaintext.')
    parser.add_argument(
        '--secure-port', type=int, default=_int_env('MOCK_GRPC_SECURE_PORT', 0),
        help='Target.secure_port. Defaults to 0 (no TLS leg to qemu in this harness); the '
             'Rust proxy only retries over TLS if the plaintext leg returns NeedSecured, '
             'which qemu never does here.')
    parser.add_argument(
        '--ticket', default=os.environ.get('MOCK_GRPC_TICKET'),
        help='Target.ticket -- the qemu SPICE password/ticket (must match the --ticket '
             'passed to start-qemu.sh). Required (via flag or env var).')
    parser.add_argument(
        '--ca-cert', default=os.environ.get('MOCK_GRPC_CA_CERT', ''),
        help='Target.ca_cert. Left empty by default: the qemu side of this harness is '
             'plaintext, so the backend leg never needs a CA to verify qemu\'s TLS cert.')
    parser.add_argument(
        '--host-subject', default=os.environ.get('MOCK_GRPC_HOST_SUBJECT', ''),
        help='Target.host_subject. Left empty by default (see --ca-cert); the ryll crate '
             'does not enforce it in this phase regardless (see PLAN-rust-proxy-phase-03).')
    parser.add_argument(
        '--source', default=os.environ.get('MOCK_GRPC_SOURCE', 'rust-proxy-verify'),
        help='Target.source -- a fixed test source name, used only for audit logging.')
    parser.add_argument(
        '--uuid', default=os.environ.get(
            'MOCK_GRPC_UUID', '6f4e2c1a-0000-0000-0000-0000000000f3'),
        help='Target.uuid -- a fixed test console UUID, used only for audit logging.')
    parser.add_argument(
        '--session-id', default=os.environ.get('MOCK_GRPC_SESSION_ID', 'rust-proxy-verify-session'),
        help='Target.session_id -- a fixed test session id, used only for audit logging.')
    parser.add_argument(
        '--workers', type=int, default=int(os.environ.get('MOCK_GRPC_WORKERS', '8')),
        help='gRPC server ThreadPoolExecutor size.')
    parser.add_argument(
        '--verbose', action='store_true', default=bool(os.environ.get('MOCK_GRPC_VERBOSE')),
        help='Enable DEBUG-level logging.')
    args = parser.parse_args()

    missing = [
        name for name, value in (
            ('--socket (or MOCK_GRPC_SOCKET)', args.socket),
            ('--insecure-port (or MOCK_GRPC_INSECURE_PORT)', args.insecure_port),
            ('--ticket (or MOCK_GRPC_TICKET)', args.ticket),
        )
        if value is None
    ]
    if missing:
        parser.error('missing required argument(s): %s' % ', '.join(missing))

    return args


def _int_env(name, default=None):
    value = os.environ.get(name)
    if value is None:
        return default
    return int(value)


def _bind(socket_path, workers):
    """Build and bind the gRPC server on socket_path, mirroring kerbside/rpc/server.py.

    Removes any stale socket file first, ensures the containing directory
    exists, and locks the socket down to 0600 after bind -- the same
    filesystem-permission trust model the real server uses (a same-UID
    trusted local peer).
    """
    socket_dir = os.path.dirname(socket_path)
    if socket_dir:
        os.makedirs(socket_dir, mode=0o700, exist_ok=True)
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=workers))
    return server, socket_dir


def main():
    args = _parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
        stream=sys.stderr)

    servicer = MockKerbsideProxyServicer(
        hypervisor=args.hypervisor,
        hypervisor_ip=args.hypervisor_ip,
        insecure_port=args.insecure_port,
        secure_port=args.secure_port,
        ticket=args.ticket,
        ca_cert=args.ca_cert,
        host_subject=args.host_subject,
        source=args.source,
        uuid=args.uuid,
        session_id=args.session_id)

    server, _ = _bind(args.socket, args.workers)
    kerbside_pb2_grpc.add_KerbsideProxyServicer_to_server(servicer, server)
    server.add_insecure_port('unix:%s' % args.socket)
    server.start()
    os.chmod(args.socket, 0o600)
    LOG.info(
        'mock KerbsideProxy gRPC server listening on unix:%s (authorizing every token; '
        'target hypervisor_ip=%s insecure_port=%s secure_port=%s)',
        args.socket, args.hypervisor_ip, args.insecure_port, args.secure_port)

    stop_event = threading.Event()

    def _handle_signal(signum, _frame):
        LOG.info('received signal %s; shutting down', signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    stop_event.wait()
    server.stop(grace=1.0).wait()
    if os.path.exists(args.socket):
        os.unlink(args.socket)
    LOG.info('mock KerbsideProxy gRPC server stopped')


if __name__ == '__main__':
    main()
