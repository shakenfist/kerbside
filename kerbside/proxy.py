#!/usr/bin/python

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import logging
import multiprocessing
import os
from prometheus_client import Counter, Gauge, start_http_server
import psutil
import queue
import select
import setproctitle
from shakenfist_utilities import logs
import signal
import socket
import ssl
import struct
import time
import traceback

from .config import config
from . import db
from . import spiceprotocol
from .spiceprotocol import constants
from .spiceprotocol.packets.linkmessages import (BadMagic, BadMajor, BadMinor)
from . import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


class MissingFileException(Exception):
    ...


class ProtocolError(Exception):
    ...


class ConnectionRefused(Exception):
    ...


class ConnectionRedirected(Exception):
    ...


class ConnectionDeclined(Exception):
    ...


class ConnectionClosed(Exception):
    ...


# The protocol is largely documented at https://www.spice-space.org/spice-protocol.html
# although that document is notably incomplete and I have had to read source
# code at https://gitlab.freedesktop.org/spice/spice-protocol and
# https://gitlab.freedesktop.org/spice/spice at various times.


class SpiceListener(object):
    def __init__(self, address, port, tls_port):
        self.unsecured = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.unsecured.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.unsecured.bind((address, port))
        self.unsecured.listen()

        if not os.path.exists(config.PROXY_HOST_CERT_PATH):
            raise MissingFileException('host certificate is missing from %s'
                                       % config.PROXY_HOST_CERT_PATH)
        if not os.path.exists(config.PROXY_HOST_CERT_KEY_PATH):
            raise MissingFileException('host key is missing from %s'
                                       % config.PROXY_HOST_CERT_KEY_PATH)
        if not os.path.exists(config.CACERT_PATH):
            raise MissingFileException('CA certificate is missing from %s'
                                       % config.CACERT_PATH)

        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(
            config.PROXY_HOST_CERT_PATH, config.PROXY_HOST_CERT_KEY_PATH)
        self.ssl_context.load_verify_locations(config.CACERT_PATH)
        self.ssl_context.set_default_verify_paths()

        self.secured = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secured.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.secured.bind((address, tls_port))
        self.secured.listen()

    def accept(self):
        readable, _, _ = select.select([self.unsecured, self.secured], [], [], 1)
        for read in readable:
            if read == self.unsecured:
                conn, addr = self.unsecured.accept()
                LOG.info('Accepted unsecured connection from %s:%s' % addr)
                yield conn, addr[0], addr[1], False
            elif read == self.secured:
                conn, addr = self.secured.accept()
                conn = self.ssl_context.wrap_socket(conn, server_side=True)
                LOG.info('Accepted secured connection from %s:%s' % addr)
                yield conn, addr[0], addr[1], True


class SpiceSession(object):
    def __init__(self, client_conn, client_host, client_port):
        self.client_conn = client_conn
        self.log = LOG.with_fields({
            'connection_type': 'insecure',
            'client_host': client_host,
            'client_port': client_port
            })

    def _cleanup_socket(self):
        try:
            self.client_conn.shutdown(socket.SHUT_RDWR)
            self.client_conn.close()
        except OSError:
            ...

    def run(self, _prometheus_updates):
        setproctitle.setproctitle('kerbside-insecure-new')
        if config.LOG_VERBOSE:
            self.log.setLevel(logging.DEBUG)

        client_buffered = bytearray()

        while True:
            try:
                readable, _, errors = select.select(
                    [self.client_conn], [], [self.client_conn], 1)
                if errors:
                    self.log.warning('Connection closed (error)')
                    self._cleanup_socket()
                    return
                if readable:
                    client_buffered += bytearray(self.client_conn.recv(1024000))

            except (ConnectionResetError, BrokenPipeError) as e:
                self.log.error('%s on read: %s\n%s' % (type(e), e,
                               traceback.format_exc()))
                self._cleanup_socket()
                return

            try:
                if client_buffered:
                    parser = spiceprotocol.ClientSpiceLinkMessPacket(
                        self.log, self.client_conn)
                    parser(client_buffered, redirect_to_secure=True)
                    self.log.info(
                        'SpiceLinkReply requesting secured connection returned')
                    raise ConnectionRedirected('redirected to secure channel')

            except (BadMagic, BadMajor, BadMinor, ProtocolError, ConnectionRedirected,
                    ConnectionRefused, ConnectionDeclined) as e:
                self.log.info('Connection termination on processing: %s' % e)
                self._cleanup_socket()
                return

            except BrokenPipeError as e:
                self.log.error('%s on processing: %s\n%s' % (type(e), e,
                               traceback.format_exc()))
                self._cleanup_socket()
                return


class SpiceTLSSession(object):
    def __init__(self, client_conn, client_host, client_port):
        self.client_host = client_host
        self.client_port = client_port

        self.client_conn = client_conn
        self.client_next_packet = self.ClientSpiceLinkMess

        self.server_conn = None
        self.server_next_packet = None

        self.client_parser = None
        self.server_parser = None
        self.client_ignore_acks = 0
        self.server_ignore_acks = 0

        self.last_statistics = time.time() - 9
        self.session_id = None

        self.log = LOG.with_fields({
            'connection_type': 'secure',
            'client_host': client_host,
            'client_port': client_port
            })

    def _cleanup_sockets(self, sockets):
        for s in sockets:
            try:
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except OSError:
                ...
        return

    def UnknownPacket(self, buffered):
        raise Exception('unknown packet %s!' % buffered)

    def _emit_statistics(self, from_client, from_server, processing_time_consumed):
        if time.time() - self.last_statistics > 10:
            labels = {
                'type': constants.channel_num_to_str[self.chan_type],
                'session': self.session_id
            }

            self.prometheus_updates.put(('bytes_proxied', labels, from_client))
            self.prometheus_updates.put(('bytes_proxied', labels, from_server))
            self.prometheus_updates.put(('proxy_time', labels, processing_time_consumed))

            self.from_client = 0
            self.from_server = 0
            self.processing_time_consumed = 0

    def run(self, prometheus_updates):
        db.record_channel_info(config.NODE_NAME, os.getpid())
        self.prometheus_updates = prometheus_updates
        setproctitle.setproctitle('kerbside-secure-new')
        if config.LOG_VERBOSE:
            self.log.setLevel(logging.DEBUG)

        client_buffered = bytearray()
        server_buffered = bytearray()

        while True:
            start_time = time.time()
            client_consumed = 0
            server_consumed = 0

            sockets = [self.client_conn]
            if self.server_conn:
                sockets.append(self.server_conn)

            try:
                # We cannot wait for data too long here, because we might have
                # queued data waiting for a ClientProxy or ServerProxy and that
                # might have changed in packet processing for the other socket.
                readable, _, errors = select.select(sockets, [], sockets, 0.2)
                if errors:
                    self.log.warning('Connection closed (error)')
                    self._cleanup_sockets(sockets)
                    return
                for r in readable:
                    # This is a little weird because even if the underlying
                    # socket is readable, that doesn't mean that the SSL
                    # wrapper is.
                    try:
                        if r == self.client_conn:
                            d = self.client_conn.recv(1024000)
                            if not d:
                                self._cleanup_sockets(sockets)
                                return
                            client_buffered += bytearray(d)
                        elif r == self.server_conn:
                            d = self.server_conn.recv(1024000)
                            if not d:
                                self._cleanup_sockets(sockets)
                                return
                            server_buffered += bytearray(d)

                    except ssl.SSLWantReadError:
                        # The ssl connection has no data to read
                        self.log.error('SSLWantReadErrror on read at:\n%s'
                                       % traceback.format_exc())

            except (ConnectionResetError, BrokenPipeError) as e:
                self.log.error('%s on read: %s\n%s' % (type(e), e,
                               traceback.format_exc()))
                self._cleanup_sockets(sockets)
                return

            try:
                if client_buffered:
                    client_consumed = self.client_next_packet(client_buffered)
                    while client_consumed > 0:
                        client_buffered = client_buffered[client_consumed:]
                        client_consumed = self.client_next_packet(client_buffered)

                if self.server_next_packet and server_buffered:
                    server_consumed = self.server_next_packet(server_buffered)
                    while server_consumed > 0:
                        server_buffered = server_buffered[server_consumed:]
                        server_consumed = self.server_next_packet(server_buffered)

            except (BadMagic, BadMajor, BadMinor, ProtocolError, ConnectionRedirected,
                    ConnectionRefused, ConnectionDeclined) as e:
                self.log.info('Connection termination on processing: %s' % e)
                self._cleanup_sockets(sockets)
                return

            except BrokenPipeError as e:
                self.log.error('%s on processing: %s\n%s' % (type(e), e,
                               traceback.format_exc()))
                self._cleanup_sockets(sockets)
                return

            if client_consumed + server_consumed > 0 and self.server_conn:
                self._emit_statistics(client_consumed, server_consumed, time.time() - start_time)

    def ClientSpiceLinkMess(self, buffered):
        parser = spiceprotocol.ClientSpiceLinkMessPacket(
            self.log, self.client_conn)
        consumed = parser(buffered)
        if consumed:
            # NOTE(mikal): there must be a nicer way to do this...
            self.conn_id = parser.conn_id
            self.chan_type = parser.chan_type
            self.chan_id = parser.chan_id
            self.capabilities = parser.capabilities
            self.private_key = parser.private_key

            db.record_channel_info(
                config.NODE_NAME, os.getpid(), client_ip=self.client_host,
                client_port=self.client_port, connection_id=self.conn_id,
                channel_type=constants.channel_num_to_str[self.chan_type],
                channel_id=self.chan_id)

            self.client_next_packet = self.ClientPassword
        return consumed

    def ClientPassword(self, buffered):
        # NOTE(mikal): I haven't moved this packet parsing into spiceprotocol
        # because its entwined with the proxy business logic -- essentially we
        # don't know the correct password for a given console until we've
        # an attempted password and looked it up.

        if len(buffered) < 132:
            # The encrypted password must be of this size (4 byte auth mechanism
            # which matches the common capabilities flags, and 128 byte
            # encrypted password).
            return 0

        mechanism = struct.unpack_from('<I', buffered)[0]
        if mechanism != 1:
            raise ProtocolError(
                'we only support AuthSpice, not mechanism %d' % mechanism)

        password = self.private_key.decrypt(
            bytes(buffered[4:132]),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                         algorithm=hashes.SHA1(), label=None))[:-1].decode()

        token = db.get_token_by_token(password)
        if not token:
            self.log.warning('Client token is invalid, closing connection')
            self.client_next_packet = self.UnknownPacket
            raise ConnectionDeclined('client token invalid')
        self.log.with_fields(token).info('Client token is valid')
        self.session_id = token['session_id']

        self.source = db.get_source(token['source'])
        if not self.source:
            self.log.warning('Requested source is invalid, closing connection')
            self.client_next_packet = self.UnknownPacket
            raise ConnectionDeclined('source invalid')

        self.console = db.get_console(token['source'], token['uuid'])
        if not self.console:
            self.log.warning('Requested console is invalid, closing connection')
            db.add_audit_event(
                self.console['source'], self.console['uuid'], self.session_id,
                constants.channel_num_to_str[self.chan_type],
                config.NODE_NAME, os.getpid(), 'Invalid console requested')
            self.client_next_packet = self.UnknownPacket
            raise ConnectionDeclined('invalid console')

        self.log.with_fields(self.console).info('Requested console is valid')
        db.record_channel_info(config.NODE_NAME, os.getpid(), session_id=self.session_id)
        db.add_audit_event(
            self.console['source'], self.console['uuid'], self.session_id,
            constants.channel_num_to_str[self.chan_type],
            config.NODE_NAME, os.getpid(), 'Channel created')
        self.client_conn.sendall(struct.pack('<I', constants.error_str_to_num['ok']))

        # Make us look nice in the process listing
        procname = ('kerbside-secure-%s-%s-%d'
                    % (self.session_id, constants.channel_num_to_str[self.chan_type],
                       self.chan_id))
        setproctitle.setproctitle(procname)
        self.log.info('Renamed process to %s' % procname)

        # Initiate a connection to the server.
        try:
            server = self.console['hypervisor']
            if self.console['hypervisor_ip']:
                server = self.console['hypervisor_ip']

            sc = spiceprotocol.SpiceClient()
            sc.from_static_configuration(
                server, self.console['insecure_port'],
                self.console['secure_port'], self.console['ticket'],
                self.source['ca_cert'], self.console['host_subject']
            )
            sc.connect(self.conn_id, self.chan_type, self.capabilities[0],
                       self.capabilities[1])

            # Rip the socket out so we can just start proxying into it
            self.server_conn = sc.sock
            self.server_conn.setblocking(0)

            db.add_audit_event(
                self.console['source'], self.console['uuid'], self.session_id,
                constants.channel_num_to_str[self.chan_type],
                config.NODE_NAME, os.getpid(), 'Hypervisor connection successful')

        except ConnectionRefusedError:
            self.log.with_fields(self.console).warning('Connection to hypervisor failed')
            db.add_audit_event(
                self.console['source'], self.console['uuid'], self.session_id,
                constants.channel_num_to_str[self.chan_type],
                config.NODE_NAME, os.getpid(), 'Hypervisor SSL connection failed')
            raise ConnectionRefused('hypervisor ssl connection failed')

        # Assume we consumed all of the data
        self.log.info('Entering pass through mode')
        self.client_next_packet = self.ClientProxy
        self.server_next_packet = self.ServerProxy
        return 132

    client_inspector_map = {
        'main': spiceprotocol.ClientMainPacket,
        'display': spiceprotocol.ClientDisplayPacket,
        'inputs': spiceprotocol.ClientInputsPacket,
        'cursor': spiceprotocol.ClientCursorPacket,
        'port': spiceprotocol.ClientPortPacket
    }

    def ClientProxy(self, buffered):
        if self.server_next_packet.__name__ == 'ServerProxy':
            if not self.client_parser:
                self.client_parser = self.client_inspector_map.get(
                    constants.channel_num_to_str[self.chan_type],
                    spiceprotocol.ClientUnknownPacket)()

                if constants.channel_num_to_str[self.chan_type] == 'port':
                    self.client_parser.channel_identifier = \
                        'port-%d-client' % self.chan_id

                self.client_parser.configure_inspection(
                    self.console['source'], self.console['uuid'], self.session_id,
                    constants.channel_num_to_str[self.chan_type])

            pt = self.client_parser(buffered)
            self.client_parser.emit_entry(
                'ClientProxy parsed from client to server: '
                '%d bytes to send, %d bytes consumed, '
                '%d inserted packets, is ack %s, ignore acks accrued %d'
                % (len(pt.data_to_send), pt.length_to_consume,
                   pt.inserted_packets, pt.packet_is_ack,
                   self.client_ignore_acks))
            if pt.inserted_packets > 0:
                self.client_parser.emit_entry(
                    'ClientProxy inserted %d packets' % pt.inserted_packets)
                self.server_ignore_acks += pt.inserted_packets
            if pt.packet_is_ack and self.client_ignore_acks > 0:
                self.client_parser.emit_entry(
                    'ClientProxy ignoring ACK for packet we inserted')
                self.client_ignore_acks -= 1
            else:
                self.server_conn.sendall(pt.data_to_send)
            return pt.length_to_consume

        self.log.info('Client has no server proxy (%s), waiting.'
                      % self.server_next_packet.__name__)
        db.add_audit_event(
            self.console['source'], self.console['uuid'], self.session_id,
            constants.channel_num_to_str[self.chan_type],
            config.NODE_NAME, os.getpid(), 'Client has no server proxy, stalling')
        return 0

    server_inspector_map = {
        'main': spiceprotocol.ServerMainPacket,
        'display': spiceprotocol.ServerDisplayPacket,
        'inputs': spiceprotocol.ServerInputsPacket,
        'cursor': spiceprotocol.ServerCursorPacket,
        'port': spiceprotocol.ServerPortPacket
    }

    def ServerProxy(self, buffered):
        if self.server_next_packet.__name__ == 'ServerProxy':
            if not self.server_parser:
                self.server_parser = self.server_inspector_map.get(
                    constants.channel_num_to_str[self.chan_type],
                    spiceprotocol.ServerUnknownPacket)()

                if constants.channel_num_to_str[self.chan_type] == 'port':
                    self.server_parser.channel_identifier = \
                        'port-%d-server' % self.chan_id

                self.server_parser.configure_inspection(
                    self.console['source'], self.console['uuid'], self.session_id,
                    constants.channel_num_to_str[self.chan_type])

            # This is a little silly in that the server never acks the client,
            # but the code is more symmetrical this way.
            pt = self.server_parser(buffered)
            self.server_parser.emit_entry(
                'ServerProxy parsed from client to server: '
                '%d bytes to send, %d bytes consumed, '
                '%d inserted packets, is ack %s, ignore acks accrued %d'
                % (len(pt.data_to_send), pt.length_to_consume,
                   pt.inserted_packets, pt.packet_is_ack,
                   self.server_ignore_acks))
            if pt.inserted_packets > 0:
                self.server_parser.emit_entry(
                    'ServerProxy inserted %d packets' % pt.inserted_packets)
                self.client_ignore_acks += pt.inserted_packets
            if pt.packet_is_ack and self.server_ignore_acks > 0:
                self.server_parser.emit_entry(
                    'ServerProxy ignoring ACK for packet we inserted')
                self.server_ignore_acks -= 1
            else:
                self.client_conn.sendall(pt.data_to_send)
            return pt.length_to_consume

        self.log.info('Server has no client proxy (%s), waiting.'
                      % self.client_next_packet.__name__)
        db.add_audit_event(
            self.console['source'], self.console['uuid'], self.session_id,
            constants.channel_num_to_str[self.chan_type],
            config.NODE_NAME, os.getpid(), 'Server has no client proxy, stalling')
        return 0


def run():
    setproctitle.setproctitle('kerbside-proxy')
    if config.LOG_VERBOSE:
        LOG.setLevel(logging.DEBUG)
    LOG.info('Proxy starting')

    db.remove_node_channels(config.NODE_NAME)

    listen = SpiceListener(config.VDI_ADDRESS, config.VDI_INSECURE_PORT,
                           config.VDI_SECURE_PORT)

    # Start the prometheus metrics server
    start_http_server(config.PROMETHEUS_METRICS_PORT)
    workers_gauge = Gauge('workers', 'The number of worker processes')
    bytes_proxied = Counter('bytes_proxied', 'Bytes transferred by the proxy',
                            ['type', 'session_id'])
    proxy_time = Counter('proxy_time', 'Time consumed by proxy processing packets',
                         ['type', 'session_id'])
    prometheus_updates = multiprocessing.JoinableQueue()

    workers = []
    last_worker_management = time.time()
    while True:
        if time.time() - last_worker_management > 1:
            # Find stray child processes
            channel_pids = {}
            for channel in db.get_node_channels(config.NODE_NAME):
                channel_pids[channel['pid']] = True

            for child in psutil.Process(os.getpid()).children(recursive=True):
                if time.time() - child.create_time() < 5:
                    # Skip really new processes
                    continue

                if child.pid in channel_pids:
                    # Active channel
                    continue

                if child.name().startswith('kerbside-secure-'):
                    # Stray!
                    os.kill(child.pid, signal.SIGKILL)
                    LOG.info('Terminated worker with pid %d' % child.pid)

            # Reap terminated processes
            remaining_workers = []
            for p in workers:
                if not p.is_alive():
                    p.join(1)
                    db.remove_proxy_channel(config.NODE_NAME, p.pid)
                    LOG.info('Reaped worker with pid %d, exit code %d'
                             % (p.pid, p.exitcode))
                else:
                    remaining_workers.append(p)

            workers = remaining_workers
            last_worker_management = time.time()

        # Update prometheus statistics
        workers_gauge.set(len(workers))

        try:
            while True:
                name, labels, value = prometheus_updates.get(block=False)
                if name == 'bytes_proxied':
                    bytes_proxied.labels(**labels).inc(value)
                if name == 'proxy_time':
                    proxy_time.labels(**labels).inc(value)
        except queue.Empty:
            ...

        for conn, client_host, client_port, secured in listen.accept():
            if not secured:
                session = SpiceSession(conn, client_host, client_port)
            else:
                session = SpiceTLSSession(conn, client_host, client_port)

            procname = 'kerbside-%s-%s' % (client_host, client_port)
            db.reset_engine()
            p = multiprocessing.Process(target=session.run, name=procname,
                                        args=(prometheus_updates,))
            p.start()
            workers.append(p)
            LOG.info('Started worker with pid %s' % p.pid)
