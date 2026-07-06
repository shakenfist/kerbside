from unittest import mock
import shutil
import tempfile

import grpc
import testtools

from kerbside.rpc import kerbside_pb2
from kerbside.rpc import kerbside_pb2_grpc
from kerbside.rpc import server as rpc_server
from kerbside.rpc import servicer as servicer_module


class KerbsideProxyRpcTestCase(testtools.TestCase):
    """Drive the KerbsideProxy servicer over a real gRPC channel.

    A server is started on a temporary unix socket and a client stub talks
    to it, so the request/response translation and the servicer's calls into
    db.py are exercised end to end. The db.py layer is mocked per-test so no
    real database is required.
    """

    def setUp(self):
        super().setUp()

        # Temporary socket for the server; cleaned up after the test.
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.sock = self.tmpdir + '/api.sock'

        # Start the server and ensure it is stopped and its socket removed.
        self.server = rpc_server.serve(socket_path=self.sock, workers=2)
        self.addCleanup(rpc_server.stop, self.server, socket_path=self.sock)

        # Client channel over the unix socket.
        self.channel = grpc.insecure_channel('unix:%s' % self.sock)
        self.addCleanup(self.channel.close)
        grpc.channel_ready_future(self.channel).result(timeout=5)
        self.stub = kerbside_pb2_grpc.KerbsideProxyStub(self.channel)

        # Pin NODE_NAME on the config object the servicer actually references
        # (servicer_module.config is the kerbside.config.config singleton) so
        # audit-node assertions are deterministic.
        node_patch = mock.patch.object(
            servicer_module.config, 'NODE_NAME', 'test-node')
        node_patch.start()
        self.addCleanup(node_patch.stop)

    @mock.patch('kerbside.db.add_audit_event')
    @mock.patch('kerbside.db.record_channel_info_by_ref')
    @mock.patch('kerbside.db.get_console')
    @mock.patch('kerbside.db.get_source')
    @mock.patch('kerbside.db.get_token_by_token')
    def test_authorize_success(self, mock_get_token, mock_get_source,
                               mock_get_console, mock_record, mock_audit):
        mock_get_token.return_value = {
            'session_id': 's', 'source': 'src', 'uuid': 'u',
            'created': 0, 'expires': 9999999999}
        mock_get_source.return_value = {'ca_cert': 'CA'}
        mock_get_console.return_value = {
            'hypervisor': 'hv', 'hypervisor_ip': '10.0.0.1',
            'insecure_port': 5901, 'secure_port': 5900, 'ticket': 'tkt',
            'host_subject': 'HS', 'source': 'src', 'uuid': 'u', 'name': 'n',
            'discovered': None}

        reply = self.stub.AuthorizeConnection(
            kerbside_pb2.AuthorizeConnectionRequest(
                token='T', connection_ref='cr', channel_type='main'),
            timeout=5)

        self.assertEqual('target', reply.WhichOneof('result'))
        target = reply.target
        self.assertEqual('hv', target.hypervisor)
        self.assertEqual('10.0.0.1', target.hypervisor_ip)
        self.assertEqual(5901, target.insecure_port)
        self.assertEqual(5900, target.secure_port)
        self.assertEqual('tkt', target.ticket)
        self.assertEqual('CA', target.ca_cert)
        self.assertEqual('HS', target.host_subject)
        self.assertEqual('src', target.source)
        self.assertEqual('u', target.uuid)
        self.assertEqual('s', target.session_id)

        mock_record.assert_called_once_with(
            'test-node', 'cr', session_id='s')
        mock_audit.assert_called_once_with(
            'src', 'u', 's', 'main', 'test-node', 'cr', 'Channel created')

    @mock.patch('kerbside.db.get_source')
    @mock.patch('kerbside.db.get_token_by_token')
    def test_authorize_denied_invalid_token(self, mock_get_token,
                                            mock_get_source):
        mock_get_token.return_value = None

        reply = self.stub.AuthorizeConnection(
            kerbside_pb2.AuthorizeConnectionRequest(
                token='T', connection_ref='cr', channel_type='main'),
            timeout=5)

        self.assertEqual('denied', reply.WhichOneof('result'))
        self.assertEqual('client token invalid', reply.denied.reason)
        mock_get_source.assert_not_called()

    @mock.patch('kerbside.db.get_source')
    @mock.patch('kerbside.db.get_token_by_token')
    def test_authorize_denied_invalid_source(self, mock_get_token,
                                             mock_get_source):
        mock_get_token.return_value = {
            'session_id': 's', 'source': 'src', 'uuid': 'u',
            'created': 0, 'expires': 9999999999}
        mock_get_source.return_value = None

        reply = self.stub.AuthorizeConnection(
            kerbside_pb2.AuthorizeConnectionRequest(
                token='T', connection_ref='cr', channel_type='main'),
            timeout=5)

        self.assertEqual('denied', reply.WhichOneof('result'))
        self.assertEqual('source invalid', reply.denied.reason)

    @mock.patch('kerbside.db.add_audit_event')
    @mock.patch('kerbside.db.get_console')
    @mock.patch('kerbside.db.get_source')
    @mock.patch('kerbside.db.get_token_by_token')
    def test_authorize_denied_invalid_console(self, mock_get_token,
                                              mock_get_source,
                                              mock_get_console, mock_audit):
        mock_get_token.return_value = {
            'session_id': 's', 'source': 'src', 'uuid': 'u',
            'created': 0, 'expires': 9999999999}
        mock_get_source.return_value = {'ca_cert': 'CA'}
        mock_get_console.return_value = None

        reply = self.stub.AuthorizeConnection(
            kerbside_pb2.AuthorizeConnectionRequest(
                token='T', connection_ref='cr', channel_type='main'),
            timeout=5)

        self.assertEqual('denied', reply.WhichOneof('result'))
        self.assertEqual('invalid console', reply.denied.reason)
        # The audit event must use the TOKEN's source/uuid/session_id (the
        # console is None here, so a None-deref bug would surface).
        mock_audit.assert_called_once_with(
            'src', 'u', 's', 'main', 'test-node', 'cr',
            'Invalid console requested')

    @mock.patch('kerbside.db.get_token_by_token')
    def test_authorize_internal_error(self, mock_get_token):
        mock_get_token.side_effect = RuntimeError('boom')

        try:
            self.stub.AuthorizeConnection(
                kerbside_pb2.AuthorizeConnectionRequest(
                    token='T', connection_ref='cr', channel_type='main'),
                timeout=5)
            self.fail('expected grpc.RpcError')
        except grpc.RpcError as e:
            self.assertEqual(grpc.StatusCode.INTERNAL, e.code())

    @mock.patch('kerbside.db.record_channel_info_by_ref')
    def test_register_channel(self, mock_record):
        reply = self.stub.RegisterChannel(
            kerbside_pb2.RegisterChannelRequest(
                node='n', connection_ref='cr', client_ip='1.2.3.4',
                client_port=5, connection_id=6, channel_type='main',
                channel_id=0),
            timeout=5)

        self.assertTrue(reply.success)
        # channel_id of 0 is coerced to None via `or None`.
        mock_record.assert_called_once_with(
            'n', 'cr', client_ip='1.2.3.4', client_port=5,
            connection_id=6, channel_type='main', channel_id=None)

    @mock.patch('kerbside.db.add_audit_event')
    def test_record_audit_event(self, mock_audit):
        reply = self.stub.RecordAuditEvent(
            kerbside_pb2.AuditEventRequest(
                source='src', uuid='u', session_id='s', channel='main',
                node='n', connection_ref='cr', message='msg'),
            timeout=5)

        self.assertTrue(reply.success)
        mock_audit.assert_called_once_with(
            'src', 'u', 's', 'main', 'n', 'cr', 'msg')

    @mock.patch('kerbside.db.remove_channel_by_ref')
    def test_deregister_channel(self, mock_remove):
        reply = self.stub.DeregisterChannel(
            kerbside_pb2.DeregisterChannelRequest(
                node='n', connection_ref='cr'),
            timeout=5)

        self.assertTrue(reply.success)
        mock_remove.assert_called_once_with('cr')

    @mock.patch('kerbside.db.remove_node_channels')
    def test_clear_node_channels(self, mock_remove):
        reply = self.stub.ClearNodeChannels(
            kerbside_pb2.ClearNodeChannelsRequest(node='n'),
            timeout=5)

        self.assertTrue(reply.success)
        mock_remove.assert_called_once_with('n')

    @mock.patch('kerbside.db.add_audit_event')
    def test_record_audit_event_internal_error(self, mock_add):
        mock_add.side_effect = RuntimeError('boom')

        try:
            self.stub.RecordAuditEvent(
                kerbside_pb2.AuditEventRequest(
                    source='s', uuid='u', session_id='sid', channel='main',
                    node='n', connection_ref='cr', message='m'),
                timeout=5)
            self.fail('expected grpc.RpcError')
        except grpc.RpcError as e:
            self.assertEqual(grpc.StatusCode.INTERNAL, e.code())

    @mock.patch('kerbside.db.remove_channel_by_ref')
    def test_deregister_channel_internal_error(self, mock_remove):
        mock_remove.side_effect = RuntimeError('boom')

        try:
            self.stub.DeregisterChannel(
                kerbside_pb2.DeregisterChannelRequest(
                    node='n', connection_ref='cr'),
                timeout=5)
            self.fail('expected grpc.RpcError')
        except grpc.RpcError as e:
            self.assertEqual(grpc.StatusCode.INTERNAL, e.code())

    @mock.patch('kerbside.db.remove_node_channels')
    def test_clear_node_channels_internal_error(self, mock_remove):
        mock_remove.side_effect = RuntimeError('boom')

        try:
            self.stub.ClearNodeChannels(
                kerbside_pb2.ClearNodeChannelsRequest(node='n'),
                timeout=5)
            self.fail('expected grpc.RpcError')
        except grpc.RpcError as e:
            self.assertEqual(grpc.StatusCode.INTERNAL, e.code())

    def test_proxy_control_heartbeat(self):
        call = self.stub.ProxyControl(
            kerbside_pb2.ProxyControlRequest(node='n'))
        # The stream yields an immediate heartbeat, so reading one returns
        # quickly without hitting the 30s keepalive sleep.
        event = next(call)
        self.assertEqual('heartbeat', event.WhichOneof('event'))
        # Cancel so we do not block on the loop's sleep.
        call.cancel()
