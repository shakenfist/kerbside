from unittest import mock
import shutil
import tempfile

import grpc
from sqlalchemy import create_engine
import testtools

from kerbside import db
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

        # A success reply carries the firewall policy the proxy enforces. With
        # the default config that is enforce mode and an empty permitted list
        # (which the proxy reads as "permit all").
        self.assertTrue(reply.HasField('firewall_policy'))
        self.assertEqual(
            kerbside_pb2.FirewallPolicy.ENFORCE, reply.firewall_policy.mode)
        self.assertEqual([], list(reply.firewall_policy.permitted_channels))

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
        # A denied reply carries no firewall policy.
        self.assertFalse(reply.HasField('firewall_policy'))
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

    @mock.patch('kerbside.db.get_terminations_for_node')
    def test_proxy_control_terminate_session(self, mock_get):
        # A session that is terminated AND live on this node yields a
        # TerminateSession, exactly once, interleaved with heartbeats.
        mock_get.return_value = ['sess-1']

        with mock.patch.object(servicer_module, 'PROXY_CONTROL_POLL_SECONDS',
                               0.05), \
             mock.patch.object(servicer_module,
                               'PROXY_CONTROL_HEARTBEAT_SECONDS', 0.05):
            call = self.stub.ProxyControl(
                kerbside_pb2.ProxyControlRequest(node='n'))
            events = [next(call) for _ in range(6)]
            call.cancel()

        # The stream polled this node's terminations.
        mock_get.assert_called_with('test-node')

        terminates = [
            e for e in events if e.WhichOneof('event') == 'terminate_session']
        # Sent once, not repeated every poll despite the intent persisting.
        self.assertEqual(1, len(terminates))
        self.assertEqual('sess-1', terminates[0].terminate_session.session_id)
        # Heartbeats still flow.
        self.assertTrue(
            any(e.WhichOneof('event') == 'heartbeat' for e in events))

    @mock.patch('kerbside.db.get_terminations_for_node')
    def test_proxy_control_db_error_does_not_kill_stream(self, mock_get):
        # A transient DB error is logged and swallowed; the stream keeps
        # heartbeating rather than tearing down.
        mock_get.side_effect = RuntimeError('boom')

        with mock.patch.object(servicer_module, 'PROXY_CONTROL_POLL_SECONDS',
                               0.05), \
             mock.patch.object(servicer_module,
                               'PROXY_CONTROL_HEARTBEAT_SECONDS', 0.05):
            call = self.stub.ProxyControl(
                kerbside_pb2.ProxyControlRequest(node='n'))
            events = [next(call) for _ in range(3)]
            call.cancel()

        self.assertTrue(
            all(e.WhichOneof('event') == 'heartbeat' for e in events))


class AuthorizeConnectionRealDbTestCase(testtools.TestCase):
    """AuthorizeConnection against the real database layer.

    Every other test in this file mocks db.get_source() and
    db.get_console(), so they keep passing whatever those functions
    return. That hides the data plane's dependence on the public/secret
    split: the proxy needs ca_cert to stay in SOURCE_PUBLIC_FIELDS and
    needs the servicer to be one of the callers which opts in to the
    console ticket. Narrow either and every proxy connection breaks,
    with no gRPC test to say so. This one says so.

    A file backed sqlite database rather than :memory: because the
    servicer answers on a gRPC worker thread, and an in-memory sqlite
    engine hands each thread its own empty database.
    """

    def setUp(self):
        super().setUp()

        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

        self.engine = create_engine('sqlite:///%s/test.db' % self.tmpdir)
        db.Base.metadata.create_all(
            self.engine,
            tables=[db.Source.__table__, db.Console.__table__])
        engine_patch = mock.patch.object(db, 'ENGINE', self.engine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)

        db.add_source(
            'src', 'ovirt', 'https://ovirt.example.com/ovirt-engine/api',
            'admin@internal', 'sekrit-source-password',
            ca_cert='CA-CERT-MARKER')
        db.add_console(
            source='src', uuid='u', hypervisor='hv', hypervisor_ip='10.0.0.1',
            insecure_port=5901, secure_port=5900, name='n',
            host_subject='HS', ticket='sekrit-hypervisor-ticket')

        self.sock = self.tmpdir + '/api.sock'
        self.server = rpc_server.serve(socket_path=self.sock, workers=2)
        self.addCleanup(rpc_server.stop, self.server, socket_path=self.sock)

        self.channel = grpc.insecure_channel('unix:%s' % self.sock)
        self.addCleanup(self.channel.close)
        grpc.channel_ready_future(self.channel).result(timeout=5)
        self.stub = kerbside_pb2_grpc.KerbsideProxyStub(self.channel)

        node_patch = mock.patch.object(
            servicer_module.config, 'NODE_NAME', 'test-node')
        node_patch.start()
        self.addCleanup(node_patch.stop)

    @mock.patch('kerbside.db.add_audit_event')
    @mock.patch('kerbside.db.record_channel_info_by_ref')
    @mock.patch('kerbside.db.get_token_by_token')
    def test_target_carries_the_ca_cert_and_ticket(
            self, mock_get_token, mock_record, mock_audit):
        mock_get_token.return_value = {
            'session_id': 's', 'source': 'src', 'uuid': 'u',
            'created': 0, 'expires': 9999999999}

        reply = self.stub.AuthorizeConnection(
            kerbside_pb2.AuthorizeConnectionRequest(
                token='T', connection_ref='cr', channel_type='main'),
            timeout=5)

        self.assertEqual('target', reply.WhichOneof('result'))
        # ca_cert is public, and the proxy validates the backend's TLS
        # identity with it.
        self.assertEqual('CA-CERT-MARKER', reply.target.ca_cert)
        # The ticket is secret, and the servicer is entitled to it: it
        # is what the proxy presents to the SPICE server.
        self.assertEqual('sekrit-hypervisor-ticket', reply.target.ticket)
        # The source password is not, and is in no field of the reply.
        self.assertNotIn('sekrit-source-password', str(reply))

    @mock.patch('kerbside.db.add_audit_event')
    @mock.patch('kerbside.db.record_channel_info_by_ref')
    @mock.patch('kerbside.db.get_token_by_token')
    def test_the_source_lookup_stays_public(
            self, mock_get_token, mock_record, mock_audit):
        """The servicer opts in for the console, and only for the console.

        Asserting the password is absent from the reply is the
        important half but not the whole of it: the servicer could
        fetch the secret-bearing source, never put it in the reply, and
        still hold a credential it has no use for -- one log line away
        from the bug this change exists to close. The proxy
        authenticates to the SPICE server with the console ticket and
        never with the source password, so the opt-in count here is
        exactly one.
        """
        mock_get_token.return_value = {
            'session_id': 's', 'source': 'src', 'uuid': 'u',
            'created': 0, 'expires': 9999999999}

        with mock.patch('kerbside.db.get_source',
                        wraps=db.get_source) as spy_source, \
                mock.patch('kerbside.db.get_console',
                           wraps=db.get_console) as spy_console:
            reply = self.stub.AuthorizeConnection(
                kerbside_pb2.AuthorizeConnectionRequest(
                    token='T', connection_ref='cr', channel_type='main'),
                timeout=5)

        self.assertEqual('target', reply.WhichOneof('result'))

        spy_source.assert_called_once()
        self.assertNotIn('include_secrets', spy_source.call_args.kwargs)

        spy_console.assert_called_once()
        self.assertTrue(spy_console.call_args.kwargs['include_secrets'])


class BuildFirewallPolicyTestCase(testtools.TestCase):
    """Unit-test the config -> FirewallPolicy mapping in isolation.

    No gRPC server is needed: build_firewall_policy reads the config
    singleton and returns a proto message.
    """

    def test_defaults_to_enforce_and_permit_all(self):
        with mock.patch.object(servicer_module.config, 'FIREWALL_MODE',
                               'enforce'), \
             mock.patch.object(servicer_module.config,
                               'FIREWALL_PERMITTED_CHANNELS', ''):
            fp = servicer_module.build_firewall_policy()
        self.assertEqual(kerbside_pb2.FirewallPolicy.ENFORCE, fp.mode)
        # Empty config -> empty list, which the proxy reads as "permit all".
        self.assertEqual([], list(fp.permitted_channels))

    def test_warn_mode_and_named_channels_map_to_discriminants(self):
        with mock.patch.object(servicer_module.config, 'FIREWALL_MODE',
                               'WARN'), \
             mock.patch.object(servicer_module.config,
                               'FIREWALL_PERMITTED_CHANNELS', 'main, inputs'):
            fp = servicer_module.build_firewall_policy()
        self.assertEqual(kerbside_pb2.FirewallPolicy.WARN_ONLY, fp.mode)
        self.assertEqual([1, 3], list(fp.permitted_channels))

    def test_unknown_mode_falls_back_to_enforce(self):
        with mock.patch.object(servicer_module.config, 'FIREWALL_MODE',
                               'bogus'), \
             mock.patch.object(servicer_module.config,
                               'FIREWALL_PERMITTED_CHANNELS', ''):
            fp = servicer_module.build_firewall_policy()
        self.assertEqual(kerbside_pb2.FirewallPolicy.ENFORCE, fp.mode)

    def test_unknown_channel_name_is_rejected(self):
        # A typo'd channel name must fail closed and loud, not be silently
        # dropped (which would weaken a restrictive policy, or -- if every
        # name is invalid -- leave permitted empty == permit-all).
        with mock.patch.object(servicer_module.config, 'FIREWALL_MODE',
                               'enforce'), \
             mock.patch.object(servicer_module.config,
                               'FIREWALL_PERMITTED_CHANNELS',
                               'main, bogus, display'):
            self.assertRaises(ValueError, servicer_module.build_firewall_policy)
