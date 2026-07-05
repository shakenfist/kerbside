import time

import grpc

from shakenfist_utilities import logs

from kerbside.config import config
from kerbside import db
from kerbside import util
from kerbside.rpc import kerbside_pb2, kerbside_pb2_grpc


LOG, _ = logs.setup(__name__, **util.configure_logging())

# Interval between keepalive heartbeats on the ProxyControl stream. The
# stream is only stubbed this phase; phase 5 replaces the heartbeat loop
# with real session-termination and policy-push events.
PROXY_CONTROL_HEARTBEAT_SECONDS = 30


class KerbsideProxyServicer(kerbside_pb2_grpc.KerbsideProxyServicer):
    """gRPC servicer implementing the unary control-plane RPCs.

    Each RPC maps to one or more db.py operations, preserving today's
    semantics (token expiry filter, audit events, channel bookkeeping).
    ProxyControl is intentionally not implemented here; it is added in a
    later phase and remains inherited (UNIMPLEMENTED).
    """

    def AuthorizeConnection(self, request, context):
        try:
            token = db.get_token_by_token(request.token)
            if not token:
                LOG.warning('Client token is invalid, denying connection')
                return kerbside_pb2.AuthorizeConnectionReply(
                    denied=kerbside_pb2.Denied(reason='client token invalid'))

            source = db.get_source(token['source'])
            if not source:
                LOG.warning('Requested source is invalid, denying connection')
                return kerbside_pb2.AuthorizeConnectionReply(
                    denied=kerbside_pb2.Denied(reason='source invalid'))

            console = db.get_console(token['source'], token['uuid'])
            if not console:
                LOG.warning('Requested console is invalid, denying connection')
                db.add_audit_event(
                    token['source'], token['uuid'], token['session_id'],
                    request.channel_type, config.NODE_NAME,
                    request.connection_ref, 'Invalid console requested')
                return kerbside_pb2.AuthorizeConnectionReply(
                    denied=kerbside_pb2.Denied(reason='invalid console'))

            db.record_channel_info_by_ref(
                config.NODE_NAME, request.connection_ref,
                session_id=token['session_id'])
            db.add_audit_event(
                console['source'], console['uuid'], token['session_id'],
                request.channel_type, config.NODE_NAME,
                request.connection_ref, 'Channel created')

            return kerbside_pb2.AuthorizeConnectionReply(
                target=kerbside_pb2.Target(
                    hypervisor=console['hypervisor'],
                    hypervisor_ip=console['hypervisor_ip'] or '',
                    insecure_port=console['insecure_port'] or 0,
                    secure_port=console['secure_port'] or 0,
                    ticket=console['ticket'] or '',
                    ca_cert=source['ca_cert'] or '',
                    host_subject=console['host_subject'] or '',
                    source=console['source'],
                    uuid=console['uuid'],
                    session_id=token['session_id']))

        except Exception as e:
            LOG.error('AuthorizeConnection failed: %s' % e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('AuthorizeConnection failed: %s' % e)
            return kerbside_pb2.AuthorizeConnectionReply()

    def RegisterChannel(self, request, context):
        try:
            db.record_channel_info_by_ref(
                request.node, request.connection_ref,
                client_ip=request.client_ip or None,
                client_port=request.client_port or None,
                connection_id=request.connection_id or None,
                channel_type=request.channel_type or None,
                channel_id=request.channel_id or None)
            return kerbside_pb2.StatusReply(success=True)

        except Exception as e:
            LOG.error('RegisterChannel failed: %s' % e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('RegisterChannel failed: %s' % e)
            return kerbside_pb2.StatusReply()

    def RecordAuditEvent(self, request, context):
        try:
            db.add_audit_event(
                request.source, request.uuid, request.session_id,
                request.channel, request.node, request.connection_ref,
                request.message)
            return kerbside_pb2.StatusReply(success=True)

        except Exception as e:
            LOG.error('RecordAuditEvent failed: %s' % e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('RecordAuditEvent failed: %s' % e)
            return kerbside_pb2.StatusReply()

    def DeregisterChannel(self, request, context):
        try:
            db.remove_channel_by_ref(request.connection_ref)
            return kerbside_pb2.StatusReply(success=True)

        except Exception as e:
            LOG.error('DeregisterChannel failed: %s' % e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('DeregisterChannel failed: %s' % e)
            return kerbside_pb2.StatusReply()

    def ClearNodeChannels(self, request, context):
        try:
            db.remove_node_channels(request.node)
            return kerbside_pb2.StatusReply(success=True)

        except Exception as e:
            LOG.error('ClearNodeChannels failed: %s' % e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('ClearNodeChannels failed: %s' % e)
            return kerbside_pb2.StatusReply()

    def ProxyControl(self, request, context):
        """Server-streaming control channel from the daemon to the proxy.

        Stubbed this phase: it opens the stream and emits periodic
        Heartbeat keepalives while the proxy stays connected. Phase 5
        replaces this with real session-termination and policy-push
        events (extending the ProxyControlEvent oneof).
        """
        LOG.info('ProxyControl stream opened for node %s' % request.node)
        try:
            # Emit an immediate heartbeat so the client knows the stream is
            # live, then keep it alive until the peer goes away.
            yield kerbside_pb2.ProxyControlEvent(
                heartbeat=kerbside_pb2.Heartbeat())
            while context.is_active():
                time.sleep(PROXY_CONTROL_HEARTBEAT_SECONDS)
                yield kerbside_pb2.ProxyControlEvent(
                    heartbeat=kerbside_pb2.Heartbeat())
        except Exception as e:
            LOG.error('ProxyControl stream failed: %s' % e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('ProxyControl stream failed: %s' % e)
