import time

import grpc

from shakenfist_utilities import logs

from kerbside.config import config
from kerbside import db
from kerbside import util
from kerbside.rpc import kerbside_pb2, kerbside_pb2_grpc


LOG, _ = logs.setup(__name__, **util.configure_logging())

# Interval between keepalive heartbeats on the ProxyControl stream.
PROXY_CONTROL_HEARTBEAT_SECONDS = 30

# How often the ProxyControl stream polls the database for terminations that
# apply to this node. Short so API-driven termination reaches the proxy
# promptly; the trade-off is termination latency vs DB load.
PROXY_CONTROL_POLL_SECONDS = 2

# SPICE ChannelType name -> discriminant (matches ryll's ChannelType and the
# FirewallPolicy.permitted_channels contract in kerbside.proto). Used to map the
# FIREWALL_PERMITTED_CHANNELS config names to the wire discriminants.
CHANNEL_NAME_TO_DISCRIMINANT = {
    'main': 1,
    'display': 2,
    'inputs': 3,
    'cursor': 4,
    'playback': 5,
    'record': 6,
    'tunnel': 7,
    'smartcard': 8,
    'usbredir': 9,
    'port': 10,
    'webdav': 11,
}


def build_firewall_policy():
    """Build the FirewallPolicy delivered in an AuthorizeConnection success.

    Python owns policy; the proxy enforces it. For v1 the value is
    deployment-wide (built from config, identical on every reply); the
    per-connection delivery mechanism lets per-console policy become a
    Python-only change later. Only the knobs with a config surface are set --
    size caps and the rate ceiling keep the proxy's compiled defaults.
    """
    mode = (config.FIREWALL_MODE or '').strip().lower()
    if mode == 'warn':
        proto_mode = kerbside_pb2.FirewallPolicy.WARN_ONLY
    elif mode in ('', 'enforce'):
        proto_mode = kerbside_pb2.FirewallPolicy.ENFORCE
    else:
        LOG.warning(
            'Unknown FIREWALL_MODE %r, defaulting to enforce' % config.FIREWALL_MODE)
        proto_mode = kerbside_pb2.FirewallPolicy.ENFORCE

    # Empty config -> empty permitted_channels, which the proxy reads as
    # "permit all". A named channel maps to its ChannelType discriminant. An
    # UNKNOWN name is a hard error, not a skip: silently dropping a typo'd name
    # would narrow the permitted set (or, if every name is invalid, leave it
    # empty == permit-all) -- turning a policy meant to RESTRICT channels into
    # a weaker or wide-open one. Fail closed and loud instead so the
    # misconfiguration is caught rather than silently disabling the gate.
    permitted = []
    for name in (config.FIREWALL_PERMITTED_CHANNELS or '').split(','):
        name = name.strip().lower()
        if not name:
            continue
        discriminant = CHANNEL_NAME_TO_DISCRIMINANT.get(name)
        if discriminant is None:
            raise ValueError(
                'FIREWALL_PERMITTED_CHANNELS contains unknown channel name %r; '
                'valid names: %s' % (
                    name, ', '.join(sorted(CHANNEL_NAME_TO_DISCRIMINANT))))
        permitted.append(discriminant)

    return kerbside_pb2.FirewallPolicy(
        mode=proto_mode, permitted_channels=permitted)


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
                    session_id=token['session_id']),
                firewall_policy=build_firewall_policy())

        except Exception as e:
            LOG.error('AuthorizeConnection failed: %s' % e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('AuthorizeConnection failed (see server logs)')
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
            context.set_details('RegisterChannel failed (see server logs)')
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
            context.set_details('RecordAuditEvent failed (see server logs)')
            return kerbside_pb2.StatusReply()

    def DeregisterChannel(self, request, context):
        try:
            db.remove_channel_by_ref(request.connection_ref)
            return kerbside_pb2.StatusReply(success=True)

        except Exception as e:
            LOG.error('DeregisterChannel failed: %s' % e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('DeregisterChannel failed (see server logs)')
            return kerbside_pb2.StatusReply()

    def ClearNodeChannels(self, request, context):
        try:
            db.remove_node_channels(request.node)
            return kerbside_pb2.StatusReply(success=True)

        except Exception as e:
            LOG.error('ClearNodeChannels failed: %s' % e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('ClearNodeChannels failed (see server logs)')
            return kerbside_pb2.StatusReply()

    def ProxyControl(self, request, context):
        """Server-streaming control channel from the daemon to the proxy.

        Each poll it emits a TerminateSession for every session that is BOTH
        marked for termination AND live on this node (scoped to NODE_NAME),
        skipping ids already sent on this stream, and interleaves Heartbeat
        keepalives. Natural token expiry is NOT a termination (matching the
        Python proxy); only an explicit session_terminations row is. The
        stream is local (this daemon and the single proxy it supervises); the
        database is the only bus that reaches proxies on other machines.
        """
        LOG.info('ProxyControl stream opened for node %s' % request.node)
        # session_ids already pushed on THIS stream, so a still-present intent
        # row is not re-sent every poll. The Rust side is idempotent anyway.
        sent = set()
        try:
            # Emit an immediate heartbeat so the client knows the stream is
            # live, then poll+heartbeat until the peer goes away.
            yield kerbside_pb2.ProxyControlEvent(
                heartbeat=kerbside_pb2.Heartbeat())
            last_heartbeat = time.time()

            while context.is_active():
                try:
                    for session_id in db.get_terminations_for_node(config.NODE_NAME):
                        if session_id in sent:
                            continue
                        sent.add(session_id)
                        LOG.info(
                            'ProxyControl terminating session %s on node %s'
                            % (session_id, config.NODE_NAME))
                        yield kerbside_pb2.ProxyControlEvent(
                            terminate_session=kerbside_pb2.TerminateSession(
                                session_id=session_id))
                except Exception as e:
                    # A transient DB error must not kill the stream: log and
                    # keep polling/heartbeating so the proxy stays connected.
                    LOG.error('ProxyControl termination poll failed: %s' % e)

                if time.time() - last_heartbeat >= PROXY_CONTROL_HEARTBEAT_SECONDS:
                    yield kerbside_pb2.ProxyControlEvent(
                        heartbeat=kerbside_pb2.Heartbeat())
                    last_heartbeat = time.time()

                # Sleep the poll interval each iteration so we do not spin.
                time.sleep(PROXY_CONTROL_POLL_SECONDS)
        except Exception as e:
            LOG.error('ProxyControl stream failed: %s' % e)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details('ProxyControl stream failed (see server logs)')
