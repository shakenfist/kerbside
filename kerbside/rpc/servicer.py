import time

import grpc
from sqlalchemy import exc as sqlalchemy_exc

from shakenfist_utilities import logs

from kerbside.config import config
from kerbside import db
from kerbside import sources
from kerbside import util
from kerbside.rpc import kerbside_pb2, kerbside_pb2_grpc
from kerbside.sources import base as source_base
from kerbside.sources import minting


LOG, _ = logs.setup(__name__, **util.configure_logging())

# Interval between keepalive heartbeats on the ProxyControl stream.
PROXY_CONTROL_HEARTBEAT_SECONDS = 30

# How often the ProxyControl stream polls the database for terminations that
# apply to this node. Short so API-driven termination reaches the proxy
# promptly; the trade-off is termination latency vs DB load.
PROXY_CONTROL_POLL_SECONDS = 2

# How many seconds a minted backend ticket is asked to outlive the client's
# token. No channel is authorized once the token has expired, so the ticket
# is never handed out after that; but a channel authorized in the token's
# last moment still has to complete its SPICE link to the hypervisor with
# the ticket, and this covers that.
TICKET_SLACK = 30

# A stored backend ticket is handed to another channel only while at least
# this many seconds of it remain. A channel given a ticket on the point of
# expiring could reach the hypervisor after it has, so such a ticket is
# replaced instead. Replacing it revokes the old ticket for new connections
# only; channels already linked with it stay up.
REUSE_MARGIN = 10

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


def _error_summary(e):
    """Name an exception without quoting its text.

    For a database error the driver's numeric error code is added, such as
    1205 for MariaDB's lock wait timeout, so that an operator can tell the
    expected database failures apart without the message, which can quote
    the statement.
    """
    summary = type(e).__name__
    if isinstance(e, sqlalchemy_exc.DBAPIError):
        args = getattr(e.orig, 'args', ())
        if args and isinstance(args[0], int):
            summary += ' (database error %d)' % args[0]
    return summary


def _mint_backend_ticket(driver, source_name, uuid, lifetime):
    """Mint a backend ticket for a console with its source's driver.

    The source's credentials are fetched here, so that only a channel which
    actually mints holds them, and the driver gets at most
    minting.MINT_DEADLINE seconds to build itself and mint. A minted tunnel
    missing its proxy, connect host or port raises ConsoleTicketUnavailable.
    """
    authed = db.get_source(source_name, include_secrets=True)
    if not authed:
        raise source_base.ConsoleTicketUnavailable(
            'source %s no longer exists' % source_name)
    minted = minting.mint_with_deadline(
        driver, authed, uuid, lifetime, minting.MINT_DEADLINE)
    # Refused here, before it is stored: the proxy could not dial it, and
    # would only find out on every channel of the session.
    if minted.tunnel is not None and not source_base.tunnel_complete(minted.tunnel):
        raise source_base.ConsoleTicketUnavailable(
            'source %s minted an incomplete tunnel' % source_name)
    return minted


class KerbsideProxyServicer(kerbside_pb2_grpc.KerbsideProxyServicer):
    """gRPC servicer implementing the unary control-plane RPCs.

    Each RPC maps to one or more db.py operations, preserving today's
    semantics (token expiry filter, audit events, channel bookkeeping).
    ProxyControl is intentionally not implemented here; it is added in a
    later phase and remains inherited (UNIMPLEMENTED).
    """

    def AuthorizeConnection(self, request, context):
        """Authorize a channel, and tell the proxy where it goes.

        The Target carries the ticket the proxy presents to the hypervisor's
        SPICE server. For a source which mints tickets, that is the session's
        backend ticket, minted for its first channel and reused by the rest
        (see db.session_ticket()); a channel is denied if no ticket can be
        minted. Any other source's ticket is the one on the console row.

        A minted ticket can come with a tunnel, for a console which is only
        reachable through an HTTP CONNECT proxy. The Target then carries the
        tunnel, and the TLS port the tunnel was minted for, and no plaintext
        port.
        """
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

            # The proxy presents this console's ticket to the SPICE
            # server on the hypervisor, so the data plane is entitled
            # to the secret and asks for it explicitly.
            console = db.get_console(
                token['source'], token['uuid'], include_secrets=True)
            if not console:
                LOG.warning('Requested console is invalid, denying connection')
                db.add_audit_event(
                    token['source'], token['uuid'], token['session_id'],
                    request.channel_type, config.NODE_NAME,
                    request.connection_ref, 'Invalid console requested')
                return kerbside_pb2.AuthorizeConnectionReply(
                    denied=kerbside_pb2.Denied(reason='invalid console'))

            try:
                driver = sources.driver_class(source['type'])
            except KeyError:
                # openstack has no driver, and mints nothing.
                driver = None

            ticket = console['ticket'] or ''
            insecure_port = console['insecure_port'] or 0
            secure_port = console['secure_port'] or 0
            tunnel = None
            if driver and driver.MINTS_TICKETS:
                # The ticket has to last for as long as the client's token
                # can still authorize a channel, plus TICKET_SLACK.
                lifetime = (max(token['expires'] - int(time.time()), 0) +
                            TICKET_SLACK)

                # db.session_ticket() calls mint only if the session has no
                # ticket worth reusing, so mint records what it did: whether
                # a ticket was minted, and for how long, or why not.
                minted_for = None
                mint_error = None

                def mint(lifetime):
                    nonlocal minted_for, mint_error
                    started = int(time.time())
                    try:
                        minted = _mint_backend_ticket(
                            driver, token['source'], console['uuid'],
                            lifetime)
                    except Exception as e:
                        mint_error = e
                        raise
                    minted_for = int(minted.expires) - started
                    return minted

                try:
                    backend = db.session_ticket(
                        token['session_id'], mint, lifetime, REUSE_MARGIN)
                except db.UnknownSession:
                    # The session was terminated or reaped after its token
                    # was looked up above.
                    LOG.warning('Client token is invalid, denying connection')
                    return kerbside_pb2.AuthorizeConnectionReply(
                        denied=kerbside_pb2.Denied(
                            reason='client token invalid'))
                except Exception:
                    if mint_error is None:
                        raise

                    # The class name only, here and in the audit trail: an
                    # API client's exception can quote the request it failed
                    # on. Nothing was stored, so the next channel tries again.
                    error = type(mint_error).__name__
                    LOG.with_fields({
                        'source': console['source'],
                        'uuid': console['uuid'],
                        'session_id': token['session_id'],
                        'error': error
                        }).warning('Backend console ticket mint failed, '
                                   'denying connection')
                    db.add_audit_event(
                        console['source'], console['uuid'],
                        token['session_id'], request.channel_type,
                        config.NODE_NAME, request.connection_ref,
                        'Backend console ticket mint failed: %s' % error)
                    return kerbside_pb2.AuthorizeConnectionReply(
                        denied=kerbside_pb2.Denied(
                            reason='console ticket unavailable'))

                if minted_for is not None:
                    db.add_audit_event(
                        console['source'], console['uuid'],
                        token['session_id'], request.channel_type,
                        config.NODE_NAME, request.connection_ref,
                        'Minted backend console ticket for %d seconds'
                        % minted_for)
                ticket = backend.ticket

                # The tunnel's connect host is a credential like the ticket:
                # it goes to the proxy in the Target, and nowhere else.
                if backend.tunnel:
                    tunnel = kerbside_pb2.Tunnel(
                        proxy_uri=backend.tunnel.proxy_uri,
                        connect_host=backend.tunnel.connect_host)
                    secure_port = backend.tunnel.port
                    insecure_port = 0

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
                    insecure_port=insecure_port,
                    secure_port=secure_port,
                    ticket=ticket,
                    ca_cert=source['ca_cert'] or '',
                    host_subject=console['host_subject'] or '',
                    source=console['source'],
                    uuid=console['uuid'],
                    session_id=token['session_id'],
                    tunnel=tunnel),
                firewall_policy=build_firewall_policy())

        except Exception as e:
            # The class name only: a source driver's API client, or
            # requests, can quote the request it failed on, and that
            # request can carry a credential.
            LOG.error('AuthorizeConnection failed: %s' % _error_summary(e))
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
                    current = set(db.get_terminations_for_node(config.NODE_NAME))
                    for session_id in current:
                        if session_id in sent:
                            continue
                        sent.add(session_id)
                        LOG.info(
                            'ProxyControl terminating session %s on node %s'
                            % (session_id, config.NODE_NAME))
                        yield kerbside_pb2.ProxyControlEvent(
                            terminate_session=kerbside_pb2.TerminateSession(
                                session_id=session_id))
                    # Bound `sent` to what is still an active intent so it does
                    # not grow for the life of a long-lived stream: once a row
                    # is reaped it drops out here. Re-sending an id that later
                    # reappears is a harmless idempotent no-op on the proxy.
                    sent &= current
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
