from collections import defaultdict
import datetime
import time

from sqlalchemy import create_engine, text
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from sqlalchemy import desc
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import exc, Session

from shakenfist_utilities import logs

from .config import config
from . import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


Base = declarative_base()
# hide_parameters=True keeps bound query parameters out of SQLAlchemy
# exception strings. Without it, a DB error while looking up a token would
# stringify the (decrypted) token plaintext into the exception — and thence
# into logs or a gRPC error detail. See kerbside/rpc/servicer.py.
ENGINE = create_engine(config.SQL_URL, pool_pre_ping=True, pool_recycle=300,
                       hide_parameters=True)


def reset_engine():
    # Force a new SQL engine because the caller is making a new process.
    ENGINE.dispose()


class ReusedToken(Exception):
    ...


class ReusedChannel(Exception):
    ...


class UnknownChannel(Exception):
    ...


class ReusedJti(Exception):
    ...


class Source(Base):
    __tablename__ = 'sources'

    name = Column(String, primary_key=True)
    type = Column(String)
    last_seen = Column(DateTime)
    seen_by = Column(String)
    errored = Column(Boolean)
    ca_cert = Column(Text)
    url = Column(String)
    username = Column(String)
    password = Column(String)
    deleted = Column(Boolean)

    # OpenStack source specific values
    project_name = Column(String)
    user_domain_id = Column(String)
    project_domain_id = Column(String)

    def __init__(self, name, type, last_seen, seen_by, errored, url, ca_cert,
                 username, password, project_name, user_domain_id,
                 project_domain_id, deleted):
        self.name = name
        self.type = type
        self.last_seen = last_seen
        self.seen_by = seen_by
        self.errored = errored
        self.url = url
        self.ca_cert = ca_cert
        self.username = username
        self.password = password
        self.project_name = project_name
        self.user_domain_id = user_domain_id
        self.project_domain_id = project_domain_id
        self.deleted = deleted

    def export(self):
        return {
            'name': self.name,
            'type': self.type,
            'last_seen': self.last_seen,
            'seen_by': self.seen_by,
            'errored': self.errored,
            'url': self.url,
            'ca_cert': self.ca_cert,
            'username': self.username,
            'password': self.password,
            'project_name': self.project_name,
            'user_domain_id': self.user_domain_id,
            'project_domain_id': self.project_domain_id,
            'deleted': self.deleted
        }


def add_source(name, type, url, username, password, project_name=None,
               user_domain_id=None, project_domain_id=None, errored=False,
               ca_cert=None):
    with Session(ENGINE) as session:
        try:
            source = session.query(Source).\
                filter(Source.name == name).\
                filter(Source.type == type).\
                one()
            source.last_seen = datetime.datetime.now()
            source.seen_by = config.NODE_NAME
            source.url = url
            source.username = username
            source.password = password
            source.project_name = project_name
            source.user_domain_id = user_domain_id
            source.project_domain_id = project_domain_id
            source.errored = errored
            source.deleted = False
            source.ca_cert = ca_cert
        except exc.NoResultFound:
            source = Source(name, type, datetime.datetime.now(), config.NODE_NAME,
                            errored, url, ca_cert, username, password,
                            project_name, user_domain_id, project_domain_id, False)
            session.add(source)
        finally:
            session.commit()


def get_sources():
    out = []
    with Session(ENGINE) as session:
        try:
            for source in session.query(Source).\
                    filter(Source.deleted == False).\
                    order_by(Source.name).\
                    all():                                          # noqa: E712
                out.append(source.export())
        except exc.NoResultFound:
            ...
    return out


def get_source(name):
    with Session(ENGINE) as session:
        try:
            source = session.query(Source).filter(Source.name == name).one()
            return source.export()
        except exc.NoResultFound:
            return None


def set_source_error_state(name, state):
    with Session(ENGINE) as session:
        source = session.query(Source).filter(Source.name == name).one()
        source.errored = state
        session.commit()


def delete_source(name):
    with Session(ENGINE) as session:
        source = session.query(Source).filter(Source.name == name).one()
        source.deleted = True
        session.commit()


class Console(Base):
    __tablename__ = 'consoles'

    uuid = Column(String, primary_key=True)
    source = Column(String)
    discovered = Column(DateTime)
    hypervisor = Column(String)
    hypervisor_ip = Column(String)
    insecure_port = Column(Integer)
    secure_port = Column(Integer)
    name = Column(String)
    host_subject = Column(String)
    ticket = Column(String)

    def __init__(self, uuid, source, hypervisor, hypervisor_ip, insecure_port,
                 secure_port, name, host_subject, ticket):
        self.uuid = uuid
        self.source = source
        self.hypervisor = hypervisor
        self.hypervisor_ip = hypervisor_ip
        self.insecure_port = insecure_port
        self.secure_port = secure_port
        self.name = name
        self.host_subject = host_subject
        self.ticket = ticket
        self.discovered = datetime.datetime.now()

    def export(self):
        return {
            'uuid': self.uuid,
            'source': self.source,
            'hypervisor': self.hypervisor,
            'hypervisor_ip': self.hypervisor_ip,
            'insecure_port': self.insecure_port,
            'secure_port': self.secure_port,
            'name': self.name,
            'host_subject': self.host_subject,
            'ticket': self.ticket,
            'discovered': self.discovered
        }


def add_console(source=None, uuid=None, hypervisor=None, hypervisor_ip=None,
                insecure_port=None, secure_port=None, name=None, host_subject=None,
                ticket=None, **kwargs):
    with Session(ENGINE) as session:
        try:
            console = session.query(Console).filter(Console.uuid == uuid).one()
            console.hypervisor = hypervisor
            console.hypervisor_ip = hypervisor_ip
            console.insecure_port = insecure_port
            console.secure_port = secure_port
            console.name = name
            console.host_subject = host_subject
        except exc.NoResultFound:
            console = Console(uuid, source, hypervisor, hypervisor_ip, insecure_port,
                              secure_port, name, host_subject, ticket)
            session.add(console)
            return True
        finally:
            session.commit()

    return False


def get_consoles(include_audit=True):
    sessions = defaultdict(list)
    out = []
    now = time.time()

    with Session(ENGINE) as session:
        try:
            for channel in session.query(ProxyChannel).all():
                sessions[channel.session_id].append(
                    (channel.node, channel.connection_ref or channel.pid))

            for console in session.query(Console).order_by(Console.name).all():
                c = console.export()
                c['sessions'] = []
                c['token_count'] = 0

                for token in session.query(ConsoleToken).\
                        filter(ConsoleToken.source == c['source']).\
                        filter(ConsoleToken.uuid == c['uuid']).\
                        all():
                    if token.expires > now:
                        c['token_count'] += 1
                    if token.session_id in sessions:
                        c['sessions'].append(token.session_id)

                c['audit'] = []
                if include_audit:
                    events_by_timestamp = {}
                    with Session(ENGINE) as subsession:
                        for audit in subsession.query(AuditEvent).\
                                filter(AuditEvent.source == c['source']).\
                                filter(AuditEvent.uuid == c['uuid']).\
                                order_by(desc(AuditEvent.timestamp)).\
                                limit(20).\
                                all():
                            events_by_timestamp[audit.timestamp] = audit.export()
                    for timestamp in sorted(events_by_timestamp):
                        c['audit'].append(events_by_timestamp[timestamp])

                out.append(c)

        except exc.NoResultFound:
            ...

    return out


def get_console(source, uuid, detailed=False):
    now = time.time()

    with Session(ENGINE) as session:
        try:
            console = session.query(Console).filter(Console.uuid == uuid).one()
            c = console.export()
            if not detailed:
                return c

            # TODO(mikal): this is a bit terrible. This is all sessions for all
            # consoles.
            sessions = defaultdict(list)
            for channel in session.query(ProxyChannel).all():
                sessions[channel.session_id].append(
                    (channel.node, channel.connection_ref or channel.pid))

            c['sessions'] = []
            c['token_count'] = 0
            for token in session.query(ConsoleToken).\
                    filter(ConsoleToken.source == c['source']).\
                    filter(ConsoleToken.uuid == c['uuid']).\
                    all():
                if token.expires > now:
                    c['token_count'] += 1
                if token.session_id in sessions:
                    c['sessions'].append(token.session_id)

            return c

        except exc.NoResultFound:
            return None


def store_console_ticket(source, uuid, ticket):
    with Session(ENGINE) as session:
        c = session.query(Console).filter(Console.uuid == uuid).one()
        c.ticket = ticket
        session.commit()


def remove_console(source=None, uuid=None, **kwargs):
    with Session(ENGINE) as session:
        try:
            for c in session.query(Console).filter(Console.uuid == uuid).all():
                session.delete(c)
        except exc.NoResultFound:
            return None
        finally:
            session.commit()


class ConsoleToken(Base):
    __tablename__ = 'consoletokens'

    token = Column(String, primary_key=True)
    session_id = Column(String)
    uuid = Column(String)
    source = Column(String)
    created = Column(Integer)
    expires = Column(Integer)

    def __init__(self, token, session_id, source, uuid, created, expires):
        self.token = token
        self.session_id = session_id
        self.source = source
        self.uuid = uuid
        self.created = created
        self.expires = expires

    def export(self):
        return {
            'token': self.token,
            'session_id': self.session_id,
            'uuid': self.uuid,
            'source': self.source,
            'created': self.created,
            'expires': self.expires
        }


def add_token(token, session_id, source, uuid, created, expires):
    with Session(ENGINE) as session:
        try:
            session.query(ConsoleToken).filter(ConsoleToken.token == token).one()
            raise ReusedToken('We already have token %s' % token)
        except exc.NoResultFound:
            token = ConsoleToken(token, session_id, source, uuid, created,
                                 expires)
            session.add(token)
            session.commit()
            return token.export()


def get_tokens_by_console(source, uuid):
    out = []
    with Session(ENGINE) as session:
        try:
            for c in session.query(ConsoleToken).\
                    filter(ConsoleToken.source == source).\
                    filter(ConsoleToken.uuid == uuid).\
                    all():
                out.append(c.export())
        except exc.NoResultFound:
            ...
    return out


def get_token_by_token(token):
    with Session(ENGINE) as session:
        try:
            c = session.query(ConsoleToken).\
                filter(ConsoleToken.token == token).\
                filter(ConsoleToken.expires > int(time.time())).\
                one()
            return c.export()
        except exc.NoResultFound:
            return None


def get_token_by_session_id(session_id):
    with Session(ENGINE) as session:
        try:
            c = session.query(ConsoleToken).\
                filter(ConsoleToken.session_id == session_id).\
                one()
            return c.export()
        except exc.NoResultFound:
            return None


def remove_session(session_id):
    with Session(ENGINE) as session:
        try:
            c = session.query(ConsoleToken).\
                filter(ConsoleToken.session_id == session_id).\
                one()
            session.delete(c)
            session.commit()
        except exc.NoResultFound:
            return None


def reap_expired_tokens():
    # This is a little subtle. We only reap tokens when they have both expired,
    # and have no open sessions. Otherwise we lose the mapping between a session
    # id and the console it is for.
    with Session(ENGINE) as session:
        candidates = []
        reaped = []

        try:
            for c in session.query(ConsoleToken).\
                    filter(ConsoleToken.expires < int(time.time())).\
                    all():
                candidates.append(c)

            for c in candidates:
                count = session.query(ProxyChannel).\
                    filter(ProxyChannel.session_id == c.session_id).\
                    count()
                if count == 0:
                    reaped.append(c.export())
                    session.delete(c)
        except exc.NoResultFound:
            ...
        finally:
            session.commit()

        return reaped


class ProxyChannel(Base):
    __tablename__ = 'proxychannels'

    id = Column(Integer, primary_key=True, autoincrement=True)
    node = Column(String)
    pid = Column(Integer, nullable=True)
    created = Column(DateTime)
    client_ip = Column(String)
    client_port = Column(Integer)
    connection_id = Column(Integer)
    channel_type = Column(String)
    channel_id = Column(Integer)
    session_id = Column(String)
    # connection_ref is the per-connection key used by the gRPC path (the
    # Rust proxy has no per-worker pid). Unique so the by-ref upsert lookup
    # is a single indexed row rather than a table scan; nullable, and MySQL
    # permits multiple NULLs in a unique index, so pid-keyed Python-proxy
    # rows (connection_ref NULL) coexist.
    connection_ref = Column(String, nullable=True, unique=True, index=True)

    def __init__(self, node, pid, created):
        self.node = node
        self.pid = pid
        self.created = created

    def export(self):
        return {
            'id': self.id,
            'node': self.node,
            'pid': self.pid,
            'created': self.created,
            'client_ip': self.client_ip,
            'client_port': self.client_port,
            'connection_id': self.connection_id,
            'channel_type': self.channel_type,
            'channel_id': self.channel_id,
            'session_id': self.session_id,
            'connection_ref': self.connection_ref
        }


def record_channel_info_by_ref(node, connection_ref, client_ip=None, client_port=None,
                               connection_id=None, channel_type=None, channel_id=None,
                               session_id=None):
    with Session(ENGINE) as session:
        try:
            channel = session.query(ProxyChannel).\
                filter(ProxyChannel.connection_ref == connection_ref).\
                one()

        except exc.NoResultFound:
            channel = ProxyChannel(node, None, datetime.datetime.now())
            channel.connection_ref = connection_ref
            session.add(channel)

        for arg in ['client_ip', 'client_port', 'connection_id',
                    'channel_type', 'channel_id', 'session_id']:
            if locals()[arg]:
                setattr(channel, arg, locals()[arg])
        session.commit()


def remove_channel_by_ref(connection_ref):
    with Session(ENGINE) as session:
        try:
            for c in list(session.query(ProxyChannel).
                          filter(ProxyChannel.connection_ref == connection_ref).
                          all()):
                session.delete(c)
            session.commit()
        except exc.NoResultFound:
            return None


def remove_node_channels(node):
    with Session(ENGINE) as session:
        try:
            for c in session.query(ProxyChannel).\
                    filter(ProxyChannel.node == node).\
                    all():
                session.delete(c)
        except exc.NoResultFound:
            return None
        finally:
            session.commit()


def get_sessions():
    out = {}

    with Session(ENGINE) as session:
        session_consoles = {}
        for ct in session.query(ConsoleToken).all():
            session_consoles[ct.session_id] = {
                    'source': ct.source,
                    'uuid': ct.uuid
                }

        for session_id in session_consoles:
            c = session.query(Console).\
                filter(Console.source == session_consoles[session_id]['source']).\
                filter(Console.uuid == session_consoles[session_id]['uuid']).\
                one()
            session_consoles[session_id]['name'] = c.name

        try:
            for channel in session.query(ProxyChannel).all():
                session_id = channel.session_id
                if session_id not in out:
                    out[session_id] = session_consoles.get(session_id, {})
                    out[session_id]['channels'] = []

                if not session_id:
                    session_id = 'Unknown'
                if session_id in out:
                    out[session_id]['channels'].append(channel.export())
        except exc.NoResultFound:
            ...

    return out


class SessionTermination(Base):
    __tablename__ = 'session_terminations'

    # A session is terminated at most once; re-requesting is idempotent, so the
    # session_id is the primary key. requested_at is a time.time() float and
    # reason is a human-readable note for audit/debugging.
    session_id = Column(String, primary_key=True)
    requested_at = Column(Float)
    reason = Column(String, nullable=True)

    def __init__(self, session_id, requested_at, reason=None):
        self.session_id = session_id
        self.requested_at = requested_at
        self.reason = reason

    def export(self):
        return {
            'session_id': self.session_id,
            'requested_at': self.requested_at,
            'reason': self.reason
        }


def request_session_termination(session_id, reason=None):
    # Record the intent to terminate a session. The API (possibly on a
    # different machine from any proxy) writes this row; each proxy node's
    # daemon polls it for the sessions it holds live channels for and pushes a
    # TerminateSession event to its local proxy. Idempotent: a session is
    # terminated at most once, so re-requesting refreshes the existing row
    # rather than erroring.
    with Session(ENGINE) as session:
        try:
            existing = session.query(SessionTermination).\
                filter(SessionTermination.session_id == session_id).\
                one()
            existing.requested_at = time.time()
            if reason is not None:
                existing.reason = reason
            session.commit()
            return
        except exc.NoResultFound:
            ...

        termination = SessionTermination(session_id, time.time(), reason)
        session.add(termination)
        try:
            session.commit()
        except IntegrityError:
            # Race: another API call inserted the same session_id between our
            # lookup and insert. The row now exists, which is exactly what we
            # wanted, so roll back and treat it as already recorded.
            session.rollback()


def terminate_session(session_id, source, uuid, reason=None):
    # Terminate a proxy session. Deleting the token blocks NEW connections;
    # recording a termination intent is what drops the IN-FLIGHT ones (each
    # proxy node polls session_terminations for the sessions it holds live
    # channels for and pushes a TerminateSession event to its local proxy).
    # Then audit it. Shared by the ConsolesTerminate and SessionTerminate API
    # endpoints so the sequence stays identical.
    remove_session(session_id)
    request_session_termination(session_id, reason=reason)
    add_audit_event(
        source, uuid, session_id, None, None, None,
        'Session terminated by request')


def get_terminations_for_node(node):
    # Return the session_ids that are BOTH marked for termination AND live on
    # this node (i.e. the sessions this node must drop). Scoped to node: a
    # session terminated but only live on another node is that node's job.
    # Implemented as a two-query intersection -- gather this node's live
    # session_ids, then filter session_terminations to that set.
    out = []
    with Session(ENGINE) as session:
        try:
            live = {
                c.session_id for c in session.query(ProxyChannel).
                filter(ProxyChannel.node == node).
                filter(ProxyChannel.session_id.isnot(None)).
                all()}
            if not live:
                return out

            for t in session.query(SessionTermination).\
                    filter(SessionTermination.session_id.in_(live)).\
                    all():
                out.append(t.session_id)
        except exc.NoResultFound:
            ...
    return out


def reap_session_terminations(max_age_seconds):
    # Delete termination-intent rows older than max_age_seconds. By then every
    # node has had time to poll and push; the Rust side is idempotent so a
    # late or duplicate event is a no-op. Returns the number of rows deleted.
    cutoff = time.time() - max_age_seconds
    with Session(ENGINE) as session:
        count = session.query(SessionTermination).\
            filter(SessionTermination.requested_at < cutoff).\
            delete(synchronize_session=False)
        session.commit()
        return count


class AuditEvent(Base):
    __tablename__ = 'auditevents'

    source = Column(String, primary_key=True)
    uuid = Column(String, primary_key=True)
    session_id = Column(String)
    channel = Column(String)
    node = Column(String)
    # pid holds an OS process id when written by the Python proxy path, or a
    # proxy-generated connection_ref when written by the gRPC path. It is a
    # String to accommodate both; treat it as an opaque per-connection tag.
    pid = Column(String)
    timestamp = Column(DATETIME(fsp=6), primary_key=True, server_default=text('CURRENT_TIMESTAMP(6)'))
    message = Column(Text)

    def __init__(self, source, uuid, session_id, channel, node, pid, message):
        self.source = source
        self.uuid = uuid
        self.session_id = session_id
        self.channel = channel
        self.node = node
        self.pid = pid
        self.message = message

    def export(self):
        return {
            'source': self.source,
            'uuid': self.uuid,
            'session_id': self.session_id,
            'channel': self.channel,
            'node': self.node,
            'pid': self.pid,
            'timestamp': self.timestamp,
            'message': self.message
        }


def add_audit_event(source, uuid, session_id, channel, node, pid, message):
    with Session(ENGINE) as session:
        event = AuditEvent(source, uuid, session_id, channel, node, pid, message)
        session.add(event)
        session.commit()
    LOG.info('Audit: %s' % message)


def count_audit_events(source, uuid):
    with Session(ENGINE) as session:
        try:
            c = session.query(AuditEvent).\
                filter(AuditEvent.source == source).\
                filter(AuditEvent.uuid == uuid).\
                count()
            return c
        except exc.NoResultFound:
            ...
    return 0


def get_audit_events(source, uuid, limit=20):
    out = []
    with Session(ENGINE) as session:
        try:
            for e in session.query(AuditEvent).\
                    filter(AuditEvent.source == source).\
                    filter(AuditEvent.uuid == uuid).\
                    order_by(desc(AuditEvent.timestamp)).\
                    limit(limit).\
                    all():
                out.append(e.export())
        except exc.NoResultFound:
            ...

    out.reverse()
    return out


class SfTokenJti(Base):
    __tablename__ = 'sf_token_jtis'

    # Records a Shaken Fist VDI console JWT's jti (a uuid4 hex) once its
    # signature has verified, so the /sf-console.vv exchange can reject a
    # replayed token. expiry mirrors the token's own exp claim (a
    # time.time()-style float): once that has passed the token could not be
    # replayed successfully anyway, so the reaper is free to drop the row.
    jti = Column(String(32), primary_key=True)
    expiry = Column(Float)

    def __init__(self, jti, expiry):
        self.jti = jti
        self.expiry = expiry

    def export(self):
        return {
            'jti': self.jti,
            'expiry': self.expiry
        }


def add_sf_token_jti(jti, expiry):
    with Session(ENGINE) as session:
        try:
            session.query(SfTokenJti).filter(SfTokenJti.jti == jti).one()
            raise ReusedJti('We already have jti %s' % jti)
        except exc.NoResultFound:
            row = SfTokenJti(jti, expiry)
            session.add(row)
            session.commit()
            return row.export()


def sf_token_jti_exists(jti):
    with Session(ENGINE) as session:
        try:
            session.query(SfTokenJti).filter(SfTokenJti.jti == jti).one()
            return True
        except exc.NoResultFound:
            return False


def reap_expired_sf_token_jtis():
    # Unlike consoletokens, a jti has no session or live-channel concept to
    # protect -- it is purely time-bounded (PyJWT already refused the token
    # once its exp passed), so this is a straight TTL delete, no liveness
    # check needed.
    with Session(ENGINE) as session:
        reaped = []

        try:
            for j in session.query(SfTokenJti).\
                    filter(SfTokenJti.expiry < int(time.time())).\
                    all():
                reaped.append(j.export())
                session.delete(j)
        except exc.NoResultFound:
            ...
        finally:
            session.commit()

        return reaped


class SfTokenKeys(Base):
    __tablename__ = 'sf_token_keys'

    # Caches one shakenfist source's signing public keys (Shaken Fist's
    # public_view payload, verbatim JSON) so offline JWT verification never
    # calls Shaken Fist on the hot path -- only a cache miss on an unknown
    # kid triggers a refetch. source matches sources.name (no FK: sources
    # are ephemeral YAML-loaded objects reloaded by the maintenance loop,
    # not a stable referenced row). fetched_at is a time.time() float.
    source = Column(String(255), primary_key=True)
    keys_json = Column(Text)
    fetched_at = Column(Float)

    def __init__(self, source, keys_json, fetched_at):
        self.source = source
        self.keys_json = keys_json
        self.fetched_at = fetched_at

    def export(self):
        return {
            'source': self.source,
            'keys_json': self.keys_json,
            'fetched_at': self.fetched_at
        }


def upsert_sf_token_keys(source, keys_json, fetched_at):
    with Session(ENGINE) as session:
        try:
            row = session.query(SfTokenKeys).\
                filter(SfTokenKeys.source == source).\
                one()
            row.keys_json = keys_json
            row.fetched_at = fetched_at
        except exc.NoResultFound:
            row = SfTokenKeys(source, keys_json, fetched_at)
            session.add(row)
        session.commit()
        return row.export()


def get_sf_token_keys(source):
    with Session(ENGINE) as session:
        try:
            row = session.query(SfTokenKeys).\
                filter(SfTokenKeys.source == source).\
                one()
            return row.keys_json
        except exc.NoResultFound:
            return None
