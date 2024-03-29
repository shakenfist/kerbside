from collections import defaultdict
import datetime
import time

from sqlalchemy import create_engine, text
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy import desc
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import exc, Session

from shakenfist_utilities import logs

from .config import config
from . import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


Base = declarative_base()
ENGINE = create_engine(config.SQL_URL, pool_pre_ping=True, pool_recycle=300)


def reset_engine():
    # Force a new SQL engine because the caller is making a new process.
    ENGINE.dispose()


class ReusedToken(Exception):
    ...


class ReusedChannel(Exception):
    ...


class UnknownChannel(Exception):
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
    flavor = Column(String)

    def __init__(self, name, type, last_seen, seen_by, errored, url, ca_cert,
                 username, password, project_name, user_domain_id,
                 project_domain_id, flavor, deleted):
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
        self.flavor = flavor
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
            'flavor': self.flavor,
            'deleted': self.deleted
        }


def add_source(name, type, url, username, password, project_name=None,
               user_domain_id=None, project_domain_id=None, flavor=None,
               errored=False, ca_cert=None):
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
            source.flavor = flavor
            source.errored = errored
            source.deleted = False
            source.ca_cert = ca_cert
        except exc.NoResultFound:
            source = Source(name, type, datetime.datetime.now(), config.NODE_NAME,
                            errored, url, ca_cert, username, password,
                            project_name, user_domain_id, project_domain_id,
                            flavor, False)
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
                sessions[channel.session_id].append((channel.node, channel.pid))

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
                sessions[channel.session_id].append((channel.node, channel.pid))

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


def expire_token(token):
    with Session(ENGINE) as session:
        try:
            for c in session.query(ConsoleToken).\
                    filter(ConsoleToken.token == token).\
                    all():
                c.expires = time.time()
        except exc.NoResultFound:
            return None
        finally:
            session.commit()


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

    node = Column(String, primary_key=True)
    pid = Column(Integer, primary_key=True)
    created = Column(DateTime)
    client_ip = Column(Integer)
    client_port = Column(Integer)
    connection_id = Column(Integer)
    channel_type = Column(String)
    channel_id = Column(Integer)
    session_id = Column(String)

    def __init__(self, node, pid, created):
        self.node = node
        self.pid = pid
        self.created = created

    def export(self):
        return {
            'node': self.node,
            'pid': self.pid,
            'created': self.created,
            'client_ip': self.client_ip,
            'client_port': self.client_port,
            'connection_id': self.connection_id,
            'channel_type': self.channel_type,
            'channel_id': self.channel_id,
            'session_id': self.session_id
        }


def record_channel_info(node, pid, client_ip=None, client_port=None,
                        connection_id=None, channel_type=None, channel_id=None,
                        session_id=None):
    with Session(ENGINE) as session:
        try:
            channel = session.query(ProxyChannel).\
                filter(ProxyChannel.node == node).\
                filter(ProxyChannel.pid == pid).\
                one()

        except exc.NoResultFound:
            channel = ProxyChannel(node, pid, datetime.datetime.now())
            session.add(channel)

        for arg in ['client_ip', 'client_port', 'connection_id',
                    'channel_type', 'channel_id', 'session_id']:
            if locals()[arg]:
                setattr(channel, arg, locals()[arg])
        session.commit()


def remove_proxy_channel(node, pid):
    with Session(ENGINE) as session:
        try:
            for c in list(session.query(ProxyChannel).
                          filter(ProxyChannel.node == node).
                          filter(ProxyChannel.pid == pid).
                          all()):
                session.delete(c)
            session.commit()
        except exc.NoResultFound:
            return None


def get_node_channels(node):
    out = []
    with Session(ENGINE) as session:
        try:
            for c in session.query(ProxyChannel).\
                filter(ProxyChannel.node == node).\
                    all():
                out.append(c.export())
        except exc.NoResultFound:
            ...
    return out


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


class AuditEvent(Base):
    __tablename__ = 'auditevents'

    source = Column(String, primary_key=True)
    uuid = Column(String, primary_key=True)
    session_id = Column(String)
    channel = Column(String)
    node = Column(String)
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
