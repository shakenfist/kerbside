#################################################################################
# DEAR FUTURE ME... The order of decorators on these API methods deeply deeply  #
# matters. We need to verify auth before anything, and we need to fetch things  #
# from the database before we make decisions based on those things. So remember #
# the outer decorator is executed first!                                        #
#################################################################################

import datetime
import flask
from flask_jwt_extended import (
    JWTManager, verify_jwt_in_request,
    create_access_token, set_access_cookies, unset_jwt_cookies)
from flask_jwt_extended.exceptions import NoAuthorizationError
from flask_request_id import RequestID
import flask_restful
import importlib
import json
import os
import requests
from webargs import fields
from webargs.flaskparser import use_kwargs
import yaml

from shakenfist_utilities import api as sf_api, logs

from .config import config
from . import consoletoken
from . import db
from .sources import ovirt as ovirt_source
from . import util


# Setup logging
logging_config = util.configure_logging()
sf_api.configure_logging(**logging_config)
LOG, HANDLER = logs.setup(__name__, **logging_config)


print(f'PID {os.getpid()} API library logging: {sf_api.LOG}')


app = flask.Flask(__name__,
                  static_url_path='/static',
                  static_folder='%s/api/static' % os.path.dirname(__file__),
                  template_folder='%s/api/templates' % os.path.dirname(__file__))
RequestID(app)
api = flask_restful.Api(app, catch_all_404s=False)

# Use our handler to get SF log format (instead of gunicorn's handlers)
app.logger.handlers = [HANDLER]

# Configure JWT authentication
app.config['JWT_SECRET_KEY'] = config.AUTH_SECRET_SEED
jwt = JWTManager(app)


OPENSTACK_CLIENT = None

# NOTE(mikal): KEYSTONE_V3 is used as a marker for if _any_ of these globals
# are already initialized.
KEYSTONE_V3 = None
KEYSTONE_CLIENT = None
KEYSTONE_EXCEPTIONS = None
KEYSTONE_SESSION = None


# A decorator to protect endpoints which require authentication
def verify_token(func):
    def wrapper(*args, **kwargs):
        # Ensure there is a valid JWT with a correct signature
        try:
            _, jwt_data = verify_jwt_in_request(
                False, False, False, ['headers', 'cookies'], True)
        except NoAuthorizationError as e:
            raise e

        return func(*args, **kwargs)
    return wrapper


class DateTimeEncoder(json.JSONEncoder):
    def default(self, value):
        if isinstance(value, datetime.datetime):
            return value.timestamp()
        else:
            return super().default(value)


def get_nav_items(current):
    base_navitems = [
        {
            'name': 'Sources',
            'href': '/source',
            'active': False
        },
        {
            'name': 'Consoles',
            'href': '/console',
            'active': False
        },
        {
            'name': 'Sessions',
            'href': '/session',
            'active': False
        }
    ]

    navitems = []
    for item in base_navitems:
        if item['name'] == current:
            item['active'] = True
        navitems.append(item)
    return navitems


class Root(sf_api.Resource):
    def get(self):
        # For API clients, we are just a static page here
        if flask.request.headers.get('Accept', 'text/html').find('text/html') == -1:
            resp = flask.Response(
                json.dumps({
                    'capabilities': [],
                    'result': 'ok'
                }, indent=4, sort_keys=True), mimetype='application/json')
            resp.status_code = 200
            return resp

        # Otherwise, we're either a login attempt, or should be redirected to
        # the web app.
        resp = None
        try:
            _, jwt_data = verify_jwt_in_request(
                False, False, False, ['headers', 'cookies'], True)
        except NoAuthorizationError:
            # Login request
            resp = flask.Response(
                flask.render_template(
                    'login.html',
                    navitems=get_nav_items(None),
                    refresh=False, when=datetime.datetime.now()),
                mimetype='text/html')
            resp.status_code = 200

        if not resp:
            return flask.redirect('/source', code=302)

        return resp


class Auth(sf_api.Resource):
    def post(self, username=None, password=None, as_cookie=False):
        # Validate arguments
        if not username or not password:
            return sf_api.error(400, 'bad request')

        # TODO(mikal): Handle non-keystone auth as well

        # We need to talk to Keystone as our service account. This is written
        # like this because I want to make the presence of OpenStack optional
        # in the future, but its not a priority right now.

        global KEYSTONE_V3
        global KEYSTONE_CLIENT
        global KEYSTONE_EXCEPTIONS
        global KEYSTONE_SESSION

        if not KEYSTONE_V3:
            try:
                KEYSTONE_V3 = importlib.import_module(
                    'keystoneauth1.identity.v3')
                KEYSTONE_CLIENT = importlib.import_module(
                    'keystoneclient.v3.client')
                KEYSTONE_EXCEPTIONS = importlib.import_module(
                    'keystoneauth1.exceptions')
                KEYSTONE_SESSION = importlib.import_module(
                    'keystoneauth1.session')
            except Exception as e:
                LOG.error(f'Failed to import Keystone v3: {e}')
                return sf_api.error(500, 'Keystone setup failure')

        service_auth = KEYSTONE_V3.Password(
            auth_url=config.KEYSTONE_AUTH_URL,
            username=config.KEYSTONE_SERVICE_AUTH_USER,
            password=config.KEYSTONE_SERVICE_AUTH_PASSWORD,
            project_name=config.KEYSTONE_SERVICE_AUTH_PROJECT,
            user_domain_id=config.KEYSTONE_SERVICE_AUTH_USER_DOMAIN_ID,
            project_domain_id=config.KEYSTONE_SERVICE_AUTH_PROJECT_DOMAIN_ID)
        service_session = KEYSTONE_SESSION.Session(auth=service_auth)
        service_keystone = KEYSTONE_CLIENT.Client(session=service_session)

        # Authenticate the user
        try:
            user_auth = KEYSTONE_V3.Password(
                auth_url=config.KEYSTONE_AUTH_URL,
                username=username,
                password=password,
                project_name='admin',
                user_domain_id='default',
                project_domain_id='default')
            user_session = KEYSTONE_SESSION.Session(
                auth=user_auth,
                verify=config.KEYSTONE_AUTH_VERIFY)
            user_id = user_session.get_user_id()
        except KEYSTONE_EXCEPTIONS.http.Unauthorized:
            return sf_api.error(401, 'unauthorized')
        except (
                requests.exceptions.SSLError,
                KEYSTONE_EXCEPTIONS.connection.SSLError
                ) as e:
            LOG.error(
                'SSL error while communicating with Keystone for auth '
                f'with verify={config.KEYSTONE_AUTH_VERIFY}: {e}')
            return sf_api.error(500, 'Keystone SSL error')

        # Ensure the user is in the correct group
        group = None
        for g in service_keystone.groups.list():
            if g.name == config.KEYSTONE_ACCESS_GROUP:
                group = g
        if not group:
            return sf_api.error(500, 'service group not found')

        # Require that the user be in that group
        try:
            service_keystone.users.check_in_group(user_id, group.id)
        except KEYSTONE_EXCEPTIONS.http.NotFound:
            return sf_api.error(401, 'unauthorized')
        except (
                requests.exceptions.SSLError,
                KEYSTONE_EXCEPTIONS.connection.SSLError
                ) as e:
            LOG.error(f'SSL error while communicating with Keystone: {e}')
            return sf_api.error(500, 'Keystone SSL error')

        # Create a JWT containing the user's keystone token
        token = user_session.get_token()
        access_token = create_access_token(
            identity=username,
            additional_claims={
                'iss': config.PUBLIC_FQDN,
                'openstack_token': token
            },
            expires_delta=datetime.timedelta(minutes=config.API_TOKEN_DURATION))

        result = {
            'expires_in': config.API_TOKEN_DURATION * 60
        }
        if as_cookie:
            resp = flask.Response(
                json.dumps(result, indent=4, sort_keys=True),
                mimetype='application/json')
            set_access_cookies(resp, access_token)
        else:
            result.update({
                'access_token': access_token,
                'token_type': 'Bearer'
            })
            resp = flask.Response(
                json.dumps(result, indent=4, sort_keys=True),
                mimetype='application/json')

        resp.status_code = 200
        return resp

    def delete(self):
        resp = flask.Response(
            json.dumps({'result': 'ok'}, indent=4, sort_keys=True),
            mimetype='application/json')
        unset_jwt_cookies(resp)
        resp.status_code = 200
        return resp


class Consoles(sf_api.Resource):
    @verify_token
    def get(self):
        if flask.request.headers.get('Accept', 'text/html').find('text/html') != -1:
            resp = flask.Response(
                flask.render_template(
                    'consoles.html', consoles=db.get_consoles(),
                    navitems=get_nav_items('Consoles'),
                    refresh=True, when=datetime.datetime.now()),
                mimetype='text/html')
        else:
            out_consoles = []
            for console in db.get_consoles(include_audit=False):
                # Remove the hypervisor auth ticket
                if 'ticket' in console:
                    del console['ticket']
                out_consoles.append(console)

            resp = flask.Response(
                json.dumps(out_consoles, indent=4, sort_keys=True, cls=DateTimeEncoder),
                mimetype='application/json')
        resp.status_code = 200
        return resp


class Console(sf_api.Resource):
    @verify_token
    def get(self, source=None, uuid=None):
        # This is a REST API only call
        console = db.get_console(source, uuid, detailed=True)
        if not console:
            return sf_api.error(404, 'console not found')

        # Remove the hypervisor auth ticket
        if 'ticket' in console:
            del console['ticket']

        resp = flask.Response(
            json.dumps(console, indent=4, sort_keys=True, cls=DateTimeEncoder),
            mimetype='application/json')
        resp.status_code = 200
        return resp


class ConsolesAudit(sf_api.Resource):
    get_args = {
        'limit': fields.Int(missing=20)
    }

    @verify_token
    @use_kwargs(get_args, location='query')
    def get(self, source=None, uuid=None, limit=20):
        if flask.request.headers.get('Accept', 'text/html').find('text/html') != -1:
            resp = flask.Response(
                flask.render_template(
                    'audit.html', console=db.get_console(source, uuid),
                    total_events=db.count_audit_events(source, uuid),
                    events=db.get_audit_events(source, uuid, limit=limit),
                    navitems=get_nav_items('Audit'),
                    refresh=True, when=datetime.datetime.now()),
                mimetype='text/html')
        else:
            out = {
                'total': db.count_audit_events(source, uuid),
                'audit': db.get_audit_events(source, uuid, limit=limit)
            }
            resp = flask.Response(
                json.dumps(out, indent=4, sort_keys=True, cls=DateTimeEncoder),
                mimetype='application/json')
        resp.status_code = 200
        return resp


# The best documentation I can find for the format of this file and the various
# fields is this source code:
# https://gitlab.com/virt-viewer/virt-viewer/-/blob/master/src/virt-viewer-file.c
VIRTVIEWER_TEMPLATE = """[virt-viewer]
type=spice
host=%(node)s
port=%(port)d%(tls_port)s
password=%(token)s
delete-this-file=1
fullscreen=0
title=%(name)s
toggle-fullscreen=shift+f11
release-cursor=shift+f12
secure-attention=ctrl+alt+end
enable-smartcard=1
enable-usb-autoshare=1
usb-filter=-1,-1,-1,-1,0
tls-ciphers=DEFAULT%(ca_cert)s%(host_subject)s
"""


class ConsolesDirectVirtViewer(sf_api.Resource):
    @verify_token
    def get(self, source=None, uuid=None):
        c = db.get_console(source, uuid)
        if not c:
            return sf_api.error(404, 'console not found')

        s = db.get_source(source)
        if not s:
            return sf_api.error(404, 'source not found')

        node = c['hypervisor']
        if not node:
            node = c['hypervisor_ip']

        # Acquire the ticket for embedding in the .vv file.  The
        # static driver persists its ticket at enumeration time; read
        # it back from the Console DB row.  oVirt fetches a fresh
        # ticket on every request.  All other types (shakenfist,
        # openstack) use an empty string here.
        if s['type'] == 'static':
            ticket = c.get('ticket') or ''
        elif s['type'] == 'ovirt':
            ticket = ''
            lookup = ovirt_source.oVirtSource(**s)
            if lookup.errored:
                return sf_api.error(404, 'source error')
            _, ticket = lookup.get_console_for_vm(c['uuid'], acquire_ticket=True)
            lookup.close()
        else:
            ticket = ''

        tls_port = ''
        if c['secure_port']:
            tls_port = '\ntls-port=%s' % c['secure_port']

        host_subject = ''
        if c['host_subject']:
            host_subject = '\nhost-subject=%s' % c['host_subject']

        ca_cert = ''
        if config.CACERT_PATH:
            with open(config.CACERT_PATH) as f:
                ca_cert_data = f.read().replace('\n', '\\n')
            ca_cert = f'\nca={ca_cert_data}'

        LOG.with_fields(c).with_fields(s).info(
            'Providing virt-viewer direct configuration for console')

        vv = VIRTVIEWER_TEMPLATE % {
            'node': node,
            'port': c['insecure_port'],
            'tls_port': tls_port,
            'token': ticket,
            'ca_cert': ca_cert,
            'name': '%s direct connection' % c['name'],
            'host_subject': host_subject
        }

        resp = flask.Response(
            vv, mimetype='application/x-virt-viewer;charset=UTF-8')
        resp.status_code = 200
        return resp


class ConsolesProxyVirtViewer(sf_api.Resource):
    @verify_token
    def get(self, source=None, uuid=None):
        s = db.get_source(source)
        if not s:
            return sf_api.error(404, 'source not found')

        c = db.get_console(source, uuid)
        if not c:
            return sf_api.error(404, 'console not found')

        cacert = ''
        with open(config.CACERT_PATH) as f:
            cacert = f.read()
        cacert = cacert.replace('\n', '\\n')

        if config.PROXY_HOST_SUBJECT:
            host_subject = '\nhost-subject=%s' % config.PROXY_HOST_SUBJECT
        else:
            host_subject = ''

        # Acquire a ticket if required.  The static driver persists
        # the ticket to the Console DB at enumeration time, so we
        # must not overwrite it with an empty string here.  oVirt
        # fetches a fresh ticket on every request.  All other source
        # types (shakenfist, openstack) manage tickets separately
        # and receive an empty string as a no-op.
        if s['type'] == 'static':
            # Ticket already stored by StaticSource.__call__() via
            # db.add_console(..., ticket=...).  Leave it intact.
            pass
        elif s['type'] == 'ovirt':
            ticket = ''
            lookup = ovirt_source.oVirtSource(**s)
            if lookup.errored:
                return sf_api.error(404, 'source error')
            _, ticket = lookup.get_console_for_vm(c['uuid'], acquire_ticket=True)
            lookup.close()
            db.store_console_ticket(source, uuid, ticket)
        else:
            # shakenfist, openstack: store an empty string as before.
            db.store_console_ticket(source, uuid, '')

        token = consoletoken.create_token(source, uuid)
        vv = VIRTVIEWER_TEMPLATE % {
            'node': config.PUBLIC_FQDN,
            'port': config.PUBLIC_INSECURE_PORT,
            'tls_port': '\ntls-port=%s' % config.PUBLIC_SECURE_PORT,
            'token': token['token'],
            'ca_cert': '\nca=%s' % cacert,
            'name': '%s via proxy session ID %s' % (c['name'], token['session_id']),
            'host_subject': host_subject
        }

        resp = flask.Response(vv, mimetype='application/x-virt-viewer;charset=UTF-8')
        resp.status_code = 200
        return resp


class ConsolesTerminate(sf_api.Resource):
    @verify_token
    def get(self, source=None, uuid=None):
        tokens = []
        for token in db.get_tokens_by_console(source, uuid):
            db.terminate_session(
                token['session_id'], token['source'], token['uuid'],
                reason='console terminated by request')
            tokens.append(token['token'])

        if flask.request.headers.get('Accept', 'text/html').find('text/html') != -1:
            return flask.redirect('/console', code=302)

        resp = flask.Response(
            json.dumps(
                {
                    'result': 'ok',
                    'tokens': tokens
                }, indent=4, sort_keys=True),
            mimetype='application/json')
        resp.status_code = 200
        return resp


class NovaToken(sf_api.Resource):
    get_args = {
        'token': fields.String()
    }

    # No token verification because this route uses an external token from
    # OpenStack Nova.
    @use_kwargs(get_args, location='query')
    def get(self, token=None):
        if not token:
            return sf_api.error(401, 'token absent')

        global OPENSTACK_CLIENT
        global KEYSTONE_V3
        global KEYSTONE_EXCEPTIONS
        global KEYSTONE_SESSION

        if not OPENSTACK_CLIENT:
            try:
                OPENSTACK_CLIENT = importlib.import_module('openstack')
            except Exception as e:
                LOG.error(f'Failed to import OpenStack client: {e}')
                return sf_api.error(
                    500, 'OpenStack client setup failure')

        if not KEYSTONE_V3:
            try:
                KEYSTONE_V3 = importlib.import_module(
                    'keystoneauth1.identity.v3')
                KEYSTONE_CLIENT = importlib.import_module(             # noqa F841
                    'keystoneclient.v3.client')
                KEYSTONE_EXCEPTIONS = importlib.import_module(
                    'keystoneauth1.exceptions')
                KEYSTONE_SESSION = importlib.import_module(
                    'keystoneauth1.session')
            except Exception as e:
                LOG.error(f'Failed to import Keystone v3: {e}')
                return sf_api.error(500, 'Keystone setup failure')

        with open(config.SOURCES_PATH) as f:
            sources = yaml.safe_load(f)
            for source in sources:
                if source['type'] != 'openstack':
                    continue

                verify = source.get('verify')
                if verify is None:
                    verify = True
                elif isinstance(verify, bool):
                    ...
                elif isinstance(verify, str):
                    verify_lower = verify.lower()
                    if verify_lower == 'true':
                        verify = True
                    elif verify_lower == 'false':
                        verify = False
                else:
                    LOG.error(
                        f'type {type(verify)} for verify value for source '
                        f'{source["name"]} is not supported')
                    return sf_api.error(500, 'Source configuration error')

                try:
                    auth = KEYSTONE_V3.Password(
                        auth_url=source['url'],
                        username=source['username'],
                        password=source['password'],
                        project_name=source['project_name'],
                        user_domain_id=source['user_domain_id'],
                        project_domain_id=source['project_domain_id'])
                    conn = OPENSTACK_CLIENT.connection.Connection(
                        session=KEYSTONE_SESSION.Session(
                            auth=auth,
                            verify=verify),
                        identity_interface='internal')
                    details = conn.compute.validate_console_auth_token(token)
                except OPENSTACK_CLIENT.exceptions.NotFoundException:
                    continue
                except (
                        requests.exceptions.SSLError,
                        KEYSTONE_EXCEPTIONS.connection.SSLError
                        ) as e:
                    LOG.error(
                        'SSL error while communicating with Keystone using '
                        f'verify={verify}: {e}')
                    return sf_api.error(500, 'Keystone SSL error')

                if not details:
                    continue

                instance_uuid = details.instance_uuid

                # Configure the console, given OpenStack does not do instance
                # scraping in advance.
                db.add_console(
                    uuid=instance_uuid,
                    source=source['source'],
                    hypervisor=details['host'],
                    insecure_port=details['port'],
                    secure_port=details['tls_port']
                )
                token = consoletoken.create_token(
                    source['source'], instance_uuid)

                cacert = ''
                with open(config.CACERT_PATH) as f:
                    cacert = f.read()
                cacert = cacert.replace('\n', '\\n')

                if config.PROXY_HOST_SUBJECT:
                    host_subject = '\nhost-subject=%s' % config.PROXY_HOST_SUBJECT
                else:
                    host_subject = ''

                vv = VIRTVIEWER_TEMPLATE % {
                    'node': config.PUBLIC_FQDN,
                    'port': config.PUBLIC_INSECURE_PORT,
                    'tls_port': '\ntls-port=%s' % config.PUBLIC_SECURE_PORT,
                    'token': token['token'],
                    'ca_cert': '\nca=%s' % cacert,
                    'name': '%s via proxy session ID %s' % (instance_uuid, token['session_id']),
                    'host_subject': host_subject
                }

                resp = flask.Response(vv, mimetype='application/x-virt-viewer;charset=UTF-8')
                resp.status_code = 200
                return resp

        return sf_api.error(404, 'nova token not found')


class Sessions(sf_api.Resource):
    @verify_token
    def get(self):
        if flask.request.headers.get('Accept', 'text/html').find('text/html') != -1:
            resp = flask.Response(
                flask.render_template(
                    'sessions.html', sessions=db.get_sessions(),
                    navitems=get_nav_items('Sessions'),
                    refresh=True, when=datetime.datetime.now()),
                mimetype='text/html')
        else:
            resp = flask.Response(
                json.dumps(db.get_sessions(), indent=4, sort_keys=True,
                           cls=DateTimeEncoder),
                mimetype='application/json')
        resp.status_code = 200
        return resp


class SessionTerminate(sf_api.Resource):
    @verify_token
    def get(self, session=None):
        token = db.get_token_by_session_id(session)
        if not token:
            return sf_api.error(404, 'session not found')

        db.terminate_session(
            token['session_id'], token['source'], token['uuid'],
            reason='session terminated by request')

        if flask.request.headers.get('Accept', 'text/html').find('text/html') != -1:
            return flask.redirect('/session', code=302)

        resp = flask.Response(
            json.dumps(
                {
                    'result': 'ok'
                }, indent=4, sort_keys=True),
            mimetype='application/json')
        resp.status_code = 200
        return resp


class Sources(sf_api.Resource):
    @verify_token
    def get(self):
        if flask.request.headers.get('Accept', 'text/html').find('text/html') != -1:
            resp = flask.Response(
                flask.render_template(
                    'sources.html', sources=db.get_sources(),
                    navitems=get_nav_items('Sources'),
                    refresh=True, when=datetime.datetime.now()),
                mimetype='text/html')
        else:
            sources = []
            for source in db.get_sources():
                del source['password']
                sources.append(source)

            resp = flask.Response(
                json.dumps(sources, indent=4, sort_keys=True, cls=DateTimeEncoder),
                mimetype='application/json')
        resp.status_code = 200
        return resp


class Source(sf_api.Resource):
    @verify_token
    def get(self, uuid):
        # This is a REST API only call
        source = db.get_source(uuid)
        if not source:
            return sf_api.error(404, 'source not found')

        resp = flask.Response(
            json.dumps(source, indent=4, sort_keys=True, cls=DateTimeEncoder),
            mimetype='application/json')
        resp.status_code = 200
        return resp


api.add_resource(Root, '/')
api.add_resource(Auth, '/auth')
api.add_resource(Consoles, '/console')
api.add_resource(Console, '/console/<source>/<uuid>')
api.add_resource(ConsolesAudit, '/console/<source>/<uuid>/audit')
api.add_resource(ConsolesDirectVirtViewer, '/console/direct/<source>/<uuid>/console.vv')
api.add_resource(ConsolesProxyVirtViewer, '/console/proxy/<source>/<uuid>/console.vv')
api.add_resource(ConsolesTerminate, '/console/<source>/<uuid>/terminate')
api.add_resource(NovaToken, '/nova-console.vv')
api.add_resource(Sessions, '/session')
api.add_resource(SessionTerminate, '/session/<session>/terminate')
api.add_resource(Sources, '/source')
api.add_resource(Source, '/source/<uuid>')
