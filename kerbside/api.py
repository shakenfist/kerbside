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
import json
from keystoneauth1 import exceptions as keystone_exceptions
from keystoneauth1.identity import v3 as keystone_v3
from keystoneauth1 import session as keystone_session
from keystoneclient.v3 import client as keystone_client
import logging
import os
import setproctitle
from shakenfist_utilities import api as sf_api, logs
import signal
import subprocess
import sys
from webargs import fields
from webargs.flaskparser import use_kwargs

from .config import config
from . import consoletoken
from . import db
from .sources import ovirt as ovirt_source
from . import util


LOG, HANDLER = logs.setup(__name__, **util.configure_logging())
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

        # We need to talk to Keystone as our service account
        service_auth = keystone_v3.Password(
            auth_url=config.KEYSTONE_AUTH_URL,
            username=config.KEYSTONE_SERVICE_AUTH_USER,
            password=config.KEYSTONE_SERVICE_AUTH_PASSWORD,
            project_name=config.KEYSTONE_SERVICE_AUTH_PROJECT,
            user_domain_id=config.KEYSTONE_SERVICE_AUTH_USER_DOMAIN_ID,
            project_domain_id=config.KEYSTONE_SERVICE_AUTH_PROJECT_DOMAIN_ID)
        service_session = keystone_session.Session(auth=service_auth)
        service_keystone = keystone_client.Client(session=service_session)

        # Authenticate the user
        try:
            user_auth = keystone_v3.Password(
                auth_url=config.KEYSTONE_AUTH_URL,
                username=username,
                password=password,
                project_name='admin',
                user_domain_id='default',
                project_domain_id='default')
            user_session = keystone_session.Session(auth=user_auth)
            user_id = user_session.get_user_id()
        except keystone_exceptions.http.Unauthorized:
            return sf_api.error(401, 'unauthorized')

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
        except keystone_exceptions.http.NotFound:
            return sf_api.error(401, 'unauthorized')

        # Create a JWT containing the user's keystone token
        token = user_session.get_token()
        access_token = create_access_token(
            identity=[username],
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

        ticket = ''
        if s['type'] == 'ovirt':
            lookup = ovirt_source.oVirtSource(**s)
            if lookup.errored:
                return sf_api.error(404, 'source error')
            _, ticket = lookup.get_console_for_vm(c['uuid'], acquire_ticket=True)
            lookup.close()

        tls_port = ''
        if c['secure_port']:
            tls_port = '\ntls-port=%s' % c['secure_port']

        host_subject = ''
        if c['host_subject']:
            host_subject = '\nhost-subject=%s' % c['host_subject']

        ca_cert = ''
        if s.get('ca_cert'):
            ca_cert = '\nca=%s' % s['ca_cert'].replace('\n', '\\n')

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

        resp = flask.Response(vv, mimetype='application/x-virt-viewer;charset=UTF-8')
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

        # Acquire a ticket if required
        ticket = ''
        if s['type'] == 'ovirt':
            lookup = ovirt_source.oVirtSource(**s)
            if lookup.errored:
                return sf_api.error(404, 'source error')
            _, ticket = lookup.get_console_for_vm(c['uuid'], acquire_ticket=True)
            lookup.close()
        db.store_console_ticket(source, uuid, ticket)

        token = consoletoken.create_token(source, uuid)
        vv = VIRTVIEWER_TEMPLATE % {
            'node': config.PUBLIC_FQDN,
            'port': config.VDI_INSECURE_PORT,
            'tls_port': '\ntls-port=%s' % config.VDI_SECURE_PORT,
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
            db.expire_token(token['token'])
            db.remove_session(token['session_id'])
            db.add_audit_event(
                token['source'], token['uuid'], token['session_id'],
                None, None, None, 'Session terminated by request')
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

        db.remove_session(token['session_id'])
        db.add_audit_event(
            token['source'], token['uuid'], token['session_id'],
            None, None, None, 'Session terminated by request')

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


api.add_resource(Root, '/')
api.add_resource(Auth, '/auth')
api.add_resource(Consoles, '/console')
api.add_resource(Console, '/console/<source>/<uuid>')
api.add_resource(ConsolesAudit, '/console/<source>/<uuid>/audit')
api.add_resource(ConsolesDirectVirtViewer, '/console/direct/<source>/<uuid>/console.vv')
api.add_resource(ConsolesProxyVirtViewer, '/console/proxy/<source>/<uuid>/console.vv')
api.add_resource(ConsolesTerminate, '/console/<source>/<uuid>/terminate')
api.add_resource(Sessions, '/session')
api.add_resource(SessionTerminate, '/session/<session>/terminate')
api.add_resource(Sources, '/source')
api.add_resource(Source, '/source/<uuid>')


def run():
    setproctitle.setproctitle('kerbside-api')
    db.reset_engine()

    pid_file = os.path.join(config.PID_FILE_LOCATION, 'gunicorn.pid')
    if os.path.exists(pid_file):
        with open(pid_file) as f:
            pid = int(f.read())
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            ...

    if config.LOG_VERBOSE:
        LOG.setLevel(logging.DEBUG)
    LOG.info('REST API starting')

    os.makedirs(config.PID_FILE_LOCATION, exist_ok=True)
    command = config.API_COMMAND_LINE % {
        'port': config.API_PORT,
        'timeout': config.API_TIMEOUT,
        'pid_file_dir': config.PID_FILE_LOCATION,
        'name': 'kerbside-api',
        'workers': 10,
        'threads': 10,
        'install_dir': os.path.dirname(sys.argv[0])
    }

    LOG.info('Starting REST API with %s' % command)
    p = subprocess.Popen(
        command, env=os.environ, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while not p.poll():
        try:
            out, err = p.communicate(timeout=1)
            if out:
                sys.stdout.write(out.decode('utf-8'))
            if err:
                sys.stdout.write(err.decode('utf-8'))
        except subprocess.TimeoutExpired:
            ...

    LOG.with_fields({'returncode', p.returncode}).info('REST API terminated')
