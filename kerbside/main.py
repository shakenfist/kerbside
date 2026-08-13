from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
import click
import datetime
import importlib.resources
from shakenfist_utilities import logs
import logging
import os
import signal
import sys
import time
import yaml

from .config import config as config
from . import db as kerbside_db
from . import proxy_supervisor
from .rpc import server as rpc_server
from .rpc import servicer as rpc_servicer
from .sources import ovirt as ovirt_source
from .sources import shakenfist as shakenfist_source
from .sources import static as static_source
from . import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


@click.group()
@click.pass_context
def cli(ctx):
    if not ctx.obj:
        ctx.obj = {}
    ctx.obj['LOGGER'] = LOG

    if config.LOG_VERBOSE:
        ctx.obj['VERBOSE'] = True
        LOG.setLevel(logging.DEBUG)
        LOG.debug('Set log level to DEBUG')
    else:
        ctx.obj['VERBOSE'] = False
        LOG.setLevel(logging.INFO)


@click.group(help='Daemon commands')
def daemon():
    pass


cli.add_command(daemon)


def _parse_sources():
    # TODO(mikal): this needs to be able to handle there being more than one
    # proxy behind a load balancer... That is, we should not scrape the clouds
    # unless no one has done it recently.
    if not os.path.exists(config.SOURCES_PATH):
        LOG.error(
            f'Sources configuration at {config.SOURCES_PATH} does not exist!'
            )
        return

    source_type = {}

    extra_sources = {}
    for source in kerbside_db.get_sources():
        extra_sources[source['name']] = source

    extra_consoles = {}
    for console in kerbside_db.get_consoles():
        extra_consoles[(console['source'], console['uuid'])] = console

    with open(config.SOURCES_PATH) as f:
        sources = yaml.safe_load(f)
        for source in sources:
            source_count = 0
            lookup = None

            if source['source'] in extra_sources:
                del extra_sources[source['source']]
            stored_source = kerbside_db.get_source(source['source'])

            # Cache the type of this source
            source_type[source['source']] = source['type']

            # If this source is new, record it with the configured CA cert
            # (if any).
            if not stored_source:
                LOG.info('Creating new source %s' % source['source'])
                kerbside_db.add_source(
                    source['source'], source['type'], source.get('url'),
                    source.get('username'), source.get('password'),
                    project_name=source.get('project_name'),
                    user_domain_id=source.get('user_domain_id'),
                    project_domain_id=source.get('project_domain_id'),
                    errored=False, ca_cert=source.get('ca_cert'))

            # Ensure that the sources.yaml configuration for the source has
            # not changed.
            else:
                dirty = False
                for field in ['type', 'url', 'username', 'password', 'project_name',
                              'user_domain_id', 'project_domain_id',
                              'deleted', 'ca_cert']:
                    if field == 'deleted':
                        new_value = False
                    else:
                        new_value = source.get(field)

                    if stored_source[field] != new_value:
                        LOG.with_fields({
                            'old': stored_source[field],
                            'new': source.get(field)
                            }).info('Source configuration changed for source %s'
                                    % source['source'])
                        dirty = True

                if dirty:
                    LOG.info('Updating source %s' % source['source'])
                    kerbside_db.add_source(
                        source['source'], source['type'], source.get('url'),
                        source.get('username'), source.get('password'),
                        project_name=source.get('project_name'),
                        user_domain_id=source.get('user_domain_id'),
                        project_domain_id=source.get('project_domain_id'),
                        errored=False, ca_cert=source.get('ca_cert'))

            # Now lookup consoles.
            try:
                if source['type'] == 'shakenfist':
                    lookup = shakenfist_source.ShakenFistSource(**source)
                elif source['type'] == 'ovirt':
                    lookup = ovirt_source.oVirtSource(**source)
                elif source['type'] == 'static':
                    lookup = static_source.StaticSource(**source)
                elif source['type'] == 'openstack':
                    # OpenStack now uses auth tokens instead of console scraping
                    continue
                else:
                    LOG.error('Unknown source type %s' % source['type'])
                    kerbside_db.set_source_error_state(source['source'], True)
                    continue

                if lookup.errored:
                    LOG.error('Source initialization failed for source %s' % source['source'])
                    kerbside_db.set_source_error_state(source['source'], True)
                    continue

                for console in lookup():
                    LOG.with_fields(console).info('Found console')
                    console_is_new = kerbside_db.add_console(**console)
                    if console_is_new:
                        kerbside_db.add_audit_event(
                            console['source'], console['uuid'], None, None, None, None,
                            'Discovered new console'
                        )
                    k = (console['source'], console['uuid'])
                    if k in extra_consoles:
                        del extra_consoles[k]
                    source_count += 1

            except Exception as e:
                LOG.warning('Exception while querying source %s: %s' % (source['source'], e))
                kerbside_db.set_source_error_state(source['source'], True)
                continue

            finally:
                if lookup:
                    lookup.close()

            LOG.info('Source %s yielded %d consoles' % (source['source'], source_count))
            kerbside_db.set_source_error_state(source['source'], False)

    for source, uuid in extra_consoles:
        if source_type[source] == 'openstack':
            continue

        LOG.with_fields(extra_consoles[(source, uuid)]).info(
            'Console is no longer available, cleaning up')
        kerbside_db.remove_console(source=source, uuid=uuid)
        kerbside_db.add_audit_event(
            source, uuid, None, None, None, None, 'Console no longer available')

    for source in extra_sources:
        kerbside_db.delete_source(source)
        kerbside_db.add_audit_event(
            source, '', None, None, None, None, 'Source no longer available')


def _reap_expired_console_tokens():
    for expired in kerbside_db.reap_expired_tokens():
        kerbside_db.add_audit_event(
            expired['source'], expired['uuid'], expired['session_id'],
            None, None, None, 'Reaped expired and unused token')


def _reap_expired_sf_token_jtis():
    # A jti has no session or live channel to protect -- it is a random,
    # purely time-bounded single-use marker -- so there is no audit event to
    # emit, just a count. The jti value is not logged.
    reaped = kerbside_db.reap_expired_sf_token_jtis()
    if reaped:
        LOG.info('Reaped %d expired Shaken Fist token jtis' % len(reaped))


# How long a session_terminations intent row lives before the reaper deletes
# it. By then every proxy node has had ample time to poll and push the
# TerminateSession (the ProxyControl poll interval is a couple of seconds), and
# the Rust side is idempotent so a late or duplicate event is a no-op.
SESSION_TERMINATION_TTL_SECONDS = 300


def _reap_session_terminations():
    count = kerbside_db.reap_session_terminations(SESSION_TERMINATION_TTL_SECONDS)
    if count:
        LOG.info('Reaped %d expired session termination intents' % count)


# How long to wait for the Rust proxy to exit after SIGTERM before we SIGKILL
# it. Longer than the proxy's own graceful-drain deadline (see main.rs
# DRAIN_TIMEOUT) so it can finish draining in-flight sessions first.
RUST_PROXY_SIGTERM_DEADLINE = 15


def _run_rust_proxy(last_maintenance):
    """Supervise the Rust kerbside-proxy binary as a child.

    Binds the gRPC control server FIRST -- the Rust proxy dials the UDS at
    startup (ClearNodeChannels) and lazily thereafter, so the socket must
    exist. The subprocess child (close_fds=True) does not inherit the gRPC
    C-core threads/fds. Forwards SIGTERM to the child with a deadline, and
    exits non-zero if the child dies.
    """
    grpc_server = rpc_server.serve()
    LOG.info('Started KerbsideProxy gRPC server')

    proc = proxy_supervisor.launch_rust_proxy(config)
    LOG.info('Launched Rust proxy child (pid %s)' % proc.pid)

    def _handle_sigterm(signum, frame):
        LOG.info('SIGTERM received; stopping Rust proxy child')
        proxy_supervisor.terminate_child(proc, RUST_PROXY_SIGTERM_DEADLINE)
        rpc_server.stop(grpc_server)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    while True:
        rc = proc.poll()
        if rc is not None:
            LOG.error('Rust proxy child died with exit code %s!' % rc)
            rpc_server.stop(grpc_server)
            sys.exit(1)

        time.sleep(1)
        if time.time() - last_maintenance > 60:
            _parse_sources()
            _reap_expired_console_tokens()
            _reap_expired_sf_token_jtis()
            _reap_session_terminations()
            last_maintenance = time.time()


@daemon.command(name='run', help='Run the kerbside proxy')
@click.pass_context
def daemon_run(ctx):
    _parse_sources()
    _reap_expired_console_tokens()
    _reap_expired_sf_token_jtis()
    last_maintenance = time.time()

    kerbside_db.reset_engine()

    # Validate the firewall policy config once at startup so a bad
    # FIREWALL_PERMITTED_CHANNELS (e.g. a typo'd channel name) fails the daemon
    # loudly here rather than failing every AuthorizeConnection at runtime.
    try:
        rpc_servicer.build_firewall_policy()
    except ValueError as e:
        LOG.error('Invalid firewall configuration: %s' % e)
        sys.exit(1)

    # The daemon supervises the Rust kerbside-proxy binary as a child.
    _run_rust_proxy(last_maintenance)


daemon.add_command(daemon_run)


def _fail(message):
    """Report a fatal CLI error and exit non-zero.

    Written to stderr as well as the log because these commands are run
    by hand by an operator, and kerbside logs to syslog by default -- so
    a log-only failure looks like the command silently did nothing.
    """
    LOG.error(message)
    click.echo(message, err=True)
    sys.exit(1)


@click.group(help='Database commands')
def db():
    pass


cli.add_command(db)


def _alembic_config():
    """Build an alembic Config pointing at the packaged migration tree.

    The migrations live inside the package (kerbside/migrations/) so that
    they ship in the wheel, which is what lets an installed kerbside
    migrate its own schema with no repository checkout present.

    script_location is overridden here rather than trusted from the
    packaged ini, because the ini's relative value only resolves when
    alembic is invoked from the directory containing it, and this command
    runs from wherever the operator happens to be.

    The database URL is not set here: kerbside/migrations/env.py already
    takes it from config.SQL_URL, so upgrade and downgrade inherit the
    same environment and INI resolution as the rest of kerbside.
    """
    migrations = importlib.resources.files('kerbside') / 'migrations'
    alembic_config = AlembicConfig(str(migrations / 'alembic.ini'))
    alembic_config.set_main_option('script_location', str(migrations))
    return alembic_config


@db.command(name='upgrade',
            help='Upgrade the database schema, by default to head')
@click.option('--revision', default='head', show_default=True,
              help='Target revision')
@click.pass_context
def db_upgrade(ctx, revision):
    # NOTE(mikal): SQL_URL is deliberately never logged, here or below --
    # it carries the database password.
    LOG.with_fields({'revision': revision}).info('Upgrading database schema')
    try:
        alembic_command.upgrade(_alembic_config(), revision)
    except Exception as e:
        _fail('Database upgrade failed: %s' % e)


db.add_command(db_upgrade)


@db.command(name='downgrade', help='Downgrade the database schema')
@click.option('--revision', required=True,
              help='Target revision. Required: a downgrade with an implied '
                   'target is too easy to run against the wrong database')
@click.pass_context
def db_downgrade(ctx, revision):
    LOG.with_fields({'revision': revision}).info('Downgrading database schema')
    try:
        alembic_command.downgrade(_alembic_config(), revision)
    except Exception as e:
        _fail('Database downgrade failed: %s' % e)


db.add_command(db_downgrade)


@click.group(help='DEMONSTRATION USE ONLY. Helpers for running the '
                  'standalone kerbside demo; not supported in production.')
def demo():
    pass


cli.add_command(demo)


# The sentinel every security-relevant config field defaults to. Minting a
# token signed with it would be signing with a constant that is public in
# this source tree -- see issue #131.
_UNCONFIGURED = '~~unconfigured~~'


def _demo_sources_or_fail():
    """Return the configured sources, refusing unless all are static.

    A session JWT is not scoped to a source: verify_token() checks the
    signature and expiry and nothing else, so the resulting token
    authorises every console of every configured source. "Only mint for
    static sources" therefore cannot be enforced per source; the only
    coherent reading is to refuse entirely unless the whole deployment is
    static, which is what this does.

    The sources file is read rather than the sources table, because the
    table can hold rows that _parse_sources() has not yet reconciled, and
    a stale row blocking a legitimate demo is how a guard ends up growing
    a --force flag.

    Every failure here is fatal and fail-closed: an unreadable or empty
    source list is "unknown", not "no non-static sources".
    """
    if not os.path.exists(config.SOURCES_PATH):
        _fail('Refusing to mint: no sources file at %s. This command only '
              'runs against a configured static-source demo.'
              % config.SOURCES_PATH)

    try:
        with open(config.SOURCES_PATH) as f:
            sources = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        _fail('Refusing to mint: could not read sources from %s: %s'
              % (config.SOURCES_PATH, e))

    if not sources or not isinstance(sources, list):
        _fail('Refusing to mint: %s defines no sources. This command only '
              'runs against a configured static-source demo.'
              % config.SOURCES_PATH)

    for source in sources:
        source_type = source.get('type')
        if source_type != 'static':
            _fail(
                'Refusing to mint: source "%s" is of type "%s", not '
                '"static". This command is a demonstration affordance and '
                'will not issue credentials for a deployment that fronts a '
                'real cloud. See issue #300 for the underlying gap.'
                % (source.get('source', '<unnamed>'), source_type))

    return sources


@demo.command(
    name='token',
    help='DEMONSTRATION USE ONLY. Mint a bearer token for the demo stack. '
         'Refuses unless every configured source is of type "static".')
@click.option('--subject', required=True,
              help='The JWT subject (a username) to mint the token for')
@click.option('--duration', type=int, default=None,
              help='Token lifetime in minutes [default: API_TOKEN_DURATION]')
@click.option('--output', type=click.Path(dir_okay=False, writable=True),
              default=None,
              help='Write the token to this file (mode 0600) instead of '
                   'stdout. Prefer this when capturing the token in a '
                   'script: kerbside prints startup diagnostics to stdout, '
                   'so stdout is not a clean channel.')
@click.pass_context
def demo_token(ctx, subject, duration, output):
    if config.AUTH_SECRET_SEED == _UNCONFIGURED:
        _fail('Refusing to mint: AUTH_SECRET_SEED is unconfigured, so the '
              'token would be signed with a constant that is public in the '
              'kerbside source tree. Set it to a random value, for example '
              'with "openssl rand -hex 32".')

    _demo_sources_or_fail()

    if duration is None:
        duration = config.API_TOKEN_DURATION

    # Minted through the same flask-jwt-extended call the Keystone login
    # path uses (api.py), inside an app context so it picks up the
    # configured signing key. Deliberately NOT a hand-rolled PyJWT
    # payload: one place decides the claim shape, which is the whole
    # reason this is a command rather than a snippet in a shell script.
    #
    # The openstack_token claim that the Keystone path adds is omitted.
    # Nothing in kerbside ever reads it -- verified by grep -- so a token
    # without it is functionally identical. Do not "fix" this by adding
    # an empty one.
    from . import api as kerbside_api

    with kerbside_api.app.app_context():
        # Sign with the seed this command validated above, rather than
        # whatever api.py captured into JWT_SECRET_KEY when it was
        # imported. They are the same value in a normal CLI run, but
        # depending on import ordering for a signing key is the kind of
        # coupling that breaks quietly and produces tokens nothing will
        # accept.
        kerbside_api.app.config['JWT_SECRET_KEY'] = config.AUTH_SECRET_SEED

        token = kerbside_api.create_access_token(
            identity=subject,
            additional_claims={'iss': config.PUBLIC_FQDN},
            expires_delta=datetime.timedelta(minutes=duration))

    LOG.with_fields({'subject': subject, 'duration': duration}).warning(
        'Minted a demonstration API token')
    click.echo(
        'WARNING: this is a demonstration token, minted directly from '
        'AUTH_SECRET_SEED because kerbside has no non-Keystone login '
        '(issue #300). Do not use this pattern in production.', err=True)

    if output:
        # 0600 before anything is written: this is a bearer credential,
        # and it is worth not racing a wider default umask.
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(token)
        click.echo('Token written to %s' % output, err=True)
        return

    # NOTE(mikal): stdout is NOT a clean channel here. util.configure_logging()
    # and api.py both print startup diagnostics to it at import time, so a
    # caller doing token=$(kerbside demo token) captures those too. Use
    # --output when scripting; this path is for reading off a terminal.
    click.echo(token)


demo.add_command(demo_token)
