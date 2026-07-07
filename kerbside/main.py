import click
from shakenfist_utilities import logs
import logging
import multiprocessing
import os
import signal
import sys
import time
import yaml

from .config import config as config
from . import db as kerbside_db
from . import proxy as kerbside_proxy
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
    """Supervise the Rust proxy binary as a child (PROXY_IMPLEMENTATION=rust).

    Binds the gRPC control server FIRST -- the Rust proxy dials the UDS at
    startup (ClearNodeChannels) and lazily thereafter, so the socket must
    exist. Unlike the multiprocessing fork, a subprocess child (close_fds=True)
    does not inherit the gRPC C-core threads/fds, so serving first is safe.
    Forwards SIGTERM to the child with a deadline, and exits non-zero if the
    child dies -- matching the Python-proxy supervision semantics.
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
            _reap_session_terminations()
            last_maintenance = time.time()


@daemon.command(name='run', help='Run the kerbside proxy')
@click.pass_context
def daemon_run(ctx):
    _parse_sources()
    _reap_expired_console_tokens()
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

    # Rust proxy (opt-in): supervise the kerbside-proxy binary as a child.
    if (config.PROXY_IMPLEMENTATION or 'python').strip().lower() == 'rust':
        _run_rust_proxy(last_maintenance)
        return

    proxy = multiprocessing.Process(
        target=kerbside_proxy.run, args=(), name='kerbside-main')
    proxy.start()

    # Stand up the KerbsideProxy gRPC control-plane server AFTER forking the
    # proxy. The server owns a listening socket and gRPC C-core threads;
    # forking after it starts would leak that socket fd (and copy locked
    # thread state) into the proxy and its per-connection SPICE workers --
    # the processes most exposed to untrusted input. Starting it here keeps
    # those fds/threads out of the proxy process tree. It runs on its own
    # ThreadPoolExecutor threads, so serve() returns immediately and the
    # maintenance loop below is unaffected. There is no client until phase 3.
    grpc_server = rpc_server.serve()
    LOG.info('Started KerbsideProxy gRPC server')

    while True:
        proxy.join(timeout=0)
        if not proxy.is_alive():
            LOG.error('Proxy process died with exit code %d!' % proxy.exitcode)
            proxy.kill()
            rpc_server.stop(grpc_server)
            sys.exit(1)

        time.sleep(1)
        if time.time() - last_maintenance > 60:
            _parse_sources()
            _reap_expired_console_tokens()
            _reap_session_terminations()
            last_maintenance = time.time()


daemon.add_command(daemon_run)
