import click
from shakenfist_utilities import logs
import logging
import multiprocessing
import os
import sys
import time
import yaml

from . import api as kerbside_api
from .config import config as config
from . import db as kerbside_db
from . import proxy as kerbside_proxy
from .sources import openstack as openstack_source
from .sources import ovirt as ovirt_source
from .sources import shakenfist as shakenfist_source
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
        LOG.error('Sources configuration at %s does not exist!' % config.SOURCES_PATH)

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

            # If this source is new, record it with the configured CA cert
            # (if any).
            if not stored_source:
                LOG.info('Creating new source %s' % source['source'])
                kerbside_db.add_source(
                    source['source'], source['type'], source['url'],
                    source['username'], source['password'],
                    project_name=source.get('project_name'),
                    user_domain_id=source.get('user_domain_id'),
                    project_domain_id=source.get('project_domain_id'),
                    flavor=';'.join(source.get('flavor', [])),
                    errored=False, ca_cert=source.get('ca_cert'))

            # Ensure that the sources.yaml configuration for the source has
            # not changed.
            else:
                dirty = False
                for field in ['type', 'url', 'username', 'password', 'project_name',
                              'user_domain_id', 'project_domain_id', 'flavor',
                              'deleted', 'ca_cert']:
                    if field == 'deleted':
                        new_value = False
                    elif field != 'flavor':
                        new_value = source.get(field)
                    elif source.get(field):
                        new_value = ';'.join(source.get(field))
                    else:
                        new_value = None

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
                        source['source'], source['type'], source['url'],
                        source['username'], source['password'],
                        project_name=source.get('project_name'),
                        user_domain_id=source.get('user_domain_id'),
                        project_domain_id=source.get('project_domain_id'),
                        flavor=';'.join(source.get('flavor', [])),
                        errored=False, ca_cert=source.get('ca_cert'))

            # Now lookup consoles.
            try:
                if source['type'] == 'shakenfist':
                    lookup = shakenfist_source.ShakenFistSource(**source)
                elif source['type'] == 'ovirt':
                    lookup = ovirt_source.oVirtSource(**source)
                elif source['type'] == 'openstack':
                    lookup = openstack_source.OpenStackSource(**source)
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


@daemon.command(name='run', help='Run the kerbside proxy')
@click.pass_context
def daemon_run(ctx):
    _parse_sources()
    _reap_expired_console_tokens()
    last_maintenance = time.time()

    kerbside_db.reset_engine()
    proxy = multiprocessing.Process(
        target=kerbside_proxy.run, args=(), name='kerbside-main')
    proxy.start()

    kerbside_db.reset_engine()
    api = multiprocessing.Process(
        target=kerbside_api.run, args=(), name='kerbside-api')
    api.start()

    while True:
        proxy.join(timeout=0)
        if not proxy.is_alive():
            LOG.error('Proxy process died with exit code %d!' % proxy.exitcode)
            proxy.kill()
            sys.exit(1)

        api.join(timeout=0)
        if not api.is_alive():
            LOG.error('API process died with exit code %d!' % api.exitcode)
            api.kill()
            sys.exit(1)

        time.sleep(1)
        if time.time() - last_maintenance > 60:
            _parse_sources()
            _reap_expired_console_tokens()
            last_maintenance = time.time()


daemon.add_command(daemon_run)
