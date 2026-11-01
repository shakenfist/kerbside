# Minting a console ticket with a source driver, within a deadline.

import queue
import threading
import time

from shakenfist_utilities import logs

from . import base
from .. import util


LOG, _ = logs.setup(__name__, **util.configure_logging())

# The most seconds a caller waits for a source to mint a console ticket,
# covering the whole mint: building the driver, logging in to the source's
# API and the ticket request. A driver bounds each request it can (oVirt's
# MINT_TIMEOUT is 15 seconds), but not every client library lets it bound
# its login. Meanwhile the caller holds something others are waiting for: a
# connecting channel holds the row lock every other channel of its session
# queues behind, and a .vv request holds a web worker. A little longer than
# one request's timeout, so that a single stalled request fails with its own
# error first.
MINT_DEADLINE = 20

# A worker still running this many seconds after it started no longer holds
# up new mints for its console. It is stuck in a request with no timeout,
# most likely on a connection that will never answer, and refusing every
# mint until the process restarts would be worse than the small chance that
# it finishes after all and replaces the console's password.
MINT_STUCK_AFTER = 300

# The mint worker running for each console, as (thread, monotonic start),
# keyed by (source name, uuid). A hypervisor has one SPICE password per
# console, so two mints for one console must not overlap: a worker abandoned
# at the deadline which finishes later would replace the password a newer
# mint had already set and stored, and every channel connecting afterwards
# would be refused. A new mint therefore waits, within its own deadline, for
# the console's running worker to finish before starting another, which
# also leaves at most one stuck worker per console. This holds within one
# process; daemons on other nodes keep their own.
_workers = {}
_workers_lock = threading.Lock()


class MintDeadlineExceeded(base.ConsoleTicketUnavailable):
    """A source did not finish minting a console ticket within the deadline."""


class SourceErrored(base.ConsoleTicketUnavailable):
    """A source driver found while being built that it cannot work."""


def mint_with_deadline(driver, source, uuid, lifetime, deadline):
    """Mint a console ticket for uuid, giving up after deadline seconds.

    driver is a source driver class with MINTS_TICKETS set, and source is
    the secret-bearing source dict it is built from, as
    db.get_source(include_secrets=True) returns it. Returns the driver's
    MintedTicket, or raises whatever building the driver or minting raised.
    A driver which marks itself errored while being built is not asked to
    mint, and SourceErrored is raised instead.

    The deadline covers the whole mint: building the driver, which may make
    requests of its own, logging in to the source's API, and the ticket
    request. Drivers bound the requests they can, but not every client
    library lets them bound all of them; ovirtsdk4 applies no timeout to
    its SSO login, for example. So the driver is built, used and closed on
    a worker thread which owns it from start to finish, and the caller
    waits for that thread's result for at most deadline seconds.

    Mints for one console run one at a time in this process: if a worker
    for the console is still running, perhaps one an earlier caller
    abandoned, the caller waits for it first, and raises
    MintDeadlineExceeded without asking the source for anything if it does
    not finish within the deadline. See _workers.

    If the deadline passes before the worker reports, MintDeadlineExceeded
    is raised and the worker is abandoned. It is a daemon thread, so one stuck in a request
    nothing can interrupt does not hold up the process exiting, and it
    still closes its driver if it ever finishes. Whatever it returns then
    is discarded: a ticket minted after the caller gave up is handed to
    nobody and stored nowhere.
    """
    # Holds the single (minted, error) outcome the worker reports. Nothing
    # reads it once the caller has given up, so a late outcome is dropped
    # along with the queue.
    outcome = queue.Queue(maxsize=1)
    key = (source['name'], uuid)
    give_up_at = time.monotonic() + deadline

    def worker():
        try:
            mint()
        finally:
            with _workers_lock:
                if _workers.get(key, (None,))[0] is thread:
                    del _workers[key]

    def mint():
        try:
            # A database row names its source 'name', where the drivers,
            # written for the sources.yaml entries the scrape loop builds
            # them from, read 'source'.
            instance = driver(**dict(source, source=source['name']))
        except Exception as e:
            outcome.put((None, e))
            return

        try:
            if instance.errored:
                raise SourceErrored(
                    'source %s is not usable' % source.get('name'))
            result = (instance.mint_console_ticket(uuid, lifetime), None)
        except Exception as e:
            result = (None, e)
        finally:
            # A driver which cannot tidy up after itself has still minted,
            # or failed to, so a failure here does not change the outcome.
            try:
                instance.close()
            except Exception as e:
                LOG.with_fields({
                    'uuid': uuid,
                    'error': type(e).__name__
                    }).warning('Closing a source driver after minting failed')
        outcome.put(result)

    thread = threading.Thread(
        target=worker, name='mint-console-ticket', daemon=True)
    while True:
        now = time.monotonic()
        with _workers_lock:
            previous, started = _workers.get(key, (None, None))
            if previous is None or now - started > MINT_STUCK_AFTER:
                _workers[key] = (thread, now)
                break
        previous.join(max(give_up_at - now, 0))
        if previous.is_alive():
            LOG.with_fields({
                'source': source['name'],
                'uuid': uuid
                }).warning('An earlier console ticket mint is still running')
            raise MintDeadlineExceeded(
                'an earlier console ticket mint for %s is still running'
                % uuid)
    if previous is not None:
        LOG.with_fields({
            'source': source['name'],
            'uuid': uuid,
            'running': int(now - started)
            }).warning('No longer waiting for a stuck console ticket mint')

    remaining = give_up_at - time.monotonic()
    if remaining <= 0:
        # The wait used the whole deadline. Starting a worker now would only
        # abandon it at once, still minting.
        with _workers_lock:
            del _workers[key]
        raise MintDeadlineExceeded(
            'no console ticket for %s within %s seconds' % (uuid, deadline))

    # A thread that never started would never unregister itself, and every
    # later mint for the console would fail to join it.
    try:
        thread.start()
    except Exception:
        with _workers_lock:
            del _workers[key]
        raise
    try:
        minted, error = outcome.get(timeout=remaining)
    except queue.Empty:
        raise MintDeadlineExceeded(
            'no console ticket for %s within %s seconds' % (uuid, deadline))
    if error is not None:
        raise error
    return minted
