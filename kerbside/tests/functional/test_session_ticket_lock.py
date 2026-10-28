"""Concurrent channels of one session mint its backend ticket once.

db.session_ticket() relies on SELECT ... FOR UPDATE on the session's token
row to make every channel but the first wait for the ticket the first one
mints. SQLite ignores FOR UPDATE, so the unit tests cannot show this; these
tests run against a real MariaDB or MySQL server named by
KERBSIDE_TEST_SQL_URL, and are skipped when it is unset.

The database the URL names is dropped and recreated, and dropped again at
the end, so its name must end in 'test'; see sql_database.

These tests use the standard library's unittest rather than testtools so
that they run in an environment holding only kerbside's runtime
dependencies:

    KERBSIDE_TEST_SQL_URL=mysql://user:pass@127.0.0.1/kerbside_locktest \\
        python -m unittest -v kerbside.tests.functional.test_session_ticket_lock
"""

import threading
import time
import unittest
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from kerbside import db
from kerbside.sources.base import MintedTicket
from kerbside.tests.functional import sql_database

CHANNELS = 8
MINT_SECONDS = 1
LIFETIME = 3600
REUSE_MARGIN = 60

# Generous bounds on waits which should take about MINT_SECONDS. They exist
# so that a hang fails the test instead of stalling the run.
BARRIER_TIMEOUT = 30
JOIN_TIMEOUT = 60

SOURCE = 'locktest-source'
UUID = 'locktest-vm'
# consoletokens.session_id is a String(12).
SESSION_ID = 'lock-session'


@unittest.skipUnless(sql_database.TEST_SQL_URL,
                     'KERBSIDE_TEST_SQL_URL is not set')
class SessionTicketLockTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.url = sql_database.migrated_database()
        cls.engine = create_engine(cls.url, hide_parameters=True)
        cls.engine_patch = mock.patch.object(db, 'ENGINE', cls.engine)
        cls.engine_patch.start()

    @classmethod
    def tearDownClass(cls):
        cls.engine_patch.stop()
        cls.engine.dispose()
        sql_database.drop_database(cls.url)
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        now = int(time.time())
        db.add_source(SOURCE, 'ovirt', 'https://engine.example.com',
                      'admin@internal', 'not-a-password')
        db.add_console(
            source=SOURCE, uuid=UUID, hypervisor='hv',
            hypervisor_ip='10.0.0.1', insecure_port=5900, secure_port=5901,
            name='vm', host_subject=None, ticket=None)
        db.add_token('locktest-token', SESSION_ID, SOURCE, UUID,
                     now, now + LIFETIME)
        self.addCleanup(self._remove_rows)

        self.mint_lock = threading.Lock()
        self.mints = 0

    def _remove_rows(self):
        db.remove_session(SESSION_ID)
        db.remove_console(source=SOURCE, uuid=UUID)
        db.delete_source(SOURCE)

    def _mint(self, lifetime):
        """Mint a distinct ticket slowly, as a remote API call would."""
        with self.mint_lock:
            self.mints += 1
            ticket = 'minted-%d' % self.mints
        time.sleep(MINT_SECONDS)
        return MintedTicket(ticket, time.time() + lifetime)

    def _store(self, ticket, expires):
        with Session(self.engine) as session:
            row = session.query(db.ConsoleToken).\
                filter(db.ConsoleToken.session_id == SESSION_ID).one()
            row.backend_ticket = ticket
            row.backend_ticket_expires = expires
            session.commit()

    def _stored(self):
        with Session(self.engine) as session:
            row = session.query(db.ConsoleToken).\
                filter(db.ConsoleToken.session_id == SESSION_ID).one()
            return row.backend_ticket

    def _race(self):
        """Call session_ticket() from CHANNELS threads released together.

        Returns the ticket each thread got, or the exception it raised, by
        thread. Fails the test if any thread did not finish in time.
        """
        barrier = threading.Barrier(CHANNELS, timeout=BARRIER_TIMEOUT)
        results = [None] * CHANNELS

        def channel(index):
            try:
                barrier.wait()
                results[index] = db.session_ticket(
                    SESSION_ID, self._mint, LIFETIME, REUSE_MARGIN)
            except Exception as e:
                results[index] = e

        threads = [threading.Thread(target=channel, args=(i,), daemon=True)
                   for i in range(CHANNELS)]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + JOIN_TIMEOUT
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))

        self.assertEqual(
            [], [i for i, t in enumerate(threads) if t.is_alive()],
            'channels still running after %d seconds' % JOIN_TIMEOUT)
        return results

    def _assert_minted_once(self, results):
        """Assert that one mint served every channel.

        The mint count is checked first because it is the property under
        test. Without the row lock every channel mints, and what follows
        depends on the engine: each may store its own ticket, or the
        engine may refuse the later writes to a row changed since it was
        read.
        """
        self.assertEqual(1, self.mints,
                         'expected one mint for %d channels' % CHANNELS)

        errors = [r for r in results if isinstance(r, Exception)]
        self.assertEqual(
            [], errors, '%d of %d channels raised' % (len(errors), CHANNELS))

        self.assertEqual([MintedTicket] * CHANNELS, [type(r) for r in results])
        self.assertEqual(['minted-1'] * CHANNELS, [r.ticket for r in results])
        self.assertEqual(1, len(set(results)),
                         'channels got different expiries: %s' % results)
        self.assertEqual('minted-1', self._stored())

    def test_concurrent_channels_mint_once(self):
        self._assert_minted_once(self._race())

    def test_concurrent_channels_remint_once_inside_the_margin(self):
        self._store('nearly-gone', int(time.time()) + REUSE_MARGIN // 2)

        self._assert_minted_once(self._race())


if __name__ == '__main__':
    unittest.main()
