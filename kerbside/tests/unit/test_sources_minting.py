import threading
import time
from unittest import mock

import testtools

from kerbside.sources import base
from kerbside.sources import minting


class MintWithDeadlineTestCase(testtools.TestCase):
    """mint_with_deadline() runs a driver on a worker which owns it."""

    def setUp(self):
        super().setUp()
        # Each event is (what, thread it happened on).
        self.events = []
        self.mint = lambda uuid, lifetime: base.MintedTicket(
            'a-ticket', 1000 + lifetime)
        self.close_error = None
        test = self

        class FakeDriver(base.BaseSource):
            MINTS_TICKETS = True

            def __init__(self, **kwargs):
                test.events.append(('init', threading.current_thread()))
                test.kwargs = kwargs

            def mint_console_ticket(self, uuid, lifetime):
                test.events.append(('mint', threading.current_thread()))
                return test.mint(uuid, lifetime)

            def close(self):
                test.events.append(('close', threading.current_thread()))
                if test.close_error:
                    raise test.close_error

        self.driver = FakeDriver

    def _mint(self, deadline=5):
        return minting.mint_with_deadline(
            self.driver, {'name': 'src', 'password': 'pw'}, 'u', 90,
            deadline)

    def test_returns_the_ticket_and_closes_on_the_worker(self):
        self.assertEqual(base.MintedTicket('a-ticket', 1090), self._mint())

        # The drivers read a source's name from 'source', as the scrape loop
        # passes it from sources.yaml, where a database row has 'name'.
        self.assertEqual('src', self.kwargs['source'])
        self.assertEqual('pw', self.kwargs['password'])
        self.assertEqual(['init', 'mint', 'close'],
                         [what for what, _ in self.events])
        # One worker, other than the caller, did all three.
        threads = {thread for _, thread in self.events}
        self.assertEqual(1, len(threads))
        self.assertNotIn(threading.current_thread(), threads)
        self.assertTrue(threads.pop().daemon)

    def test_a_mint_error_is_raised_and_the_driver_closed(self):
        error = RuntimeError('engine said no')

        def fail(uuid, lifetime):
            raise error
        self.mint = fail

        raised = self.assertRaises(RuntimeError, self._mint)
        self.assertIs(error, raised)
        self.assertEqual('close', self.events[-1][0])

    def test_an_errored_driver_is_not_asked_to_mint(self):
        class ErroredDriver(self.driver):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.errored = True
        self.driver = ErroredDriver

        self.assertRaises(minting.SourceErrored, self._mint)
        self.assertEqual(['init', 'close'],
                         [what for what, _ in self.events])

    def test_a_driver_which_cannot_be_built_is_raised(self):
        def broken(**kwargs):
            raise ValueError('bad source')
        self.driver = broken

        self.assertRaises(ValueError, self._mint)

    def test_a_close_failure_does_not_lose_the_ticket(self):
        self.close_error = OSError('ca file already gone')

        with mock.patch.object(minting, 'LOG') as mock_log:
            self.assertEqual('a-ticket', self._mint().ticket)

        logged = repr(mock_log.mock_calls)
        self.assertIn('OSError', logged)
        self.assertNotIn('ca file already gone', logged)

    def test_the_deadline_abandons_a_stuck_worker(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def stall(uuid, lifetime):
            release.wait(30)
            return base.MintedTicket('late-ticket', 0)
        self.mint = stall

        started = time.monotonic()
        raised = self.assertRaises(
            minting.MintDeadlineExceeded, self._mint, deadline=0.2)
        self.assertLess(time.monotonic() - started, 5)
        self.assertIsInstance(raised, base.ConsoleTicketUnavailable)
        # The caller did not close a driver its worker was still using.
        self.assertNotIn('close', [what for what, _ in self.events])

        # Released, the worker closes its own driver and exits, and its
        # ticket goes nowhere.
        release.set()
        worker = self.events[0][1]
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(worker.daemon)
        self.assertEqual(('close', worker), self.events[-1])
