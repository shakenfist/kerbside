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
        # Each test starts with no console's worker running.
        patcher = mock.patch.object(minting, '_workers', {})
        patcher.start()
        self.addCleanup(patcher.stop)
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

    def _mint(self, deadline=5, uuid='u'):
        return minting.mint_with_deadline(
            self.driver, {'name': 'src', 'password': 'pw'}, uuid, 90,
            deadline)

    def _stall_first_mint(self):
        """Make the first mint wait for the returned event; others mint."""
        release = threading.Event()
        self.addCleanup(release.set)
        mints = []

        def stall_first(uuid, lifetime):
            mints.append(uuid)
            if len(mints) == 1:
                release.wait(30)
                return base.MintedTicket('late-ticket', 0)
            return base.MintedTicket('new-ticket', 1000 + lifetime)
        self.mint = stall_first
        return release

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

    def test_a_finished_mint_leaves_no_worker_registered(self):
        self._mint()
        self.assertEqual({}, minting._workers)

    def test_a_mint_waits_for_an_abandoned_worker_on_its_console(self):
        # An abandoned worker which finishes later sets the console's
        # password. A newer mint must set its own after that, or the
        # password the newer caller stores is not the hypervisor's.
        release = self._stall_first_mint()
        self.assertRaises(
            minting.MintDeadlineExceeded, self._mint, deadline=0.2)
        abandoned = self.events[0][1]

        threading.Timer(0.3, release.set).start()
        self.assertEqual('new-ticket', self._mint().ticket)

        self.assertFalse(abandoned.is_alive())
        whats = [what for what, _ in self.events]
        self.assertEqual(['init', 'mint', 'close', 'init', 'mint', 'close'],
                         whats)
        self.assertEqual({}, minting._workers)

    def test_a_still_running_worker_refuses_a_new_mint(self):
        self._stall_first_mint()
        self.assertRaises(
            minting.MintDeadlineExceeded, self._mint, deadline=0.2)

        with mock.patch.object(minting, 'LOG') as mock_log:
            started = time.monotonic()
            self.assertRaises(
                minting.MintDeadlineExceeded, self._mint, deadline=0.2)
        self.assertLess(time.monotonic() - started, 5)

        # The source was not asked again, so there is still one worker.
        self.assertEqual(['init', 'mint'], [what for what, _ in self.events])
        self.assertIn('still running', repr(mock_log.mock_calls))

    def test_another_console_is_not_held_up(self):
        self._stall_first_mint()
        self.assertRaises(
            minting.MintDeadlineExceeded, self._mint, deadline=0.2)

        self.assertEqual('new-ticket', self._mint(uuid='other').ticket)

    def test_a_worker_stuck_for_long_enough_stops_blocking(self):
        self._stall_first_mint()
        self.assertRaises(
            minting.MintDeadlineExceeded, self._mint, deadline=0.2)
        stuck = self.events[0][1]

        with mock.patch.object(minting, 'MINT_STUCK_AFTER', 0), \
                mock.patch.object(minting, 'LOG') as mock_log:
            self.assertEqual('new-ticket', self._mint().ticket)

        self.assertIn('stuck', repr(mock_log.mock_calls))
        self.assertTrue(stuck.is_alive())
        # The newer worker unregistered itself, and the stuck one is no
        # longer registered to hold up anything else.
        self.assertEqual({}, minting._workers)

    def test_a_stuck_worker_finishing_keeps_a_newer_one_registered(self):
        releases = []

        def stall(uuid, lifetime):
            release = threading.Event()
            self.addCleanup(release.set)
            releases.append(release)
            release.wait(30)
            return base.MintedTicket('late-ticket', 0)
        self.mint = stall

        self.assertRaises(
            minting.MintDeadlineExceeded, self._mint, deadline=0.2)
        with mock.patch.object(minting, 'MINT_STUCK_AFTER', 0):
            self.assertRaises(
                minting.MintDeadlineExceeded, self._mint, deadline=0.2)
        stuck, newer = self.events[0][1], self.events[2][1]
        self.assertIsNot(stuck, newer)

        releases[0].set()
        stuck.join(timeout=5)
        self.assertFalse(stuck.is_alive())
        # The newer worker is still running, so it still holds the console.
        self.assertIs(newer, minting._workers[('src', 'u')][0])
