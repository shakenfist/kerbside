from unittest import mock
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
import testtools

from kerbside import db


class SessionTerminationDbTestCase(testtools.TestCase):
    """Exercise the session_terminations helpers against a real (sqlite) DB.

    db.py talks to a module-level ENGINE; here it is pointed at an in-memory
    sqlite database with the ORM schema created, so the query logic (the
    terminated-and-live-here intersection, the TTL reap, idempotent insert)
    runs for real rather than being mocked.
    """

    def setUp(self):
        super().setUp()
        self.engine = create_engine('sqlite://')
        # Create only the tables these helpers touch. The full metadata cannot
        # be created under sqlite (auditevents uses a MySQL CURRENT_TIMESTAMP(6)
        # default sqlite cannot parse), and these two tables are all we need.
        db.Base.metadata.create_all(
            self.engine,
            tables=[db.SessionTermination.__table__, db.ProxyChannel.__table__])
        engine_patch = mock.patch.object(db, 'ENGINE', self.engine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)

    def _terminations(self):
        with Session(self.engine) as session:
            return session.query(db.SessionTermination).all()

    def test_request_session_termination_is_idempotent(self):
        db.request_session_termination('sess', reason='first')
        db.request_session_termination('sess', reason='second')

        rows = self._terminations()
        self.assertEqual(1, len(rows))
        self.assertEqual('sess', rows[0].session_id)
        # The reason is refreshed on the repeat request.
        self.assertEqual('second', rows[0].reason)

    def test_get_terminations_for_node_intersection(self):
        # Terminated AND live on this node -> returned.
        db.record_channel_info_by_ref(
            'node-a', 'ref-here', session_id='sess-here')
        # Terminated but only live on another node -> NOT returned for node-a.
        db.record_channel_info_by_ref(
            'node-b', 'ref-other', session_id='sess-other')
        # Live on this node but not terminated -> NOT returned.
        db.record_channel_info_by_ref(
            'node-a', 'ref-live', session_id='sess-live')

        db.request_session_termination('sess-here')
        db.request_session_termination('sess-other')
        # Terminated but not live anywhere (e.g. a merely-expired token) ->
        # NOT returned.
        db.request_session_termination('sess-nolive')

        self.assertEqual(['sess-here'], db.get_terminations_for_node('node-a'))

    def test_get_terminations_for_node_empty_when_no_live_channels(self):
        db.request_session_termination('sess')
        self.assertEqual([], db.get_terminations_for_node('node-a'))

    def test_reap_session_terminations_deletes_aged_rows(self):
        db.request_session_termination('old')
        db.request_session_termination('fresh')

        # Age the 'old' row well past the TTL.
        with Session(self.engine) as session:
            row = session.query(db.SessionTermination).\
                filter(db.SessionTermination.session_id == 'old').one()
            row.requested_at = time.time() - 10000
            session.commit()

        deleted = db.reap_session_terminations(300)
        self.assertEqual(1, deleted)

        remaining = [r.session_id for r in self._terminations()]
        self.assertEqual(['fresh'], remaining)


class SfTokenJtiDbTestCase(testtools.TestCase):
    """Exercise the sf_token_jtis helpers (single-use JWT tracking) against a
    real (sqlite) DB, matching SessionTerminationDbTestCase's approach.
    """

    def setUp(self):
        super().setUp()
        self.engine = create_engine('sqlite://')
        db.Base.metadata.create_all(
            self.engine, tables=[db.SfTokenJti.__table__])
        engine_patch = mock.patch.object(db, 'ENGINE', self.engine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)

    def _jtis(self):
        with Session(self.engine) as session:
            return session.query(db.SfTokenJti).all()

    def test_add_then_exists(self):
        self.assertFalse(db.sf_token_jti_exists('some-jti'))
        db.add_sf_token_jti('some-jti', time.time() + 300)
        self.assertTrue(db.sf_token_jti_exists('some-jti'))

    def test_add_duplicate_raises_reused_jti(self):
        db.add_sf_token_jti('dupe-jti', time.time() + 300)
        self.assertRaises(
            db.ReusedJti, db.add_sf_token_jti, 'dupe-jti', time.time() + 300)

    def test_reap_expired_sf_token_jtis_removes_expired_keeps_live(self):
        db.add_sf_token_jti('expired-jti', time.time() - 100)
        db.add_sf_token_jti('live-jti', time.time() + 300)

        reaped = db.reap_expired_sf_token_jtis()
        self.assertEqual(['expired-jti'], [r['jti'] for r in reaped])

        remaining = [r.jti for r in self._jtis()]
        self.assertEqual(['live-jti'], remaining)
        self.assertTrue(db.sf_token_jti_exists('live-jti'))
        self.assertFalse(db.sf_token_jti_exists('expired-jti'))


class SfTokenKeysDbTestCase(testtools.TestCase):
    """Exercise the sf_token_keys helpers (cached Shaken Fist signing keys)
    against a real (sqlite) DB, matching SessionTerminationDbTestCase's
    approach.
    """

    def setUp(self):
        super().setUp()
        self.engine = create_engine('sqlite://')
        db.Base.metadata.create_all(
            self.engine, tables=[db.SfTokenKeys.__table__])
        engine_patch = mock.patch.object(db, 'ENGINE', self.engine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)

    def test_get_sf_token_keys_returns_none_when_absent(self):
        self.assertIsNone(db.get_sf_token_keys('sf1'))

    def test_upsert_sf_token_keys_inserts_then_updates(self):
        first_fetch = time.time()
        db.upsert_sf_token_keys('sf1', '{"active_kid": "a"}', first_fetch)
        self.assertEqual(
            '{"active_kid": "a"}', db.get_sf_token_keys('sf1'))

        second_fetch = first_fetch + 60
        db.upsert_sf_token_keys('sf1', '{"active_kid": "b"}', second_fetch)
        self.assertEqual(
            '{"active_kid": "b"}', db.get_sf_token_keys('sf1'))

        # The upsert replaced the row rather than adding a second one.
        with Session(self.engine) as session:
            rows = session.query(db.SfTokenKeys).all()
        self.assertEqual(1, len(rows))
        self.assertEqual(second_fetch, rows[0].fetched_at)
