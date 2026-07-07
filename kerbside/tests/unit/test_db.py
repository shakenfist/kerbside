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
