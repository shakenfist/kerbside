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


class SourceSecretsDbTestCase(testtools.TestCase):
    """The database layer decides what a source looks like to a caller.

    Issue #132: two API handlers each had to remember to strip the
    backend cloud password, and one of them did not. get_source() and
    get_sources() now return the non-secret representation by default,
    so forgetting means returning less, not leaking more.
    """

    def setUp(self):
        super().setUp()
        self.engine = create_engine('sqlite://')
        db.Base.metadata.create_all(
            self.engine, tables=[db.Source.__table__])
        engine_patch = mock.patch.object(db, 'ENGINE', self.engine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)

        db.add_source(
            'sf1', 'shakenfist', 'https://sf.example.com/api', 'sfvdi',
            'sekrit-source-password', ca_cert='CA-CERT-MARKER')

    def test_get_source_omits_secrets_by_default(self):
        source = db.get_source('sf1')

        self.assertNotIn('password', source)
        self.assertEqual('sf1', source['name'])

    def test_get_source_with_secrets_is_opt_in(self):
        source = db.get_source('sf1', include_secrets=True)

        self.assertEqual('sekrit-source-password', source['password'])

    def test_get_sources_omits_secrets_by_default(self):
        sources = db.get_sources()

        self.assertEqual(1, len(sources))
        self.assertNotIn('password', sources[0])

    def test_get_sources_with_secrets_is_opt_in(self):
        sources = db.get_sources(include_secrets=True)

        self.assertEqual('sekrit-source-password', sources[0]['password'])

    def test_public_export_keeps_the_non_secret_fields(self):
        # ca_cert is the public half of the backend's TLS identity, not
        # a credential, and the sources page renders it. url and
        # username are retained because the list endpoint has always
        # returned them and removing them is a separate decision.
        source = db.get_source('sf1')

        self.assertEqual('CA-CERT-MARKER', source['ca_cert'])
        self.assertEqual('https://sf.example.com/api', source['url'])
        self.assertEqual('sfvdi', source['username'])

    def test_public_export_is_exactly_this_field_set(self):
        # Pinned rather than derived from SOURCE_PUBLIC_FIELDS on
        # purpose. A test which walks the same list the code walks
        # agrees with whatever the code does, including being wrong;
        # this one fails when a column starts being returned to API
        # clients, and the way to make it pass is to decide that it
        # should be.
        source = db.get_source('sf1')

        self.assertEqual(
            ['ca_cert', 'deleted', 'errored', 'last_seen', 'name',
             'project_domain_id', 'project_name', 'seen_by', 'type', 'url',
             'user_domain_id', 'username'],
            sorted(source.keys()))

    def test_every_exported_field_is_classified(self):
        # The pair above and below this one only see fields somebody
        # has already thought about. This one sees the fields nobody
        # has: a column added to export() and to neither list fails
        # here, which is the failure mode of issue #132.
        exported = set(db.get_source('sf1', include_secrets=True).keys())
        classified = (set(db.SOURCE_PUBLIC_FIELDS) |
                      set(db.SOURCE_SECRET_FIELDS))

        self.assertEqual(set(), exported - classified,
                         'exported source fields are neither public nor '
                         'secret')
        self.assertEqual(set(), classified - exported,
                         'classified source fields are not exported at all')

    def test_secret_fields_are_never_public(self):
        self.assertEqual(
            set(),
            set(db.SOURCE_PUBLIC_FIELDS) & set(db.SOURCE_SECRET_FIELDS))

    def test_get_source_returns_none_when_absent(self):
        self.assertIsNone(db.get_source('nosuch'))


class ConsoleSecretsDbTestCase(testtools.TestCase):
    """The database layer decides what a console looks like too.

    The source fix left console tickets being stripped by each handler
    which returned one, which is structurally the same arrangement that
    produced #132. get_console() and get_consoles() now return the
    non-secret representation by default, and the two callers which
    spend the ticket opt in.
    """

    def setUp(self):
        super().setUp()
        self.engine = create_engine('sqlite://')
        db.Base.metadata.create_all(
            self.engine,
            tables=[db.Console.__table__, db.ConsoleToken.__table__,
                    db.ProxyChannel.__table__])
        engine_patch = mock.patch.object(db, 'ENGINE', self.engine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)

        db.add_console(
            source='sf1', uuid='console-1', hypervisor='hv1',
            hypervisor_ip='10.0.0.1', insecure_port=5900, secure_port=5901,
            name='a console', host_subject='CN=hv1',
            ticket='sekrit-hypervisor-ticket')

    def test_get_console_omits_secrets_by_default(self):
        console = db.get_console('sf1', 'console-1')

        self.assertNotIn('ticket', console)
        self.assertEqual('console-1', console['uuid'])

    def test_get_console_with_secrets_is_opt_in(self):
        console = db.get_console('sf1', 'console-1', include_secrets=True)

        self.assertEqual('sekrit-hypervisor-ticket', console['ticket'])

    def test_get_console_detailed_omits_secrets_by_default(self):
        # detailed=True takes a different path through get_console(),
        # so it gets its own assertion rather than being assumed.
        console = db.get_console('sf1', 'console-1', detailed=True)

        self.assertNotIn('ticket', console)
        self.assertEqual([], console['sessions'])

    def test_get_consoles_omits_secrets_by_default(self):
        # include_audit=False because the auditevents table's schema
        # does not create under sqlite; the audit scan is orthogonal to
        # what a console dict contains.
        consoles = db.get_consoles(include_audit=False)

        self.assertEqual(1, len(consoles))
        self.assertNotIn('ticket', consoles[0])

    def test_get_consoles_with_secrets_is_opt_in(self):
        consoles = db.get_consoles(
            include_audit=False, include_secrets=True)

        self.assertEqual('sekrit-hypervisor-ticket', consoles[0]['ticket'])

    def test_public_export_is_exactly_this_field_set(self):
        # Pinned rather than derived from CONSOLE_PUBLIC_FIELDS, for
        # the same reason as the source equivalent above: a test which
        # walks the same list the code walks agrees with the code even
        # when the code is wrong.
        console = db.get_console('sf1', 'console-1')

        self.assertEqual(
            ['discovered', 'host_subject', 'hypervisor', 'hypervisor_ip',
             'insecure_port', 'name', 'secure_port', 'source', 'uuid'],
            sorted(console.keys()))

    def test_every_exported_field_is_classified(self):
        exported = set(
            db.get_console('sf1', 'console-1', include_secrets=True).keys())
        classified = (set(db.CONSOLE_PUBLIC_FIELDS) |
                      set(db.CONSOLE_SECRET_FIELDS))

        self.assertEqual(set(), exported - classified,
                         'exported console fields are neither public nor '
                         'secret')
        self.assertEqual(set(), classified - exported,
                         'classified console fields are not exported at all')

    def test_secret_fields_are_never_public(self):
        self.assertEqual(
            set(),
            set(db.CONSOLE_PUBLIC_FIELDS) & set(db.CONSOLE_SECRET_FIELDS))

    def test_get_console_returns_none_when_absent(self):
        self.assertIsNone(db.get_console('sf1', 'nosuch'))


class AddConsoleUpdateTestCase(testtools.TestCase):
    """Pin which fields add_console() refreshes on an existing console.

    This is a change detector, deliberately. The update branch assigns
    every mutable field except the ticket, which is set only when the
    row is first inserted, and three documents now state that as a
    property an operator has to work around: the standalone use case
    page, the static source section of docs/console-sources.md, and
    the header comment in kerbside/sources/static.py. Issue #463 is
    open to make the update branch carry the ticket like everything
    else.

    So the assertion below is not an endorsement. It exists so that
    fixing #463 fails here rather than silently falsifying all three
    documents, and so that someone extending the update branch cannot
    quietly leave a new field out the way the ticket was left out.
    """

    def setUp(self):
        super().setUp()
        self.engine = create_engine('sqlite://')
        db.Base.metadata.create_all(
            self.engine, tables=[db.Console.__table__])
        engine_patch = mock.patch.object(db, 'ENGINE', self.engine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)

    def _console(self, uuid='console-1'):
        with Session(self.engine) as session:
            return session.query(db.Console).filter(
                db.Console.uuid == uuid).one()

    def _add(self, **overrides):
        kwargs = {
            'source': 'lab',
            'uuid': 'console-1',
            'hypervisor': 'bench',
            'hypervisor_ip': '10.0.0.1',
            'insecure_port': 5900,
            'secure_port': None,
            'name': 'first name',
            'host_subject': None,
            'ticket': 'first-password',
        }
        kwargs.update(overrides)
        return db.add_console(**kwargs)

    def test_insert_then_update_keeps_the_original_ticket(self):
        self.assertTrue(self._add())
        self.assertEqual('first-password', self._console().ticket)

        # Every field the caller passes changes, except the ticket.
        self.assertFalse(self._add(
            hypervisor='bench2', hypervisor_ip='10.0.0.2',
            insecure_port=5901, secure_port=5902, name='second name',
            host_subject='CN=bench2', ticket='second-password'))

        console = self._console()
        self.assertEqual('bench2', console.hypervisor)
        self.assertEqual('10.0.0.2', console.hypervisor_ip)
        self.assertEqual(5901, console.insecure_port)
        self.assertEqual(5902, console.secure_port)
        self.assertEqual('second name', console.name)
        self.assertEqual('CN=bench2', console.host_subject)

        # The documented gap, issue #463. When this assertion fails
        # because #463 has been fixed, update the three documents named
        # in this class's docstring before changing it.
        self.assertEqual('first-password', console.ticket)

    def test_add_console_reports_whether_it_inserted(self):
        self.assertTrue(self._add())
        self.assertFalse(self._add())
