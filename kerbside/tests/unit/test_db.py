import io
from unittest import mock
import time

from sqlalchemy import create_engine
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
import testtools

from kerbside import db
from kerbside import util
from kerbside.sources import static as static_source


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

    def test_concurrent_add_raises_reused_jti(self):
        # Issue #409. Two concurrent exchanges of one token can both look for
        # its jti before either has inserted it. Model the loser of that race
        # by hiding the winner's row from any lookup, so that only the primary
        # key stands between it and a second insert. That collision must
        # surface as ReusedJti, which the API turns into an audited 401,
        # rather than as an IntegrityError and a 500.
        expiry = time.time() + 300
        db.add_sf_token_jti('raced-jti', expiry)

        unseen = mock.MagicMock()
        unseen.filter.return_value.one.side_effect = (
            db.exc.NoResultFound())
        with mock.patch.object(Session, 'query', return_value=unseen):
            self.assertRaises(
                db.ReusedJti, db.add_sf_token_jti, 'raced-jti',
                time.time() + 600)

        rows = self._jtis()
        self.assertEqual(['raced-jti'], [r.jti for r in rows])
        self.assertEqual(expiry, rows[0].expiry)

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


class ConsoleKeyedOnSourceTestCase(testtools.TestCase):
    """Two sources publishing one identifier are two consoles (#468).

    The identifier is only unique within the source which published it,
    and a static source's identifiers are whatever the operator wrote.
    Keyed on the identifier alone, the second source overwrote the
    first's hypervisor and ports while the row kept the first's source,
    so a token issued for one console was relayed to the other.
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

        for source, ip, ticket in (('cloud', '10.0.0.1', 'cloud-ticket'),
                                   ('lab', '10.9.9.9', 'lab-ticket')):
            self.assertEqual(
                (db.CONSOLE_ADDED, []),
                db.add_console(
                    source=source, uuid='shared', hypervisor='hv',
                    hypervisor_ip=ip, insecure_port=5900, secure_port=None,
                    name=source, host_subject=None, ticket=ticket))

    def test_each_source_gets_its_own_console(self):
        cloud = db.get_console('cloud', 'shared', include_secrets=True)
        lab = db.get_console('lab', 'shared', include_secrets=True)

        self.assertEqual(('cloud', '10.0.0.1', 'cloud-ticket'),
                         (cloud['source'], cloud['hypervisor_ip'],
                          cloud['ticket']))
        self.assertEqual(('lab', '10.9.9.9', 'lab-ticket'),
                         (lab['source'], lab['hypervisor_ip'],
                          lab['ticket']))
        self.assertEqual(2, len(db.get_consoles(include_audit=False)))

    def test_lookup_under_another_source_finds_nothing(self):
        self.assertIsNone(db.get_console('elsewhere', 'shared'))

    def test_update_touches_only_its_own_source(self):
        self.assertEqual(
            (db.CONSOLE_UPDATED, ['hypervisor_ip']),
            db.add_console(
                source='lab', uuid='shared', hypervisor='hv',
                hypervisor_ip='10.9.9.10', insecure_port=5900,
                secure_port=None, name='lab', host_subject=None,
                ticket='lab-ticket'))

        self.assertEqual(
            '10.0.0.1', db.get_console('cloud', 'shared')['hypervisor_ip'])

    def test_store_ticket_touches_only_its_own_source(self):
        db.store_console_ticket('lab', 'shared', 'per-request')

        self.assertEqual(
            'cloud-ticket',
            db.get_console('cloud', 'shared', include_secrets=True)['ticket'])
        self.assertEqual(
            'per-request',
            db.get_console('lab', 'shared', include_secrets=True)['ticket'])

    def test_remove_touches_only_its_own_source(self):
        db.remove_console(source='lab', uuid='shared')

        self.assertIsNone(db.get_console('lab', 'shared'))
        self.assertIsNotNone(db.get_console('cloud', 'shared'))


class ConsoleTokenCascadeTestCase(testtools.TestCase):
    """remove_console() deletes the console's tokens through the database.

    It issues one bulk delete, with no ORM relationship, so the tokens go
    only because fk_consoletokens_console cascades -- and they must be
    only that console's: a reference to the identifier alone would also
    delete another source's tokens for the same identifier (#468).
    SQLite enforces foreign keys only when asked, so this engine asks.
    """

    def setUp(self):
        super().setUp()
        self.engine = create_engine('sqlite://')
        event.listen(
            self.engine, 'connect',
            lambda conn, _: conn.execute('PRAGMA foreign_keys=ON'))
        db.Base.metadata.create_all(
            self.engine,
            tables=[db.Console.__table__, db.ConsoleToken.__table__])
        engine_patch = mock.patch.object(db, 'ENGINE', self.engine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)

        for source in ('cloud', 'lab'):
            db.add_console(
                source=source, uuid='shared', hypervisor='hv',
                hypervisor_ip='10.0.0.1', insecure_port=5900,
                secure_port=None, name=source, host_subject=None,
                ticket='ticket')
            db.add_token('%s-token' % source, None, source, 'shared',
                         0, 2 ** 31)

    def test_remove_deletes_only_that_consoles_tokens(self):
        db.remove_console(source='lab', uuid='shared')

        self.assertEqual([], db.get_tokens_by_console('lab', 'shared'))
        self.assertEqual(
            ['cloud-token'],
            [t['token'] for t in db.get_tokens_by_console('cloud', 'shared')])

    def test_a_token_needs_its_console(self):
        self.assertRaises(
            IntegrityError, db.add_token, 'orphan', None, 'elsewhere',
            'shared', 0, 2 ** 31)


class StaticSourceRoundTripTestCase(testtools.TestCase):
    """A static entry must read back as unchanged on the next pass.

    YAML types an unquoted 123456 as an int and a quoted "5910" as a
    str, where the database returns the column's type. util.load_sources()
    reads both as text and the static source makes the port an int;
    unnormalised, each would be reported as changed and audited on every
    60 second pass, forever.
    """

    def setUp(self):
        super().setUp()
        self.engine = create_engine('sqlite://')
        db.Base.metadata.create_all(
            self.engine, tables=[db.Console.__table__])
        engine_patch = mock.patch.object(db, 'ENGINE', self.engine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)

    def test_yaml_typed_entry_is_stable_across_passes(self):
        text = (
            '- source: lab\n'
            '  type: static\n'
            '  consoles:\n'
            '    - {uuid: 1001, name: 4, hypervisor: bench,\n'
            '       hypervisor_ip: 10.0.0.1, insecure_port: 5910,\n'
            '       secure_port: "5911", ticket: 012345, host_subject: null}\n')
        results = []
        for _ in range(2):
            source = static_source.StaticSource(
                **util.load_sources(io.StringIO(text))[0])
            self.assertFalse(source.errored)
            for console in source():
                results.append(db.add_console(**console))

        self.assertEqual(
            [(db.CONSOLE_ADDED, []), (db.CONSOLE_UPDATED, [])], results)


class AddConsoleUpdateTestCase(testtools.TestCase):
    """Pin which fields add_console() refreshes on an existing console.

    The update branch assigns every mutable field, and the ticket too
    when the caller supplies one (issue #463), and reports the
    names of the fields that changed (issue #459). A caller which passes
    no ticket -- every driver but the static one -- must leave the
    stored ticket alone, because oVirt writes a per-request ticket to
    the same column and the next maintenance pass would erase it.
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

    def test_insert_then_update_refreshes_every_field(self):
        self.assertEqual((db.CONSOLE_ADDED, []), self._add())
        self.assertEqual('first-password', self._console().ticket)

        self.assertEqual(
            (db.CONSOLE_UPDATED,
             ['host_subject', 'hypervisor', 'hypervisor_ip',
              'insecure_port', 'name', 'secure_port', 'ticket']),
            self._add(
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
        self.assertEqual('second-password', console.ticket)

    def test_unchanged_console_reports_no_fields(self):
        # Every maintenance pass re-sees every console; only a real
        # edit may be reported, or the log fills with noise (#459).
        self.assertEqual((db.CONSOLE_ADDED, []), self._add())
        self.assertEqual((db.CONSOLE_UPDATED, []), self._add())

    def test_changed_fields_are_named_individually(self):
        self.assertEqual((db.CONSOLE_ADDED, []), self._add())
        self.assertEqual(
            (db.CONSOLE_UPDATED, ['insecure_port', 'name']),
            self._add(name='second name', insecure_port=5901))
        self.assertEqual('first-password', self._console().ticket)

    def test_absent_ticket_leaves_the_stored_one_alone(self):
        # The oVirt shape: enumeration yields no ticket, and the .vv
        # handler stores a fresh one per request. Not supplying one is
        # not a change to it either.
        self.assertEqual((db.CONSOLE_ADDED, []), self._add(ticket=None))
        db.store_console_ticket('lab', 'console-1', 'per-request')

        self.assertEqual((db.CONSOLE_UPDATED, []), self._add(ticket=None))
        self.assertEqual('per-request', self._console().ticket)
