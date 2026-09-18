import json
import os
from sqlalchemy import create_engine
import tempfile
import time
from unittest import mock
import testtools

from kerbside import api
from kerbside import db
from kerbside import sf_token


class GetNavItemsTestCase(testtools.TestCase):
    """Unit tests for api.get_nav_items(), a pure function with no Flask
    or database dependency, so it is exercised directly rather than
    through the test client the other classes here use.

    This is the guard for a defect the sfui conversion fixed:
    ConsolesAudit.get() used to pass 'Audit', a name that never appears
    in base_navitems, so nothing was ever marked active on the audit
    page. A name that is not in the list must leave every item
    inactive rather than silently matching nothing -- these tests would
    have caught that.
    """

    def test_named_section_is_the_only_one_active(self):
        for current in ('Sources', 'Consoles', 'Sessions'):
            navitems = api.get_nav_items(current)

            active = [item['name'] for item in navitems if item['active']]
            self.assertEqual([current], active)

    def test_unknown_name_leaves_every_item_inactive(self):
        navitems = api.get_nav_items('Audit')

        self.assertEqual(
            [], [item['name'] for item in navitems if item['active']])

    def test_none_leaves_every_item_inactive(self):
        navitems = api.get_nav_items(None)

        self.assertEqual(
            [], [item['name'] for item in navitems if item['active']])


class TerminateApiTestCase(testtools.TestCase):
    """The terminate endpoints must ADD a session-termination intent alongside
    removing the token, so in-flight connections get dropped.

    Driven through the Flask test client with JWT verification stubbed and the
    db layer mocked, so no real database or auth is required.
    """

    def setUp(self):
        super().setUp()
        api.app.config['TESTING'] = True
        self.client = api.app.test_client()
        jwt_patch = mock.patch(
            'kerbside.api.verify_jwt_in_request', return_value=(None, {}))
        jwt_patch.start()
        self.addCleanup(jwt_patch.stop)

    @mock.patch('kerbside.db.request_session_termination')
    @mock.patch('kerbside.db.add_audit_event')
    @mock.patch('kerbside.db.remove_session')
    @mock.patch('kerbside.db.get_tokens_by_console')
    def test_consoles_terminate_writes_intent(
            self, mock_get_tokens, mock_remove, mock_audit, mock_request):
        mock_get_tokens.return_value = [{
            'token': 'tok', 'session_id': 'sess-1', 'source': 'src',
            'uuid': 'u'}]

        resp = self.client.post(
            '/console/src/u/terminate',
            headers={'Accept': 'application/json'})

        self.assertEqual(200, resp.status_code)
        # The token is removed (blocks new connections)...
        mock_remove.assert_called_once_with('sess-1')
        # ...and an intent row is written for the terminated session (drops
        # in-flight connections).
        mock_request.assert_called_once_with('sess-1', reason=mock.ANY)

    @mock.patch('kerbside.db.request_session_termination')
    @mock.patch('kerbside.db.add_audit_event')
    @mock.patch('kerbside.db.remove_session')
    @mock.patch('kerbside.db.get_token_by_session_id')
    def test_session_terminate_writes_intent(
            self, mock_get_token, mock_remove, mock_audit, mock_request):
        mock_get_token.return_value = {
            'token': 'tok', 'session_id': 'sess-2', 'source': 'src',
            'uuid': 'u'}

        resp = self.client.post(
            '/session/sess-2/terminate',
            headers={'Accept': 'application/json'})

        self.assertEqual(200, resp.status_code)
        mock_remove.assert_called_once_with('sess-2')
        mock_request.assert_called_once_with('sess-2', reason=mock.ANY)

    # These two are the falsifiable proof that the terminate verbs actually
    # moved. A GET carrying a cookie borne JWT is not covered by
    # flask-jwt-extended's CSRF check, which is the blind CSRF of issue #133,
    # so the routes must refuse GET outright rather than merely also accepting
    # POST. The db calls are mocked so that a regression fails as 200 != 405
    # rather than as a database error.
    @mock.patch('kerbside.db.request_session_termination')
    @mock.patch('kerbside.db.add_audit_event')
    @mock.patch('kerbside.db.remove_session')
    @mock.patch('kerbside.db.get_tokens_by_console')
    def test_consoles_terminate_rejects_get(
            self, mock_get_tokens, mock_remove, mock_audit, mock_request):
        mock_get_tokens.return_value = [{
            'token': 'tok', 'session_id': 'sess-1', 'source': 'src',
            'uuid': 'u'}]

        resp = self.client.get(
            '/console/src/u/terminate',
            headers={'Accept': 'application/json'})

        self.assertEqual(405, resp.status_code)
        mock_request.assert_not_called()

    @mock.patch('kerbside.db.request_session_termination')
    @mock.patch('kerbside.db.add_audit_event')
    @mock.patch('kerbside.db.remove_session')
    @mock.patch('kerbside.db.get_token_by_session_id')
    def test_session_terminate_rejects_get(
            self, mock_get_token, mock_remove, mock_audit, mock_request):
        mock_get_token.return_value = {
            'token': 'tok', 'session_id': 'sess-2', 'source': 'src',
            'uuid': 'u'}

        resp = self.client.get(
            '/session/sess-2/terminate',
            headers={'Accept': 'application/json'})

        self.assertEqual(405, resp.status_code)
        mock_request.assert_not_called()


class SfTokenApiTestCase(testtools.TestCase):
    """Endpoint-level tests for /sf-console.vv (matrix cells 8-10: replay,
    unscraped console, and a genuine end-to-end valid exchange).

    sf_token.verify_sf_token's own adversarial matrix (valid/expired/wrong
    aud/forged signature/unknown kid) is covered in isolation by
    test_sf_token.py; here it is mocked to a fixed claims dict so these
    tests are only about the endpoint's replay/lookup/issuance logic, driven
    through the Flask test client as TerminateApiTestCase above does.
    """

    def setUp(self):
        super().setUp()
        api.app.config['TESTING'] = True
        self.client = api.app.test_client()

        # SfToken.get() unconditionally reads config.CACERT_PATH to embed in
        # the .vv; point it at a temp file so that read succeeds.
        cacert_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.pem', delete=False)
        cacert_file.write(
            '-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n')
        cacert_file.close()
        self.addCleanup(os.unlink, cacert_file.name)
        cacert_patch = mock.patch.object(
            api.config, 'CACERT_PATH', cacert_file.name)
        cacert_patch.start()
        self.addCleanup(cacert_patch.stop)

        self.claims = {
            'source': 'sf1', 'sub': 'console-uuid', 'jti': 'jti-1',
            'exp': int(time.time()) + 300,
        }
        verify_patch = mock.patch(
            'kerbside.api.sf_token.verify_sf_token', return_value=self.claims)
        self.mock_verify = verify_patch.start()
        self.addCleanup(verify_patch.stop)

    # --- 8. replay -----------------------------------------------------

    @mock.patch('kerbside.api.db.add_audit_event')
    @mock.patch('kerbside.api.db.sf_token_jti_exists', return_value=True)
    def test_replayed_jti_rejected(self, mock_exists, mock_audit):
        resp = self.client.get('/sf-console.vv?token=some.jwt.value')

        self.assertEqual(401, resp.status_code)
        self.assertEqual(
            'token already used', resp.get_json()['error'])
        mock_exists.assert_called_once_with('jti-1')

    # --- 9. unscraped console --------------------------------------------

    @mock.patch('kerbside.api.db.add_audit_event')
    @mock.patch('kerbside.api.db.get_console', return_value=None)
    @mock.patch('kerbside.api.db.add_sf_token_jti')
    @mock.patch('kerbside.api.db.sf_token_jti_exists', return_value=False)
    def test_unscraped_console_returns_404(
            self, mock_exists, mock_add_jti, mock_get_console, mock_audit):
        resp = self.client.get('/sf-console.vv?token=some.jwt.value')

        self.assertEqual(404, resp.status_code)
        self.assertEqual('console not found', resp.get_json()['error'])
        mock_get_console.assert_called_once_with('sf1', 'console-uuid')
        # The single-use jti must NOT be consumed on the 404 path, so a retry
        # after the console is scraped can still succeed.
        mock_add_jti.assert_not_called()

    # --- 10. valid end-to-end exchange -----------------------------------

    @mock.patch('kerbside.api.db.add_audit_event')
    @mock.patch('kerbside.api.consoletoken.create_token')
    @mock.patch('kerbside.api.db.get_console')
    @mock.patch('kerbside.api.db.add_sf_token_jti')
    @mock.patch('kerbside.api.db.sf_token_jti_exists', return_value=False)
    def test_valid_exchange_returns_vv_with_consoletoken(
            self, mock_exists, mock_add_jti, mock_get_console,
            mock_create_token, mock_audit):
        mock_get_console.return_value = {
            'source': 'sf1', 'uuid': 'console-uuid'}
        mock_create_token.return_value = {
            'token': 'minted-consoletoken-not-the-jwt',
            'session_id': 'sess-1'}

        resp = self.client.get('/sf-console.vv?token=some.jwt.value')

        self.assertEqual(200, resp.status_code)
        self.assertEqual(
            'application/x-virt-viewer;charset=UTF-8', resp.content_type)

        body = resp.get_data(as_text=True)
        self.assertTrue(body.startswith('[virt-viewer]'))
        # The password is the freshly minted kerbside consoletoken, NOT the
        # JWT that was exchanged for it.
        self.assertIn('password=minted-consoletoken-not-the-jwt', body)
        self.assertNotIn('some.jwt.value', body)

        # The jti is now recorded as used.
        mock_add_jti.assert_called_once_with('jti-1', self.claims['exp'])
        mock_create_token.assert_called_once_with('sf1', 'console-uuid')

    # --- 12. pre-verification rejections are logged, never audited -------

    @mock.patch('kerbside.api.db.add_audit_event')
    def test_malformed_token_writes_no_audit_event(self, mock_audit):
        # /sf-console.vv is unauthenticated by design and this rejection
        # happens before any signature check, so anyone can drive it with a
        # single round trip. An audit row here is an unbounded
        # unauthenticated write into a table nothing reaps.
        self.mock_verify.side_effect = sf_token.Malformed('nope')

        resp = self.client.get('/sf-console.vv?token=not-a-jwt')

        self.assertEqual(401, resp.status_code)
        self.assertEqual('malformed token', resp.get_json()['error'])
        mock_audit.assert_not_called()

    @mock.patch('kerbside.api.db.add_audit_event')
    def test_no_pre_verification_rejection_writes_an_audit_event(
            self, mock_audit):
        # Every arm of the verification try/except, not just the malformed
        # one -- they are all reachable without a credential.
        for error, message in [
                (sf_token.Malformed, 'malformed token'),
                (sf_token.UnknownKid, 'unknown signing key'),
                (sf_token.BadSignature, 'invalid token signature'),
                (sf_token.Expired, 'token expired'),
                (sf_token.WrongAudience, 'token audience rejected'),
                (sf_token.SfTokenError, 'token rejected')]:
            self.mock_verify.side_effect = error('nope')

            resp = self.client.get('/sf-console.vv?token=some.jwt.value')

            self.assertEqual(401, resp.status_code)
            self.assertEqual(message, resp.get_json()['error'])

        mock_audit.assert_not_called()

    @mock.patch('kerbside.api.db.add_audit_event')
    @mock.patch('kerbside.api.db.sf_token_jti_exists', return_value=True)
    def test_replayed_jti_still_writes_an_audit_event(
            self, mock_exists, mock_audit):
        # The other half of the contract: a POST-verification rejection has
        # a verified source and console uuid to attribute, and costs an
        # attacker a validly signed single-use token to provoke, so it
        # stays audited.
        resp = self.client.get('/sf-console.vv?token=some.jwt.value')

        self.assertEqual(401, resp.status_code)
        mock_audit.assert_called_once_with(
            'sf1', 'console-uuid', None, None, None, None,
            'Rejected Shaken Fist console token: token already used')

    @mock.patch('kerbside.api.db.add_audit_event')
    @mock.patch('kerbside.api.db.get_console', return_value=None)
    @mock.patch('kerbside.api.db.add_sf_token_jti')
    @mock.patch('kerbside.api.db.sf_token_jti_exists', return_value=False)
    def test_unknown_console_still_writes_an_audit_event(
            self, mock_exists, mock_add_jti, mock_get_console, mock_audit):
        resp = self.client.get('/sf-console.vv?token=some.jwt.value')

        self.assertEqual(404, resp.status_code)
        mock_audit.assert_called_once_with(
            'sf1', 'console-uuid', None, None, None, None,
            'Rejected Shaken Fist console token: console not found')

    # --- 11. 404 does not burn the jti; a later retry succeeds -----------

    @mock.patch('kerbside.api.db.add_audit_event')
    @mock.patch('kerbside.api.consoletoken.create_token')
    @mock.patch('kerbside.api.db.get_console')
    @mock.patch('kerbside.api.db.add_sf_token_jti')
    @mock.patch('kerbside.api.db.sf_token_jti_exists', return_value=False)
    def test_404_does_not_burn_jti_retry_succeeds(
            self, mock_exists, mock_add_jti, mock_get_console,
            mock_create_token, mock_audit):
        mock_create_token.return_value = {
            'token': 'minted-consoletoken', 'session_id': 'sess-1'}

        # First attempt: console not yet scraped -> 404, jti NOT consumed.
        mock_get_console.return_value = None
        resp = self.client.get('/sf-console.vv?token=some.jwt.value')
        self.assertEqual(404, resp.status_code)
        mock_add_jti.assert_not_called()

        # Second attempt after the next scrape lands the console: the same
        # token now exchanges successfully because its jti was never burned.
        mock_get_console.return_value = {
            'source': 'sf1', 'uuid': 'console-uuid'}
        resp = self.client.get('/sf-console.vv?token=some.jwt.value')
        self.assertEqual(200, resp.status_code)
        mock_add_jti.assert_called_once_with('jti-1', self.claims['exp'])


class SourceApiSecretsTestCase(testtools.TestCase):
    """The source endpoints must never disclose a backend credential.

    Issue #132: the list endpoint stripped the password in the handler
    and the single source endpoint forgot to, so any JWT holder could
    read the management plane credentials of any configured source.
    The strip now lives in db.get_source()/db.get_sources(), so these
    tests drive the real database layer through the Flask client rather
    than mocking it -- a mocked db would only prove the handler passes
    through whatever it is handed, which is exactly the thing that went
    wrong.
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

        api.app.config['TESTING'] = True
        self.client = api.app.test_client()
        jwt_patch = mock.patch(
            'kerbside.api.verify_jwt_in_request', return_value=(None, {}))
        jwt_patch.start()
        self.addCleanup(jwt_patch.stop)

    def test_single_source_does_not_disclose_the_password(self):
        resp = self.client.get(
            '/source/sf1', headers={'Accept': 'application/json'})

        self.assertEqual(200, resp.status_code)
        self.assertNotIn('sekrit-source-password', resp.get_data(as_text=True))
        source = json.loads(resp.get_data(as_text=True))
        self.assertNotIn('password', source)
        # ...but the source is still described.
        self.assertEqual('sf1', source['name'])
        self.assertEqual('shakenfist', source['type'])

    def test_source_list_does_not_disclose_the_password(self):
        resp = self.client.get(
            '/source', headers={'Accept': 'application/json'})

        self.assertEqual(200, resp.status_code)
        self.assertNotIn('sekrit-source-password', resp.get_data(as_text=True))
        sources = json.loads(resp.get_data(as_text=True))
        self.assertEqual(1, len(sources))
        self.assertNotIn('password', sources[0])

    def test_both_endpoints_return_the_same_fields(self):
        # The two handlers drifting apart is the bug, so assert they
        # cannot: whatever one of them exposes, the other exposes too.
        # This is about the shape of a source, not about which sources
        # each endpoint returns -- see the soft delete test below.
        single = json.loads(self.client.get(
            '/source/sf1',
            headers={'Accept': 'application/json'}).get_data(as_text=True))
        listed = json.loads(self.client.get(
            '/source',
            headers={'Accept': 'application/json'}).get_data(as_text=True))

        self.assertEqual(sorted(single.keys()), sorted(listed[0].keys()))

    def test_unknown_source_is_a_404(self):
        resp = self.client.get(
            '/source/nosuch', headers={'Accept': 'application/json'})

        self.assertEqual(404, resp.status_code)

    def test_soft_deleted_source_is_described_but_not_listed(self):
        # The two endpoints agree on what a source looks like but not
        # on which sources exist: a source dropped from sources.yaml is
        # soft deleted, which removes it from the list and leaves it
        # readable by name. Pinned because it is surprising, and
        # because the thing which must not vary -- the password staying
        # out of the response -- is asserted for this row too.
        db.delete_source('sf1')

        listed = json.loads(self.client.get(
            '/source',
            headers={'Accept': 'application/json'}).get_data(as_text=True))
        self.assertEqual([], listed)

        resp = self.client.get(
            '/source/sf1', headers={'Accept': 'application/json'})
        self.assertEqual(200, resp.status_code)
        self.assertNotIn('sekrit-source-password', resp.get_data(as_text=True))
        source = json.loads(resp.get_data(as_text=True))
        self.assertTrue(source['deleted'])
        self.assertNotIn('password', source)


class VirtViewerSecretsTestCase(testtools.TestCase):
    """The .vv handlers hold a credential only when they spend one.

    ConsolesDirectVirtViewer.get() used to log the whole source dict,
    password included, on every request. Both handlers now fetch the
    public source and re-fetch with include_secrets=True inside the
    oVirt branch, which is the only branch that authenticates to a
    backend, so there is nothing to remember to scrub on the way out.
    """

    def setUp(self):
        super().setUp()

        self.engine = create_engine('sqlite://')
        db.Base.metadata.create_all(
            self.engine, tables=[db.Source.__table__, db.Console.__table__])
        engine_patch = mock.patch.object(db, 'ENGINE', self.engine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)

        db.add_source(
            'sf1', 'shakenfist', 'https://sf.example.com/api', 'sfvdi',
            'sekrit-source-password', ca_cert='CA-CERT-MARKER')
        db.add_console(
            source='sf1', uuid='console-1', hypervisor='hv1',
            hypervisor_ip='10.0.0.1', insecure_port=5900, secure_port=5901,
            name='a console', host_subject='CN=hv1')

        api.app.config['TESTING'] = True
        self.client = api.app.test_client()
        jwt_patch = mock.patch(
            'kerbside.api.verify_jwt_in_request', return_value=(None, {}))
        jwt_patch.start()
        self.addCleanup(jwt_patch.stop)

        config_patch = mock.patch.object(api.config, 'CACERT_PATH', None)
        config_patch.start()
        self.addCleanup(config_patch.stop)

        # The proxy handler reads the CA unconditionally, so it needs a
        # real file where the direct handler is happy with None.
        cacert = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
        cacert.write(b'CA-CERT-MARKER\n')
        cacert.close()
        self.cacert_path = cacert.name
        self.addCleanup(os.unlink, self.cacert_path)

        self.logged = []
        log_patch = mock.patch.object(api, 'LOG', self._recording_log())
        log_patch.start()
        self.addCleanup(log_patch.stop)

    def _recording_log(self):
        """A LOG stand in which remembers every field it is given."""
        recorder = self

        class RecordingLog:
            def with_fields(self, fields):
                recorder.logged.append(fields)
                return self

            def info(self, *args, **kwargs):
                ...

            def warning(self, *args, **kwargs):
                ...

            def error(self, *args, **kwargs):
                ...

        return RecordingLog()

    def test_direct_vv_does_not_log_the_password(self):
        resp = self.client.get('/console/direct/sf1/console-1/console.vv')

        self.assertEqual(200, resp.status_code)
        self.assertNotIn('sekrit-source-password', resp.get_data(as_text=True))
        for fields in self.logged:
            self.assertNotIn('password', fields)
            self.assertNotIn('sekrit-source-password', repr(fields))

    def test_direct_vv_does_not_log_the_console_ticket(self):
        # The same log line carries the console dict, and for a static
        # source the ticket in it is the SPICE password this handler is
        # about to write into the .vv file. It legitimately appears in
        # the response body, so only the log fields are asserted on.
        db.add_source(
            'static1', 'static', None, None, None, ca_cert=None)
        db.add_console(
            source='static1', uuid='console-3', hypervisor='hv3',
            hypervisor_ip='10.0.0.3', insecure_port=5900, secure_port=5901,
            name='a static console', host_subject='CN=hv3',
            ticket='sekrit-hypervisor-ticket')

        resp = self.client.get(
            '/console/direct/static1/console-3/console.vv')

        self.assertEqual(200, resp.status_code)
        # The ticket is spent, so it is in the file...
        self.assertIn(
            'password=sekrit-hypervisor-ticket', resp.get_data(as_text=True))
        # ...and nowhere in the log.
        for fields in self.logged:
            self.assertNotIn('ticket', fields)
            self.assertNotIn('sekrit-hypervisor-ticket', repr(fields))

    def test_direct_vv_log_line_names_its_fields(self):
        """The log line is built from named fields, not from the dicts.

        Both dicts are public, so splatting them would disclose
        nothing -- but the source dict carries ca_cert, a multi
        kilobyte PEM, and this line is emitted on every request. The
        assertion is on the marker rather than the key, so it fails
        whichever way the line regresses.
        """
        resp = self.client.get('/console/direct/sf1/console-1/console.vv')

        self.assertEqual(200, resp.status_code)
        for fields in self.logged:
            self.assertNotIn('CA-CERT-MARKER', repr(fields))

        # The console is still identifiable in the log, or the
        # trimming has cost an operator the ability to find it.
        vv_lines = [fields for fields in self.logged
                    if fields.get('uuid') == 'console-1']
        self.assertEqual(1, len(vv_lines))
        self.assertEqual('sf1', vv_lines[0]['source'])
        self.assertEqual('hv1', vv_lines[0]['hypervisor'])
        self.assertEqual('shakenfist', vv_lines[0]['type'])

    def test_static_console_without_a_ticket_serves_an_empty_password(self):
        """A static console row may have a NULL ticket.

        db.add_console() defaults ticket to None, so a static source
        whose row predates a ticket, or whose yaml omitted one, reaches
        the `authed_console.get('ticket') or \'\'` guard. Without it the
        template renders password=None, which a SPICE client would send
        as the literal string.
        """
        db.add_source('static2', 'static', None, None, None, ca_cert=None)
        db.add_console(
            source='static2', uuid='console-5', hypervisor='hv5',
            hypervisor_ip='10.0.0.5', insecure_port=5900, secure_port=5901,
            name='a ticketless console', host_subject='CN=hv5', ticket=None)

        resp = self.client.get(
            '/console/direct/static2/console-5/console.vv')

        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertIn('password=\n', body)
        self.assertNotIn('password=None', body)

    def test_console_endpoints_do_not_disclose_the_ticket(self):
        db.add_console(
            source='sf1', uuid='console-4', hypervisor='hv4',
            hypervisor_ip='10.0.0.4', insecure_port=5900, secure_port=5901,
            name='another console', host_subject='CN=hv4',
            ticket='sekrit-hypervisor-ticket')

        # The single console endpoint uses detailed=True, which needs
        # the token and channel tables.
        db.Base.metadata.create_all(
            self.engine,
            tables=[db.ConsoleToken.__table__, db.ProxyChannel.__table__])

        single = self.client.get('/console/sf1/console-4')
        self.assertEqual(200, single.status_code)
        self.assertNotIn(
            'sekrit-hypervisor-ticket', single.get_data(as_text=True))
        self.assertNotIn('ticket', json.loads(single.get_data(as_text=True)))

        listed = self.client.get(
            '/console', headers={'Accept': 'application/json'})
        self.assertEqual(200, listed.status_code)
        self.assertNotIn(
            'sekrit-hypervisor-ticket', listed.get_data(as_text=True))
        for console in json.loads(listed.get_data(as_text=True)):
            self.assertNotIn('ticket', console)

    def test_vv_handlers_404_when_the_source_vanishes_mid_request(self):
        # Fetching the public source and then re-fetching it with the
        # secrets opens a window the single fetch did not have: a hard
        # delete between the two used to reach oVirtSource(**None) and
        # return a 500. Both handlers now 404, which is what the first
        # fetch would have done.
        db.add_source(
            'ovirt1', 'ovirt', 'https://ovirt.example.com/ovirt-engine/api',
            'admin@internal', 'sekrit-ovirt-password', ca_cert='CA')
        db.add_console(
            source='ovirt1', uuid='console-6', hypervisor='hv6',
            hypervisor_ip='10.0.0.6', insecure_port=5900, secure_port=5901,
            name='an ovirt console', host_subject='CN=hv6')
        public = db.get_source('ovirt1')

        for url in ('/console/direct/ovirt1/console-6/console.vv',
                    '/console/proxy/ovirt1/console-6/console.vv'):
            with mock.patch('kerbside.api.db.get_source',
                            side_effect=[public, None]):
                with mock.patch.object(
                        api.config, 'CACERT_PATH', self.cacert_path):
                    resp = self.client.get(url)
            self.assertEqual(404, resp.status_code, url)

    def test_direct_vv_404s_when_the_console_vanishes_mid_request(self):
        # The same window, for the static branch's ticket re-fetch.
        db.add_source('static1', 'static', None, None, None, ca_cert=None)
        db.add_console(
            source='static1', uuid='console-7', hypervisor='hv7',
            hypervisor_ip='10.0.0.7', insecure_port=5900, secure_port=5901,
            name='a static console', host_subject='CN=hv7',
            ticket='sekrit-hypervisor-ticket')
        public = db.get_console('static1', 'console-7')

        with mock.patch('kerbside.api.db.get_console',
                        side_effect=[public, None]):
            resp = self.client.get(
                '/console/direct/static1/console-7/console.vv')

        self.assertEqual(404, resp.status_code)

    @mock.patch('kerbside.consoletoken.create_token',
                return_value={'token': 'a-proxy-token', 'session_id': 'sess'})
    @mock.patch('kerbside.sources.ovirt.oVirtSource')
    def test_ovirt_proxy_vv_is_given_the_password(self, mock_ovirt,
                                                  mock_create_token):
        # The second .vv handler has its own opt in, and nothing else
        # asserts it: without this, that re-fetch could regress to the
        # public source dict and oVirtSource would simply be handed
        # password=None, which only fails against a real engine.
        db.add_source(
            'ovirt1', 'ovirt', 'https://ovirt.example.com/ovirt-engine/api',
            'admin@internal', 'sekrit-ovirt-password', ca_cert='CA')
        db.add_console(
            source='ovirt1', uuid='console-5', hypervisor='hv5',
            hypervisor_ip='10.0.0.5', insecure_port=5900, secure_port=5901,
            name='an ovirt console', host_subject='CN=hv5')
        mock_ovirt.return_value.errored = False
        mock_ovirt.return_value.get_console_for_vm.return_value = (
            None, 'a-ticket')

        with mock.patch.object(api.config, 'CACERT_PATH', self.cacert_path):
            resp = self.client.get(
                '/console/proxy/ovirt1/console-5/console.vv')

        self.assertEqual(200, resp.status_code)
        self.assertEqual(
            'sekrit-ovirt-password', mock_ovirt.call_args.kwargs['password'])
        # The proxy .vv file carries the session token, never the
        # hypervisor ticket.
        self.assertIn('password=a-proxy-token', resp.get_data(as_text=True))
        self.assertNotIn('a-ticket', resp.get_data(as_text=True))

    @mock.patch('kerbside.sources.ovirt.oVirtSource')
    def test_ovirt_direct_vv_is_given_the_password(self, mock_ovirt):
        # The opt in is load bearing rather than decorative: oVirt
        # cannot acquire a ticket without the credential, so assert it
        # arrives, and that it still does not reach the log.
        db.add_source(
            'ovirt1', 'ovirt', 'https://ovirt.example.com/ovirt-engine/api',
            'admin@internal', 'sekrit-ovirt-password', ca_cert='CA')
        db.add_console(
            source='ovirt1', uuid='console-2', hypervisor='hv2',
            hypervisor_ip='10.0.0.2', insecure_port=5900, secure_port=5901,
            name='an ovirt console', host_subject='CN=hv2')
        mock_ovirt.return_value.errored = False
        mock_ovirt.return_value.get_console_for_vm.return_value = (
            None, 'a-ticket')

        resp = self.client.get('/console/direct/ovirt1/console-2/console.vv')

        self.assertEqual(200, resp.status_code)
        self.assertEqual(
            'sekrit-ovirt-password', mock_ovirt.call_args.kwargs['password'])
        self.assertIn('a-ticket', resp.get_data(as_text=True))
        for fields in self.logged:
            self.assertNotIn('password', fields)
            self.assertNotIn('sekrit-ovirt-password', repr(fields))
