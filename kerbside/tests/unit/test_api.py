import os
import tempfile
import time
from unittest import mock
import testtools

from kerbside import api


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

        resp = self.client.get(
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

        resp = self.client.get(
            '/session/sess-2/terminate',
            headers={'Accept': 'application/json'})

        self.assertEqual(200, resp.status_code)
        mock_remove.assert_called_once_with('sess-2')
        mock_request.assert_called_once_with('sess-2', reason=mock.ANY)


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
