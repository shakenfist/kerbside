from unittest import mock
import testtools

from kerbside import api


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
