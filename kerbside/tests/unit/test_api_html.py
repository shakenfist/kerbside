import copy
import datetime
from unittest import mock
import testtools

from kerbside import api


NOW = datetime.datetime(2024, 1, 1, 12, 0, 0)

CONSOLE = {
    'name': 'testvm', 'source': 'sf1', 'uuid': 'u-1234',
    'hypervisor': 'hv1', 'hypervisor_ip': '192.0.2.1',
    'insecure_port': 5900, 'secure_port': 5901,
    'token_count': 2, 'sessions': ['sess-1'],
    'audit': [{'timestamp': NOW, 'session_id': 'sess-1',
               'channel': 'main',
               'message': 'audit-marker-event'}],
    'ticket': 'sekrit-hypervisor-ticket',
}
SESSIONS = {'sess-1': {
    'name': 'testvm', 'source': 'sf1',
    'channels': [{'node': 'node1', 'pid': 123,
                  'created': NOW,
                  'client_ip': '198.51.100.7',
                  'client_port': 40000,
                  'connection_id': 77,
                  'channel_type': 'main'}],
}}
SOURCE = {
    'name': 'sf1', 'type': 'shakenfist',
    'last_seen': NOW, 'seen_by': 'node1',
    'errored': False, 'ca_cert': 'CA-CERT-MARKER',
    'password': 'sekrit-source-password',
}
AUDIT_EVENT = {
    'timestamp': NOW, 'session_id': 'sess-1',
    'channel': 'main', 'node': 'node1', 'pid': 123,
    'message': 'audit-marker-event',
}


class LoginPageTestCase(testtools.TestCase):
    """Smoke test for the unauthenticated login page.

    These assertions must only ever look for fixture data markers (words,
    ids, sentinel strings), never for markup (tags, CSS classes, element
    ids). The sfui conversion is going to rewrite every template; a test
    tied to markup would break on every rewrite, defeating the point of
    having a safety net that spans the conversion.
    """

    def setUp(self):
        super().setUp()
        api.app.config['TESTING'] = True
        self.client = api.app.test_client()

    def test_unauthenticated_root_renders_login(self):
        # Root.get() calls verify_jwt_in_request itself and only falls back
        # to login.html when that raises NoAuthorizationError, which an
        # unauthenticated request triggers naturally -- no JWT patch needed.
        resp = self.client.get('/', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        self.assertIn('text/html', resp.content_type)
        body = resp.get_data(as_text=True)
        self.assertIn('Username', body)
        self.assertIn('Password', body)

    def test_login_page_offers_no_navigation(self):
        # Root.get() passes navitems=[] for the login branch (design
        # decision 2 of the phase 4 plan), so base-sfui.html's
        # {% if navitems %} guard renders neither the nav strip nor the
        # logout control. '/console' and '/session' would only appear as
        # navitem hrefs, so their absence is the signal that no navigation
        # was offered to an unauthenticated user.
        #
        # '/source' is deliberately NOT asserted here: it is legitimately
        # present regardless, because login.html's own script redirects
        # there on a successful sign-in.
        resp = self.client.get('/', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertNotIn('/console', body)
        self.assertNotIn('/session', body)


class HtmlPagesTestCase(testtools.TestCase):
    """Smoke tests for the authenticated HTML pages and the HTML-mode
    terminate redirects.

    These assertions must only ever look for fixture data markers (words,
    ids, sentinel strings), never for markup (tags, CSS classes, element
    ids). The sfui conversion is going to rewrite every template; a test
    tied to markup would break on every rewrite, defeating the point of
    having a safety net that spans the conversion.

    Two of these tests (consoles, sources) also double as leak guards: the
    HTML views pass raw db dicts straight to the template, unlike the JSON
    views which strip 'ticket' and 'password' before serializing. The
    fixtures include those sensitive fields and the tests assert they never
    appear in the rendered page.
    """

    def setUp(self):
        super().setUp()
        api.app.config['TESTING'] = True
        self.client = api.app.test_client()
        jwt_patch = mock.patch(
            'kerbside.api.verify_jwt_in_request', return_value=(None, {}))
        jwt_patch.start()
        self.addCleanup(jwt_patch.stop)

    def test_authenticated_root_redirects_to_source(self):
        resp = self.client.get('/', headers={'Accept': 'text/html'})

        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].endswith('/source'))

    @mock.patch('kerbside.api.db.get_consoles')
    def test_consoles_page_renders_and_hides_ticket(self, mock_get_consoles):
        mock_get_consoles.return_value = [copy.deepcopy(CONSOLE)]

        resp = self.client.get('/console', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        self.assertIn('text/html', resp.content_type)
        body = resp.get_data(as_text=True)
        self.assertIn('testvm', body)
        self.assertNotIn('sekrit-hypervisor-ticket', body)

    @mock.patch('kerbside.api.db.get_consoles')
    def test_consoles_page_renders_without_sessions(
            self, mock_get_consoles):
        # The no-sessions branch (decision 3 of the phase 5 plan) renders
        # a dim zero badge and no terminate disclosure instead of the
        # dropdown the sessions case exercises above -- a distinct
        # fixture proves that branch renders too, not just that it
        # exists in the template.
        quiet_console = copy.deepcopy(CONSOLE)
        quiet_console.update({
            'name': 'quietvm', 'sessions': [], 'token_count': 0, 'audit': [],
        })
        mock_get_consoles.return_value = [quiet_console]

        resp = self.client.get('/console', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        self.assertIn('text/html', resp.content_type)
        body = resp.get_data(as_text=True)
        self.assertIn('quietvm', body)
        self.assertNotIn('sekrit-hypervisor-ticket', body)

    @mock.patch('kerbside.api.db.get_sessions')
    def test_sessions_page_renders(self, mock_get_sessions):
        mock_get_sessions.return_value = copy.deepcopy(SESSIONS)

        resp = self.client.get('/session', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        self.assertIn('text/html', resp.content_type)
        body = resp.get_data(as_text=True)
        self.assertIn('sess-1', body)
        self.assertIn('testvm', body)

    @mock.patch('kerbside.api.db.get_sources')
    def test_sources_page_renders_and_hides_password(self, mock_get_sources):
        mock_get_sources.return_value = [copy.deepcopy(SOURCE)]

        resp = self.client.get('/source', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        self.assertIn('text/html', resp.content_type)
        body = resp.get_data(as_text=True)
        self.assertIn('sf1', body)
        self.assertIn('CA-CERT-MARKER', body)
        self.assertNotIn('sekrit-source-password', body)

    @mock.patch('kerbside.api.db.get_audit_events')
    @mock.patch('kerbside.api.db.count_audit_events')
    @mock.patch('kerbside.api.db.get_console')
    def test_audit_page_renders(
            self, mock_get_console, mock_count_events, mock_get_events):
        mock_get_console.return_value = copy.deepcopy(CONSOLE)
        # count_audit_events feeds total_events, which the current template
        # never renders; the value is set here for realism but deliberately
        # not asserted on. Phase 6 of the master plan will start using it.
        mock_count_events.return_value = 42
        mock_get_events.return_value = [copy.deepcopy(AUDIT_EVENT)]

        resp = self.client.get(
            '/console/sf1/u-1234/audit', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        self.assertIn('text/html', resp.content_type)
        body = resp.get_data(as_text=True)
        self.assertIn('audit-marker-event', body)
        self.assertIn('testvm', body)

    # NOTE(phase 8): the terminate routes below move from GET to POST when
    # phase 8 of the sfui conversion lands; these two tests will need to
    # change to issue POSTs at that point.
    @mock.patch('kerbside.api.db.request_session_termination')
    @mock.patch('kerbside.api.db.add_audit_event')
    @mock.patch('kerbside.api.db.remove_session')
    @mock.patch('kerbside.api.db.get_tokens_by_console')
    def test_consoles_terminate_redirects_to_console(
            self, mock_get_tokens, mock_remove, mock_audit, mock_request):
        mock_get_tokens.return_value = [{
            'token': 'tok', 'session_id': 'sess-1', 'source': 'src',
            'uuid': 'u'}]

        resp = self.client.get(
            '/console/src/u/terminate', headers={'Accept': 'text/html'})

        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].endswith('/console'))

    # NOTE(phase 8): see the note above -- this route also moves to POST.
    @mock.patch('kerbside.api.db.request_session_termination')
    @mock.patch('kerbside.api.db.add_audit_event')
    @mock.patch('kerbside.api.db.remove_session')
    @mock.patch('kerbside.api.db.get_token_by_session_id')
    def test_session_terminate_redirects_to_session(
            self, mock_get_token, mock_remove, mock_audit, mock_request):
        mock_get_token.return_value = {
            'token': 'tok', 'session_id': 'sess-2', 'source': 'src',
            'uuid': 'u'}

        resp = self.client.get(
            '/session/sess-2/terminate', headers={'Accept': 'text/html'})

        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].endswith('/session'))
