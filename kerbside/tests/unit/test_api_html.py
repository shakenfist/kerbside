import copy
import datetime
import os
import re
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
    ids). The sfui conversion did rewrite every template, and a test tied
    to markup would have broken on every rewrite, defeating the point of
    having a safety net that spanned the conversion. The rule stands for
    the rewrites that come after it.
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
        # Root.get() passes navitems=[] for the login branch, so
        # base.html's {% if navitems %} guard renders neither the nav
        # strip nor the logout control. '/console' and '/session' would only
        # appear as navitem hrefs, so their absence is the signal that no
        # navigation was offered to an unauthenticated user.
        #
        # '/source' is deliberately NOT asserted here: it is legitimately
        # present regardless, because login.html's own script redirects
        # there on a successful sign-in.
        resp = self.client.get('/', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertNotIn('/console', body)
        self.assertNotIn('/session', body)

    def test_login_page_does_not_poll(self):
        # base.html renders refresh=False for the login branch, so
        # neither the old meta refresh nor the morphdom poll's status span
        # appears. These are behavioural absences tied to whether the page
        # polls, not to markup cosmetics, so they survive a future rewrite
        # of the login template the same way the fixture-marker assertions
        # above do.
        resp = self.client.get('/', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertNotIn('http-equiv="refresh"', body)
        self.assertNotIn('kb-refresh-status', body)


class HtmlPagesTestCase(testtools.TestCase):
    """Smoke tests for the authenticated HTML pages and the HTML-mode
    terminate redirects.

    These assertions must only ever look for fixture data markers (words,
    ids, sentinel strings), never for markup (tags, CSS classes, element
    ids). The sfui conversion did rewrite every template, and a test tied
    to markup would have broken on every rewrite, defeating the point of
    having a safety net that spanned the conversion. The rule stands for
    the rewrites that come after it.

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
    def test_polling_page_carries_poll_not_meta_refresh(
            self, mock_get_consoles):
        # A behavioural absence/presence pair, not a markup check: this
        # proves the consoles page (rendered with refresh=True) polls via
        # the morphdom include rather than the old meta refresh, which
        # survives a future rewrite of the consoles template the same way
        # the fixture-marker assertions elsewhere in this file do.
        mock_get_consoles.return_value = [copy.deepcopy(CONSOLE)]

        resp = self.client.get('/console', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertNotIn('http-equiv="refresh"', body)
        self.assertIn('kb-refresh-status', body)

    @mock.patch('kerbside.api.db.get_consoles')
    def test_consoles_page_renders_without_sessions(
            self, mock_get_consoles):
        # The no-sessions branch renders a dim zero badge and no
        # terminate disclosure instead of the dropdown the sessions case
        # exercises above -- a distinct fixture proves that branch
        # renders too, not just that it exists in the template.
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

    @mock.patch('kerbside.api.db.get_sessions')
    def test_sessions_page_renders_empty(self, mock_get_sessions):
        mock_get_sessions.return_value = {}

        resp = self.client.get('/session', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        self.assertIn('text/html', resp.content_type)
        body = resp.get_data(as_text=True)
        self.assertIn('There are no active sessions', body)

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

    @mock.patch('kerbside.api.db.get_sources')
    def test_sources_page_renders_without_ca_cert(self, mock_get_sources):
        source = copy.deepcopy(SOURCE)
        source.update({'name': 'no-ca-source', 'ca_cert': None})
        mock_get_sources.return_value = [source]

        resp = self.client.get('/source', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        self.assertIn('text/html', resp.content_type)
        body = resp.get_data(as_text=True)
        self.assertIn('no-ca-source', body)
        self.assertNotIn('sekrit-source-password', body)

    @mock.patch('kerbside.api.db.get_audit_events')
    @mock.patch('kerbside.api.db.count_audit_events')
    @mock.patch('kerbside.api.db.get_console')
    def test_audit_page_renders(
            self, mock_get_console, mock_count_events, mock_get_events):
        mock_get_console.return_value = copy.deepcopy(CONSOLE)
        # count_audit_events feeds total_events, which the current template
        # never renders; the value is set here for realism but deliberately
        # not asserted on.
        mock_count_events.return_value = 42
        mock_get_events.return_value = [copy.deepcopy(AUDIT_EVENT)]

        resp = self.client.get(
            '/console/sf1/u-1234/audit', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        self.assertIn('text/html', resp.content_type)
        body = resp.get_data(as_text=True)
        self.assertIn('audit-marker-event', body)
        self.assertIn('testvm', body)

    @mock.patch('kerbside.api.db.get_audit_events')
    @mock.patch('kerbside.api.db.count_audit_events')
    @mock.patch('kerbside.api.db.get_console')
    def test_audit_page_hides_ticket_and_shows_total(
            self, mock_get_console, mock_count_events, mock_get_events):
        mock_get_console.return_value = copy.deepcopy(CONSOLE)
        mock_count_events.return_value = 4242
        mock_get_events.return_value = [copy.deepcopy(AUDIT_EVENT)]

        resp = self.client.get(
            '/console/sf1/u-1234/audit', headers={'Accept': 'text/html'})

        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        self.assertIn('audit-marker-event', body)
        self.assertIn('4242', body)
        self.assertNotIn('sekrit-hypervisor-ticket', body)

    @mock.patch('kerbside.api.db.request_session_termination')
    @mock.patch('kerbside.api.db.add_audit_event')
    @mock.patch('kerbside.api.db.remove_session')
    @mock.patch('kerbside.api.db.get_tokens_by_console')
    def test_consoles_terminate_redirects_to_console(
            self, mock_get_tokens, mock_remove, mock_audit, mock_request):
        mock_get_tokens.return_value = [{
            'token': 'tok', 'session_id': 'sess-1', 'source': 'src',
            'uuid': 'u'}]

        resp = self.client.post(
            '/console/src/u/terminate', headers={'Accept': 'text/html'})

        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].endswith('/console'))

    @mock.patch('kerbside.api.db.request_session_termination')
    @mock.patch('kerbside.api.db.add_audit_event')
    @mock.patch('kerbside.api.db.remove_session')
    @mock.patch('kerbside.api.db.get_token_by_session_id')
    def test_session_terminate_redirects_to_session(
            self, mock_get_token, mock_remove, mock_audit, mock_request):
        mock_get_token.return_value = {
            'token': 'tok', 'session_id': 'sess-2', 'source': 'src',
            'uuid': 'u'}

        resp = self.client.post(
            '/session/sess-2/terminate', headers={'Accept': 'text/html'})

        self.assertEqual(302, resp.status_code)
        self.assertTrue(resp.headers['Location'].endswith('/session'))


class StaticAssetReferenceTestCase(testtools.TestCase):
    """Every /static/ reference a rendered page makes resolves to a file.

    This class is deliberately exempt from the markup rule the two
    classes above state, and the exemption is a narrow one. Those
    assertions avoid markup because a test naming particular tags or
    classes breaks on every template rewrite. This test names no markup:
    it asserts a referential invariant between whatever markup exists
    and the filesystem, so a rewrite that changes which assets a page
    loads passes it unchanged, while one that points a page at an asset
    that is not there fails it.

    It exists because deleting the Bootstrap era static assets had no
    such safety net: nothing but a human loading the page would have
    noticed a template left referencing a file that had been removed.
    """

    # Deliberately not an HTML parser. The invariant is about the
    # reference strings the template emits, and a regex over the body
    # cannot be fooled into resolving a path the browser would not see.
    STATIC_REF_RE = re.compile(r'(?:src|href)="(/static/[^"]*)"')

    def setUp(self):
        super().setUp()
        api.app.config['TESTING'] = True
        self.client = api.app.test_client()

    def _authenticate(self):
        jwt_patch = mock.patch(
            'kerbside.api.verify_jwt_in_request', return_value=(None, {}))
        jwt_patch.start()
        self.addCleanup(jwt_patch.stop)

    def _assert_static_references_resolve(self, resp):
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)
        refs = set(self.STATIC_REF_RE.findall(body))

        # A page that referenced no assets at all would otherwise pass
        # vacuously, which is the failure this test is here to catch.
        self.assertNotEqual(set(), refs)

        # app.static_folder is built from kerbside/api.py's __file__, so
        # this resolves the same way whatever the test's cwd is.
        for ref in refs:
            path = ref[len('/static/'):].split('?')[0].split('#')[0]
            candidate = os.path.join(api.app.static_folder, path)
            self.assertTrue(
                os.path.isfile(candidate),
                '%s does not resolve to a file (looked for %s)'
                % (ref, candidate))

    def test_login_page_assets_resolve(self):
        self._assert_static_references_resolve(
            self.client.get('/', headers={'Accept': 'text/html'}))

    @mock.patch('kerbside.api.db.get_consoles')
    def test_consoles_page_assets_resolve(self, mock_get_consoles):
        self._authenticate()
        mock_get_consoles.return_value = [copy.deepcopy(CONSOLE)]

        self._assert_static_references_resolve(
            self.client.get('/console', headers={'Accept': 'text/html'}))

    @mock.patch('kerbside.api.db.get_sessions')
    def test_sessions_page_assets_resolve(self, mock_get_sessions):
        self._authenticate()
        mock_get_sessions.return_value = copy.deepcopy(SESSIONS)

        self._assert_static_references_resolve(
            self.client.get('/session', headers={'Accept': 'text/html'}))

    @mock.patch('kerbside.api.db.get_sources')
    def test_sources_page_assets_resolve(self, mock_get_sources):
        self._authenticate()
        mock_get_sources.return_value = [copy.deepcopy(SOURCE)]

        self._assert_static_references_resolve(
            self.client.get('/source', headers={'Accept': 'text/html'}))

    @mock.patch('kerbside.api.db.get_audit_events')
    @mock.patch('kerbside.api.db.count_audit_events')
    @mock.patch('kerbside.api.db.get_console')
    def test_audit_page_assets_resolve(
            self, mock_get_console, mock_count_events, mock_get_events):
        self._authenticate()
        mock_get_console.return_value = copy.deepcopy(CONSOLE)
        mock_count_events.return_value = 42
        mock_get_events.return_value = [copy.deepcopy(AUDIT_EVENT)]

        self._assert_static_references_resolve(
            self.client.get('/console/sf1/u-1234/audit',
                            headers={'Accept': 'text/html'}))
