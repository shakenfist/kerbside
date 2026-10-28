import importlib.util
import io
import json
import os
import shlex
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import requests
import testtools
import yaml


# The Proxmox lane's helpers live in tools/proxmox-e2e/ (outside the
# importable package), and check-privileges.py's filename contains a
# hyphen, so load each by path.
_TOOLS = Path(__file__).resolve().parents[3] / 'tools' / 'proxmox-e2e'
_DOC = Path(__file__).resolve().parents[3] / 'docs' / 'console-sources.md'


def _load_tool(name, filename):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


account_commands = _load_tool('proxmox_account_commands', 'account_commands.py')
check_privileges = _load_tool('proxmox_check_privileges', 'check-privileges.py')
gen_sources = _load_tool('proxmox_gen_sources', 'gen-sources.py')
drive_console = _load_tool('proxmox_drive_console', 'drive-console.py')


def _doc(block, heading='### Proxmox VE account'):
    """A minimal console-sources.md with one account section."""
    return '\n'.join([
        '## Proxmox VE',
        '',
        heading,
        '',
        'Create the account:',
        '',
        '```shell',
        block,
        '```',
        '',
        '### Proxmox VE network',
        '',
        '```shell',
        'rm -rf /',
        '```',
    ])


_GOOD_BLOCK = '\n'.join([
    'pveum role add KerbsideConsole --privs "VM.Audit VM.Console"',
    'pveum user add kerbside@pve',
    'pveum acl modify /vms --roles KerbsideConsole --users kerbside@pve',
    'pveum user token add kerbside@pve console --privsep 1',
    "pveum acl modify /vms --roles KerbsideConsole --tokens 'kerbside@pve!console'",
])


class AccountCommandsDocTestCase(testtools.TestCase):
    def test_the_documented_block(self):
        # The lane runs exactly what the documentation says, less the user's
        # name. If this fails because the documentation changed, check the
        # new commands still create the account the lane expects.
        commands, token_id = account_commands.account_commands(_DOC.read_text())
        self.assertEqual([
            ['pveum', 'role', 'add', 'KerbsideConsole', '--privs', 'VM.Audit VM.Console'],
            ['pveum', 'user', 'add', 'kerbside-lane@pve'],
            ['pveum', 'acl', 'modify', '/vms', '--roles', 'KerbsideConsole', '--users', 'kerbside-lane@pve'],
            ['pveum', 'user', 'token', 'add', 'kerbside-lane@pve', 'console', '--privsep', '1',
             '--output-format', 'json'],
            ['pveum', 'acl', 'modify', '/vms', '--roles', 'KerbsideConsole',
             '--tokens', 'kerbside-lane@pve!console'],
        ], commands)
        self.assertEqual('kerbside-lane@pve!console', token_id)

    def test_the_cli_prints_commands_a_shell_reads_back_unchanged(self):
        out = io.StringIO()
        with mock.patch.object(sys, 'argv', ['account_commands.py', '--doc', str(_DOC)]), redirect_stdout(out):
            self.assertEqual(0, account_commands.main())
        expected, _ = account_commands.account_commands(_DOC.read_text())
        self.assertEqual(expected, [shlex.split(line) for line in out.getvalue().splitlines()])

    def test_the_cli_prints_the_token_id(self):
        out = io.StringIO()
        with mock.patch.object(sys, 'argv', ['account_commands.py', '--doc', str(_DOC), '--token-id']), \
                redirect_stdout(out):
            self.assertEqual(0, account_commands.main())
        self.assertEqual('kerbside-lane@pve!console\n', out.getvalue())

    def test_the_cli_refuses_with_a_reason_and_prints_no_commands(self):
        with tempfile.NamedTemporaryFile('w', suffix='.md') as f:
            f.write(_doc(_GOOD_BLOCK + '\nrm -rf /'))
            f.flush()
            out = io.StringIO()
            err = io.StringIO()
            with mock.patch.object(sys, 'argv', ['account_commands.py', '--doc', f.name]), \
                    redirect_stdout(out), mock.patch.object(sys, 'stderr', err):
                self.assertEqual(1, account_commands.main())
        self.assertEqual('', out.getvalue())
        self.assertIn('not one the account needs: rm -rf /', err.getvalue())


class AccountCommandsRenameTestCase(testtools.TestCase):
    def test_every_mention_of_the_user_is_renamed(self):
        commands, token_id = account_commands.account_commands(_doc(_GOOD_BLOCK))
        args = [arg for argv in commands for arg in argv]
        self.assertNotIn('kerbside@pve', args)
        self.assertNotIn('kerbside@pve!console', args)
        self.assertEqual(3, args.count('kerbside-lane@pve'))
        self.assertIn('kerbside-lane@pve!console', args)
        self.assertEqual('kerbside-lane@pve!console', token_id)

    def test_a_user_in_a_list_is_renamed(self):
        commands, _ = account_commands.account_commands(_doc(
            'pveum acl modify /vms --roles R --users other@pve,kerbside@pve\n'
            'pveum user token add kerbside@pve console'))
        self.assertEqual('other@pve,kerbside-lane@pve', commands[0][-1])

    def test_only_the_whole_user_is_renamed(self):
        commands, _ = account_commands.account_commands(_doc(
            'pveum user add kerbside@pve2\n'
            'pveum user add xkerbside@pve\n'
            'pveum role add kerbside@pve-role\n'
            'pveum user token add kerbside@pve console'))
        self.assertEqual(['kerbside@pve2', 'xkerbside@pve', 'kerbside@pve-role'],
                         [argv[3] for argv in commands[:3]])

    def test_another_user_is_left_alone(self):
        commands, token_id = account_commands.account_commands(_doc(
            'pveum user add console@pve\npveum user token add console@pve kerbside'))
        self.assertEqual(['pveum', 'user', 'add', 'console@pve'], commands[0])
        self.assertEqual('console@pve!kerbside', token_id)

    def test_json_output_is_asked_for_once(self):
        commands, _ = account_commands.account_commands(_doc(
            'pveum user token add kerbside@pve console --output-format json'))
        self.assertEqual(1, commands[0].count('--output-format'))

    def test_comments_blank_lines_and_continuations(self):
        commands, _ = account_commands.account_commands(_doc(
            '# The account\n'
            '\n'
            'pveum user token add kerbside@pve console \\\n'
            '    --privsep 1  # one token\n'
            'pveum role add Has#Hash'))
        self.assertEqual([
            ['pveum', 'user', 'token', 'add', 'kerbside-lane@pve', 'console', '--privsep', '1',
             '--output-format', 'json'],
            ['pveum', 'role', 'add', 'Has#Hash'],
        ], commands)


class AccountCommandsRefusalTestCase(testtools.TestCase):
    def assertRefused(self, markdown, reason):
        e = self.assertRaises(account_commands.RefusedBlock, account_commands.account_commands, markdown)
        self.assertIn(reason, str(e))

    def assertCommandRefused(self, line, reason):
        # The bad line is added to an otherwise good block, so that only it
        # can be what is refused.
        self.assertRefused(_doc(_GOOD_BLOCK + '\n' + line), reason)

    def test_the_good_block_is_accepted(self):
        account_commands.account_commands(_doc(_GOOD_BLOCK))

    def test_each_allowed_command_is_accepted_alone(self):
        for line in ('pveum role add R', 'pveum user add u@pve', 'pveum acl modify / --roles R'):
            account_commands.account_commands(_doc(line + '\npveum user token add u@pve t'))

    def test_another_command(self):
        self.assertCommandRefused('rm -rf /', 'not one the account needs')

    def test_another_pveum_command(self):
        for line in ('pveum user delete kerbside@pve', 'pveum user token remove kerbside@pve console',
                     'pveum acl delete /vms --roles R --users kerbside@pve', 'pveum role modify R --privs Sys.Modify',
                     'pveum useradd kerbside@pve', 'pveum user', 'pveum'):
            self.assertCommandRefused(line, 'not one the account needs')

    def test_an_allowed_command_behind_another(self):
        for line in ('sudo pveum user add u@pve', 'PATH=/tmp pveum user add u@pve', 'env pveum user add u@pve',
                     '/usr/sbin/pveum user add u@pve'):
            self.assertCommandRefused(line, 'not one the account needs')

    def test_a_second_command_on_the_line(self):
        for line in ('pveum role add R; rm -rf /', 'pveum role add R;rm -rf /', 'pveum role add R && rm -rf /',
                     'pveum role add R || rm -rf /', 'pveum role add R | sh', 'pveum role add R & rm -rf /',
                     'pveum role add (R)'):
            self.assertCommandRefused(line, 'shell operator')

    def test_a_redirection(self):
        for line in ('pveum role add R > /etc/passwd', 'pveum role add R</etc/shadow', 'pveum role add R >> x',
                     'pveum role add R <<EOF'):
            self.assertCommandRefused(line, 'shell operator')

    def test_an_expansion(self):
        for line in ('pveum role add $(rm -rf /)', 'pveum role add `rm -rf /`', 'pveum role add ${HOME}',
                     "pveum role add '$(quoted)'"):
            self.assertCommandRefused(line, 'expansion')

    def test_an_unterminated_quote(self):
        self.assertCommandRefused('pveum role add "R', 'cannot be parsed')

    def test_no_section(self):
        for heading in ('### Proxmox VE accounts', '## Proxmox VE account'):
            self.assertRefused(_doc(_GOOD_BLOCK, heading=heading), 'there is no "### Proxmox VE account" section')

    def test_no_shell_block_in_the_section(self):
        # The next section's block is not taken in its place.
        markdown = _doc(_GOOD_BLOCK).replace('```shell\n' + _GOOD_BLOCK, '```text\n' + _GOOD_BLOCK, 1)
        self.assertRefused(markdown, 'there is no shell block')

    def test_an_unclosed_block(self):
        self.assertRefused('### Proxmox VE account\n\n```shell\n' + _GOOD_BLOCK + '\n', 'is not closed')

    def test_two_blocks(self):
        markdown = _doc(_GOOD_BLOCK).replace('\n### Proxmox VE network', '\n```shell\npveum role add R\n```\n'
                                             '### Proxmox VE network')
        self.assertRefused(markdown, 'more than one shell block')

    def test_an_empty_block(self):
        self.assertRefused(_doc(''), 'is empty')
        self.assertRefused(_doc('\n# only a comment\n'), 'is empty')

    def test_no_token(self):
        self.assertRefused(_doc('pveum user add kerbside@pve'), 'creates 0 tokens')

    def test_two_tokens(self):
        self.assertRefused(_doc(_GOOD_BLOCK + '\npveum user token add kerbside@pve other'), 'creates 2 tokens')

    def test_a_token_without_a_name(self):
        self.assertRefused(_doc('pveum user token add kerbside@pve'), 'without a user and a token name')


_SECRETS = {
    'documented': 'secret-documented-1111',
    'audit_only': 'secret-audit-2222',
    'console_only': 'secret-console-3333',
}
_IDS = {
    'documented': 'kerbside-lane@pve!console',
    'audit_only': 'kerbside-lane@pve!audit-only',
    'console_only': 'kerbside-lane@pve!console-only',
}


class CheckPrivilegesTestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        workdir = tempfile.TemporaryDirectory()
        self.addCleanup(workdir.cleanup)
        self.workdir = workdir.name
        tokens = {}
        for name, secret in _SECRETS.items():
            path = os.path.join(self.workdir, name)
            with open(path, 'w') as f:
                f.write(secret)
            tokens[name] = {'token_id': _IDS[name], 'secret_file': path}
        self.lane_file = os.path.join(self.workdir, 'lane-node.json')
        with open(self.lane_file, 'w') as f:
            json.dump({'tokens': tokens}, f)

    def run_tool(self, responses):
        """Run main() with requests replaced, returning (rc, stdout, the mock)."""
        fake = mock.Mock()
        # The real exception classes, so that the tool's except clause works.
        fake.exceptions = requests.exceptions
        fake.request.side_effect = responses
        out = io.StringIO()
        argv = ['check-privileges.py', '--api-url', 'https://pve1.example.org:8006', '--node', 'pve1',
                '--vmid', '100', '--ca-file', '/ca.pem', '--lane-file', self.lane_file]
        with mock.patch.object(check_privileges, 'requests', fake), mock.patch.object(sys, 'argv', argv), \
                redirect_stdout(out):
            rc = check_privileges.main()
        return rc, out.getvalue(), fake

    def response(self, status, reason='Permission check failed', body='{"data":null}'):
        return mock.Mock(status_code=status, reason=reason, text=body, json=mock.Mock(return_value={}))

    def assertOnlyTheThreeRequests(self, fake):
        api = 'https://pve1.example.org:8006/api2/json'
        common = {'verify': '/ca.pem', 'timeout': 5, 'proxies': {'http': None, 'https': None},
                  'allow_redirects': False}

        def auth(name):
            return {'Authorization': 'PVEAPIToken=%s=%s' % (_IDS[name], _SECRETS[name])}

        self.assertEqual([
            mock.call.request('GET', api + '/nodes/pve1/qemu/100/config', headers=auth('console_only'),
                              data=None, **common),
            mock.call.request('POST', api + '/nodes/pve1/qemu/100/spiceproxy', headers=auth('audit_only'),
                              data={'proxy': 'pve1.example.org'}, **common),
            mock.call.request('POST', api + '/nodes/pve1/qemu/100/status/stop', headers=auth('documented'),
                              data=None, **common),
        ], fake.method_calls)

    def assertNoSecret(self, out):
        for secret in _SECRETS.values():
            self.assertNotIn(secret, out)

    def test_three_refusals_pass(self):
        rc, out, fake = self.run_tool([self.response(403)] * 3)
        self.assertEqual(0, rc)
        self.assertOnlyTheThreeRequests(fake)
        self.assertEqual(3, out.count('PASS: '))
        self.assertNotIn('FAIL', out)
        self.assertNoSecret(out)

    def test_each_accepted_request_fails(self):
        for accepted in range(3):
            responses = [self.response(403)] * 3
            responses[accepted] = self.response(200, reason='OK', body='{"data":{"password":"live-ticket"}}')
            rc, out, fake = self.run_tool(responses)
            self.assertEqual(1, rc)
            # A failure does not stop the other checks.
            self.assertOnlyTheThreeRequests(fake)
            self.assertEqual(2, out.count('PASS: '))
            self.assertIn('FAIL: ', out)
            self.assertIn('was not refused: 200 OK', out)
            self.assertIn('1 of 3 privilege checks failed', out)
            # Never the body of an accepted request.
            self.assertNotIn('live-ticket', out)
            self.assertNoSecret(out)

    def test_another_refusal_is_not_a_403(self):
        # 401 is a bad secret, not a missing privilege, so it proves nothing.
        rc, out, fake = self.run_tool([self.response(401, reason='invalid token value')] + [self.response(403)] * 2)
        self.assertEqual(1, rc)
        self.assertOnlyTheThreeRequests(fake)
        self.assertIn('was not refused: 401 invalid token value', out)

    def test_a_failed_request_fails(self):
        rc, out, fake = self.run_tool([requests.exceptions.ConnectTimeout('slow')] + [self.response(403)] * 2)
        self.assertEqual(1, rc)
        self.assertOnlyTheThreeRequests(fake)
        self.assertIn('the request failed: ConnectTimeout', out)
        self.assertNoSecret(out)


_CA = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'


class GenSourcesTestCase(testtools.TestCase):
    def test_the_source(self):
        self.assertEqual({
            'source': 'proxmox',
            'type': 'proxmox',
            'url': 'https://pve1.example.org:8006',
            'username': 'kerbside-lane@pve!console',
            'password': 'secret-documented-1111',
            'ca_cert': _CA,
        }, gen_sources.proxmox_source('proxmox', 'https://pve1.example.org:8006/', 'kerbside-lane@pve!console',
                                      'secret-documented-1111', _CA))

    def test_refusals(self):
        good = ('proxmox', 'https://pve1.example.org:8006', 'kerbside-lane@pve!console', 'secret-1111', _CA)
        for index, value, reason in (
                (1, 'http://pve1.example.org:8006', 'must be https'),
                (1, 'https://pve1.example.org:8006/api2/json', 'must end at its port'),
                (1, 'https://pve1.example.org:8006/?x=1', 'must end at its port'),
                (2, 'kerbside-lane@pve', 'not of the form'),
                (2, 'kerbside!console', 'not of the form'),
                (3, '', 'is empty'),
                (3, ' secret-1111', 'surrounding whitespace'),
                (4, 'not a certificate', 'does not hold a PEM certificate')):
            args = list(good)
            args[index] = value
            e = self.assertRaises(gen_sources.BadSource, gen_sources.proxmox_source, *args)
            self.assertIn(reason, str(e))
            self.assertNotIn('secret-1111', str(e))

    def test_the_file_is_0600_even_when_it_was_not(self):
        with tempfile.TemporaryDirectory() as workdir:
            path = os.path.join(workdir, 'sources.yaml')
            with open(path, 'w') as f:
                f.write('old')
            os.chmod(path, 0o644)
            gen_sources.write_sources(path, [{'source': 'proxmox'}])
            self.assertEqual(0o600, os.stat(path).st_mode & 0o777)

    def test_main_writes_the_documented_token_and_prints_no_secret(self):
        with tempfile.TemporaryDirectory() as workdir:
            secret_file = os.path.join(workdir, 'token-console')
            with open(secret_file, 'w') as f:
                f.write('secret-documented-1111\n')
            lane_file = os.path.join(workdir, 'lane-node.json')
            with open(lane_file, 'w') as f:
                json.dump({'tokens': {
                    'documented': {'token_id': 'kerbside-lane@pve!console', 'secret_file': secret_file},
                    'audit_only': {'token_id': 'kerbside-lane@pve!audit-only', 'secret_file': '/nonexistent'},
                }}, f)
            ca_file = os.path.join(workdir, 'ca.pem')
            with open(ca_file, 'w') as f:
                f.write(_CA)
            output = os.path.join(workdir, 'sources.yaml')
            argv = ['gen-sources.py', '--output', output, '--api-url', 'https://pve1.example.org:8006',
                    '--lane-file', lane_file, '--ca-file', ca_file]
            out = io.StringIO()
            err = io.StringIO()
            with mock.patch.object(sys, 'argv', argv), redirect_stdout(out), mock.patch.object(sys, 'stderr', err):
                self.assertEqual(0, gen_sources.main())
            with open(output) as f:
                sources = yaml.safe_load(f)
            self.assertEqual(0o600, os.stat(output).st_mode & 0o777)

        self.assertEqual(1, len(sources))
        self.assertEqual('kerbside-lane@pve!console', sources[0]['username'])
        self.assertEqual('secret-documented-1111', sources[0]['password'])
        self.assertEqual(_CA, sources[0]['ca_cert'])
        self.assertIn('username=kerbside-lane@pve!console', err.getvalue())
        self.assertNotIn('secret-documented-1111', out.getvalue() + err.getvalue())


_TOKEN = 'kerbside-lane@pve!console'


def _access(user=_TOKEN, method='POST', path='/api2/json/nodes/pve1/qemu/100/spiceproxy', status=200):
    return '10.0.2.1 - %s [29/10/2026:11:02:03 +0100] "%s %s HTTP/1.1" %d 1234' % (user, method, path, status)


_SCRAPE = _access(method='GET', path='/api2/json/cluster/resources?type=vm')


class AccessLogTestCase(testtools.TestCase):
    def test_a_mint_parses(self):
        self.assertEqual({
            'client': '10.0.2.1', 'user': _TOKEN, 'time': '29/10/2026:11:02:03 +0100', 'method': 'POST',
            'target': '/api2/json/nodes/pve1/qemu/100/spiceproxy', 'status': 200,
            'path': '/api2/json/nodes/pve1/qemu/100/spiceproxy',
        }, drive_console.parse_access_line(_access() + '\n'))

    def test_a_length_of_dash_parses(self):
        self.assertIsNotNone(drive_console.parse_access_line(_access()[:-len('1234')] + '-'))

    def test_what_does_not_parse(self):
        for line in ('', 'garbage', _access().replace(' - ', ' '), _access().replace('[', ''),
                     _access().replace('HTTP/1.1', 'HTTP'), _access() + ' trailing'):
            self.assertIsNone(drive_console.parse_access_line(line), line)

    def test_counting(self):
        count = drive_console.count_mints([
            _SCRAPE,
            _access(method='GET', path='/api2/json/nodes/pve1/qemu/100/config?current=1'),
            _access(),
            _access(path='/api2/json/nodes/pve1/qemu/100/spiceproxy?proxy=pve1'),
            _access(status=403),
            _access(status=500),
            '',
        ], _TOKEN)
        self.assertEqual(drive_console.MintCount(mints=2, refused=2, requests=6, scrapes=1, unparseable=0), count)

    def test_only_the_token_is_counted(self):
        # The action's token, the single-privilege tokens of the same user,
        # and spiceproxy's CONNECTs are all other users.
        count = drive_console.count_mints([
            _access(user='kerbside@pve!console'),
            _access(user='kerbside-lane@pve!audit-only'),
            _access(user='kerbside-lane@pve!console2'),
            _access(user='kerbside-lane@pve'),
            _access(user='root@pam'),
            '10.0.2.1 - - [29/10/2026:11:02:03 +0100] "CONNECT pvespiceproxy:abc:100:pve1::def:61000 HTTP/1.1" '
            '200 -',
        ], _TOKEN)
        self.assertEqual(drive_console.MintCount(0, 0, 0, 0, 0), count)

    def test_only_a_post_to_spiceproxy_is_a_mint(self):
        count = drive_console.count_mints([
            _access(method='GET'),
            _access(method='PUT'),
            _access(path='/api2/json/nodes/pve1/qemu/100/spiceproxy/extra'),
            _access(path='/api2/json/nodes/pve1/qemu/100/vncproxy'),
            _access(path='/api2/json/nodes/pve1/lxc/100/spiceproxy'),
            _access(path='/api2/json/nodes/pve1/qemu/100/status/stop'),
        ], _TOKEN)
        self.assertEqual(0, count.mints)
        self.assertEqual(0, count.refused)
        self.assertEqual(6, count.requests)

    def test_the_extjs_api_counts(self):
        self.assertEqual(1, drive_console.count_mints(
            [_access(path='/api2/extjs/nodes/pve1/qemu/100/spiceproxy')], _TOKEN).mints)

    def test_only_a_get_of_the_guest_list_is_a_scrape(self):
        count = drive_console.count_mints([
            _access(method='POST', path='/api2/json/cluster/resources'),
            _access(method='GET', path='/api2/json/cluster/resources/x'),
            _access(method='GET', path='/api2/json/cluster/resources'),
        ], _TOKEN)
        self.assertEqual(1, count.scrapes)

    def test_a_line_which_does_not_parse_is_counted(self):
        count = drive_console.count_mints([_SCRAPE, 'kerbside-lane@pve!console spiceproxy', _access()], _TOKEN)
        self.assertEqual(1, count.unparseable)
        self.assertEqual(1, count.mints)


class MintVerdictTestCase(testtools.TestCase):
    WINDOW = 15

    def verdict(self, mints, expected, sessions=None, refused=0, scrapes=1, unparseable=0):
        count = drive_console.MintCount(mints, refused, mints + refused + scrapes, scrapes, unparseable)
        return drive_console.mint_verdict(count, expected, sessions or {}, self.WINDOW)

    def test_as_expected(self):
        for mints in (0, 1, 2):
            self.assertEqual(drive_console.OK, self.verdict(mints, mints)[0])

    def test_too_few_is_a_defect(self):
        kind, message = self.verdict(0, 1, {'s1': [0.0, 1.0]})
        self.assertEqual(drive_console.DEFECT, kind)
        self.assertIn('fewer than the 1 expected', message)

    def test_too_many_with_every_channel_in_time_is_a_defect(self):
        kind, message = self.verdict(2, 1, {'s1': [100.0, 100.5, 101.0, 114.9]})
        self.assertEqual(drive_console.DEFECT, kind)
        self.assertIn('every channel connected within 15s', message)

    def test_too_many_after_a_late_channel_is_a_timing_fault(self):
        kind, message = self.verdict(2, 1, {'s1': [100.0, 100.5, 115.0]})
        self.assertEqual(drive_console.TIMING, kind)
        self.assertIn('s1 +15.0s', message)

    def test_one_mint_per_late_channel_at_most(self):
        sessions = {'s1': [100.0, 120.0, 121.0], 's2': [300.0, 301.0]}
        self.assertEqual(drive_console.TIMING, self.verdict(3, 2, sessions)[0])
        self.assertEqual(drive_console.TIMING, self.verdict(4, 2, sessions)[0])
        kind, message = self.verdict(5, 2, sessions)
        self.assertEqual(drive_console.DEFECT, kind)
        self.assertIn('only 2 channel(s) connected late', message)

    def test_late_is_judged_within_each_session(self):
        # The second session opened long after the first, which is not late.
        sessions = {'s1': [100.0, 101.0], 's2': [300.0, 301.0]}
        self.assertEqual(drive_console.DEFECT, self.verdict(3, 2, sessions)[0])

    def test_a_correct_count_is_not_a_timing_fault(self):
        self.assertEqual(drive_console.OK, self.verdict(1, 1, {'s1': [100.0, 130.0]})[0])

    def test_lines_which_do_not_parse_are_a_harness_fault(self):
        kind, message = self.verdict(1, 1, unparseable=1)
        self.assertEqual(drive_console.HARNESS, kind)
        self.assertIn('did not parse', message)

    def test_no_scrape_is_a_harness_fault(self):
        # The log is not being read, so a count of zero proves nothing.
        kind, message = self.verdict(0, 0, scrapes=0)
        self.assertEqual(drive_console.HARNESS, kind)
        self.assertIn('no scrape', message)

    def test_a_refused_mint_is_a_defect(self):
        kind, message = self.verdict(1, 1, refused=1)
        self.assertEqual(drive_console.DEFECT, kind)
        self.assertIn('refused 1 spiceproxy', message)

    def test_late_channels(self):
        self.assertEqual([('s1', 15.0), ('s1', 20.0)],
                         drive_console.late_channels({'s1': [120.0, 100.0, 114.9, 115.0], 's2': []}, 15))


_SUBJECT = 'OU=PVE Cluster Node,O=Proxmox Virtual Environment,CN=pve1.example.org'


def _stamp(seconds):
    return '2026-10-29T01:00:%02d.%06dZ' % (int(seconds), int(round((seconds % 1) * 1000000)))


def _connected(seconds, ref, session, tunnelled='true'):
    return ('%s  INFO kerbside_proxy::backend: hypervisor connection successful; handing off to relay '
            'connection_ref=%s hypervisor=pve1 hypervisor_ip= tunnelled=%s session_id=%s channel_type="main" '
            'channel_id=0 connection_id=7' % (_stamp(seconds), ref, tunnelled, session))


def _crate(message, level='DEBUG'):
    return '%s %s shakenfist_spice_protocol::client: %s' % (_stamp(0), level, message)


_DIAL = _crate('Connecting to pve1.example.org:3128 (tunnelled, target redacted) (TLS: true)')
_PIN = _crate('TLS: certificate subject matches pinned host_subject ' + _SUBJECT)


def _leg(sessions):
    """A proxy log in which each (ref, session) connected through a pinned tunnel."""
    lines = ['{"level": "INFO", "message": "Audit: Channel created"}']
    for i, (ref, session) in enumerate(sessions):
        lines.extend([_DIAL, _PIN, _crate('main: connected successfully', level=' INFO'),
                      _connected(i, ref, session)])
    return '\n'.join(lines) + '\n'


class ProxyLogTestCase(testtools.TestCase):
    def test_facts(self):
        text = _leg([('r1', 's1'), ('r2', 's1')]) + '\n'.join([
            '%s  INFO kerbside_proxy::relay: session terminated by control plane; ending relay connection_ref=r1 '
            'channel_type="main"' % _stamp(9),
            _crate('TLS: rejecting certificate: pinned host_subject CN=x: no', level=' WARN'),
            '%s  INFO kerbside_proxy::backend: hypervisor requires TLS; retrying backend connection over the secure '
            'port connection_ref=r3 hypervisor=pve1 channel_type="main" host_subject=CN=x' % _stamp(9),
            _crate('Connecting to 10.0.2.2:5900 (TLS: false)'),
        ])
        facts = drive_console.proxy_log_facts(text)
        self.assertEqual([
            {'time': drive_console._line_time(_stamp(0) + ' '), 'connection_ref': 'r1', 'session_id': 's1',
             'tunnelled': True},
            {'time': drive_console._line_time(_stamp(1) + ' '), 'connection_ref': 'r2', 'session_id': 's1',
             'tunnelled': True},
        ], facts['connections'])
        self.assertEqual(1.0, facts['connections'][1]['time'] - facts['connections'][0]['time'])
        self.assertEqual(1, facts['escalations'])
        self.assertEqual(2, facts['tls_dials'])
        self.assertEqual(1, facts['other_dials'])
        self.assertEqual([_SUBJECT, _SUBJECT], facts['pins'])
        self.assertEqual(1, facts['rejections'])
        self.assertEqual(['r1'], facts['terminated'])
        self.assertEqual([], facts['unparseable'])
        self.assertEqual({'s1'}, drive_console.terminated_sessions(facts))

    def test_fractional_times(self):
        later = drive_console._line_time(_stamp(1.25) + ' ')
        self.assertEqual(0.25, later - drive_console._line_time(_stamp(1) + ' '))
        self.assertIsNone(drive_console._line_time('Oct 29 01:00:00 INFO'))

    def test_colour_is_stripped(self):
        line = _connected(0, 'r1', 's1').replace('tunnelled=', '\x1b[3mtunnelled\x1b[0m\x1b[2m=\x1b[0m')
        facts = drive_console.proxy_log_facts(line)
        self.assertEqual(1, len(facts['connections']))
        self.assertTrue(facts['connections'][0]['tunnelled'])

    def test_a_connection_line_missing_a_field_does_not_parse(self):
        for broken in (_connected(0, 'r1', 's1').replace('session_id=', 'session='),
                       _connected(0, 'r1', 's1').replace('connection_ref=', 'ref='),
                       _connected(0, 'r1', 's1', tunnelled='yes'),
                       _connected(0, 'r1', 's1')[len(_stamp(0)):]):
            facts = drive_console.proxy_log_facts(broken)
            self.assertEqual([], facts['connections'])
            self.assertEqual(1, len(facts['unparseable']), broken)

    def test_fields_before_the_message_are_not_read(self):
        line = '%s  INFO kerbside_proxy::backend: session_id=wrong %s' % (
            _stamp(0), _connected(0, 'r1', 's1').split(': ', 1)[1])
        self.assertEqual('s1', drive_console.proxy_log_facts(line)['connections'][0]['session_id'])

    def test_a_dial_line_without_its_flag_does_not_parse(self):
        facts = drive_console.proxy_log_facts(_crate('Connecting to pve1.example.org:3128 (tunnelled, target '
                                                     'redacted)'))
        self.assertEqual(1, len(facts['unparseable']))

    def test_a_terminate_line_without_a_ref_does_not_parse(self):
        facts = drive_console.proxy_log_facts('%s  INFO kerbside_proxy::relay: session terminated by control '
                                              'plane; ending relay' % _stamp(0))
        self.assertEqual(1, len(facts['unparseable']))

    def test_a_terminated_relay_of_an_unknown_connection_names_no_session(self):
        facts = {'connections': [{'connection_ref': 'r1', 'session_id': 's1'}], 'terminated': ['r9']}
        self.assertEqual(set(), drive_console.terminated_sessions(facts))

    def test_channel_times(self):
        facts = drive_console.proxy_log_facts(_leg([('r1', 's1'), ('r2', 's2'), ('r3', 's1')]))
        times = drive_console.session_channel_times(facts, ['s1', 's3'])
        self.assertEqual(2, len(times['s1']))
        self.assertEqual(2.0, times['s1'][1] - times['s1'][0])
        self.assertEqual([], times['s3'])


class BackendLegVerdictTestCase(testtools.TestCase):
    def verdict(self, text, sessions=('s1',)):
        return drive_console.backend_leg_verdict(drive_console.proxy_log_facts(text), set(sessions), _SUBJECT)

    def assertVerdict(self, kind, needle, text, sessions=('s1',)):
        got, message = self.verdict(text, sessions)
        self.assertEqual(kind, got, message)
        self.assertIn(needle, message)

    def test_tunnelled_tls_and_pinned(self):
        self.assertVerdict(drive_console.OK, 'all 2 backend connection(s) were tunnelled, over TLS, and pinned',
                           _leg([('r1', 's1'), ('r2', 's1')]))

    def test_a_line_which_does_not_parse(self):
        self.assertVerdict(drive_console.HARNESS, 'cannot see',
                           _leg([('r1', 's1')]) + _connected(1, 'r2', 's1').replace('session_id=', 'sid='))

    def test_no_connection_for_the_session(self):
        self.assertVerdict(drive_console.HARNESS, 'no ', _leg([('r1', 's2')]))

    def test_a_direct_connection(self):
        self.assertVerdict(drive_console.DEFECT, 'not tunnelled',
                           _leg([('r1', 's1')]) + _DIAL + '\n' + _PIN + '\n' + _connected(1, 'r2', 's1', 'false'))

    def test_an_escalation(self):
        self.assertVerdict(drive_console.DEFECT, 'escalated 1', _leg([('r1', 's1')]) + (
            '%s  INFO kerbside_proxy::backend: hypervisor requires TLS; retrying backend connection over the secure '
            'port connection_ref=r1 hypervisor=pve1 channel_type="main" host_subject=%s' % (_stamp(0), _SUBJECT)))

    def test_a_plaintext_or_untunnelled_dial(self):
        for dial in ('Connecting to pve1.example.org:3128 (tunnelled, target redacted) (TLS: false)',
                     'Connecting to 10.0.2.2:61000 (TLS: true)'):
            self.assertVerdict(drive_console.DEFECT, 'were not TLS through a tunnel',
                               _leg([('r1', 's1')]) + _crate(dial))

    def test_no_dial_lines(self):
        # The crate's debug logging is off, so nothing can be said.
        self.assertVerdict(drive_console.HARNESS, 'RUST_LOG',
                           _leg([('r1', 's1')]).replace(_DIAL, '').replace(_PIN, ''))

    def test_a_rejection(self):
        self.assertVerdict(drive_console.DEFECT, 'rejected 1', _leg([('r1', 's1')]) + _crate(
            'TLS: rejecting certificate: pinned host_subject %s: mismatch' % _SUBJECT, level=' WARN'))

    def test_no_pin_lines(self):
        self.assertVerdict(drive_console.HARNESS, 'cannot tell whether pinning happened',
                           _leg([('r1', 's1')]).replace(_PIN, ''))

    def test_an_empty_pin(self):
        self.assertVerdict(drive_console.DEFECT, 'empty pinned subject',
                           _leg([('r1', 's1')]).replace(_PIN, _crate('TLS: certificate subject matches pinned '
                                                                     'host_subject ')))

    def test_a_wrong_pin(self):
        self.assertVerdict(drive_console.DEFECT, 'pinned to CN=other', _leg([('r1', 's1')]).replace(
            _PIN, _crate('TLS: certificate subject matches pinned host_subject CN=other')))

    def test_fewer_pins_or_dials_than_connections(self):
        two = _leg([('r1', 's1'), ('r2', 's1')])
        for text in (two.replace(_PIN + '\n', '', 1), two.replace(_DIAL + '\n', '', 1)):
            self.assertVerdict(drive_console.DEFECT, 'relayed 2 connection(s)', text)

    def test_every_session_is_judged(self):
        text = _leg([('r1', 's1')]) + _DIAL + '\n' + _PIN + '\n' + _connected(1, 'r2', 's2', 'false')
        self.assertVerdict(drive_console.DEFECT, 'not tunnelled', text, sessions=('s1',))


class DaemonLogTestCase(testtools.TestCase):
    def record(self, **fields):
        record = {'logger_name': 'kerbside.sources.proxmox', 'ts': '2026-10-29T01:00:00.000Z', 'level': 'INFO',
                  'message': 'Ignoring VM with no SMBIOS UUID, which its console uuid needs', 'source': 'proxmox',
                  'vmid': 102, 'node': 'pve1'}
        record.update(fields)
        return json.dumps(record)

    def skip(self, *lines):
        return drive_console.logged_skip('\n'.join(lines), 102, drive_console.NO_SMBIOS_SKIP_MESSAGE)

    def test_found(self):
        self.assertEqual((True, 2), self.skip(_connected(0, 'r1', 's1'), self.record(vmid=101), self.record()))
        self.assertEqual((True, 1), self.skip(self.record(vmid='102')))

    def test_not_at_info(self):
        self.assertEqual((False, 1), self.skip(self.record(level='DEBUG')))

    def test_another_guest_or_message(self):
        self.assertEqual((False, 2), self.skip(self.record(vmid=1102), self.record(message='Ignoring VM template')))

    def test_no_records(self):
        self.assertEqual((False, 0), self.skip(_connected(0, 'r1', 's1'), '{not json', '[1, 2]', '"text"'))


class SmbiosUuidTestCase(testtools.TestCase):
    def test_parsed(self):
        for smbios1 in ('uuid=0B3C9D6A-1F4E-4C8A-9D52-7A1E5F0C2B44',
                        'manufacturer=x,uuid=0b3c9d6a-1f4e-4c8a-9d52-7a1e5f0c2b44,serial=y'):
            self.assertEqual('0b3c9d6a-1f4e-4c8a-9d52-7a1e5f0c2b44', drive_console.smbios_uuid_of({'smbios1': smbios1}))

    def test_absent(self):
        for config in ({}, {'smbios1': None}, {'smbios1': 'serial=x'}, {'smbios1': 'uuid=0b3c9d6a'},
                       {'smbios1': 'xuuid=0b3c9d6a-1f4e-4c8a-9d52-7a1e5f0c2b44'}):
            self.assertIsNone(drive_console.smbios_uuid_of(config))


_LEAKS = {
    'the documented token\'s secret': 'secret-documented-1111',
    'the literal pvespiceproxy:': 'pvespiceproxy:',
}


class FindSecretsTestCase(testtools.TestCase):
    def test_found_by_file_and_label(self):
        self.assertEqual([
            ('a.log', 'the documented token\'s secret'),
            ('b.log', 'the documented token\'s secret'),
            ('b.log', 'the literal pvespiceproxy:'),
        ], drive_console.find_secrets({
            'b.log': 'x secret-documented-1111 CONNECT pvespiceproxy:abc:100',
            'a.log': 'Authorization: PVEAPIToken=kerbside-lane@pve!console=secret-documented-1111',
            'c.log': 'secret-documented-111 pvespiceproxy',
        }, _LEAKS))

    def test_a_value_split_by_colour(self):
        self.assertEqual([('a.log', 'the documented token\'s secret')], drive_console.find_secrets(
            {'a.log': 'secret-\x1b[3mdocumented\x1b[0m-1111'}, _LEAKS))

    def test_clean(self):
        self.assertEqual([], drive_console.find_secrets({'a.log': 'nothing here', 'b.log': ''}, _LEAKS))

    def test_a_short_value_is_refused(self):
        for value in ('', None, 'short'):
            e = self.assertRaises(ValueError, drive_console.find_secrets, {'a.log': 'x'}, {'the seed': value})
            self.assertIn('the seed is too short', str(e))


class ScanTestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        workdir = tempfile.TemporaryDirectory()
        self.addCleanup(workdir.cleanup)
        self.workdir = workdir.name
        self.secrets_dir = os.path.join(self.workdir, 'node')
        os.mkdir(self.secrets_dir)

        tokens = {}
        for name, secret in _SECRETS.items():
            path = os.path.join(self.secrets_dir, 'token-' + name)
            with open(path, 'w') as f:
                f.write(secret + '\n')
            tokens[name] = {'token_id': _IDS[name], 'secret_file': path}
        lane_file = os.path.join(self.secrets_dir, 'lane-node.json')
        with open(lane_file, 'w') as f:
            json.dump({'tokens': tokens}, f)
        action_file = os.path.join(self.secrets_dir, 'action-token')
        with open(action_file, 'w') as f:
            f.write('secret-action-4444')
        seed_file = os.path.join(self.workdir, 'kerbside-auth-seed.txt')
        with open(seed_file, 'w') as f:
            f.write('seed-5555555555')
        with open(os.path.join(self.workdir, 'kerbside.env'), 'w') as f:
            f.write('PROXMOX_LANE_FILE=%s\nPROXMOX_ACTION_TOKEN_FILE=%s\nKERBSIDE_SEED_FILE=%s\n'
                    % (lane_file, action_file, seed_file))
        for name in drive_console.UPLOADED_FILES:
            if name != 'kerbside.env':
                self.write(name, 'clean\n')

        # main() loads the env file into os.environ.
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))

    def write(self, name, text):
        with open(os.path.join(self.workdir, name), 'w') as f:
            f.write(text)

    def scan_only(self):
        out = io.StringIO()
        err = io.StringIO()
        argv = ['drive-console.py', '--scan-only', '--workdir', self.workdir]
        with mock.patch.object(sys, 'argv', argv), redirect_stdout(out), mock.patch.object(sys, 'stderr', err):
            rc = drive_console.main()
        return rc, out.getvalue() + err.getvalue()

    def assertNoValue(self, output):
        for value in list(_SECRETS.values()) + ['secret-action-4444', 'seed-5555555555', 'live-ticket-6666']:
            self.assertNotIn(value, output)

    def test_clean(self):
        rc, output = self.scan_only()
        self.assertEqual(0, rc)
        self.assertIn('none of 6 secret(s) is in the %d uploaded file(s)' % len(drive_console.UPLOADED_FILES),
                      output)
        for name in drive_console.UPLOADED_FILES:
            self.assertTrue(os.path.exists(os.path.join(self.workdir, name)))

    def test_each_secret_is_found_and_its_file_removed(self):
        for value, label in ((_SECRETS['documented'], 'the documented token\'s secret'),
                             (_SECRETS['audit_only'], 'the audit-only token\'s secret'),
                             (_SECRETS['console_only'], 'the console-only token\'s secret'),
                             ('secret-action-4444', 'the action\'s token\'s secret'),
                             ('seed-5555555555', 'the auth seed'),
                             ('CONNECT pvespiceproxy:abc:100:pve1', 'the literal pvespiceproxy:')):
            self.write('ryll-proxmox-2.stderr', 'before %s after\n' % value)
            rc, output = self.scan_only()
            self.assertEqual(1, rc)
            self.assertIn('ryll-proxmox-2.stderr holds %s' % label, output)
            self.assertNoValue(output)
            self.assertFalse(os.path.exists(os.path.join(self.workdir, 'ryll-proxmox-2.stderr')))
            self.assertTrue(os.path.exists(os.path.join(self.workdir, 'kerbside.log')))

    def test_every_uploaded_file_is_scanned(self):
        for name in drive_console.UPLOADED_FILES:
            with open(os.path.join(self.workdir, name), 'a') as f:
                f.write('pvespiceproxy:\n')
            rc, output = self.scan_only()
            self.assertEqual(1, rc, name)
            self.assertIn('%s holds the literal pvespiceproxy:' % name, output)
            self.assertFalse(os.path.exists(os.path.join(self.workdir, name)))

    def test_a_backend_ticket_held_in_memory(self):
        drive_console._load_env_file(os.path.join(self.workdir, 'kerbside.env'))
        self.write('kerbside.log', 'password live-ticket-6666\n')
        err = io.StringIO()
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(sys, 'stderr', err):
            self.assertTrue(drive_console._scan(self.workdir, {'session 1\'s backend ticket': 'live-ticket-6666'}))
        self.assertIn('kerbside.log holds session 1\'s backend ticket', out.getvalue())
        self.assertNoValue(out.getvalue() + err.getvalue())

    def test_a_missing_secret_is_left_out_and_said_so(self):
        os.remove(os.path.join(self.secrets_dir, 'token-audit_only'))
        rc, output = self.scan_only()
        self.assertEqual(0, rc)
        self.assertIn('the audit-only token\'s secret could not be read', output)
        self.assertIn('none of 5 secret(s)', output)

    def test_without_an_env_file_only_the_literal(self):
        os.remove(os.path.join(self.workdir, 'kerbside.env'))
        self.write('kerbside.log', _SECRETS['documented'] + ' pvespiceproxy:x\n')
        rc, output = self.scan_only()
        self.assertEqual(1, rc)
        self.assertIn('kerbside.log holds the literal pvespiceproxy:', output)

    def test_missing_files_are_not_searched(self):
        for name in drive_console.UPLOADED_FILES[1:]:
            path = os.path.join(self.workdir, name)
            if os.path.exists(path):
                os.remove(path)
        found, searched = drive_console.scan_artifacts(
            [os.path.join(self.workdir, name) for name in drive_console.UPLOADED_FILES], _LEAKS)
        self.assertEqual([], found)
        self.assertEqual(['kerbside.log'], searched)


class UploadListTestCase(testtools.TestCase):
    def test_nothing_secret_is_uploaded(self):
        for name in drive_console.UPLOADED_FILES:
            self.assertNotIn('sources', name)
            self.assertNotIn('seed', name)
            self.assertNotIn('token', name)
            self.assertFalse(name.startswith('access'), name)
            self.assertFalse(name.endswith('.vv'), name)
            self.assertNotIn('ryll.log', name)

    def test_the_readme_lists_the_uploaded_files(self):
        # The workflow's upload list is copied from the README, so the
        # README and the list the scan reads must agree.
        readme = (_TOOLS / 'README.md').read_text()
        block = readme.split('<!-- uploaded-files -->', 2)[1]
        listed = [line.strip()[len('- '):].strip('`').rsplit('/', 1)[-1]
                  for line in block.splitlines() if line.strip().startswith('- `')]
        self.assertEqual(sorted(drive_console.UPLOADED_FILES), sorted(listed))
