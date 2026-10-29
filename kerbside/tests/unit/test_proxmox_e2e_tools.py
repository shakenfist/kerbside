import importlib.util
import io
import json
import os
import re
import shlex
import subprocess
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
_WORKFLOW = Path(__file__).resolve().parents[3] / '.github' / 'workflows' / 'proxmox-functional.yml'


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

    def test_a_token_user_which_is_not_plain(self):
        # prepare-node.sh builds root commands and a file path from the
        # token ID, so a quote, a slash or a space in it must never get
        # that far.
        for user in ('"a\'b@pve"', 'a/b@pve', '"a b@pve"', 'kerbside', '"a@b@pve"'):
            self.assertRefused(_doc('pveum user token add %s console' % user), 'not of the form name@realm')

    def test_a_token_name_which_is_not_plain(self):
        for name in ('"t\'x"', 't/x', '"t x"', '"t!x"', '"t@x"'):
            self.assertRefused(_doc('pveum user token add kerbside@pve %s' % name), 'not a plain PVE token name')

    def test_a_plain_token_id_is_accepted(self):
        _, token_id = account_commands.account_commands(_doc('pveum user token add a.b_c-d@pve-2 t.1_x-y'))
        self.assertEqual('a.b_c-d@pve-2!t.1_x-y', token_id)


_SENTINELS = {
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
        for name, sentinel in _SENTINELS.items():
            path = os.path.join(self.workdir, name)
            with open(path, 'w') as f:
                f.write(sentinel)
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
            return {'Authorization': 'PVEAPIToken=%s=%s' % (_IDS[name], _SENTINELS[name])}

        self.assertEqual([
            mock.call.request('GET', api + '/nodes/pve1/qemu/100/config', headers=auth('console_only'),
                              data=None, **common),
            mock.call.request('POST', api + '/nodes/pve1/qemu/100/spiceproxy', headers=auth('audit_only'),
                              data={'proxy': 'pve1.example.org'}, **common),
            mock.call.request('POST', api + '/nodes/pve1/qemu/100/status/stop', headers=auth('documented'),
                              data=None, **common),
        ], fake.method_calls)

    def assertNoSentinel(self, out):
        for sentinel in _SENTINELS.values():
            self.assertNotIn(sentinel, out)

    def test_three_refusals_pass(self):
        rc, out, fake = self.run_tool([self.response(403)] * 3)
        self.assertEqual(0, rc)
        self.assertOnlyTheThreeRequests(fake)
        self.assertEqual(3, out.count('PASS: '))
        self.assertNotIn('FAIL', out)
        self.assertNoSentinel(out)

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
            self.assertNoSentinel(out)

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
        self.assertNoSentinel(out)


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
            sentinel_file = os.path.join(workdir, 'token-console')
            with open(sentinel_file, 'w') as f:
                f.write('secret-documented-1111\n')
            lane_file = os.path.join(workdir, 'lane-node.json')
            with open(lane_file, 'w') as f:
                json.dump({'tokens': {
                    'documented': {'token_id': 'kerbside-lane@pve!console', 'secret_file': sentinel_file},
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


def _ended(seconds, ref, error=True):
    """A relay ended line, with an error as qemu closing the connection gives, or without."""
    if error:
        return ('%s  WARN kerbside_proxy::relay: relay ended with error connection_ref=%s channel_type="main" '
                'error=peer closed connection without sending TLS close_notify: '
                'https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof'
                % (_stamp(seconds), ref))
    return '%s  INFO kerbside_proxy::relay: relay ended connection_ref=%s channel_type="main"' % (_stamp(seconds), ref)


class ProxyLogTestCase(testtools.TestCase):
    def test_facts(self):
        text = _leg([('r1', 's1'), ('r2', 's1')]) + '\n'.join([
            '%s  INFO kerbside_proxy::relay: session terminated by control plane; ending relay connection_ref=r1 '
            'channel_type="main"' % _stamp(9),
            _crate('TLS: rejecting certificate: pinned host_subject CN=x: no', level=' WARN'),
            '%s  INFO kerbside_proxy::backend: hypervisor requires TLS; retrying backend connection over the secure '
            'port connection_ref=r3 hypervisor=pve1 channel_type="main" host_subject=CN=x' % _stamp(9),
            _crate('Connecting to 10.0.2.2:5900 (TLS: false)'),
            _ended(9, 'r2'),
            _ended(9, 'r1', error=False),
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
        self.assertEqual(['r2', 'r1'], facts['ended'])
        self.assertEqual([], facts['unparseable'])
        self.assertEqual({'s1'}, drive_console.terminated_sessions(facts))

    def test_only_a_relay_ending_is_an_ending(self):
        facts = drive_console.proxy_log_facts('\n'.join([
            '%s  INFO kerbside_proxy::relay: relay starting connection_ref=r2 channel_type="main"' % _stamp(0),
            '%s  INFO kerbside_proxy::relay: session terminated by control plane; ending relay connection_ref=r1 '
            'channel_type="main"' % _stamp(0),
        ]))
        self.assertEqual(['r1'], facts['terminated'])
        self.assertEqual([], facts['ended'])
        self.assertEqual([], facts['unparseable'])

    def test_a_relay_ended_line_without_a_ref_does_not_parse(self):
        for broken in (_ended(0, 'r1').replace('connection_ref=', 'ref='),
                       _ended(0, 'r1', error=False).replace('connection_ref=', 'ref=')):
            facts = drive_console.proxy_log_facts(broken)
            self.assertEqual([], facts['ended'])
            self.assertEqual(['a relay ended line without a connection_ref'], facts['unparseable'])

    def test_a_ref_before_the_relay_ended_message_is_not_read(self):
        line = '%s  WARN kerbside_proxy::relay: connection_ref=wrong %s' % (
            _stamp(0), _ended(0, 'r1').split(': ', 1)[1])
        self.assertEqual(['r1'], drive_console.proxy_log_facts(line)['ended'])

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


class DisplacementVerdictTestCase(testtools.TestCase):
    # Session s1 has two relays, r1 and r2; session s2, which displaces it,
    # has r3.
    def text(self, ended=('r1', 'r2'), extra=''):
        return (_leg([('r1', 's1'), ('r2', 's1'), ('r3', 's2')]) + '\n'.join(_ended(9, ref) for ref in ended) +
                '\n' + extra)

    def assertVerdict(self, kind, needle, text, exited=True):
        got, message = drive_console.displacement_verdict(drive_console.proxy_log_facts(text), 's1', 's2', exited)
        self.assertEqual(kind, got, message)
        self.assertIn(needle, message)

    def test_displaced(self):
        self.assertVerdict(drive_console.OK, 'session s2 displaced session s1: all 2 of its backend relay(s) ended',
                           self.text())

    def test_a_relay_which_ended_cleanly_counts(self):
        text = _leg([('r1', 's1'), ('r2', 's1'), ('r3', 's2')]) + _ended(9, 'r1') + '\n' + _ended(9, 'r2', False)
        self.assertVerdict(drive_console.OK, 'all 2', text)

    def test_not_displaced(self):
        self.assertVerdict(drive_console.DEFECT, 'the first session was not displaced: session s1\'s ryll is still '
                           'running and none of its 2 backend relay(s) ended once session s2 linked',
                           self.text(ended=()), exited=False)

    def test_not_displaced_while_another_relay_ended(self):
        self.assertVerdict(drive_console.DEFECT, 'the first session was not displaced',
                           self.text(ended=('r9',)), exited=False)

    def test_a_relay_left_behind(self):
        self.assertVerdict(drive_console.DEFECT, 'displaced only in part: 1 of its 2 backend relay(s) ended, and its '
                           'ryll exited', self.text(ended=('r1',)))

    def test_a_ryll_left_behind(self):
        self.assertVerdict(drive_console.DEFECT, 'displaced only in part: 2 of its 2 backend relay(s) ended, and its '
                           'ryll is still running', self.text(), exited=False)

    def test_part_ended_and_the_ryll_running(self):
        self.assertVerdict(drive_console.DEFECT, '1 of its 2 backend relay(s) ended, and its ryll is still running',
                           self.text(ended=('r1',)), exited=False)

    def test_only_other_relays_ended(self):
        self.assertVerdict(drive_console.DEFECT, '0 of its 2 backend relay(s) ended', self.text(ended=('r9',)))

    def test_no_relay_ended_line_at_all(self):
        # The ryll exited, so its relays ended; that none is logged means
        # the message has changed.
        self.assertVerdict(drive_console.HARNESS, 'no \'relay ended\' line at all', self.text(ended=()))

    def test_a_relay_of_the_displacing_session_ended(self):
        self.assertVerdict(drive_console.DEFECT, '1 backend relay(s) of session s2, the one which should have '
                           'displaced session s1, ended too', self.text(ended=('r1', 'r2', 'r3')))

    def test_a_line_which_does_not_parse(self):
        self.assertVerdict(drive_console.HARNESS, 'cannot see',
                           self.text(extra=_ended(9, 'r4').replace('connection_ref=', 'ref=')))

    def test_no_connection_for_the_displaced_session(self):
        text = _leg([('r3', 's2')]) + _ended(9, 'r1')
        self.assertVerdict(drive_console.HARNESS, 'no %r line for session s1' % drive_console.CONNECTED_ORACLE, text)


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


# Fake values to search for, and the index of each in the list.
_NEEDLES = ['secret-documented-1111', 'pvespiceproxy:']
_DOCUMENTED = 0
_LITERAL = 1


class FindNeedlesTestCase(testtools.TestCase):
    def test_found_by_file_and_label(self):
        self.assertEqual([
            ('a.log', _DOCUMENTED),
            ('b.log', _DOCUMENTED),
            ('b.log', _LITERAL),
        ], drive_console.find_needles({
            'b.log': 'x secret-documented-1111 CONNECT pvespiceproxy:abc:100',
            'a.log': 'Authorization: PVEAPIToken=kerbside-lane@pve!console=secret-documented-1111',
            'c.log': 'secret-documented-111 pvespiceproxy',
        }, _NEEDLES))

    def test_found_by_index_in_the_order_given(self):
        self.assertEqual([('b.log', 0), ('b.log', 1)], drive_console.find_needles(
            {'b.log': 'x secret-documented-1111 CONNECT pvespiceproxy:abc:100'}, list(reversed(_NEEDLES))))

    def test_a_value_split_by_colour(self):
        self.assertEqual([('a.log', _DOCUMENTED)], drive_console.find_needles(
            {'a.log': 'secret-\x1b[3mdocumented\x1b[0m-1111'}, _NEEDLES))

    def test_clean(self):
        self.assertEqual([], drive_console.find_needles({'a.log': 'nothing here', 'b.log': ''}, _NEEDLES))

    def test_a_short_value_is_refused(self):
        for value in ('', None, 'short'):
            e = self.assertRaises(ValueError, drive_console.find_needles, {'a.log': 'x'}, _NEEDLES + [value])
            self.assertIn('needle 2 is too short', str(e))


class _LaneFilesTestCase(testtools.TestCase):
    """A work directory with the lane's secret files, its env file and clean uploaded files."""

    def setUp(self):
        super().setUp()
        workdir = tempfile.TemporaryDirectory()
        self.addCleanup(workdir.cleanup)
        self.workdir = workdir.name
        self.node_dir = os.path.join(self.workdir, 'node')
        os.mkdir(self.node_dir)

        tokens = {}
        for name, sentinel in _SENTINELS.items():
            path = os.path.join(self.node_dir, 'token-' + name)
            with open(path, 'w') as f:
                f.write(sentinel + '\n')
            tokens[name] = {'token_id': _IDS[name], 'secret_file': path}
        lane_file = os.path.join(self.node_dir, 'lane-node.json')
        with open(lane_file, 'w') as f:
            json.dump({'tokens': tokens}, f)
        action_file = os.path.join(self.node_dir, 'action-token')
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

    def assertNoValue(self, output):
        for value in list(_SENTINELS.values()) + ['secret-action-4444', 'seed-5555555555', 'live-ticket-6666']:
            self.assertNotIn(value, output)


class ScanTestCase(_LaneFilesTestCase):
    def scan_only(self):
        out = io.StringIO()
        err = io.StringIO()
        argv = ['drive-console.py', '--scan-only', '--workdir', self.workdir]
        with mock.patch.object(sys, 'argv', argv), redirect_stdout(out), mock.patch.object(sys, 'stderr', err):
            rc = drive_console.main()
        return rc, out.getvalue() + err.getvalue()

    def test_clean(self):
        rc, output = self.scan_only()
        self.assertEqual(0, rc)
        self.assertIn('none of 6 secret(s) is in the %d uploaded file(s)' % len(drive_console.UPLOADED_FILES),
                      output)
        for name in drive_console.UPLOADED_FILES:
            self.assertTrue(os.path.exists(os.path.join(self.workdir, name)))

    def test_each_secret_is_found_and_its_file_removed(self):
        for value, label in ((_SENTINELS['documented'], 'the documented token\'s secret'),
                             (_SENTINELS['audit_only'], 'the audit-only token\'s secret'),
                             (_SENTINELS['console_only'], 'the console-only token\'s secret'),
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
            self.assertTrue(drive_console._scan(self.workdir, ['session 1\'s backend ticket'], ['live-ticket-6666']))
        self.assertIn('kerbside.log holds session 1\'s backend ticket', out.getvalue())
        self.assertNoValue(out.getvalue() + err.getvalue())

    def test_each_secret_held_in_memory_is_named(self):
        drive_console._load_env_file(os.path.join(self.workdir, 'kerbside.env'))
        held = [('session 1\'s backend ticket', 'live-ticket-6666'),
                ('the password in .vv 1', 'vv-password-7777'),
                ('the API JWT', 'eyJhbGciOi.jwt-8888'),
                ('the administrator API JWT', 'eyJhbGciOi.admin-jwt-9999')]
        for description, value in held:
            self.write('ryll-proxmox-1.stderr', 'before %s after\n' % value)
            err = io.StringIO()
            out = io.StringIO()
            with redirect_stdout(out), mock.patch.object(sys, 'stderr', err):
                self.assertTrue(drive_console._scan(self.workdir, [d for d, _ in held], [v for _, v in held]))
            self.assertIn('ryll-proxmox-1.stderr holds %s;' % description, out.getvalue())
            self.assertEqual(1, out.getvalue().count(' holds '))
            for _, other in held:
                self.assertNotIn(other, out.getvalue() + err.getvalue())
            self.assertFalse(os.path.exists(os.path.join(self.workdir, 'ryll-proxmox-1.stderr')))

    def test_the_drive_s_held_secrets_are_scanned_for(self):
        self.write('ryll-proxmox-1.stdout', 'before vv-password-7777 after\n')
        lane = _bare_lane(self.workdir)

        def drive(lane):
            lane.remember('the password in .vv 1', 'vv-password-7777')

        out = io.StringIO()
        argv = ['drive-console.py', '--workdir', self.workdir]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(drive_console, 'Lane', return_value=lane), \
                mock.patch.object(drive_console, '_drive', side_effect=drive), redirect_stdout(out), \
                mock.patch.object(sys, 'stderr', io.StringIO()):
            self.assertRaises(SystemExit, drive_console.main)
        self.assertIn('ryll-proxmox-1.stdout holds the password in .vv 1;', out.getvalue())
        self.assertNotIn('vv-password-7777', out.getvalue())

    def test_a_missing_secret_is_left_out_and_said_so(self):
        for name in sorted(_SENTINELS):
            path = os.path.join(self.node_dir, 'token-' + name)
            os.remove(path)
            rc, output = self.scan_only()
            self.assertEqual(0, rc)
            self.assertIn('the %s token\'s secret could not be read' % name.replace('_', '-'), output)
            self.assertIn('none of 5 secret(s)', output)
            with open(path, 'w') as f:
                f.write(_SENTINELS[name] + '\n')

    def test_without_an_env_file_only_the_literal(self):
        os.remove(os.path.join(self.workdir, 'kerbside.env'))
        self.write('kerbside.log', _SENTINELS['documented'] + ' pvespiceproxy:x\n')
        rc, output = self.scan_only()
        self.assertEqual(1, rc)
        self.assertIn('kerbside.log holds the literal pvespiceproxy:', output)

    def test_missing_files_are_not_searched(self):
        for name in drive_console.UPLOADED_FILES[1:]:
            path = os.path.join(self.workdir, name)
            if os.path.exists(path):
                os.remove(path)
        found, searched = drive_console.scan_artifacts(
            [os.path.join(self.workdir, name) for name in drive_console.UPLOADED_FILES], _NEEDLES)
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

    def test_the_workflow_uploads_exactly_the_scanned_files(self):
        # The scan reads UPLOADED_FILES, so a file the workflow uploads
        # which is not in it would be uploaded unscanned, and a file in it
        # which is not uploaded is a list out of step with the workflow.
        workflow = yaml.safe_load(_WORKFLOW.read_text())
        steps = [step for step in workflow['jobs']['proxmox']['steps']
                 if step.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertEqual(1, len(steps))
        prefix = '${{ env.PROXMOX_LANE_WORKDIR }}/'
        uploaded = []
        for line in steps[0]['with']['path'].splitlines():
            line = line.strip()
            if not line:
                continue
            self.assertTrue(line.startswith(prefix), line)
            uploaded.append(line[len(prefix):])
        self.assertEqual(len(uploaded), len(set(uploaded)))
        self.assertEqual(set(drive_console.UPLOADED_FILES), set(uploaded))

    def test_the_readme_lists_the_uploaded_files(self):
        # The README documents the upload list for a person, so it and the
        # list the scan reads must agree, as the test above makes the
        # workflow's list agree with it too.
        readme = (_TOOLS / 'README.md').read_text()
        block = readme.split('<!-- uploaded-files -->', 2)[1]
        listed = [line.strip()[len('- '):].strip('`').rsplit('/', 1)[-1]
                  for line in block.splitlines() if line.strip().startswith('- `')]
        self.assertEqual(sorted(drive_console.UPLOADED_FILES), sorted(listed))


class TicketVerdictTestCase(testtools.TestCase):
    NOW = 1000.0
    LIFETIME = 30

    def verdict(self, ticket=None, expires=None, minted=0, failures=(), first_channel=None):
        return drive_console.ticket_verdict(ticket, expires, minted, list(failures), first_channel, self.NOW,
                                            self.LIFETIME)

    def test_a_live_ticket(self):
        kind, message = self.verdict('live-ticket-6666', self.NOW + 20, first_channel=self.NOW - 1)
        self.assertEqual(drive_console.OK, kind)
        self.assertIn('16 characters', message)
        self.assertNotIn('live-ticket-6666', message)

    def test_a_ticket_found_before_any_channel_is_logged(self):
        self.assertEqual(drive_console.OK, self.verdict('live-ticket-6666', self.NOW + 29)[0])

    def test_a_ticket_with_no_expiry_is_a_defect(self):
        self.assertEqual(drive_console.DEFECT, self.verdict('live-ticket-6666', None)[0])

    def test_a_ticket_first_seen_expired_is_a_timing_fault(self):
        for expires in (self.NOW, self.NOW - 1, self.NOW - 60):
            kind, message = self.verdict('live-ticket-6666', expires, first_channel=self.NOW - 40)
            self.assertEqual(drive_console.TIMING, kind, expires)
            self.assertNotIn('live-ticket-6666', message)

    def test_a_ticket_the_sweep_cleared_is_a_timing_fault(self):
        # The mint came up to CHANNEL_TIME_SLACK before the first channel,
        # so 25 seconds after it the ticket may have expired.
        for age in (25, 26, 90):
            self.assertEqual(drive_console.TIMING, self.verdict(minted=1, first_channel=self.NOW - age)[0], age)

    def test_a_ticket_gone_while_live_is_a_defect(self):
        for age in (0, 3, 24.9):
            self.assertEqual(drive_console.DEFECT, self.verdict(minted=1, first_channel=self.NOW - age)[0], age)

    def test_a_mint_with_no_connection_logged_is_a_harness_fault(self):
        self.assertEqual(drive_console.HARNESS, self.verdict(minted=1)[0])

    def test_channels_with_no_mint_is_a_defect(self):
        kind, message = self.verdict(failures=['Backend console ticket mint failed: HTTPError'],
                                     first_channel=self.NOW - 2)
        self.assertEqual(drive_console.DEFECT, kind)
        self.assertIn('no backend ticket was ever minted', message)
        self.assertIn('Backend console ticket mint failed: HTTPError', message)

    def test_no_channel_is_a_harness_fault(self):
        self.assertEqual(drive_console.HARNESS, self.verdict()[0])


class VvPasswordTestCase(testtools.TestCase):
    def test_parsed(self):
        vv = '[virt-viewer]\ntype=spice\nhost=kerbside\nport=5900\npassword=vv-password-7777\ntitle=x\n'
        self.assertEqual('vv-password-7777', drive_console.vv_password(vv))

    def test_absent_or_empty(self):
        for vv in ('[virt-viewer]\ntype=spice\n', '[virt-viewer]\npassword=\n', 'proxy-password=vv-7777\n'):
            self.assertIsNone(drive_console.vv_password(vv), vv)


def _bare_lane(workdir, seed_path=None):
    """A Lane without its environment, for the parts of the drive which need little of it."""
    lane = drive_console.Lane.__new__(drive_console.Lane)
    lane.run_dir = workdir
    lane.source = 'pve'
    lane.console_uuid = '100-uuid'
    lane.api = 'http://127.0.0.1:1'
    lane.seed_path = seed_path
    lane.needle_descriptions = []
    lane.needles = []
    return lane


class HeldSecretsTestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        workdir = tempfile.TemporaryDirectory()
        self.addCleanup(workdir.cleanup)
        self.workdir = workdir.name

    def test_the_vv_password_is_held(self):
        lane = _bare_lane(self.workdir)
        resp = mock.Mock(status_code=200, text='[virt-viewer]\ntype=spice\npassword=vv-password-7777\n')
        db = mock.Mock()
        db.get_tokens_by_console.return_value = [{'session_id': 's1'}]
        err = io.StringIO()
        with mock.patch.object(requests, 'get', return_value=resp), \
                mock.patch.object(drive_console, 'Ryll'), mock.patch.object(sys, 'stderr', err):
            _, session_id = drive_console._open_session(db, lane, {}, 1, set())
        self.assertEqual('s1', session_id)
        self.assertEqual(['the password in .vv 1'], lane.needle_descriptions)
        self.assertEqual(['vv-password-7777'], lane.needles)
        self.assertNotIn('vv-password-7777', err.getvalue())

    def test_the_api_jwts_are_held(self):
        import jwt as pyjwt

        seed_path = os.path.join(self.workdir, 'seed')
        with open(seed_path, 'w') as f:
            f.write('seed-5555555555')
        lane = _bare_lane(self.workdir, seed_path)
        lane.checkpoint = mock.Mock()
        err = io.StringIO()
        # The drive is stopped at its first request, once the JWTs are minted.
        with mock.patch.object(drive_console, '_discover', return_value=({'uuid': '100-uuid'}, 'subject')), \
                mock.patch.object(requests, 'get', side_effect=SystemExit('stop')), \
                mock.patch('kerbside.db.get_audit_events', return_value=[]), mock.patch.object(sys, 'stderr', err):
            self.assertRaises(SystemExit, drive_console._drive, lane)
        self.assertEqual(['the API JWT', 'the administrator API JWT'], lane.needle_descriptions)
        claims = [pyjwt.decode(t, 'seed-5555555555', algorithms=['HS256']) for t in lane.needles]
        self.assertEqual([False, True], [c.get('kerbside_admin', False) for c in claims])
        for token in lane.needles:
            self.assertNotIn(token, err.getvalue())


_MINTED = {'password': 'spice-sentinel-8888', 'host': 'pvespiceproxy:6720:100:pve1::sentinel',
           'proxy': 'http://pve1.example.org:3128', 'tls-port': 61000, 'type': 'spice'}


class LaneMintTestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        workdir = tempfile.TemporaryDirectory()
        self.addCleanup(workdir.cleanup)
        self.lane = _bare_lane(workdir.name)
        self.lane.node = 'pve1'
        self.lane.vmid = 100
        self.lane.token_id = _TOKEN
        self.lane.documented_file = os.path.join(workdir.name, 'documented')
        with open(self.lane.documented_file, 'w') as f:
            f.write('sentinel-documented-1111\n')
        env = mock.patch.dict(os.environ, {'PROXMOX_API_URL': 'https://pve1.example.org:8006/',
                                           'PROXMOX_CA_FILE': '/ca.pem'})
        env.start()
        self.addCleanup(env.stop)

    def mint(self, response=None, side_effect=None):
        """Run _lane_mint against a mocked POST; return (the mock, what it printed, the exit or None)."""
        post = mock.Mock(return_value=response, side_effect=side_effect)
        out = io.StringIO()
        err = io.StringIO()
        exit_ = None
        with mock.patch.object(requests, 'post', post), redirect_stdout(out), mock.patch.object(sys, 'stderr', err):
            try:
                drive_console._lane_mint(self.lane)
            except SystemExit as e:
                exit_ = str(e)
        printed = out.getvalue() + err.getvalue() + (exit_ or '')
        for value in (_MINTED['password'], _MINTED['host'], 'sentinel-documented-1111'):
            self.assertNotIn(value, printed)
        return post, printed, exit_

    def reply(self, data, status=200):
        return mock.Mock(status_code=status, reason='OK', **{'json.return_value': {'data': data}})

    def test_kerbside_s_request(self):
        post, _, exit_ = self.mint(self.reply(dict(_MINTED)))
        self.assertIsNone(exit_)
        post.assert_called_once_with(
            'https://pve1.example.org:8006/api2/json/nodes/pve1/qemu/100/spiceproxy',
            headers={'Authorization': 'PVEAPIToken=kerbside-lane@pve!console=sentinel-documented-1111'},
            data={'proxy': 'pve1.example.org'}, verify='/ca.pem', timeout=5, proxies={'http': None, 'https': None},
            allow_redirects=False)

    def test_the_values_are_held(self):
        _, printed, _ = self.mint(self.reply(dict(_MINTED)))
        self.assertEqual(['the SPICE password of the lane\'s own mint', 'the connect host of the lane\'s own mint'],
                         self.lane.needle_descriptions)
        self.assertEqual([_MINTED['password'], _MINTED['host']], self.lane.needles)
        self.assertIn('the lane minted a ticket for guest 100 with %s' % _TOKEN, printed)

    def test_a_refusal_is_a_harness_fault_and_holds_nothing(self):
        response = self.reply(dict(_MINTED), status=403)
        response.reason = 'Permission check failed'
        _, printed, exit_ = self.mint(response)
        self.assertIn('HARNESS FAULT', exit_)
        self.assertIn('answered 403 Permission check failed', printed)
        self.assertEqual([], self.lane.needles)
        response.json.assert_not_called()

    def test_a_failed_request_is_a_harness_fault(self):
        _, _, exit_ = self.mint(side_effect=requests.exceptions.ConnectionError('refused'))
        self.assertIn('HARNESS FAULT', exit_)
        self.assertIn('failed: ConnectionError', exit_)

    def test_a_missing_value_is_a_harness_fault_and_the_other_is_held(self):
        for missing, kept in (('password', 'host'), ('host', 'password')):
            self.lane.needles = []
            data = dict(_MINTED)
            del data[missing]
            _, _, exit_ = self.mint(self.reply(data))
            self.assertIn('HARNESS FAULT', exit_)
            self.assertIn('without a password and a connect host', exit_)
            self.assertEqual([_MINTED[kept]], self.lane.needles)

    def test_an_empty_or_odd_value_is_not_held(self):
        for value in ('', 12345678901, None):
            self.lane.needles = []
            data = dict(_MINTED)
            data['host'] = value
            _, _, exit_ = self.mint(self.reply(data))
            self.assertIn('HARNESS FAULT', exit_)
            self.assertEqual([_MINTED['password']], self.lane.needles)

    def test_a_reply_which_is_not_a_mapping(self):
        for response in (self.reply(['a', 'list']), self.reply(None),
                         mock.Mock(status_code=200, reason='OK', **{'json.side_effect': ValueError('not JSON')}),
                         mock.Mock(status_code=200, reason='OK', **{'json.return_value': ['not', 'a', 'dict']})):
            _, _, exit_ = self.mint(response)
            self.assertIn('HARNESS FAULT', exit_)
            self.assertEqual([], self.lane.needles)


class ReadAccessLogTestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {'PROXMOX_SSH_USER': 'debian', 'PROXMOX_NODE_ADDRESS': '10.0.0.5',
                                           'PROXMOX_SSH_KEY': '/k/id'})
        env.start()
        self.addCleanup(env.stop)

    def read(self, stdout='', returncode=0, stderr='', offset=100, token_id=_TOKEN):
        result = subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)
        out = io.StringIO()
        with mock.patch.object(drive_console.subprocess, 'run', return_value=result) as run, \
                redirect_stdout(out), mock.patch.object(sys, 'stderr', io.StringIO()):
            try:
                lines = drive_console._read_access_log(offset, token_id)
            except SystemExit as e:
                return run, None, str(e)
        return run, lines, None

    def test_the_command_filters_on_the_node(self):
        run, lines, failure = self.read('100\n')
        self.assertIsNone(failure)
        argv = run.call_args[0][0]
        self.assertEqual(['timeout', '60', 'ssh'], argv[:3])
        self.assertEqual('debian@10.0.0.5', argv[-2])
        remote = shlex.split(argv[-1])
        self.assertEqual(['bash', '-o', 'pipefail', '-c'], remote[:4])
        self.assertEqual(5, len(remote))
        inner = remote[4]
        self.assertEqual(['sudo', '-n', 'stat', '-c', '%s', drive_console.ACCESS_LOG, '&&',
                          'sudo', '-n', 'tail', '-c', '+101', drive_console.ACCESS_LOG, '|',
                          'awk', '-v', 'user=%s' % _TOKEN, '$3 == user'], shlex.split(inner))
        # The token ID reaches the node quoted, never bare.
        self.assertIn('user=%s ' % shlex.quote(_TOKEN), inner)
        self.assertNotEqual(_TOKEN, shlex.quote(_TOKEN))

    def test_a_malformed_token_id_is_refused_before_ssh(self):
        for token_id in ('kerbside@pve!console; cat /etc/shadow', 'kerbside@pve', 'kerbside!console',
                         "kerbside@pve!con'sole", 'kerbside@pve!console x', ''):
            run, lines, failure = self.read('100\n', token_id=token_id)
            self.assertIsNotNone(failure, token_id)
            self.assertTrue(failure.startswith('HARNESS FAULT: '), failure)
            run.assert_not_called()

    def test_the_lines_after_the_size_are_returned(self):
        run, lines, failure = self.read('1234\n%s\n%s\n' % (_access(), _SCRAPE))
        self.assertIsNone(failure)
        self.assertEqual([_access(), _SCRAPE], lines)

    def test_an_unchanged_log_holds_nothing(self):
        run, lines, failure = self.read('100\n', offset=100)
        self.assertIsNone(failure)
        self.assertEqual([], lines)

    def test_a_shrunken_log_is_a_harness_fault(self):
        run, lines, failure = self.read('99\n%s\n' % _access(), offset=100)
        self.assertTrue(failure.startswith('HARNESS FAULT: '), failure)
        self.assertIn('rotated', failure)

    def test_no_size_is_a_harness_fault(self):
        for stdout in ('', 'stat: cannot stat\n', '%s\n' % _access()):
            run, lines, failure = self.read(stdout)
            self.assertIsNotNone(failure, stdout)
            self.assertTrue(failure.startswith('HARNESS FAULT: '), failure)

    def test_a_failed_read_names_only_the_last_stderr_line(self):
        run, lines, failure = self.read('', returncode=255,
                                        stderr='debug1: an earlier line\nPermission denied (publickey).\n')
        self.assertTrue(failure.startswith('HARNESS FAULT: '), failure)
        self.assertIn('exit 255: Permission denied (publickey).', failure)
        self.assertNotIn('an earlier line', failure)

    def test_a_failed_read_with_no_message(self):
        run, lines, failure = self.read('100\n', returncode=1)
        self.assertIn('exit 1: no message', failure)


class RedactTestCase(testtools.TestCase):
    NEEDLES = ['secret-documented-1111', 'live-ticket-6666']

    def test_each_needle_is_replaced(self):
        self.assertEqual('a [redacted] b [redacted] c [redacted]', drive_console.redact(
            'a secret-documented-1111 b live-ticket-6666 c secret-documented-1111', self.NEEDLES))

    def test_a_connect_host_is_replaced_whole(self):
        self.assertEqual('CONNECT [redacted] HTTP/1.1\nnext [redacted]', drive_console.redact(
            'CONNECT pvespiceproxy:abc:100:pve1 HTTP/1.1\nnext pvespiceproxy:', []))

    def test_a_needle_split_by_colour(self):
        self.assertEqual('before [redacted] after', drive_console.redact(
            'before secret-\x1b[3mdocumented\x1b[0m-1111 after', self.NEEDLES))

    def test_a_connect_host_split_by_colour(self):
        self.assertEqual('CONNECT [redacted] tail', drive_console.redact(
            'CONNECT pvespice\x1b[1mproxy:\x1b[0mabc:100 tail', []))

    def test_colour_is_kept_when_nothing_is_split(self):
        self.assertEqual('\x1b[1mINFO\x1b[0m [redacted]', drive_console.redact(
            '\x1b[1mINFO\x1b[0m secret-documented-1111', self.NEEDLES))

    def test_a_longer_needle_is_replaced_whole(self):
        self.assertEqual('x [redacted] y', drive_console.redact('x abcdefgh-longer y', ['abcdefgh', 'abcdefgh-longer']))

    def test_an_empty_needle_is_passed_over(self):
        self.assertEqual('clean text', drive_console.redact('clean text', ['', None]))

    def test_clean_text_is_unchanged(self):
        self.assertEqual('\x1b[1mclean\x1b[0m text\n', drive_console.redact('\x1b[1mclean\x1b[0m text\n', self.NEEDLES))


# A line holding a file-backed secret of each kind, a held one and a connect host.
_PLANTED = ('a %s b secret-action-4444 c seed-5555555555 d live-ticket-6666 e CONNECT pvespiceproxy:abc:100:pve1 f\n'
            % _SENTINELS['documented'])
_PLANTED_REDACTED = 'a [redacted] b [redacted] c [redacted] d [redacted] e CONNECT [redacted] f\n'


class RedactedOutputTestCase(_LaneFilesTestCase):
    """Every print site for text read from a file or another process prints it redacted."""

    def setUp(self):
        super().setUp()
        drive_console._load_env_file(os.path.join(self.workdir, 'kerbside.env'))
        self.lane = _bare_lane(self.workdir)
        self.lane.remember('session 1\'s backend ticket', 'live-ticket-6666')
        patcher = mock.patch.object(drive_console, '_active_lane', self.lane)
        patcher.start()
        self.addCleanup(patcher.stop)

    def assertRedacted(self, output):
        self.assertNoValue(output)
        self.assertNotIn('pvespiceproxy:', output)
        self.assertIn(_PLANTED_REDACTED, output)

    def test_ryll_diagnostics(self):
        for name in ('ryll-proxmox-1.stdout', 'ryll-proxmox-1.stderr', 'kerbside.log'):
            self.write(name, 'earlier\n' + _PLANTED)
        err = io.StringIO()
        with mock.patch.object(sys, 'stderr', err):
            drive_console._dump_ryll_diagnostics(
                mock.Mock(pid=1, returncode=1, **{'poll.return_value': 1}),
                *[os.path.join(self.workdir, n) for n in ('ryll-proxmox-1.stdout', 'ryll-proxmox-1.stderr',
                                                          'kerbside.log')])
        self.assertRedacted(err.getvalue())
        self.assertEqual(3, err.getvalue().count(_PLANTED_REDACTED))

    def test_a_tail(self):
        self.write('kerbside.log', _PLANTED)
        self.assertEqual(_PLANTED_REDACTED, drive_console._tail(os.path.join(self.workdir, 'kerbside.log'), 60))

    def test_the_smoke_client_output(self):
        ryll = drive_console.Ryll.__new__(drive_console.Ryll)
        ryll.lane = self.lane
        self.lane.smoke_client = 'smoke-client.py'
        ryll.n = 1
        ryll.sock = 'ryll.sock'
        ryll.proc = mock.Mock(**{'poll.return_value': None})
        err = io.StringIO()
        with mock.patch.object(subprocess, 'run', return_value=mock.Mock(returncode=1, stdout=_PLANTED)), \
                mock.patch.object(sys, 'stderr', err):
            self.assertRaises(SystemExit, ryll.smoke, 'smoke-client-1.log')
        self.assertRedacted(err.getvalue())

    def test_a_verdict(self):
        out = io.StringIO()
        with redirect_stdout(out):
            e = self.assertRaises(SystemExit, drive_console._require, drive_console.DEFECT,
                                  'failed mints audited: ' + _PLANTED)
        self.assertRedacted(out.getvalue())
        self.assertRedacted(str(e))

    def test_the_redact_mode(self):
        out = io.StringIO()
        stdin = mock.Mock(buffer=io.BytesIO(_PLANTED.encode('utf-8')))
        argv = ['drive-console.py', '--redact', '--workdir', self.workdir]
        # Run as from a shell script: no Lane, so only the file-backed values and connect hosts, which it
        # learns from the env file.
        for key in ('PROXMOX_LANE_FILE', 'PROXMOX_ACTION_TOKEN_FILE', 'KERBSIDE_SEED_FILE'):
            del os.environ[key]
        with mock.patch.object(drive_console, '_active_lane', None), mock.patch.object(sys, 'argv', argv), \
                mock.patch.object(sys, 'stdin', stdin), redirect_stdout(out), \
                mock.patch.object(sys, 'stderr', io.StringIO()):
            self.assertEqual(0, drive_console.main())
        self.assertEqual(_PLANTED_REDACTED.replace('[redacted] e', 'live-ticket-6666 e'), out.getvalue())

    def test_deploy_kerbside_prints_no_tail_unredacted(self):
        script = (_TOOLS / 'deploy-kerbside.sh').read_text()
        tails = [line for line in script.splitlines() if re.search(r'\btail -', line) and
                 not line.lstrip().startswith('#')]
        self.assertNotEqual([], tails)
        for line in tails:
            self.assertIn('| redact >&2', line)
        self.assertIn('redact < "${START_STDERR}" >&2', script)
        self.assertIn('2> "${START_STDERR}"', script)


class ReuseWindowTestCase(testtools.TestCase):
    def test_today_s_window(self):
        from kerbside.rpc.servicer import REUSE_MARGIN
        from kerbside.sources.proxmox import TICKET_LIFETIME

        self.assertEqual(15, drive_console.reuse_window(TICKET_LIFETIME, REUSE_MARGIN))
        self.assertEqual(MintVerdictTestCase.WINDOW, drive_console.reuse_window(TICKET_LIFETIME, REUSE_MARGIN))

    def test_the_smallest_window(self):
        self.assertEqual(1, drive_console.reuse_window(16, 10))

    def test_no_window_is_refused(self):
        for lifetime, margin in ((15, 10), (14, 10), (10, 10), (5, 10)):
            e = self.assertRaises(ValueError, drive_console.reuse_window, lifetime, margin)
            self.assertIn('leaves no reuse window', str(e))

    def test_a_checkpoint_with_no_window_is_a_harness_fault(self):
        lane = _bare_lane(tempfile.gettempdir())
        lane.offset = 0
        lane.token_id = _IDS['documented']
        lane.log_path = '/nonexistent'
        with mock.patch.object(drive_console, '_read_access_log', return_value=[_SCRAPE]), \
                mock.patch('kerbside.sources.proxmox.TICKET_LIFETIME', 15), \
                redirect_stdout(io.StringIO()), mock.patch.object(sys, 'stderr', io.StringIO()):
            e = self.assertRaises(SystemExit, lane.checkpoint, 'test', 0)
        self.assertTrue(str(e).startswith('HARNESS FAULT: '), str(e))
        self.assertIn('leaves no reuse window', str(e))


class JwtLifetimeTestCase(testtools.TestCase):
    def test_a_jwt_lasts_jwt_lifetime(self):
        import jwt as pyjwt

        workdir = tempfile.TemporaryDirectory()
        self.addCleanup(workdir.cleanup)
        seed_path = os.path.join(workdir.name, 'seed')
        with open(seed_path, 'w') as f:
            f.write('seed-5555555555')
        claims = pyjwt.decode(drive_console._mint_auth_jwt(seed_path), 'seed-5555555555', algorithms=['HS256'])
        self.assertEqual(drive_console.JWT_LIFETIME, claims['exp'] - claims['iat'])

    def test_the_lifetime_covers_the_drive_step_and_little_more(self):
        workflow = yaml.safe_load(_WORKFLOW.read_text())
        steps = [step for step in workflow['jobs']['proxmox']['steps']
                 if step.get('name') == 'Drive a proxied SPICE console']
        self.assertEqual(1, len(steps))
        timeout = steps[0]['timeout-minutes'] * 60
        self.assertGreater(drive_console.JWT_LIFETIME, timeout)
        self.assertLessEqual(drive_console.JWT_LIFETIME, timeout + 600)
