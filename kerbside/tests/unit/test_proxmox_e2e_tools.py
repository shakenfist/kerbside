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
