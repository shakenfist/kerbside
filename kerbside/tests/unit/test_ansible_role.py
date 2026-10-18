"""Tests for the kerbside Ansible role's host subject script and defaults.

Kerbside embeds PROXY_HOST_SUBJECT in the console files it hands to
SPICE clients, and the client compares it with the subject of the
certificate the proxy presents. The role renders it with
ansible/roles/kerbside/files/kerbside-host-subject.py, whose rules must
match Shaken Fist's node.py, which renders a hypervisor's subject for
the same comparison. A difference surfaces only as clients refusing to
connect, never as a failed deploy.

Shaken Fist is not a dependency of Kerbside, so the script is held to
tests/fixtures/host-subject-renderings.json: the renderings and
refusals node.py produced, recorded with the commit they came from.

The role's defaults are checked against its argument specs here too,
and the logic of two more of its helper scripts: the one which checks
sources.yaml, and the one register polls for readiness, which reports
several Shaken Fist sources as one.
"""

import datetime
import importlib.util
import io
import json
import os
import tempfile
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import testtools
import yaml

from kerbside import config


# The repository root. The role and the fixture are repository data,
# outside the kerbside package, so no wheel contains them and the
# tests find them from this file instead.
_ROOT = Path(__file__).resolve().parents[3]
_ROLE = _ROOT / 'ansible' / 'roles' / 'kerbside'
_DEFAULTS = _ROLE / 'defaults' / 'main.yml'
_ARGUMENT_SPECS = _ROLE / 'meta' / 'argument_specs.yml'
_FIXTURE = _ROOT / 'tests' / 'fixtures' / 'host-subject-renderings.json'


def _load_script(name, filename):
    """Load one of the role's helper scripts, which have hyphenated names."""
    spec = importlib.util.spec_from_file_location(
        name, _ROLE / 'files' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


script = _load_script('kerbside_host_subject', 'kerbside-host-subject.py')
check_sources = _load_script(
    'kerbside_check_sources', 'kerbside-check-sources.py')
ready = _load_script('kerbside_ready', 'kerbside-ready.py')
check_ini = _load_script('kerbside_check_ini', 'kerbside-check-ini.py')

with open(_FIXTURE) as _f:
    FIXTURE = json.load(_f)


def _make_cert(subject):
    """A self-signed certificate whose subject is exactly subject.

    subject is a list of [dotted OID, value] pairs, in order.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([
        x509.NameAttribute(x509.ObjectIdentifier(oid), value)
        for oid, value in subject])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(key, None))


class HostSubjectScriptTestCase(testtools.TestCase):
    def test_fixture_is_not_empty(self):
        # An emptied fixture would pass every loop below.
        self.assertNotEqual({}, FIXTURE['short_names'])
        self.assertNotEqual([], FIXTURE['renderable'])
        self.assertNotEqual([], FIXTURE['unrenderable'])

    def test_short_names_match_the_fixture(self):
        self.assertEqual(
            FIXTURE['short_names'],
            {oid.dotted_string: short
             for oid, short in script.SHORT_NAMES.items()})

    def test_renders_as_the_fixture_does(self):
        for case in FIXTURE['renderable']:
            self.assertEqual(
                case['host_subject'],
                script.host_subject(_make_cert(case['subject'])),
                '%s: the script renders differently from node.py'
                % case['name'])

    def test_refuses_where_the_fixture_does(self):
        for case in FIXTURE['unrenderable']:
            self.assertRaises(
                script.SubjectError, script.host_subject,
                _make_cert(case['subject']))

    def _run_main(self, subject):
        cert = _make_cert(subject)
        with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            path = f.name
        self.addCleanup(os.unlink, path)

        stdout = mock.MagicMock()
        stdout.buffer = io.BytesIO()
        stderr = io.StringIO()
        with mock.patch('sys.stdout', stdout), \
                mock.patch('sys.stderr', stderr):
            rc = script.main(['kerbside-host-subject.py', path])
        return rc, stdout.buffer.getvalue(), stderr.getvalue()

    def test_main_prints_the_subject(self):
        case = FIXTURE['renderable'][0]
        rc, written, errors = self._run_main(case['subject'])
        self.assertEqual(0, rc)
        self.assertEqual(
            case['host_subject'].encode('utf-8') + b'\n', written)
        self.assertEqual('', errors)

    def test_main_fails_and_says_why(self):
        case = [c for c in FIXTURE['unrenderable']
                if c['name'] == 'unknown_oid'][0]
        rc, written, errors = self._run_main(case['subject'])
        self.assertEqual(1, rc)
        self.assertEqual(b'', written)
        self.assertIn('2.5.4.5', errors)

    def test_main_fails_on_a_missing_file(self):
        stderr = io.StringIO()
        with mock.patch('sys.stderr', stderr):
            rc = script.main(
                ['kerbside-host-subject.py', '/nonexistent.pem'])
        self.assertEqual(1, rc)
        self.assertIn('/nonexistent.pem', stderr.getvalue())


class RoleDefaultsTestCase(testtools.TestCase):
    def test_defaults_are_declared_in_the_argument_specs(self):
        with open(_DEFAULTS) as f:
            defaults = yaml.safe_load(f)
        with open(_ARGUMENT_SPECS) as f:
            specs = yaml.safe_load(f)
        options = specs['argument_specs']['main']['options']
        self.assertNotEqual({}, defaults)
        undeclared = sorted(set(defaults) - set(options))
        self.assertEqual(
            [], undeclared,
            'role defaults not declared in argument_specs.yml: %s'
            % ', '.join(undeclared))

    def test_documented_defaults_are_the_real_ones(self):
        # Ansible does not apply an argument spec's default, so nothing
        # but this test keeps what ansible-doc shows equal to what the
        # role does.
        with open(_DEFAULTS) as f:
            defaults = yaml.safe_load(f)
        with open(_ARGUMENT_SPECS) as f:
            specs = yaml.safe_load(f)
        drifted = sorted(
            '%s.%s' % (entry_point, name)
            for entry_point, spec in specs['argument_specs'].items()
            for name, option in spec.get('options', {}).items()
            if name in defaults and option.get('default') != defaults[name])
        self.assertEqual(
            [], drifted,
            'argument_specs.yml documents a default other than '
            'defaults/main.yml sets: %s' % ', '.join(drifted))


class CheckSourcesScriptTestCase(testtools.TestCase):
    def _check(self, text):
        return check_sources.check_stream(io.StringIO(text))

    def test_numbers_are_read_as_kerbside_reads_them(self):
        # An unquoted 012345 is the text Kerbside reads, not octal 5349,
        # so it is a password; a port may be written either way.
        self.assertEqual([], self._check(
            '- {source: a, type: shakenfist, url: u, username: system,\n'
            '   password: 012345, ca_cert: c}\n'
            '- source: b\n'
            '  type: static\n'
            '  consoles:\n'
            '  - {uuid: 1, name: n, hypervisor: h, hypervisor_ip: i,\n'
            '     insecure_port: "5910", secure_port: 5911, ticket: 0x1F}\n'))

    def test_a_boolean_is_not_text(self):
        self.assertEqual(
            ['source 0: password is not text'],
            self._check('- {source: a, type: shakenfist, url: u, '
                        'username: system, password: true, ca_cert: c}\n'))

    def test_an_empty_list_is_refused(self):
        self.assertEqual(
            ['the file is not a non-empty list of sources'],
            self._check('[]\n'))

    def test_a_yaml_error_names_only_the_line(self):
        errors = self._check('- source: a\n  password: "secret\n  :\n')
        self.assertEqual(1, len(errors))
        self.assertNotIn('secret', errors[0])
        self.assertIn('line', errors[0])


class ReadyScriptTestCase(testtools.TestCase):
    def test_combine_reports_the_oldest_fetch(self):
        self.assertEqual(
            (False, 100.0),
            ready.combine([(False, 300.0), (False, 100.0), (False, 200.0)]))

    def test_combine_reports_null_until_every_source_fetched(self):
        self.assertEqual(
            (False, None), ready.combine([(False, 300.0), (False, None)]))

    def test_combine_reports_any_error_and_any_missing_source(self):
        self.assertEqual(
            (True, None), ready.combine([(None, None), (True, 1.0)]))
        self.assertEqual(
            (None, 1.0), ready.combine([(None, 1.0), (False, 2.0)]))

    def test_main_reads_every_source_named(self):
        states = {'sf': (False, 200.0), 'sf2': (False, 150.0)}
        stdout = io.StringIO()
        with mock.patch.object(ready, 'load_db',
                               return_value=(object(), None)), \
                mock.patch.object(ready, 'read_state',
                                  side_effect=lambda db, name: states[name]), \
                mock.patch('sys.stdout', stdout):
            rc = ready.main(['kerbside-ready.py', 'sf', 'sf2'])
        self.assertEqual(0, rc)
        self.assertEqual(
            {'errored': False, 'fetched_at': 150.0},
            json.loads(stdout.getvalue()))

    def test_main_needs_a_source_name(self):
        stdout = io.StringIO()
        with mock.patch('sys.stdout', stdout):
            rc = ready.main(['kerbside-ready.py'])
        self.assertEqual(2, rc)
        self.assertIn('usage', json.loads(stdout.getvalue())['error'])


class CheckIniScriptTestCase(testtools.TestCase):
    def _check(self, text):
        with tempfile.NamedTemporaryFile('w', suffix='.ini') as f:
            f.write(text)
            f.flush()
            return check_ini.check(f.name)

    def test_reads_as_kerbside_reads(self):
        # The checker must parse exactly as kerbside/config.py does, or it
        # refuses files Kerbside accepts, or the reverse. A percent-encoded
        # password, a lone % and an interpolation-shaped value are all
        # literal to Kerbside.
        text = ('[kerbside]\n'
                'sql_url = mysql://u:pw%40x@db/kerbside\n'
                'auth_secret_seed = 100%(really)s%%\n')
        with tempfile.NamedTemporaryFile('w', suffix='.ini') as f:
            f.write(text)
            f.flush()
            ours = check_ini.make_parser()
            ours.read(f.name)
            theirs = config.make_ini_parser()
            theirs.read(f.name)
        self.assertEqual(dict(theirs['kerbside']), dict(ours['kerbside']))
        self.assertEqual([], self._check(text))

    def test_a_good_file_passes(self):
        self.assertEqual(
            [], self._check('[kerbside]\nsql_url = sqlite://\n'))

    def test_a_missing_section_is_refused(self):
        self.assertEqual(
            ['the file has no [kerbside] section'],
            self._check('[other]\nsql_url = sqlite://\n'))

    def test_no_section_header_is_refused_by_line(self):
        self.assertEqual(
            ['MissingSectionHeaderError at line 1'],
            self._check('sql_url = secret-value\n'))

    def test_a_multi_line_value_is_refused(self):
        self.assertEqual(
            ['sql_url spans more than one line'],
            self._check('[kerbside]\nsql_url = first\n  second\n'))

    def test_no_message_quotes_a_value(self):
        for text in ('sql_url = secret-value\n',
                     '[kerbside]\nsql_url = secret-value\n  more\n',
                     '[kerbside]\nsql_url = a\nsql_url = secret-value\n'):
            for reason in self._check(text):
                self.assertNotIn('secret-value', reason)
