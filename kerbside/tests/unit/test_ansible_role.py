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

The role's defaults are checked against its argument specs here too.
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


# The repository root. The role and the fixture are repository data,
# outside the kerbside package, so no wheel contains them and the
# tests find them from this file instead.
_ROOT = Path(__file__).resolve().parents[3]
_ROLE = _ROOT / 'ansible' / 'roles' / 'kerbside'
_SCRIPT = _ROLE / 'files' / 'kerbside-host-subject.py'
_DEFAULTS = _ROLE / 'defaults' / 'main.yml'
_ARGUMENT_SPECS = _ROLE / 'meta' / 'argument_specs.yml'
_FIXTURE = _ROOT / 'tests' / 'fixtures' / 'host-subject-renderings.json'

# The script is a standalone file in the role, with a hyphenated name,
# so load it by path.
_spec = importlib.util.spec_from_file_location(
    'kerbside_host_subject', _SCRIPT)
script = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(script)

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
