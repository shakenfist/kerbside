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

import ast
import datetime
import importlib.util
import io
import json
import os
import re
import tempfile
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import testtools
import yaml

from kerbside import config
from kerbside import db
from kerbside.sources import static


# The repository root. The role and the fixture are repository data,
# outside the kerbside package, so no wheel contains them and the
# tests find them from this file instead.
_ROOT = Path(__file__).resolve().parents[3]
_ROLE = _ROOT / 'ansible' / 'roles' / 'kerbside'
_KERBSIDE = _ROOT / 'kerbside'
_DEFAULTS = _ROLE / 'defaults' / 'main.yml'
_ARGUMENT_SPECS = _ROLE / 'meta' / 'argument_specs.yml'
_ANSIBLE_README = _ROOT / 'ansible' / 'README.md'
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

    # Rows whose default is prose rather than one literal, because it
    # depends on something outside defaults/main.yml: both of these
    # differ between a checkout and a release. Pinned rather than
    # skipped on shape, so a new prose default is a deliberate edit.
    PROSE_DEFAULTS = ('kerbside_collection_version', 'kerbside_package')
    # Rows for variables defaults/main.yml does not set. Pinned for the
    # same reason: a row left behind by a renamed or deleted variable is
    # drift in the other direction, and must fail rather than be skipped.
    # kerbside_collection_version is set by the collection's build, not
    # by the role.
    NOT_DEFAULTED = ('kerbside_collection_version',)

    def test_the_readme_documents_the_real_defaults(self):
        """ansible/README.md's tables are read in place of the code.

        A default stated there which the role does not set is a claim
        the tree contradicts, and operators act on those: review of
        #717 found docs/network-ports.md telling them that
        kerbside_reserved_ports already reserved Shaken Fist's console
        range, where the role reserves nothing and the README's
        [30000, 65535] is a worked example of what to pass.
        """
        documented = _documented_defaults()
        defaults = _rendered_defaults()

        self.assertNotEqual({}, defaults)
        undocumented = sorted(set(defaults) - set(documented))
        self.assertEqual(
            [], undocumented,
            'role defaults with no row in ansible/README.md: %s'
            % ', '.join(undocumented))
        stale = sorted(set(documented) - set(defaults))
        self.assertEqual(
            sorted(self.NOT_DEFAULTED), stale,
            'ansible/README.md documents a default for a variable the role '
            'does not set; if that is deliberate, add it to NOT_DEFAULTED')

        prose = sorted(name for name, cell in documented.items()
                       if not _README_LITERAL_RE.match(cell))
        self.assertEqual(
            sorted(self.PROSE_DEFAULTS), prose,
            'ansible/README.md states a default this test cannot read as '
            'one literal; if that is deliberate, add it to '
            'PROSE_DEFAULTS, which is what exempts it')

        # Every remaining row is compared, so the regex above cannot
        # stop matching a table without the count moving.
        compared = 0
        drifted = []
        for name, cell in sorted(documented.items()):
            if name in self.PROSE_DEFAULTS:
                continue
            literal = _README_LITERAL_RE.match(cell).group(1)
            stated = yaml.safe_load(literal) if literal else ''
            compared += 1
            if stated != defaults[name]:
                drifted.append('%s: README says %r, the role sets %r'
                               % (name, stated, defaults[name]))
        self.assertEqual([], drifted, '; '.join(drifted))
        expected = len(set(defaults) - set(self.PROSE_DEFAULTS))
        self.assertEqual(expected, compared,
                         'only %d of %d comparable role defaults were '
                         'compared: %r' % (compared, expected, documented))


# A row of one of ansible/README.md's variable tables: the variable, the
# default it documents, and the prose, which is not read here.
_README_ROW_RE = re.compile(
    r'^\|\s*`(kerbside_[a-z_0-9]+)`\s*\|\s*(.*?)\s*\|.*\|\s*$')
# A documented default which is one literal, so comparable with the
# role's. A row saying more than that is listed below instead.
_README_LITERAL_RE = re.compile(r'^`([^`]*)`$')
# A default referring to another, as kerbside_pki_dir does. Only the
# bare `{{ name }}` form appears, and a reference to a variable the role
# does not default, or to one which is not a string, is left alone, so it
# fails the comparison rather than rendering as nothing or as a repr.
_JINJA_REF_RE = re.compile(r'{{\s*(kerbside_[a-z_0-9]+)\s*}}')


def _documented_defaults():
    """Each kerbside_* variable ansible/README.md documents a default for."""
    rows = {}
    with open(_ANSIBLE_README, encoding='utf-8') as f:
        for line in f:
            match = _README_ROW_RE.match(line)
            if match:
                rows[match.group(1)] = match.group(2)
    return rows


def _rendered_defaults():
    """defaults/main.yml, with references to its own variables resolved.

    The role's default for kerbside_pki_dir is written in terms of
    kerbside_config_dir, which the README spells out, so comparing the
    two needs the reference rendered. Four passes is more depth than
    the file has. A reference which cannot be resolved to a string -- to
    a variable the role does not default, or to a list or a number -- is
    left in place to fail the comparison.
    """
    def resolve(match):
        value = defaults.get(match.group(1))
        return value if isinstance(value, str) else match.group(0)

    with open(_DEFAULTS, encoding='utf-8') as f:
        defaults = yaml.safe_load(f)
    for _ in range(4):
        for name, value in list(defaults.items()):
            if isinstance(value, str) and '{{' in value:
                defaults[name] = _JINJA_REF_RE.sub(resolve, value)
    return defaults


def _source_fields():
    """Every source field validate's check knows, checked or not."""
    fields = set(check_sources.COMMON_REQUIRED + check_sources.COMMON_TEXT
                 + check_sources.DRIVER_OPTIONAL + ('consoles',))
    for required in check_sources.TYPE_REQUIRED.values():
        fields.update(required)
    return fields


def _console_fields():
    """Every static console field validate's check knows."""
    return set(check_sources.CONSOLE_REQUIRED + check_sources.CONSOLE_PORTS
               + check_sources.CONSOLE_OPTIONAL_TEXT)


def _keys_read(path, name):
    """The constant keys a module reads from the mapping spelled name.

    That is name['key'], name.get('key') and 'key' in name.
    """
    keys = set()
    for node in ast.walk(ast.parse(path.read_text())):
        mapping = key = None
        if isinstance(node, ast.Subscript):
            mapping, key = node.value, node.slice
        elif (isinstance(node, ast.Call)
              and isinstance(node.func, ast.Attribute)
              and node.func.attr == 'get' and node.args):
            mapping, key = node.func.value, node.args[0]
        elif (isinstance(node, ast.Compare) and len(node.ops) == 1
              and isinstance(node.ops[0], (ast.In, ast.NotIn))):
            mapping, key = node.comparators[0], node.left
        if (mapping is not None and ast.unparse(mapping) == name
                and isinstance(key, ast.Constant)
                and isinstance(key.value, str)):
            keys.add(key.value)
    return keys


class SourcesArgumentSpecTestCase(testtools.TestCase):
    """kerbside_sources' argument spec masks exactly Kerbside's secrets.

    ansible-core 2.22 redacts every value of a no_log option from all of
    its output, so the spec declares each source and console field and
    marks only the credentials no_log (#687). A key it does not declare
    is refused, so it must declare every field the check knows.
    """

    def setUp(self):
        super().setUp()
        with open(_ARGUMENT_SPECS) as f:
            specs = yaml.safe_load(f)
        self.sources = specs['argument_specs']['main']['options'][
            'kerbside_sources']
        self.source_options = self.sources['options']
        self.console_options = self.source_options['consoles']['options']

    def _no_log(self, options):
        return sorted(name for name, option in options.items()
                      if option.get('no_log'))

    def test_the_list_itself_is_not_no_log(self):
        self.assertFalse(self.sources.get('no_log', False))
        self.assertFalse(
            self.source_options['consoles'].get('no_log', False))

    def test_only_kerbside_secret_fields_are_no_log(self):
        self.assertEqual(
            sorted(db.SOURCE_SECRET_FIELDS),
            self._no_log(self.source_options))
        self.assertEqual(
            sorted(db.CONSOLE_SECRET_FIELDS),
            self._no_log(self.console_options))

    def test_declared_fields_are_those_the_check_knows(self):
        # Both ways: a field the check knows and the specs do not declare is
        # refused before the check sees it, and one the specs declare and
        # nothing knows is stale.
        self.assertEqual(
            sorted(_source_fields()), sorted(self.source_options))
        self.assertEqual(
            sorted(_console_fields()), sorted(self.console_options))

    def test_console_fields_are_those_the_static_driver_reads(self):
        self.assertEqual(
            sorted(_console_fields()),
            sorted(static._REQUIRED_FIELDS + tuple(static._OPTIONAL_FIELDS)))

    def test_every_source_field_kerbside_reads_is_known(self):
        # A source's fields are read by its driver, as self.args, and by the
        # API's OpenStack lookup, as source. The specs refuse a field they do
        # not declare, so one Kerbside starts reading must be added there.
        read = set()
        for path in sorted((_KERBSIDE / 'sources').glob('*.py')):
            read |= _keys_read(path, 'self.args')
        read |= _keys_read(_KERBSIDE / 'api.py', 'source')
        self.assertEqual([], sorted(read - _source_fields()))
        # And the scan still sees the readers of the fields only they read,
        # so that it cannot pass by finding nothing.
        self.assertEqual(
            [], sorted(set(check_sources.DRIVER_OPTIONAL) - read))

    def test_values_are_passed_on_unconverted(self):
        # validate's check must see an unquoted numeric password as the
        # number it is, so no field may be converted on the way.
        options = dict(self.source_options)
        options.pop('consoles')
        options.update(self.console_options)
        self.assertEqual(
            [], sorted(name for name, option in options.items()
                       if option.get('type') != 'raw'))


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

    def test_a_complete_proxmox_source_passes(self):
        self.assertEqual([], self._check(
            '- {source: a, type: proxmox, url: "https://u:8006", username: "k@pve!t",\n'
            '   password: s3cret, ca_cert: c}\n'))

    def test_a_proxmox_source_needs_an_https_url(self):
        for url in ('http://u:8006', 'u:8006'):
            errors = self._check(
                '- {source: a, type: proxmox, url: "%s", username: "k@pve!t",\n'
                '   password: s3cret, ca_cert: c}\n' % url)
            self.assertEqual(['source 0 (proxmox): url is not https, which Kerbside '
                              'refuses for Proxmox VE'], errors, url)

    def test_a_proxmox_source_needs_a_ca_cert(self):
        errors = self._check(
            '- {source: a, type: proxmox, url: "https://u:8006", username: "k@pve!t",\n'
            '   password: s3cret}\n')
        self.assertEqual(['source 0 (proxmox): ca_cert is missing'], errors)
        self.assertNotIn('s3cret', ' '.join(errors))

    def test_a_boolean_is_not_text(self):
        self.assertEqual(
            ['source 0: password is not text'],
            self._check('- {source: a, type: shakenfist, url: u, '
                        'username: system, password: true, ca_cert: c}\n'))

    def test_json_keeps_a_numeric_credential_a_number(self):
        # As YAML, the rendered 5349 would read back as text; as JSON, the
        # variable's own type, it is refused.
        text = ('[{"source": "a", "type": "shakenfist", "url": "u", '
                '"username": "system", "password": 5349, "ca_cert": "c"}]')
        self.assertEqual([], self._check(text))
        self.assertEqual(
            ['source 0: password is not text'],
            check_sources.check_stream(io.StringIO(text), as_json=True))

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

    def test_no_role_helper_writes_with_a_raw_print(self):
        """The push audit fails any range that adds one to this tree.

        kerbside-ready.py's one JSON object on stdout is its contract,
        and it used print() for it, so every audit range touching the
        file exited 3 at "raw print() added" and never reached the
        bare-except check (#623). The alternative, wave 1's opt-in
        marker comment, suppresses the print check for the whole diff
        rather than for the file carrying it, so these scripts write to
        stdout instead -- and that is worth a test here rather than
        only in a gate nobody runs before pushing.
        """
        offenders = []
        for path in sorted((_ROLE / 'files').glob('*.py')):
            text = path.read_text(encoding='utf-8')
            if 'audit-allow-print' in text:
                continue
            for node in ast.walk(ast.parse(text)):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == 'print'):
                    offenders.append('%s:%d' % (path.name, node.lineno))

        self.assertEqual([], offenders)

    def test_the_output_matches_the_patterns_register_parses_it_with(self):
        """One JSON object on one line, as kerbside_ready_pattern reads it.

        register's readiness wait matches stdout against that pattern
        before from_json, because from_json on anything else fails the
        task rather than counting as not ready -- so a change to how
        this script writes its object is a change to whether the deploy
        can see readiness at all. Nothing asserted the two agreed, so
        the pattern is read out of the role rather than restated here.
        """
        with open(_ROLE / 'vars' / 'main.yml', encoding='utf-8') as f:
            pattern = yaml.safe_load(f)['kerbside_ready_pattern']

        cases = (
            {'errored': False, 'fetched_at': 150.0},
            {'errored': None, 'fetched_at': None},
            {'errored': True, 'fetched_at': 1791234567.123},
            {'errored': None, 'fetched_at': None,
             'error': 'usage: kerbside-ready.py SOURCE_NAME...'},
        )
        for case in cases:
            stdout = io.StringIO()
            with mock.patch('sys.stdout', stdout):
                ready.report(**case)
            written = stdout.getvalue()

            self.assertTrue(
                written.endswith('\n'), 'no trailing newline: %r' % written)
            self.assertEqual(
                1, len(written.splitlines()), 'not one line: %r' % written)
            self.assertRegex(written.strip(), pattern)
            self.assertEqual(case, json.loads(written))


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
