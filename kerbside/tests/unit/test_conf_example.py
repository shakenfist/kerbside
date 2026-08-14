import configparser
import os
import re

import testtools

from kerbside import config as kerbside_config
from kerbside.config import Config


# A live setting: "key = value" at the start of a line.
_LIVE = re.compile(r'^([a-z_][a-z0-9_]*) = ?(.*)$')

# A documented default: "# key = value", exactly one leading "# ".
# The example file's header tells the reader this form is asserted
# here, so it cannot be reformatted casually.
_COMMENTED = re.compile(r'^# ([a-z_][a-z0-9_]*) = ?(.*)$')

_SENTINEL = '~~unconfigured~~'


def _example_path():
    """Find etc/kerbside.conf.example, or None outside a checkout.

    The example is repository data rather than package data -- it is
    not under a package directory, so setuptools_scm's file finder
    does not contribute it and no wheel contains it (this is the same
    rule that stranded the migrations before phase 1 moved them into
    kerbside/migrations/). So importlib.resources cannot find it and
    the tests walk up from __file__ instead.
    """
    path = os.path.dirname(os.path.abspath(__file__))
    while path != '/':
        candidate = os.path.join(path, 'etc', 'kerbside.conf.example')
        if os.path.isfile(candidate):
            return candidate
        path = os.path.dirname(path)
    return None


def _read_example():
    """Return (text, live, commented) for the example file."""
    path = _example_path()
    if path is None:
        raise testtools.TestCase.skipException(
            'no etc/kerbside.conf.example above %s; not running from a '
            'checkout, and the example does not ship in the wheel'
            % os.path.abspath(__file__))

    with open(path) as f:
        text = f.read()

    live, commented = {}, {}
    for line in text.splitlines():
        match = _LIVE.match(line)
        if match:
            live[match.group(1)] = match.group(2)
            continue
        match = _COMMENTED.match(line)
        if match:
            commented[match.group(1)] = match.group(2)

    return text, live, commented


class ConfExampleCoverageTestCase(testtools.TestCase):
    """etc/kerbside.conf.example must not fall behind config.py.

    Two documents have pointed at this file for a long time while it
    did not exist at all, which is the failure mode a coverage test
    cannot fix. What it can fix is the next one: a setting added to
    Config and never documented, so the file decays into a partial
    reference that looks complete.

    Both directions are asserted. A missing key means an undocumented
    setting; an extra key means a setting was renamed or removed and
    the example still advertises it, which is worse than silence
    because the reader will copy it.
    """

    def setUp(self):
        super().setUp()
        self.text, self.live, self.commented = _read_example()
        self.documented = set(self.live) | set(self.commented)
        self.fields = {name.lower() for name in Config.model_fields}

    def test_every_setting_is_documented(self):
        missing = sorted(self.fields - self.documented)
        self.assertEqual(
            [], missing,
            'these settings exist on Config but are absent from '
            'etc/kerbside.conf.example: %s' % ', '.join(missing))

    def test_no_orphan_keys(self):
        orphans = sorted(self.documented - self.fields)
        self.assertEqual(
            [], orphans,
            'etc/kerbside.conf.example documents keys that are not '
            'fields on Config: %s' % ', '.join(orphans))

    def test_the_file_parses(self):
        """It must parse the way load_ini_settings() parses it.

        Same parser, same interpolation. A literal percent sign in a
        value raises here, which matters because config.py catches
        that and exits -- with status zero -- so a malformed file
        takes the daemon down while reporting success.
        """
        parser = configparser.ConfigParser()
        parser.read_string(self.text)

        self.assertEqual(['kerbside'], parser.sections())

        # Reading each value is what triggers interpolation, so a
        # bare percent sign would not be caught by read_string alone.
        for key in parser['kerbside']:
            parser['kerbside'][key]

    def test_live_keys_are_the_ones_without_usable_defaults(self):
        """Decision 4: live keys are a judgement, so pin the judgement.

        No field on Config is required -- all 34 have defaults -- so
        nothing in the model distinguishes these. Without this
        assertion the live set could drift silently, and a reader who
        copies the file would either miss a setting they must review
        or be prompted for one they need not touch.
        """
        self.assertEqual(
            sorted(['auth_secret_seed', 'cacert_path',
                    'proxy_host_cert_key_path', 'proxy_host_cert_path',
                    'proxy_host_subject', 'public_fqdn', 'sources_path',
                    'sql_url']),
            sorted(self.live))


class ConfExampleSafetyTestCase(testtools.TestCase):
    """No line of the example may work if pasted.

    Three defaults on Config read as usable values: SQL_URL embeds a
    plausible password, PUBLIC_FQDN is a host on one person's network,
    and AUTH_SECRET_SEED is a sentinel that nothing rejects at
    startup (issue #131). An example file that reproduces them hands
    the reader something that looks configured and is not, and in the
    seed's case something that makes session JWTs forgeable.

    The forbidden values are read from Config rather than written
    here, so changing a default in config.py cannot quietly defeat
    this.
    """

    def setUp(self):
        super().setUp()
        self.text, self.live, _ = _read_example()

    def _default(self, name):
        return Config.model_fields[name].default

    def test_the_real_sql_url_default_is_absent(self):
        default = self._default('SQL_URL')
        self.assertNotIn(
            default, self.text,
            'the example reproduces SQL_URL\'s built-in default, which '
            'embeds a password; describe it instead')

    def test_the_real_public_fqdn_default_is_absent(self):
        default = self._default('PUBLIC_FQDN')
        self.assertNotIn(
            default, self.text,
            'the example reproduces PUBLIC_FQDN\'s built-in default, '
            'which is a personal hostname; describe it instead')

    def test_the_seed_is_not_live_at_its_sentinel(self):
        """The sentinel may be documented, but not offered as a value.

        It legitimately appears as the documented default of the four
        Keystone settings. What it must not be is the live value of
        auth_secret_seed, which would be a working configuration that
        signs tokens with a public constant.
        """
        self.assertNotEqual(_SENTINEL, self.live.get('auth_secret_seed'))

    def test_no_plausible_secret_is_shipped(self):
        """A hex run long enough to be a real key must not appear.

        auth_secret_seed is generated with `openssl rand -hex 32`, so
        a 64-character hex string in this file would be
        indistinguishable from a real seed and someone would keep it.
        """
        self.assertIsNone(
            re.search(r'[0-9a-fA-F]{64}', self.text),
            'the example contains something shaped like a generated '
            'secret')


class IniLoadingTestCase(testtools.TestCase):
    """The mechanism the example demonstrates, which nothing tested.

    docs/configuration.md:3 promises that environment variables take
    priority over the INI file. That promise is one `if` in
    load_ini_settings(), it is the reason a container can override a
    baked-in config file, and until now no test held it. Phase 2 is
    what turns the INI file into the documented way to configure
    kerbside, so the precedence stops being incidental.

    These tests drive the real function against the real example file
    rather than a fixture, so they also prove the shipped example is
    loadable -- a syntactically broken example would fail here.
    """

    def setUp(self):
        super().setUp()

        path = _example_path()
        if path is None:
            raise testtools.TestCase.skipException(
                'no etc/kerbside.conf.example above %s'
                % os.path.abspath(__file__))

        # Restore INI_PATH first: the getattr is evaluated now, before
        # the overwrite below, so the cleanup restores the original.
        self.addCleanup(
            setattr, kerbside_config, 'INI_PATH',
            kerbside_config.INI_PATH)
        kerbside_config.INI_PATH = path

        saved = {k: v for k, v in os.environ.items()
                 if k.startswith(kerbside_config.ENV_PREFIX)}
        self.addCleanup(self._restore_environment, saved)
        self._clear_environment()

    def _clear_environment(self):
        for key in list(os.environ):
            if key.startswith(kerbside_config.ENV_PREFIX):
                del os.environ[key]

    def _restore_environment(self, saved):
        self._clear_environment()
        os.environ.update(saved)

    def test_settings_arrive_as_prefixed_environment_variables(self):
        """Keys are upper-cased and prefixed, so lower case is fine.

        The example is written in lower case deliberately. If this
        ever stopped holding, every key in the file would be silently
        ignored while the file still looked correct.
        """
        kerbside_config.load_ini_settings()

        self.assertEqual(
            'kerbside.example.com', os.environ['KERBSIDE_PUBLIC_FQDN'])
        self.assertIn('KERBSIDE_SQL_URL', os.environ)
        self.assertIn('KERBSIDE_AUTH_SECRET_SEED', os.environ)

    def test_commented_defaults_are_inert(self):
        """Documented defaults must not become live settings.

        The 26 commented keys exist to tell the reader what the
        default is. If configparser ever treated them as values, the
        example would be quietly imposing defaults rather than
        documenting them -- and the coverage test above, which counts
        them as documented, would be masking it.
        """
        kerbside_config.load_ini_settings()

        self.assertNotIn('KERBSIDE_API_GRPC_WORKERS', os.environ)
        self.assertNotIn('KERBSIDE_KEYSTONE_ACCESS_GROUP', os.environ)

    def test_an_existing_environment_variable_wins(self):
        """The promise in docs/configuration.md:3.

        A deployment that sets KERBSIDE_* in the environment -- a
        container, a systemd unit, the direct-qemu lane -- must not
        have those values replaced by whatever is in the file.
        """
        os.environ['KERBSIDE_PUBLIC_FQDN'] = 'preset.example.net'

        kerbside_config.load_ini_settings()

        self.assertEqual(
            'preset.example.net', os.environ['KERBSIDE_PUBLIC_FQDN'])
