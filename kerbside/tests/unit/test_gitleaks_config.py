import os
import re
import subprocess
import tomllib

import testtools

# .gitleaks.toml and the role test are repository data, not package
# data, so no wheel carries them.
from kerbside.tests.unit.test_docs_links import _repo_root


_ROOT = _repo_root()
_CONFIG = '.gitleaks.toml'
_ROLE_TEST = os.path.join('tools', 'ci-test-ansible-role.sh')

# Allowlist entries which are not one of the role test's planted
# fixtures. Each is a claim that gitleaks reports something which is not
# a credential, and the claim should be argued for in a comment beside
# the entry in .gitleaks.toml and named here. Keeping the two in step is
# what makes widening the allowlist a deliberate act rather than the
# easiest way to make a red lane green.
_NOT_A_FIXTURE = frozenset({
    # tools/quic-bench/src/main.rs's PEM fixture, whose body is the three
    # bytes 0x01 0x02 0x03: no key at all.
    r'BEGIN PRIVATE KEY-----\\nAQID\\n-----END PRIVATE KEY',
})


def _allowlist_regexes(text):
    """The global allowlist's regexes, read the way gitleaks reads them.

    Parsed as TOML rather than scraped, so that a malformed file fails
    here rather than in the lane, and so that reformatting the list
    cannot change what this test sees.
    """
    config = tomllib.loads(text)
    return list(config.get('allowlist', {}).get('regexes', []))


def _fixture_secrets(text):
    """The values tools/ci-test-ansible-role.sh plants as secrets.

    Read from its SECRETS array rather than from every assignment in
    the script: that array is what the role test's last case searches
    the ansible output for, so it is the script's own definition of a
    planted secret. A substring reference, which the seed uses to prove
    a truncated copy would be found, resolves to the whole value.
    """
    array = re.search(r'^SECRETS=\((.*?)\)', text, re.M | re.S)
    if not array:
        raise AssertionError('%s has no SECRETS array' % _ROLE_TEST)
    names = re.findall(r'\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[^}]*)?\}', array.group(1))
    if not names:
        raise AssertionError('%s names no secrets in SECRETS' % _ROLE_TEST)
    secrets = {}
    for name in names:
        assigned = re.search(r"^%s='([^']*)'$" % re.escape(name), text, re.M)
        if not assigned:
            raise AssertionError(
                'SECRETS names %s, which the script does not assign as a single-quoted literal' % name)
        secrets[name] = assigned.group(1)
    return secrets


class GitleaksConfigTestCase(testtools.TestCase):
    """The credential scan's allowlist against what the tree plants.

    The scan runs over all of history in CI and nowhere else, so a
    fixture added without an allowlist entry is a red lane minutes
    later rather than a failure where it was written. These hold the
    two files to each other instead.
    """

    def setUp(self):
        super().setUp()
        if not _ROOT:
            self.skipTest('not running from a checkout')

    def _read(self, relpath):
        path = os.path.join(_ROOT, relpath)
        if not os.path.exists(path):
            self.fail('%s is missing' % relpath)
        with open(path) as f:
            return f.read()

    def _tracked_files(self):
        """Tracked files, so a developer's scratch notes are exempt."""
        try:
            out = subprocess.check_output(['git', 'ls-files', '-z'], cwd=_ROOT, text=True)
        except (OSError, subprocess.CalledProcessError) as e:
            raise self.skipException('cannot list tracked files: %s' % e)
        return [f for f in out.split('\0') if f]

    def test_every_planted_fixture_is_allowlisted(self):
        """A planted secret gitleaks has not been told about fails the scan."""
        regexes = _allowlist_regexes(self._read(_CONFIG))
        for name, value in sorted(_fixture_secrets(self._read(_ROLE_TEST)).items()):
            if not any(re.search(regex, value) for regex in regexes):
                self.fail(
                    '%s plants %s, which no .gitleaks.toml allowlist entry matches, so the credential '
                    'scan may report it over every commit that touches the script. Add the value to the '
                    'allowlist regexes.' % (_ROLE_TEST, name))

    def test_the_allowlist_holds_nothing_but_the_fixtures(self):
        """An entry which forgives something else has to say so here."""
        planted = set(_fixture_secrets(self._read(_ROLE_TEST)).values())
        for regex in _allowlist_regexes(self._read(_CONFIG)):
            if regex in _NOT_A_FIXTURE:
                continue
            if not any(re.search(regex, value) for value in planted):
                self.fail(
                    '.gitleaks.toml allowlists %r, which is not one of the role test\'s fixtures. An '
                    'allowlist entry stops the scan reporting that text anywhere in history, so add it '
                    'to _NOT_A_FIXTURE here with the reason beside the entry.' % regex)

    def test_no_allowlist_entry_is_dead(self):
        """An entry for text the tree no longer holds only blinds the scan."""
        regexes = _allowlist_regexes(self._read(_CONFIG))
        unmatched = {regex: re.compile(regex) for regex in regexes}
        for relpath in self._tracked_files():
            if not unmatched:
                break
            # Not the config itself: it holds every entry by
            # definition, so counting it would make this test pass
            # whatever the rest of the tree says.
            if relpath == _CONFIG:
                continue
            path = os.path.join(_ROOT, relpath)
            try:
                with open(path, 'rb') as f:
                    # A NUL in the first block is git's own test for a
                    # binary file, and the tree commits disk images:
                    # no reason to read one whole to learn that.
                    head = f.read(8192)
                    if b'\0' in head:
                        continue
                    content = (head + f.read()).decode('utf-8')
            except (OSError, UnicodeDecodeError):
                continue
            for regex in [r for r, compiled in unmatched.items() if compiled.search(content)]:
                del unmatched[regex]
        if unmatched:
            self.fail(
                '.gitleaks.toml allowlists %s, which no tracked file holds any more. A forgiving entry '
                'nobody needs is one a real credential can hide behind: remove it.'
                % ', '.join(repr(regex) for regex in sorted(unmatched)))

    def test_the_fixture_parser_reads_the_script(self):
        """What the two tests above depend on being able to see."""
        # OTHER_TICKET is referenced only as a truncation, the shape
        # the seed uses to prove a shortened copy would be found, and
        # resolves to the whole value. UNUSED_KEY is assigned but never
        # planted, so it is not a secret this tree has to account for.
        script = (
            "SOME_PASSWORD='pw-one'\n"
            "OTHER_TICKET='ticket-two'\n"
            "UNUSED_KEY='key-three'\n"
            "SECRETS=(\"${SOME_PASSWORD}\"\n"
            "    \"${OTHER_TICKET:0:4}\")\n")
        self.assertEqual(
            {'SOME_PASSWORD': 'pw-one', 'OTHER_TICKET': 'ticket-two'}, _fixture_secrets(script))
        # A secret named in SECRETS but assigned some other way is a
        # value this test would otherwise miss entirely.
        self.assertRaises(
            AssertionError, _fixture_secrets,
            "SECRETS=(\"${COMPUTED}\")\nCOMPUTED=\"$(generate)\"\n")
        self.assertRaises(AssertionError, _fixture_secrets, "OVIRT_PASSWORD='pw'\n")
        # The real script's own shape, as a check that the pattern above
        # is not a private dialect: the fixtures are found, and each is
        # long enough for the scanner to care about.
        if _ROOT:
            secrets = _fixture_secrets(self._read(_ROLE_TEST))
            self.assertGreaterEqual(len(secrets), 8)
            for name, value in secrets.items():
                self.assertGreaterEqual(len(value), 10, name)
