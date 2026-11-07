import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import testtools


# tools/flake8wrap.sh chooses which files the lint gate inspects, and
# that choice is the whole of its behaviour. Getting it wrong is quiet:
# "No python files in change." reads like a clean result, which is how
# the push audit's lint gate inspected the wrong commit for weeks
# without anyone noticing (#488). So the selection is asserted here
# against a throwaway repository, with flake8 itself stubbed out so the
# arguments it was handed can be read back.
_FLAKE8WRAP = (
    Path(__file__).resolve().parents[3] / 'tools' / 'flake8wrap.sh')

_GIT_ENV = {
    'GIT_AUTHOR_NAME': 'Test',
    'GIT_AUTHOR_EMAIL': 'test@example.com',
    'GIT_COMMITTER_NAME': 'Test',
    'GIT_COMMITTER_EMAIL': 'test@example.com',
    # A developer's ~/.gitconfig must not decide whether these pass.
    'GIT_CONFIG_GLOBAL': os.devnull,
    'GIT_CONFIG_SYSTEM': os.devnull,
}


class Flake8WrapTestCase(testtools.TestCase):
    """Exercise both file-selection modes against fixture history.

    The fixture lands two python files in two commits, so -HEAD and
    -RANGE necessarily disagree: whichever the script actually used is
    visible in what the stub was asked to lint.
    """

    def setUp(self):
        super().setUp()
        self.env = dict(os.environ)
        self.env.update(_GIT_ENV)

        self.repo = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)

        # A stub flake8 at the front of PATH. It records its arguments
        # and succeeds, so a test can assert on the file list without
        # needing the real flake8 in this environment, and a mode that
        # lints nothing is distinguishable from one that lints the
        # wrong thing rather than both looking like a pass.
        self.bin = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.bin, ignore_errors=True)
        self.record = Path(self.bin) / 'flake8-args'
        stub = Path(self.bin) / 'flake8'
        stub.write_text(
            '#!/bin/sh\ncat >/dev/null\nfor a in "$@"; do echo "$a"; '
            'done >> %s\nexit 0\n' % self.record)
        stub.chmod(0o755)
        self.env['PATH'] = '%s:%s' % (self.bin, self.env['PATH'])

        self.git('init', '-q', '-b', 'develop')
        # A base commit, so that the commit adding first.py has a parent
        # and `first~1..first` is a range at all.
        self.commit('base.txt', 'base\n')
        self.commit('first.py', 'x = 1\n')
        self.first = self.git('rev-parse', 'HEAD').stdout.strip()
        self.commit('second.py', 'y = 2\n')

    def git(self, *args):
        return subprocess.run(
            ('git',) + args, cwd=self.repo, check=True, capture_output=True,
            text=True, env=self.env)

    def commit(self, path, content):
        target = Path(self.repo) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        self.git('add', '--', path)
        self.git('commit', '-q', '-m', 'commit %s' % path)

    def run_wrap(self, *args):
        return subprocess.run(
            ['bash', str(_FLAKE8WRAP)] + list(args), cwd=self.repo,
            capture_output=True, text=True, env=self.env)

    def linted(self):
        """The python files the stub was asked to lint."""
        if not self.record.exists():
            return []
        return sorted(
            line for line in self.record.read_text().split()
            if line.endswith('.py'))

    def test_head_mode_lints_the_last_commit(self):
        """Unchanged behaviour: the bare CI gate still runs this way."""
        result = self.run_wrap('-HEAD')

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(['second.py'], self.linted())

    def test_range_mode_lints_the_range_rather_than_the_last_commit(self):
        """The defect: the gate ignored the range it was auditing."""
        result = self.run_wrap('-RANGE', '%s~1..%s' % (self.first, self.first))

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(['first.py'], self.linted())

    def test_range_mode_unions_several_ranges(self):
        """One range per merge, so the gate must cover all of them."""
        result = self.run_wrap(
            '-RANGE', '%s~1..%s' % (self.first, self.first), 'HEAD~1..HEAD')

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(['first.py', 'second.py'], self.linted())

    def test_range_mode_names_the_ranges_when_nothing_matches(self):
        """"No python files in change" is what made #488 read as a pass."""
        self.commit('notes.txt', 'words\n')

        result = self.run_wrap('-RANGE', 'HEAD~1..HEAD')

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual([], self.linted())
        self.assertIn('HEAD~1..HEAD', result.stdout)

    def test_range_mode_rejects_an_unresolvable_range(self):
        """git diff's lost exit status would otherwise pass vacuously."""
        result = self.run_wrap('-RANGE', 'nosuchref..HEAD')

        self.assertEqual(1, result.returncode)
        self.assertIn('does not resolve', result.stderr)
        self.assertEqual([], self.linted())

    def test_range_mode_rejects_an_unresolvable_tip(self):
        result = self.run_wrap('-RANGE', 'HEAD~1..nosuchtip')

        self.assertEqual(1, result.returncode)
        self.assertIn('does not resolve', result.stderr)
        self.assertEqual([], self.linted())

    def test_range_mode_catches_a_bad_range_after_a_good_one(self):
        """Every range is resolved before any of them is diffed."""
        result = self.run_wrap('-RANGE', 'HEAD~1..HEAD', 'nosuchref..HEAD')

        self.assertEqual(1, result.returncode)
        self.assertIn('nosuchref..HEAD', result.stderr)
        self.assertEqual([], self.linted())

    def test_range_mode_requires_a_range(self):
        result = self.run_wrap('-RANGE')

        self.assertEqual(1, result.returncode)
        self.assertIn('needs at least one git range', result.stderr)

    def test_a_file_the_range_deleted_is_skipped(self):
        """flake8 with no arguments walks the whole tree, _pb2 and all."""
        self.git('rm', '-q', '--', 'second.py')
        self.git('commit', '-q', '-m', 'delete second.py')

        result = self.run_wrap('-RANGE', 'HEAD~1..HEAD')

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual([], self.linted())
        self.assertIn('No python files remain', result.stdout)
