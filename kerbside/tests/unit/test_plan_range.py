import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import testtools


# plan-range.sh derives the AUDIT_RANGE and AUDIT_PATHS that every future
# push-audit phase runs the wave scripts with. Its failure modes are quiet
# rather than loud -- a wrong-but-plausible range or path set makes the
# audit inspect the wrong content and pass -- so each guard is exercised
# here against a throwaway repository rather than read.
_PLAN_RANGE = (
    Path(__file__).resolve().parents[3] / 'tools' / 'audit' / 'plan-range.sh')

_GIT_ENV = {
    'GIT_AUTHOR_NAME': 'Test',
    'GIT_AUTHOR_EMAIL': 'test@example.com',
    'GIT_COMMITTER_NAME': 'Test',
    'GIT_COMMITTER_EMAIL': 'test@example.com',
    # A developer's ~/.gitconfig must not decide whether these pass.
    'GIT_CONFIG_GLOBAL': os.devnull,
    'GIT_CONFIG_SYSTEM': os.devnull,
    # Nor may an exported audit range: the phase's own documented
    # workflow is `eval "$(plan-range.sh ...)"` and then a wave script,
    # which runs this suite. The scripts treat empty as unset.
    'AUDIT_RANGE': '',
    'AUDIT_PATHS': '',
}


class PlanRangeTestCase(testtools.TestCase):
    """Exercise plan-range.sh against a fixture repository.

    The fixture mirrors the shape plan-range.sh is given in anger: a
    develop branch onto which each phase lands as a merge commit, with an
    unrelated merge in between, so `sha^1..sha` is the phase's own diff
    and the union of those diffs is the path set the audit is scoped to.
    """

    def setUp(self):
        super().setUp()
        self.env = dict(os.environ)
        self.env.update(_GIT_ENV)

        self.repo = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)

        self.git('init', '-q', '-b', 'develop')
        self.commit('base.txt', 'base\n')

        self.git('checkout', '-q', '-b', 'phase1')
        self.commit('one.py', 'x = 1\n')
        self.git('checkout', '-q', 'develop')
        self.first = self.merge('phase1')

        # An unrelated merge between the two phases. The path scoping
        # exists precisely to keep this file out of the audited diff, so
        # it has to be here for the scoping assertions to mean anything.
        self.git('checkout', '-q', '-b', 'unrelated', self.first)
        self.commit('unrelated.py', 'y = 2\n')
        self.git('checkout', '-q', 'develop')
        self.merge('unrelated')

        self.git('checkout', '-q', '-b', 'phase2')
        self.commit('two.py', 'z = 3\n')
        self.git('checkout', '-q', 'develop')
        self.last = self.merge('phase2')

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

    def merge(self, branch):
        self.git('merge', '--no-ff', '-q', '-m', 'merge %s' % branch, branch)
        return self.git('rev-parse', 'HEAD').stdout.strip()

    def run_script(self, *args, cwd=None):
        return subprocess.run(
            ['bash', str(_PLAN_RANGE)] + list(args), cwd=cwd or self.repo,
            capture_output=True, text=True, env=self.env)

    def exports(self, result):
        """Parse the two export lines into a dict."""
        out = {}
        for line in result.stdout.strip().splitlines():
            self.assertTrue(line.startswith('export '), line)
            key, _, value = line[len('export '):].partition('=')
            out[key] = value.strip("'")
        return out

    def test_emits_range_and_paths_for_a_plans_merges(self):
        result = self.run_script(self.first, self.last)

        self.assertEqual(0, result.returncode, result.stderr)
        # Exactly two lines, both exports -- the contract callers eval.
        self.assertEqual(2, len(result.stdout.strip().splitlines()))
        exports = self.exports(result)
        self.assertEqual(
            '%s^1..%s' % (self.first, self.last), exports['AUDIT_RANGE'])
        self.assertEqual(
            ['one.py', 'two.py'], sorted(exports['AUDIT_PATHS'].split()))

    def test_path_set_excludes_unrelated_merges_in_the_range(self):
        """The scoping's whole job: the range spans a merge it must omit."""
        exports = self.exports(self.run_script(self.first, self.last))

        self.assertNotIn('unrelated.py', exports['AUDIT_PATHS'])
        # ... and that file really is inside the derived range, so the
        # assertion above cannot pass just because it is absent anyway.
        spanned = self.git(
            'diff', '--name-only', exports['AUDIT_RANGE']).stdout.split()
        self.assertIn('unrelated.py', spanned)

    def test_paths_intersect_rather_than_union(self):
        """git unions positive pathspecs; the two-stage form must not.

        This is the property the phase plan makes a done-criterion, and
        the reason the audit scripts filter a scoped file list by name
        instead of appending '*.py' to the pathspec list.
        """
        exports = self.exports(self.run_script(self.first, self.last))

        scoped = self.git(
            'diff', '--name-only', exports['AUDIT_RANGE'], '--',
            *exports['AUDIT_PATHS'].split()).stdout.split()
        intersected = [p for p in scoped if p.endswith('.py')]

        unioned = self.git(
            'diff', '--name-only', exports['AUDIT_RANGE'], '--',
            *exports['AUDIT_PATHS'].split(), '*.py').stdout.split()

        self.assertEqual(['one.py', 'two.py'], sorted(intersected))
        self.assertIn('unrelated.py', unioned)

    def test_accepts_a_single_merge(self):
        result = self.run_script(self.last)

        self.assertEqual(0, result.returncode, result.stderr)
        exports = self.exports(result)
        self.assertEqual(
            '%s^1..%s' % (self.last, self.last), exports['AUDIT_RANGE'])
        self.assertEqual(['two.py'], exports['AUDIT_PATHS'].split())

    def test_rejects_no_arguments(self):
        result = self.run_script()

        self.assertEqual(1, result.returncode)
        self.assertIn('usage:', result.stderr)

    def test_rejects_a_sha_that_is_not_a_commit(self):
        result = self.run_script('0' * 40)

        self.assertEqual(1, result.returncode)
        self.assertIn('is not a commit', result.stderr)

    def test_rejects_a_commit_that_is_not_on_develop(self):
        self.git('checkout', '-q', '-b', 'sidebranch', self.first)
        self.commit('side.py', 'w = 4\n')
        side = self.git('rev-parse', 'HEAD').stdout.strip()

        result = self.run_script(side)

        self.assertEqual(1, result.returncode)
        self.assertIn('is not an ancestor of develop', result.stderr)

    def test_rejects_reversed_merge_shas(self):
        """Reversed, the range diffs backwards and the style checks pass
        on reverted content while the path set still looks correct."""
        result = self.run_script(self.last, self.first)

        self.assertEqual(1, result.returncode)
        self.assertIn('oldest-first', result.stderr)
        self.assertEqual('', result.stdout)

    def test_rejects_a_path_containing_whitespace(self):
        self.git('checkout', '-q', '-b', 'spacey', self.last)
        self.commit('a file.py', 'v = 5\n')
        self.git('checkout', '-q', 'develop')
        spacey = self.merge('spacey')

        result = self.run_script(spacey)

        self.assertEqual(1, result.returncode)
        self.assertIn('whitespace, a glob', result.stderr)

    def test_rejects_a_path_containing_a_glob_metacharacter(self):
        """AUDIT_PATHS is glob-expanded as well as word-split."""
        self.git('checkout', '-q', '-b', 'globby', self.last)
        self.commit('a[1].py', 'u = 6\n')
        self.git('checkout', '-q', 'develop')
        globby = self.merge('globby')

        result = self.run_script(globby)

        self.assertEqual(1, result.returncode)
        self.assertIn('whitespace, a glob', result.stderr)

    def test_rejects_a_path_containing_a_single_quote(self):
        """AUDIT_PATHS is emitted inside single quotes for the caller to
        eval, and git does not escape a quote in a path."""
        self.git('checkout', '-q', '-b', 'quoted', self.last)
        self.commit("it's.py", 't = 7\n')
        self.git('checkout', '-q', 'develop')
        quoted = self.merge('quoted')

        result = self.run_script(quoted)

        self.assertEqual(1, result.returncode)
        self.assertIn('quoting character', result.stderr)

    def test_accepts_a_non_ascii_path_literally(self):
        """git quotes a non-ASCII path as "caf\\303\\251.py" by default,
        which carries no whitespace and no glob character, so it would
        survive the guard and then match nothing when handed back to
        git -- a silently narrowed audit."""
        self.git('checkout', '-q', '-b', 'accented', self.last)
        self.commit('caf\u00e9.py', 's = 8\n')
        self.git('checkout', '-q', 'develop')
        accented = self.merge('accented')

        result = self.run_script(accented)

        self.assertEqual(0, result.returncode, result.stderr)
        exports = self.exports(result)
        self.assertEqual(['caf\u00e9.py'], exports['AUDIT_PATHS'].split())
        self.assertNotIn('303', exports['AUDIT_PATHS'])

    def test_rejects_a_commit_with_no_first_parent(self):
        """The path set diffs sha^1..sha, so a root commit would abort
        with git's own error rather than this script's."""
        root = self.git(
            'rev-list', '--max-parents=0', 'HEAD').stdout.split()[0]

        result = self.run_script(root)

        self.assertEqual(1, result.returncode)
        self.assertIn('no first parent', result.stderr)

    def test_rejects_an_empty_derived_path_set(self):
        """An empty AUDIT_PATHS means 'no restriction' to the audit
        scripts, so emitting one silently widens the audit."""
        self.git('checkout', '-q', '-b', 'empty', self.last)
        self.git(
            'commit', '-q', '--allow-empty', '-m', 'touches nothing')
        self.git('checkout', '-q', 'develop')
        empty = self.merge('empty')

        result = self.run_script(empty)

        self.assertEqual(1, result.returncode)
        self.assertIn('derived path set is empty', result.stderr)

    def test_resolves_origin_develop_when_no_local_develop_exists(self):
        """A CI-style PR checkout has origin/develop and no local ref."""
        clone = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, clone, ignore_errors=True)
        subprocess.run(
            ['git', 'clone', '-q', '--no-local', self.repo, clone],
            check=True, capture_output=True, env=self.env)
        subprocess.run(
            ['git', 'checkout', '-q', '--detach', 'HEAD'], cwd=clone,
            check=True, capture_output=True, env=self.env)
        subprocess.run(
            ['git', 'branch', '-q', '-D', 'develop'], cwd=clone, check=True,
            capture_output=True, env=self.env)

        result = self.run_script(self.first, self.last, cwd=clone)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('AUDIT_RANGE', result.stdout)
        # git's own 'Not a valid object name' must not reach the reader.
        self.assertNotIn('Not a valid object name', result.stderr)

    def test_reports_an_unresolvable_base_branch_as_such(self):
        """Neither develop nor origin/develop: say that, not 'ancestry'."""
        self.git('checkout', '-q', '--detach', 'HEAD')
        self.git('branch', '-q', '-D', 'develop')

        result = self.run_script(self.first, self.last)

        self.assertEqual(1, result.returncode)
        self.assertIn('cannot resolve', result.stderr)
        self.assertNotIn('is not an ancestor', result.stderr)


_WAVE2 = (
    Path(__file__).resolve().parents[3] / 'tools' / 'audit'
    / 'wave2-mechanical.sh')


class AuditBaseResolutionTestCase(testtools.TestCase):
    """Cover the 'does the base revision exist' guard in the wave scripts.

    The guard derives the base by stripping AUDIT_RANGE at the first
    '..'. Stripping at the first '.' instead -- as it did originally --
    truncates a dotted ref like 'v0.5.0..HEAD' to 'v0', which does not
    resolve, so the script reports nothing to diff and exits 0 having
    checked nothing. That silent pass is the failure mode the
    AUDIT_RANGE knob exists to eliminate, so it is pinned here.

    wave2-mechanical.sh is used rather than wave1.sh because wave1 runs
    tox before reaching the guard. The two scripts carry the same
    expression; wave1's copy is exercised by the shared shellcheck and
    by this file's sibling assertions on the range forms.
    """

    def setUp(self):
        super().setUp()
        self.env = dict(os.environ)
        self.env.update(_GIT_ENV)

        # The script cd's to its own repository root, so it has to be
        # copied into the fixture to be run against fixture history.
        self.repo = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
        audit_dir = Path(self.repo) / 'tools' / 'audit'
        audit_dir.mkdir(parents=True)
        shutil.copy(_WAVE2, audit_dir / 'wave2-mechanical.sh')

        subprocess.run(
            ['git', 'init', '-q', '-b', 'develop'], cwd=self.repo, check=True,
            capture_output=True, env=self.env)
        self._commit('one.py', 'x = 1\n')
        subprocess.run(
            ['git', 'tag', 'v0.1.0'], cwd=self.repo, check=True,
            capture_output=True, env=self.env)
        self._commit('two.py', 'z = 3\n')

    def _commit(self, path, content):
        (Path(self.repo) / path).write_text(content)
        for args in (['git', 'add', '--', path],
                     ['git', 'commit', '-q', '-m', 'commit %s' % path]):
            subprocess.run(
                args, cwd=self.repo, check=True, capture_output=True,
                env=self.env)

    def _run(self, audit_range):
        env = dict(self.env)
        env['AUDIT_RANGE'] = audit_range
        return subprocess.run(
            ['bash', 'tools/audit/wave2-mechanical.sh'], cwd=self.repo,
            capture_output=True, text=True, env=env)

    def test_a_dotted_base_ref_still_resolves(self):
        result = self._run('v0.1.0..HEAD')

        self.assertNotIn('nothing to diff', result.stdout)
        self.assertIn('wave 2a', result.stdout)

    def test_an_unresolvable_explicit_range_is_fatal(self):
        """An explicitly-set range that does not resolve must not read as
        a clean audit: every git diff produces nothing, so every report
        below it says (none) and the script would otherwise exit 0."""
        result = self._run('nosuchref..HEAD')

        self.assertEqual(1, result.returncode)
        self.assertIn('does not resolve', result.stderr)

    def test_an_unresolvable_tip_is_caught_not_just_the_base(self):
        result = self._run('develop..nosuchtip')

        self.assertEqual(1, result.returncode)
        self.assertIn('does not resolve', result.stderr)

    def test_the_default_two_dot_and_three_dot_forms_resolve(self):
        for audit_range in ('develop...HEAD', 'v0.1.0..HEAD'):
            result = self._run(audit_range)
            self.assertNotIn('nothing to diff', result.stdout, audit_range)


_WAVE1 = (
    Path(__file__).resolve().parents[3] / 'tools' / 'audit' / 'wave1.sh')


class Wave1StyleCheckTestCase(testtools.TestCase):
    """Pin wave 1's two fatal style checks against going dead again.

    These checks inspected no line at all between 2026-07-06 and this
    phase, because `grep -v '^\\+\\+\\+'` is a BRE in which `\\+` is the
    repetition operator, so the pattern stripped every added line rather
    than the two diff headers. Nothing failed, because nothing exercised
    them: they reported PASS over an empty variable. That is the defect
    with the largest blast radius this phase found, so it is pinned
    here rather than left to the next reader to rediscover.

    AUDIT_SKIP_TOX reaches wave 1b without a tox cycle.
    """

    def setUp(self):
        super().setUp()
        self.env = dict(os.environ)
        self.env.update(_GIT_ENV)
        self.env['AUDIT_SKIP_TOX'] = '1'
        # Colour codes would otherwise wrap the strings asserted on.
        self.env['TERM'] = 'dumb'

        self.repo = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
        audit_dir = Path(self.repo) / 'tools' / 'audit'
        audit_dir.mkdir(parents=True)
        shutil.copy(_WAVE1, audit_dir / 'wave1.sh')

        self._git('init', '-q', '-b', 'develop')
        self._write('kerbside/mod.py', 'import os\n')
        self._commit('base')

    def _git(self, *args):
        return subprocess.run(
            ('git',) + args, cwd=self.repo, check=True, capture_output=True,
            text=True, env=self.env)

    def _write(self, path, content):
        target = Path(self.repo) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def _commit(self, message):
        self._git('add', '-A')
        self._git('commit', '-q', '-m', message)

    def _run_wave1(self):
        return subprocess.run(
            ['bash', 'tools/audit/wave1.sh'], cwd=self.repo,
            capture_output=True, text=True, env=self.env)

    def test_a_clean_diff_passes(self):
        self._git('checkout', '-q', '-b', 'feature')
        self._write('kerbside/mod.py', 'import os\nimport sys\n')
        self._commit('add an import')

        result = self._run_wave1()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('no raw print() added', result.stdout)
        self.assertIn('no bare except added', result.stdout)

    def test_an_added_print_is_fatal(self):
        self._git('checkout', '-q', '-b', 'feature')
        self._write('kerbside/mod.py', 'import os\nprint("hi")\n')
        self._commit('add a print')

        result = self._run_wave1()

        self.assertEqual(3, result.returncode, result.stdout + result.stderr)
        self.assertIn('raw print() added', result.stdout)

    def test_an_added_bare_except_is_fatal(self):
        self._git('checkout', '-q', '-b', 'feature')
        self._write(
            'kerbside/mod.py', 'import os\ntry:\n    pass\nexcept:\n    pass\n')
        self._commit('add a bare except')

        result = self._run_wave1()

        self.assertEqual(4, result.returncode, result.stdout + result.stderr)
        self.assertIn("bare 'except:' added", result.stdout)

    def test_a_pre_existing_print_is_not_fatal(self):
        """The checks inspect added lines only, which is why they can be
        strict about print() in a tree that legitimately contains some."""
        self._write('kerbside/mod.py', 'import os\nprint("hi")\n')
        self._commit('a print that is already there')
        self._git('checkout', '-q', '-b', 'feature')
        self._write('kerbside/mod.py', 'import os\nprint("hi")\nx = 1\n')
        self._commit('touch the file without adding a print')

        result = self._run_wave1()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_a_print_in_a_test_file_is_not_fatal(self):
        self._git('checkout', '-q', '-b', 'feature')
        self._write('kerbside/tests/unit/test_x.py', 'print("hi")\n')
        self._commit('add a test that prints')

        result = self._run_wave1()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_the_marker_exempts_and_says_so(self):
        self._git('checkout', '-q', '-b', 'feature')
        self._write(
            'kerbside/mod.py',
            'import os\n# audit-allow-print\nprint("hi")\n')
        self._commit('add an exempted print')

        result = self._run_wave1()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        # The exemption must be visible, not silent: it suppresses the
        # check for the whole diff, not just the marked file.
        self.assertIn('suppressed', result.stdout)
        self.assertIn('kerbside/mod.py', result.stdout)

    def test_a_print_in_a_non_ascii_filename_is_still_caught(self):
        """The helpers round-trip a filename back into a pathspec.

        git renders a non-ASCII path as "caf\\303\\251.py" by default,
        which then matches nothing when handed back, so the file drops
        out of the diff and its added print() is never seen. This is
        the consumer side of the same round trip plan-range.sh guards;
        its guard cannot help here, because the wave scripts derive
        this list from the range rather than from AUDIT_PATHS.
        """
        self._git('checkout', '-q', '-b', 'feature')
        self._write('kerbside/caf\u00e9.py', 'print("boom")\n')
        self._commit('add a print in a non-ascii filename')

        result = self._run_wave1()

        self.assertEqual(3, result.returncode, result.stdout + result.stderr)
        self.assertIn('raw print() added', result.stdout)

    def test_a_print_in_a_filename_with_a_glob_character_is_caught(self):
        """The file list is word-split, so it must not also be globbed."""
        self._git('checkout', '-q', '-b', 'feature')
        self._write('kerbside/a1.py', 'x = 1\n')
        self._write('kerbside/a[1].py', 'print("boom")\n')
        self._commit('add a print in a globbable filename')

        result = self._run_wave1()

        self.assertEqual(3, result.returncode, result.stdout + result.stderr)

    def test_an_unresolvable_explicit_range_is_fatal(self):
        """A typo'd AUDIT_RANGE must not read as a clean audit."""
        self._git('checkout', '-q', '-b', 'feature')
        self._write('kerbside/mod.py', 'import os\nprint("hi")\n')
        self._commit('add a print')

        env = dict(self.env)
        env['AUDIT_RANGE'] = 'develop..nosuchtip'
        result = subprocess.run(
            ['bash', 'tools/audit/wave1.sh'], cwd=self.repo,
            capture_output=True, text=True, env=env)

        self.assertEqual(6, result.returncode, result.stdout + result.stderr)
        self.assertNotIn('all mechanical checks passed', result.stdout)
