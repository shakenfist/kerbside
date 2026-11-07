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
        #
        # It also edits one.py, which phase 1 landed. Path scoping cannot
        # exclude that -- it is a change to the very path being scoped to
        # -- so it is the contamination a single contiguous range admits
        # and per-merge ranges do not.
        self.git('checkout', '-q', '-b', 'unrelated', self.first)
        self.commit('unrelated.py', 'y = 2\n')
        self.commit('one.py', 'x = 1\nunrelated = True\n')
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

    def union_diff(self, exports):
        """The diff the wave scripts see, over every derived range."""
        text = ''
        for audit_range in exports['AUDIT_RANGE'].split():
            text += self.git(
                'diff', audit_range, '--',
                *exports['AUDIT_PATHS'].split()).stdout
        return text

    def test_emits_range_and_paths_for_a_plans_merges(self):
        result = self.run_script(self.first, self.last)

        self.assertEqual(0, result.returncode, result.stderr)
        # Exactly two lines, both exports -- the contract callers eval.
        self.assertEqual(2, len(result.stdout.strip().splitlines()))
        exports = self.exports(result)
        self.assertEqual(
            ['%s^1..%s' % (self.first, self.first),
             '%s^1..%s' % (self.last, self.last)],
            exports['AUDIT_RANGE'].split())
        self.assertEqual(
            ['one.py', 'two.py'], sorted(exports['AUDIT_PATHS'].split()))

    def test_ranges_exclude_a_foreign_commit_touching_a_plan_path(self):
        """The defect a single contiguous span could not avoid.

        An unrelated commit that edits a file the plan also touched is
        inside the span between the plan's first and last merge, and
        path scoping cannot exclude it, because it is a change to the
        path being scoped to. Auditing it credits the plan with work it
        did not do, which happened: PLAN-use-case-docs.md's audit read
        991 added Python lines against the 758 its merges landed.
        """
        exports = self.exports(self.run_script(self.first, self.last))

        self.assertNotIn('unrelated = True', self.union_diff(exports))
        # ... and that line really is in the span the derived ranges
        # replace, so the assertion above cannot pass vacuously.
        spanned = self.git(
            'diff', '%s^1..%s' % (self.first, self.last), '--',
            *exports['AUDIT_PATHS'].split()).stdout
        self.assertIn('unrelated = True', spanned)

    def test_path_set_excludes_unrelated_merges_in_the_range(self):
        """The scoping's other half: a file no listed merge touched."""
        exports = self.exports(self.run_script(self.first, self.last))

        self.assertNotIn('unrelated.py', exports['AUDIT_PATHS'])
        # ... and that file really is inside the span the derived ranges
        # replace, so the assertion above cannot pass just because it is
        # absent anyway.
        spanned = self.git(
            'diff', '--name-only',
            '%s^1..%s' % (self.first, self.last)).stdout.split()
        self.assertIn('unrelated.py', spanned)

    def test_paths_intersect_rather_than_union(self):
        """git unions positive pathspecs; the two-stage form must not.

        This is the property the phase plan makes a done-criterion, and
        the reason the audit scripts filter a scoped file list by name
        instead of appending '*.py' to the pathspec list. The union
        hazard is per range, so it is checked over the span, where the
        foreign file is reachable at all.
        """
        exports = self.exports(self.run_script(self.first, self.last))
        span = '%s^1..%s' % (self.first, self.last)

        scoped = self.git(
            'diff', '--name-only', span, '--',
            *exports['AUDIT_PATHS'].split()).stdout.split()
        intersected = [p for p in scoped if p.endswith('.py')]

        unioned = self.git(
            'diff', '--name-only', span, '--',
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

    def test_keeps_the_merges_in_the_order_given(self):
        """The ranges are audited and reported in landing order."""
        exports = self.exports(self.run_script(self.first, self.last))

        ranges = exports['AUDIT_RANGE'].split()
        self.assertEqual(2, len(ranges))
        self.assertTrue(ranges[0].startswith(self.first), ranges)
        self.assertTrue(ranges[1].startswith(self.last), ranges)

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

    def clone_with_stale_develop(self, stale_at):
        """A clone whose local develop sits behind origin/develop.

        The shape a git worktree is in when the main clone has an old
        `develop` checked out: the local ref cannot be fast-forwarded
        from the worktree, because another worktree holds it.
        """
        clone = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, clone, ignore_errors=True)
        subprocess.run(
            ['git', 'clone', '-q', '--no-local', self.repo, clone],
            check=True, capture_output=True, env=self.env)
        subprocess.run(
            ['git', 'reset', '-q', '--hard', stale_at], cwd=clone, check=True,
            capture_output=True, env=self.env)
        return clone

    def test_prefers_origin_develop_when_the_local_develop_is_stale(self):
        """A stale ref must not decide whether a merge is on develop.

        Resolving `develop` first made the script reject a merge that
        had landed, blaming the SHA for a ref the reader had not
        thought about.
        """
        clone = self.clone_with_stale_develop(self.first)

        result = self.run_script(self.first, self.last, cwd=clone)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn('is not an ancestor', result.stderr)
        # ... and it says which ref it used, so a reader who expected
        # the local one is not left guessing.
        self.assertIn("local 'develop' is behind", result.stderr)
        exports = self.exports(result)
        self.assertEqual(
            ['%s^1..%s' % (self.first, self.first),
             '%s^1..%s' % (self.last, self.last)],
            exports['AUDIT_RANGE'].split())

    def test_prefers_the_local_develop_when_it_is_ahead(self):
        """A merge landed locally but not yet pushed is still auditable."""
        clone = self.clone_with_stale_develop(self.first)
        subprocess.run(
            ['git', 'merge', '-q', '--ff-only', self.last], cwd=clone,
            check=True, capture_output=True, env=self.env)
        subprocess.run(
            ['git', 'update-ref', 'refs/remotes/origin/develop', self.first],
            cwd=clone, check=True, capture_output=True, env=self.env)

        result = self.run_script(self.first, self.last, cwd=clone)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn('is not an ancestor', result.stderr)
        self.assertNotIn('is behind', result.stderr)

    def test_uses_origin_develop_when_the_local_develop_has_diverged(self):
        """Neither contains the other: the remote is the authority."""
        clone = self.clone_with_stale_develop(self.first)
        (Path(clone) / 'local-only.txt').write_text('local\n')
        subprocess.run(
            ['git', 'add', '--', 'local-only.txt'], cwd=clone, check=True,
            capture_output=True, env=self.env)
        subprocess.run(
            ['git', 'commit', '-q', '-m', 'local only'], cwd=clone,
            check=True, capture_output=True, env=self.env)

        result = self.run_script(self.first, self.last, cwd=clone)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('has diverged', result.stderr)
        self.assertNotIn('is not an ancestor', result.stderr)

    def test_says_nothing_about_staleness_when_the_refs_agree(self):
        """The common case stays silent; stdout is an eval contract."""
        clone = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, clone, ignore_errors=True)
        subprocess.run(
            ['git', 'clone', '-q', '--no-local', self.repo, clone],
            check=True, capture_output=True, env=self.env)

        result = self.run_script(self.first, self.last, cwd=clone)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('', result.stderr)

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

    def test_a_list_of_ranges_resolves(self):
        result = self._run('v0.1.0..HEAD HEAD~1..HEAD')

        self.assertNotIn('nothing to diff', result.stdout)
        self.assertIn('wave 2a', result.stdout)

    def test_one_unresolvable_range_among_several_is_fatal(self):
        """Validating only the first range drops a merge's work silently."""
        result = self._run('v0.1.0..HEAD nosuchref..HEAD')

        self.assertEqual(1, result.returncode)
        self.assertIn('does not resolve', result.stderr)
        # Name the range that failed, not the whole list.
        self.assertIn('nosuchref..HEAD', result.stderr)

    def test_a_whitespace_only_range_is_fatal(self):
        """An empty list would otherwise diff nothing and report clean."""
        result = self._run('   ')

        self.assertEqual(1, result.returncode)
        self.assertIn('does not resolve', result.stderr)


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

    def test_one_unresolvable_range_among_several_is_fatal_in_wave_1(self):
        """Wave 1 has its own copy of the guard, so it has its own test.

        Validating only the first range drops the rest of the plan from
        the audit without saying so, which is the vacuous pass the knob
        exists to eliminate.
        """
        self._git('checkout', '-q', '-b', 'feature')
        self._write('kerbside/mod.py', 'import os\nprint("hi")\n')
        self._commit('add a print')

        result = self._run_wave1_over('develop..HEAD nosuchref..HEAD')

        self.assertEqual(6, result.returncode, result.stdout + result.stderr)
        self.assertIn('nosuchref..HEAD', result.stdout)
        self.assertNotIn('all mechanical checks passed', result.stdout)

    def test_a_whitespace_only_range_is_fatal_in_wave_1(self):
        """An empty range list would inspect nothing and report clean."""
        self._git('checkout', '-q', '-b', 'feature')
        self._write('kerbside/mod.py', 'import os\nprint("hi")\n')
        self._commit('add a print')

        result = self._run_wave1_over('   ')

        self.assertEqual(6, result.returncode, result.stdout + result.stderr)
        self.assertNotIn('all mechanical checks passed', result.stdout)

    def test_the_lint_gate_is_given_the_audited_ranges(self):
        """The gate selected files with `git diff --name-only HEAD~1`.

        Whatever AUDIT_RANGE said, `tox -eflake8` ran flake8wrap.sh
        with -HEAD, so in a fresh worktree cut from develop to audit an
        already-merged plan the lint gate inspected the previous
        unrelated merge and reported "No python files in change" as a
        pass (#488). tox is stubbed here: what the gate was told is the
        whole of the behaviour under test.
        """
        recorded = Path(self.repo) / 'tox-args'
        stub = Path(self.repo) / 'bin' / 'tox'
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text(
            '#!/bin/sh\nfor a in "$@"; do echo "$a"; done >> %s\nexit 0\n'
            % recorded)
        stub.chmod(0o755)

        self._git('checkout', '-q', '-b', 'feature')
        self._write('kerbside/mod.py', 'import os\nimport sys\n')
        self._commit('add an import')

        env = dict(self.env)
        del env['AUDIT_SKIP_TOX']
        env['PATH'] = '%s:%s' % (stub.parent, env['PATH'])
        # Two ranges, so that handing the gate only the first is
        # distinguishable from handing it all of them.
        env['AUDIT_RANGE'] = 'develop..HEAD HEAD~1..HEAD'
        result = subprocess.run(
            ['bash', 'tools/audit/wave1.sh'], cwd=self.repo,
            capture_output=True, text=True, env=env)

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        args = recorded.read_text().split()
        self.assertIn('-RANGE', args)
        self.assertIn('develop..HEAD', args)
        self.assertIn('HEAD~1..HEAD', args)
        self.assertNotIn('-HEAD', args)

    def test_the_lint_gate_falls_back_to_head_for_an_unresolved_default(self):
        """No develop, no explicit range: today's behaviour is kept."""
        recorded = Path(self.repo) / 'tox-args'
        stub = Path(self.repo) / 'bin' / 'tox'
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text(
            '#!/bin/sh\nfor a in "$@"; do echo "$a"; done >> %s\nexit 0\n'
            % recorded)
        stub.chmod(0o755)

        self._git('checkout', '-q', '-b', 'feature')
        self._write('kerbside/mod.py', 'import os\nimport sys\n')
        self._commit('add an import')
        self._git('branch', '-q', '-D', 'develop')

        env = dict(self.env)
        del env['AUDIT_SKIP_TOX']
        env['PATH'] = '%s:%s' % (stub.parent, env['PATH'])
        result = subprocess.run(
            ['bash', 'tools/audit/wave1.sh'], cwd=self.repo,
            capture_output=True, text=True, env=env)

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        args = recorded.read_text().split()
        self.assertIn('-HEAD', args)
        self.assertNotIn('-RANGE', args)

    def _land_as_merge(self, branch, path, content, message):
        """Land one commit on develop as a merge, and return the merge."""
        self._git('checkout', '-q', '-b', branch)
        self._write(path, content)
        self._commit(message)
        self._git('checkout', '-q', 'develop')
        self._git('merge', '--no-ff', '-q', '-m', 'merge %s' % branch, branch)
        return self._git('rev-parse', 'HEAD').stdout.strip()

    def _run_wave1_over(self, audit_range):
        env = dict(self.env)
        env['AUDIT_RANGE'] = audit_range
        return subprocess.run(
            ['bash', 'tools/audit/wave1.sh'], cwd=self.repo,
            capture_output=True, text=True, env=env)

    def test_a_print_in_the_second_of_two_ranges_is_caught(self):
        """Every range in the list is inspected, not just the first."""
        first = self._land_as_merge(
            'phase1', 'kerbside/one.py', 'x = 1\n', 'phase 1')
        last = self._land_as_merge(
            'phase2', 'kerbside/two.py', 'print("boom")\n', 'phase 2')

        result = self._run_wave1_over(
            '%s^1..%s %s^1..%s' % (first, first, last, last))

        self.assertEqual(3, result.returncode, result.stdout + result.stderr)
        self.assertIn('raw print() added', result.stdout)

    def test_a_foreign_commits_print_is_not_reported_as_the_plans(self):
        """The defect: a contiguous span audits work the plan never did.

        A commit that is not part of any listed merge lands between two
        phases and adds a print to a file phase 1 created. Path scoping
        cannot exclude it. Over per-merge ranges it is invisible, which
        is the point; over the span it is reported as the plan's.
        """
        first = self._land_as_merge(
            'phase1', 'kerbside/one.py', 'x = 1\n', 'phase 1')
        self._write('kerbside/one.py', 'x = 1\nprint("not ours")\n')
        self._commit('a foreign commit touching a phase path')
        last = self._land_as_merge(
            'phase2', 'kerbside/two.py', 'z = 3\n', 'phase 2')

        per_merge = self._run_wave1_over(
            '%s^1..%s %s^1..%s' % (first, first, last, last))
        span = self._run_wave1_over('%s^1..%s' % (first, last))

        self.assertEqual(
            0, per_merge.returncode, per_merge.stdout + per_merge.stderr)
        self.assertIn('no raw print() added', per_merge.stdout)
        # ... and the span really does see it, so the assertion above is
        # not passing because the print went missing some other way.
        self.assertEqual(3, span.returncode, span.stdout + span.stderr)
        self.assertIn('not ours', span.stdout)
