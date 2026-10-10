#!/usr/bin/env python3

"""Assert that a built wheel contains everything kerbside needs at runtime.

The unit tests cannot do this. .stestr.conf sets top_dir=./, so unittest
discovery puts the repository root on sys.path and
importlib.resources.files('kerbside') resolves to ./kerbside in the
checkout rather than to anything installed. So the unit suite is a layout
guard: it catches the migration tree being moved back out of the package,
but it is blind to the files being dropped from the built artifact by an
exclude-package-data entry, include-package-data being switched off, or a
build-backend change.

That is exactly the regression class that produced the defect this script
exists for. kerbside's migrations lived in a top-level alembic/ directory
for a long time, outside the package, so no wheel contained them and
`pip install kerbside` could not create its own schema -- while every
developer, working from a checkout, saw a working `alembic upgrade head`.
Nothing failed until someone installed from PyPI.

It also guards a second regression class. setuptools_scm's git file
finder adds every tracked file beneath a package directory to the wheel,
so a build from a git checkout can include files that pyproject.toml does
not declare. kerbside relied on exactly that for its migrations, source
drivers, templates and static assets, until a build from a tree with no
git metadata -- a container build context without .git, a vendored copy
-- installed cleanly and then failed at import (issue #326). So with no
--wheel argument this builds twice: once from the checkout, and once from
a copy of its tracked files with no .git, and requires the two wheels to
hold the same files. A difference means pyproject.toml is not declaring
something the git build ships.

Usage:
    tools/check-wheel.py [--wheel PATH]

With no argument it builds both wheels into temporary directories. With
--wheel it checks only that wheel's required files. Exits non-zero,
listing every problem, if anything required is absent or the two builds
differ. Runnable from any working directory: the tree to build is
derived from this file's location, not from cwd.
"""

import argparse
import glob
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile


# The tree to build, derived from this file rather than from cwd so the
# script can be run from anywhere.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Files that must be present verbatim.
REQUIRED_FILES = [
    'kerbside/__init__.py',
    'kerbside/api.py',
    'kerbside/config.py',
    'kerbside/db.py',
    'kerbside/main.py',
    'kerbside/proxy_supervisor.py',

    # The migration environment. `kerbside db upgrade` loads the ini
    # through importlib.resources and drives env.py from it, so all three
    # have to be in the artifact.
    'kerbside/migrations/alembic.ini',
    'kerbside/migrations/env.py',
    'kerbside/migrations/script.py.mako',
]

# Directory prefixes that must contain at least a minimum number of
# files. Counts are floors, not equalities: adding a migration or a
# template should not fail this script.
REQUIRED_TREES = [
    ('kerbside/migrations/versions/', 9, '.py'),
    ('kerbside/sources/', 4, '.py'),
    ('kerbside/rpc/', 4, '.py'),
    ('kerbside/api/templates/', 5, '.html'),
    ('kerbside/api/static/', 5, None),
]


def require_build_module():
    """Exit with an actionable message if `python -m build` is unusable.

    Without this the failure arrives as a CalledProcessError traceback
    wrapping whatever the subprocess printed, which does not say what to
    do about it. Debian-based systems enforce PEP 668, so the system
    interpreter usually will not have `build` and cannot be given it
    without a virtualenv. CI installs it, so this only fires locally.

    A namespace-package hit does not count as available: `spec.origin`
    is None for a directory with no __init__.py, which is exactly what a
    leftover build/ in the source tree looks like.
    """
    spec = importlib.util.find_spec('build')
    if spec is not None and spec.origin is not None:
        return

    raise SystemExit(
        'FAIL: the `build` module is not available to %s.\n'
        '\n'
        'Install it into a virtualenv and run this with that '
        'interpreter:\n'
        '    python3 -m venv /tmp/wheelcheck\n'
        '    /tmp/wheelcheck/bin/pip install build\n'
        '    /tmp/wheelcheck/bin/python tools/check-wheel.py\n'
        % sys.executable)


def build_wheel(destination, source=REPO_ROOT, env=None):
    """Build a wheel into destination and return its path.

    The tree to build is passed explicitly rather than inherited from
    cwd, so this works from any directory. It previously built whatever
    happened to be in the caller's working directory.

    The subprocess also runs in the empty destination directory rather
    than in REPO_ROOT, because `python -m` prepends cwd to sys.path and
    setuptools leaves a build/ directory in the source tree as a side
    effect of the wheel build. That directory does *not* shadow an
    installed `build` package -- a directory without __init__.py is only
    a namespace-package candidate, and a regular package found later on
    sys.path wins -- but when `build` is not installed it turns the
    honest "No module named build" into the thoroughly misleading "No
    module named build.__main__; 'build' is a package and cannot be
    directly executed". Keeping cwd off the import path costs nothing
    and removes a genuinely confusing failure mode.
    """
    print('Building %s into %s' % (source, destination), flush=True)
    subprocess.run(
        [sys.executable, '-m', 'build', '--wheel', '--outdir', destination,
         source],
        cwd=destination, env=env, check=True)

    wheels = glob.glob(os.path.join(destination, '*.whl'))
    if len(wheels) != 1:
        raise SystemExit(
            'expected exactly one wheel in %s, found %d'
            % (destination, len(wheels)))
    return wheels[0]


def export_without_git(destination):
    """Copy the checkout's tracked files into destination, without .git.

    This is what a container build context with .git excluded, or a
    vendored copy, looks like to setuptools. The working-tree content is
    copied rather than HEAD's, so uncommitted edits are checked too. A
    tracked file deleted from the working tree is skipped, as it would be
    from any copy of the tree.
    """
    tracked = subprocess.run(
        ['git', '-C', REPO_ROOT, 'ls-files', '-z'],
        check=True, capture_output=True).stdout.decode().split('\0')
    for name in filter(None, tracked):
        source = os.path.join(REPO_ROOT, name)
        if not os.path.isfile(source):
            continue
        target = os.path.join(destination, name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(source, target)


def build_wheel_without_git():
    """Build a wheel from a copy of the tree that has no git metadata.

    setuptools_scm cannot derive a version without git, so one is
    supplied; the version only names the dist-info directory, which the
    comparison ignores.
    """
    tree = tempfile.mkdtemp(prefix='kerbside-nogit-tree-')
    export_without_git(tree)
    env = dict(os.environ, SETUPTOOLS_SCM_PRETEND_VERSION='0.0.0')
    return build_wheel(
        tempfile.mkdtemp(prefix='kerbside-nogit-wheel-'), source=tree,
        env=env)


def package_files(path):
    """Return the wheel's file names, less its version-named dist-info."""
    with zipfile.ZipFile(path) as archive:
        return {n for n in archive.namelist()
                if '.dist-info/' not in n}


def compare_wheels(with_git, without_git):
    """Return a list of complaints about files only one build ships."""
    git_files = package_files(with_git)
    nogit_files = package_files(without_git)
    problems = []
    for name in sorted(git_files - nogit_files):
        problems.append('only the git build ships: %s' % name)
    for name in sorted(nogit_files - git_files):
        problems.append('only the git-less build ships: %s' % name)
    return problems


def check_wheel(path):
    """Return a list of complaints about the wheel at path."""
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())

    problems = []

    for required in REQUIRED_FILES:
        if required not in names:
            problems.append('missing file: %s' % required)

    for prefix, minimum, suffix in REQUIRED_TREES:
        matching = [
            n for n in names
            if n.startswith(prefix) and (suffix is None or n.endswith(suffix))
        ]
        if len(matching) < minimum:
            problems.append(
                'expected at least %d files under %s%s, found %d'
                % (minimum, prefix,
                   '' if suffix is None else ' matching *%s' % suffix,
                   len(matching)))

    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--wheel',
        help='Check this wheel instead of building one')
    args = parser.parse_args()

    nogit_wheel = None
    if args.wheel:
        wheel = args.wheel
    else:
        require_build_module()

        # Deliberately not cleaned up on failure: a wheel that failed the
        # check is worth keeping around to look at.
        wheel = build_wheel(tempfile.mkdtemp(prefix='kerbside-wheel-'))
        nogit_wheel = build_wheel_without_git()

    print('Checking %s' % os.path.basename(wheel), flush=True)
    problems = check_wheel(wheel)

    if problems:
        print('', flush=True)
        print('FAIL: the wheel is missing runtime files.', file=sys.stderr)
        for problem in problems:
            print('  - %s' % problem, file=sys.stderr)
        print('', file=sys.stderr)
        print('Packages are found by [tool.setuptools.packages.find] and '
              'non-Python files by [tool.setuptools.package-data] in '
              'pyproject.toml. A file in a new directory or with a new '
              'extension may need adding there.', file=sys.stderr)
        return 1

    print('OK: every required runtime file is present.')

    if nogit_wheel:
        problems = compare_wheels(wheel, nogit_wheel)
        if problems:
            print('', flush=True)
            print('FAIL: a build without git metadata ships different '
                  'files.', file=sys.stderr)
            for problem in problems:
                print('  - %s' % problem, file=sys.stderr)
            print('', file=sys.stderr)
            print('setuptools_scm\'s git file finder adds tracked files '
                  'that pyproject.toml does not declare, so a build from '
                  'a tree without .git loses them (issue #326). Declare '
                  'them in [tool.setuptools.package-data] or the '
                  'packages.find include list.', file=sys.stderr)
            return 1
        print('OK: a build without git metadata ships the same files.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
