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

Note what makes this fragile: pyproject.toml names only the kerbside and
kerbside.rpc packages. Everything else that ships -- the migrations, the
web UI templates and static assets, the source drivers -- ships because
setuptools_scm's git file-finder contributes tracked files found beneath
a package directory. That is implicit and easy to break from a distance,
which is why it is asserted here rather than assumed.

Usage:
    tools/check-wheel.py [--wheel PATH]

With no argument it builds a wheel into a temporary directory. Exits
non-zero, listing every missing path, if anything required is absent.
Runnable from any working directory: the tree to build is derived from
this file's location, not from cwd.
"""

import argparse
import glob
import importlib.util
import os
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


def build_wheel(destination):
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
    print('Building %s into %s' % (REPO_ROOT, destination), flush=True)
    subprocess.run(
        [sys.executable, '-m', 'build', '--wheel', '--outdir', destination,
         REPO_ROOT],
        cwd=destination, check=True)

    wheels = glob.glob(os.path.join(destination, '*.whl'))
    if len(wheels) != 1:
        raise SystemExit(
            'expected exactly one wheel in %s, found %d'
            % (destination, len(wheels)))
    return wheels[0]


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

    if args.wheel:
        wheel = args.wheel
    else:
        require_build_module()

        # Deliberately not cleaned up on failure: a wheel that failed the
        # check is worth keeping around to look at.
        wheel = build_wheel(tempfile.mkdtemp(prefix='kerbside-wheel-'))

    print('Checking %s' % os.path.basename(wheel), flush=True)
    problems = check_wheel(wheel)

    if problems:
        print('', flush=True)
        print('FAIL: the wheel is missing runtime files.', file=sys.stderr)
        for problem in problems:
            print('  - %s' % problem, file=sys.stderr)
        print('', file=sys.stderr)
        print('pyproject.toml lists only the kerbside and kerbside.rpc '
              'packages; everything else ships via setuptools_scm\'s git '
              'file-finder, which only contributes TRACKED files found '
              'beneath a package directory. A new file that has not been '
              'git added will not ship.', file=sys.stderr)
        return 1

    print('OK: every required runtime file is present.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
