#!/usr/bin/env python3

"""Prove the backend TLS claims test by breaking the guard on purpose.

A suite that passes tells you the tests pass, not that they would have
failed. Each mutation below removes one property the guard actually
lost at some point during review of pull request #469, and the run
asserts kerbside/tests/unit/test_check_backend_tls_claims.py notices.

Add a mutation whenever you add a rule to the guard. Run it with:

    tools/mutate-backend-tls-claims.py
"""

# audit-allow-print: this is a reporting CLI -- it prints which
# mutations the guard's tests caught, and is run by hand rather
# than by the daemon.

import os
import shutil
import subprocess
import sys
import tempfile


GUARD = 'tools/check-backend-tls-claims.py'
TOX_PYTHON = '.tox/py3/bin/python'

# (name, the text to replace, what to replace it with). Each is applied
# to a fresh copy of the guard, so they do not interact.
MUTATIONS = [
    ('configured back in the conditional vocabulary',
     r"unpinned|untested)", r"unpinned|untested|configured)"),
    ('should back in the conditional vocabulary',
     r"unpinned|untested)", r"unpinned|untested|should)"),
    ('none back in the conditional vocabulary',
     r"unpinned|untested)", r"unpinned|untested|none)"),
    ('pinned dropped from the assertion vocabulary',
     r"retries|checks|pinned)", r"retries|checks)"),
    ('underscore emphasis stripped again',
     r"EMPHASIS = re.compile(r'\*{1,3}|`')",
     r"EMPHASIS = re.compile(r'\*{1,3}|_{1,3}|`')"),
    ('sentences split on a bare terminator',
     r"SENTENCE_END = re.compile(r'(?<=[.!?])\s+')",
     r"SENTENCE_END = re.compile(r'(?<=[.!?])')"),
    ('file encoding left to the locale',
     "with open(path, encoding='utf-8') as f:", 'with open(path) as f:'),
    ('index.md dropped from the scanned set',
     "DOC_PATHS = ('docs/use-cases/*.md', 'docs/index.md')",
     "DOC_PATHS = ('docs/use-cases/*.md',)"),
    ('headings blanked before they are examined again',
     "        if stripped.startswith('#'):\n"
     '            if block:\n'
     '                yield block\n'
     '            yield [(number, stripped)]\n'
     '            block = []\n'
     '            continue',
     "        if stripped.startswith('#'):\n"
     "            stripped = ''"),
    ('paths resolved against the working directory again',
     "glob.glob(os.path.join(root, pattern))", 'glob.glob(pattern)'),
    ('findings no longer deduplicated per block',
     '                yield number, sentence\n                break',
     '                yield number, sentence'),
]


def interpreter():
    """The tox environment if it is built, else this interpreter.

    stestr and testtools live in .tox/py3, so a bare sys.executable
    usually cannot run the suite -- but failing with an ImportError is
    a better answer than FileNotFoundError on a path the reader has to
    guess the meaning of.
    """
    if os.path.exists(TOX_PYTHON):
        return TOX_PYTHON
    print('%s is not built; falling back to %s. Run "tox -e py3" first '
          'if this cannot import stestr.' % (TOX_PYTHON, sys.executable))
    return sys.executable


def suite_passes():
    return subprocess.run(
        [interpreter(), '-m', 'stestr', 'run',
         'test_check_backend_tls_claims'],
        capture_output=True).returncode == 0


def apply_mutation(backup, old, new):
    with open(backup, encoding='utf-8') as f:
        text = f.read()
    if text.count(old) != 1:
        sys.exit('mutation no longer applies (%d matches): %s'
                 % (text.count(old), old))
    with open(GUARD, 'w', encoding='utf-8') as f:
        f.write(text.replace(old, new))


def main():
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    # Restore from a copy rather than with git checkout, which would
    # discard uncommitted work elsewhere in tools/.
    handle, backup = tempfile.mkstemp(suffix='.py')
    os.close(handle)
    shutil.copy(GUARD, backup)

    try:
        # Without this, an unbuilt tox environment makes every mutation
        # look caught -- suite_passes() cannot tell "the test noticed"
        # from "stestr is not importable" -- and the run then fails at
        # the end blaming the backup.
        if not suite_passes():
            sys.exit('the suite does not pass before any mutation was '
                     'applied; run "tox -e py3" first')

        missed = []
        for name, old, new in MUTATIONS:
            apply_mutation(backup, old, new)
            if suite_passes():
                missed.append(name)
                print('NOT CAUGHT: %s' % name)
            else:
                print('caught: %s' % name)

        shutil.copy(backup, GUARD)
        if not suite_passes():
            sys.exit('the restored tree fails: the backup is not clean')
    finally:
        shutil.copy(backup, GUARD)
        os.unlink(backup)

    if missed:
        return 1
    print('\nAll %d mutations caught, and the restored tree passes.'
          % len(MUTATIONS))
    return 0


if __name__ == '__main__':
    sys.exit(main())
