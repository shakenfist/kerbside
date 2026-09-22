#!/usr/bin/env python3

"""Prove the backend TLS claims test by breaking the guard on purpose.

A suite that passes tells you the tests pass, not that they would have
failed. Each mutation below removes one property the guard actually
lost at some point during review of pull request #469, and the run
asserts kerbside/tests/unit/test_check_backend_tls_claims.py notices.

Add a mutation whenever you add a rule to the guard. Run it with:

    tools/mutate-backend-tls-claims.py
"""

import os
import shutil
import subprocess
import sys
import tempfile


GUARD = 'tools/check-backend-tls-claims.py'

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
    ('findings no longer deduplicated per block',
     '                yield number, sentence\n                break',
     '                yield number, sentence'),
]


def suite_passes():
    return subprocess.run(
        ['.tox/py3/bin/python', '-m', 'stestr', 'run',
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
