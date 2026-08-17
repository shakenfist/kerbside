#!/usr/bin/env python3

"""Watch the kerbside-proxy PyPI project's storage and dev-release count.

PyPI enforces a default 10 GB per-project storage limit, and exposes no
API to delete or yank a release -- Warehouse issue #12810 ("Warehouse API
to delete old .dev wheels (nightly builds)") is open and labelled
"Blocked". Pruning is therefore a manual web-UI action (see
RELEASE-SETUP.md), which means nobody will do it until something asks.
This script is what asks: it is the credential-free check a weekly
workflow runs so that a slow-growing dev-release stream is a scheduled
chore with a threshold, rather than a surprise the day a publish starts
failing.

kerbside-proxy publishes a fresh PEP 440 dev release
(0.4.1.devN, ...) on most merges to develop that touch the Rust proxy
(see dev-proxy-wheel.yml), so both axes -- bytes and release count --
grow over time even though nothing is wrong. Neither axis alone is a
reliable signal: a handful of huge wheels can exhaust the byte budget
long before the release count looks alarming, and conversely a long tail
of small releases can pile up without ever troubling the byte budget.
Hence two independent thresholds.

The data comes from PyPI's read-only, unauthenticated JSON API
(https://pypi.org/pypi/<project>/json), which lists every release and,
for each, every uploaded file with its size. Summing those sizes is the
normal client-side way to approximate project storage: PyPI does not
publish a usage total anywhere else.

That is the legacy per-project JSON endpoint, and its 'releases' key is
the least-committed part of PyPI's API surface -- Warehouse has signalled
an intent to slim the response down. If it goes, parse_project_data fails
loudly rather than silently reporting zero, and the PEP 691/700 Simple
API JSON view (GET https://pypi.org/simple/<project>/ with Accept:
application/vnd.pypi.simple.v1+json) carries the same per-file size and
upload-time fields under slightly different names.

Usage:
    tools/check-pypi-storage.py [--project NAME] [--limit-bytes N]
        [--max-bytes-pct PCT] [--max-dev-releases N] [--input-file PATH]

Exit codes are three-way, and the distinction matters to the workflow
that runs this: 0 when the project is under both thresholds, 1 when a
threshold is genuinely crossed, and 2 when the report could not be
produced at all (a fetch or parse failure). Collapsing 2 into 1 would
make a transient network error file a "threshold crossed" issue
carrying an empty report, so callers must treat anything above 1 as a
broken monitor rather than as news about the project.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request


# 10 GB using PyPI's own convention (decimal, not binary): "PyPI's
# documented default project limit is 10.0 GB", i.e. 10 * 1000**3 bytes.
DEFAULT_LIMIT_BYTES = 10 * 1000 ** 3

DEFAULT_PROJECT = 'kerbside-proxy'
DEFAULT_MAX_BYTES_PCT = 50
DEFAULT_MAX_DEV_RELEASES = 300

REQUEST_TIMEOUT_SECONDS = 30
USER_AGENT = ('kerbside/check-pypi-storage.py '
              '(+https://github.com/shakenfist/kerbside)')

# Reserved for "the check could not run", as distinct from exit 1, which
# means the check ran and found a threshold crossed. See the module
# docstring.
EXIT_BROKEN = 2


def fail(message):
    """Abort with EXIT_BROKEN and a message on stderr."""
    print(message, file=sys.stderr)
    raise SystemExit(EXIT_BROKEN)


def fetch_project_data(project):
    """Fetch and parse the PyPI JSON API response for project.

    Aborts via fail() with a clear message on any network or parse
    failure -- there is no fallback value that is safe to report as "the
    project is fine" when the data could not actually be obtained.
    """
    url = 'https://pypi.org/pypi/%s/json' % project
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})

    try:
        with urllib.request.urlopen(
                request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        fail('FAIL: fetching %s returned HTTP %s' % (url, exc.code))
    except urllib.error.URLError as exc:
        fail('FAIL: fetching %s failed: %s' % (url, exc.reason))
    except OSError as exc:
        fail('FAIL: fetching %s failed: %s' % (url, exc))

    return parse_project_data(body)


def parse_project_data(body):
    """Parse the PyPI JSON API response body (bytes or str) into a dict.

    Aborts via fail() if the body is not valid JSON, or is missing the
    'releases' key the rest of this script depends on, or if that key is
    not the version-to-files mapping it is documented to be. The last
    check is what turns a PyPI schema change into a legible message
    rather than a traceback.
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        fail('FAIL: could not parse PyPI JSON response: %s' % exc)

    if not isinstance(data, dict) or 'releases' not in data:
        fail('FAIL: PyPI JSON response is missing the "releases" key')

    if not isinstance(data['releases'], dict):
        fail('FAIL: PyPI JSON "releases" is %s, expected an object'
             % type(data['releases']).__name__)

    return data


def summarise(data):
    """Reduce a parsed PyPI response to the numbers this check needs.

    Returns a dict with total_bytes, final_versions and dev_versions
    (both lists of version strings, unsorted -- sorting dev versions by
    upload time, not by string, is the caller's job since setuptools_scm
    dev version strings do not sort the way their upload times do once
    double digits appear).
    """
    total_bytes = 0
    final_versions = []
    dev_versions = []

    for version, files in data['releases'].items():
        # An empty file list means every file for that version was
        # removed (e.g. yanked-and-deleted); PyPI still lists the
        # version key. Nothing to sum, but it still counts as a release
        # for the dev/final split below.
        for file_info in files:
            total_bytes += file_info.get('size', 0)

        if '.dev' in version:
            dev_versions.append(version)
        else:
            final_versions.append(version)

    return {
        'total_bytes': total_bytes,
        'final_versions': final_versions,
        'dev_versions': dev_versions,
    }


def oldest_and_newest_dev_upload(data, dev_versions):
    """Return (oldest, newest) dev versions by earliest upload_time.

    A version whose files have all been removed has no upload_time and
    so sorts first, making it the reported oldest. That is harmless
    here: such a version is exactly one a previous prune already
    emptied, and so is exactly the one a reader should see first.
    Returns (None, None) if there are no dev versions.
    """
    if not dev_versions:
        return None, None

    def earliest_upload(version):
        files = data['releases'].get(version, [])
        times = [f['upload_time'] for f in files if 'upload_time' in f]
        return min(times) if times else ''

    ordered = sorted(dev_versions, key=earliest_upload)
    return ordered[0], ordered[-1]


def format_bytes(num_bytes):
    """Format a byte count as both MB and GB, for a human-readable report."""
    mb = num_bytes / 1000 ** 2
    gb = num_bytes / 1000 ** 3
    return '%.1f MB (%.3f GB)' % (mb, gb)


def build_report(project, data, limit_bytes, max_bytes_pct,
                 max_dev_releases):
    """Return (report_text, ok); ok is False if a threshold is crossed."""
    summary = summarise(data)
    total_bytes = summary['total_bytes']
    final_count = len(summary['final_versions'])
    dev_count = len(summary['dev_versions'])
    oldest_dev, newest_dev = oldest_and_newest_dev_upload(
        data, summary['dev_versions'])

    pct_of_limit = (total_bytes / limit_bytes) * 100 if limit_bytes else 0.0

    lines = []
    lines.append('PyPI storage report for %s' % project)
    lines.append('=' * (len('PyPI storage report for ') + len(project)))
    lines.append('')
    lines.append('Total size: %s' % format_bytes(total_bytes))
    lines.append('Limit:      %s' % format_bytes(limit_bytes))
    lines.append('Usage:      %.2f%% of the limit (threshold: %s%%)'
                 % (pct_of_limit, max_bytes_pct))
    lines.append('')
    lines.append('Final releases: %d' % final_count)
    lines.append('Dev releases:   %d (threshold: %d)'
                 % (dev_count, max_dev_releases))
    if oldest_dev is not None:
        lines.append('Oldest dev version: %s' % oldest_dev)
        lines.append('Newest dev version: %s' % newest_dev)
    else:
        lines.append('No dev releases found.')

    # These two strings are the body of the GitHub issue an operator
    # reads months from now to decide whether to spend an evening
    # pruning by hand, so they state the total, the limit and the
    # threshold once each rather than restating the percentage.
    problems = []
    if pct_of_limit >= max_bytes_pct:
        threshold_bytes = limit_bytes * max_bytes_pct / 100
        problems.append(
            'storage: %s of %s used (%.2f%%), at or above the %s%% '
            'threshold (%s)'
            % (format_bytes(total_bytes), format_bytes(limit_bytes),
               pct_of_limit, max_bytes_pct, format_bytes(threshold_bytes)))
    if dev_count >= max_dev_releases:
        problems.append(
            'dev release count is %d, at or above the %d threshold'
            % (dev_count, max_dev_releases))

    lines.append('')
    if problems:
        lines.append('THRESHOLD CROSSED:')
        for problem in problems:
            lines.append('  - %s' % problem)
    else:
        lines.append('OK: both thresholds are clear.')

    return '\n'.join(lines), not problems


def build_parser():
    """Return the argument parser for this script."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '--project', default=DEFAULT_PROJECT,
        help='PyPI project name to check (default: %s)' % DEFAULT_PROJECT)
    parser.add_argument(
        '--limit-bytes', type=int, default=DEFAULT_LIMIT_BYTES,
        help='PyPI project storage limit in bytes (default: %d, i.e. 10 GB)'
        % DEFAULT_LIMIT_BYTES)
    parser.add_argument(
        '--max-bytes-pct', type=float, default=DEFAULT_MAX_BYTES_PCT,
        help='Alarm when usage reaches this percentage of --limit-bytes '
             '(default: %s)' % DEFAULT_MAX_BYTES_PCT)
    parser.add_argument(
        '--max-dev-releases', type=int, default=DEFAULT_MAX_DEV_RELEASES,
        help='Alarm when the dev release count reaches this many '
             '(default: %d)' % DEFAULT_MAX_DEV_RELEASES)
    parser.add_argument(
        '--input-file', metavar='PATH',
        help='Read the PyPI JSON API response from this file instead of '
             'the network (bypasses the network entirely; exists so the '
             'thresholds can be tested)')
    return parser


def load_data(args):
    """Return the parsed PyPI response, from --input-file or the network."""
    if not args.input_file:
        return fetch_project_data(args.project)

    try:
        with open(args.input_file, 'rb') as handle:
            body = handle.read()
    except OSError as exc:
        fail('FAIL: could not read %s: %s' % (args.input_file, exc))

    return parse_project_data(body)


def main():
    args = build_parser().parse_args()

    # The three-way exit contract is enforced structurally here, not
    # only at the call sites that use fail(). An exception nobody
    # anticipated -- a PyPI schema surprise, a null size -- would
    # otherwise reach the interpreter and exit 1, which is the code
    # meaning "threshold crossed", and the workflow would file an alarm
    # carrying an empty report. Anything unexpected is a broken monitor,
    # so it exits EXIT_BROKEN.
    try:
        data = load_data(args)
        report, ok = build_report(
            args.project, data, args.limit_bytes, args.max_bytes_pct,
            args.max_dev_releases)
    except SystemExit:
        raise
    except Exception as exc:
        fail('FAIL: unexpected error producing the report: %r' % exc)

    print(report)

    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
