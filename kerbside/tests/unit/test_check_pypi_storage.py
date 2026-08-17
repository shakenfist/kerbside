import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import testtools


# check-pypi-storage.py lives in tools/ (outside the importable package) and
# its filename contains a hyphen, so load it as a module by path.
_CHECK_PYPI_STORAGE_PATH = (
    Path(__file__).resolve().parents[3] / 'tools' / 'check-pypi-storage.py')
_spec = importlib.util.spec_from_file_location(
    'check_pypi_storage', _CHECK_PYPI_STORAGE_PATH)
check_pypi_storage = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_pypi_storage)


def _release(size, upload_time):
    return {'size': size, 'upload_time': upload_time}


def _data(releases):
    return {'releases': releases}


class SummariseTestCase(testtools.TestCase):
    """Cover the dev/final split and the byte sum."""

    def test_splits_dev_from_final(self):
        summary = check_pypi_storage.summarise(_data({
            '0.4.0': [_release(10, '2026-01-01T00:00:00')],
            '0.4.1.dev1': [_release(20, '2026-01-02T00:00:00')],
            '0.4.1.dev2': [_release(30, '2026-01-03T00:00:00')],
        }))

        self.assertEqual(['0.4.0'], summary['final_versions'])
        self.assertEqual(
            ['0.4.1.dev1', '0.4.1.dev2'], sorted(summary['dev_versions']))
        self.assertEqual(60, summary['total_bytes'])

    def test_sums_every_file_in_a_release(self):
        summary = check_pypi_storage.summarise(_data({
            '0.4.1.dev1': [
                _release(100, '2026-01-02T00:00:00'),
                _release(250, '2026-01-02T00:00:01'),
            ],
        }))

        self.assertEqual(350, summary['total_bytes'])

    def test_version_with_no_files_still_counts_as_a_release(self):
        """A pruned version keeps its key on PyPI with an empty file list."""
        summary = check_pypi_storage.summarise(_data({
            '0.4.1.dev1': [],
            '0.4.1.dev2': [_release(30, '2026-01-03T00:00:00')],
        }))

        self.assertEqual(2, len(summary['dev_versions']))
        self.assertEqual(30, summary['total_bytes'])

    def test_no_releases_at_all(self):
        summary = check_pypi_storage.summarise(_data({}))

        self.assertEqual(0, summary['total_bytes'])
        self.assertEqual([], summary['dev_versions'])
        self.assertEqual([], summary['final_versions'])


class OldestAndNewestDevUploadTestCase(testtools.TestCase):
    """Ordering must follow upload_time, not the version string."""

    def test_orders_by_upload_time_not_version_string(self):
        """dev9 sorts after dev10 as a string, but was uploaded first.

        This is the exact case the function exists for: setuptools_scm
        commit-count versions stop sorting lexically the moment they
        reach double digits.
        """
        data = _data({
            '0.4.1.dev9': [_release(10, '2026-01-01T00:00:00')],
            '0.4.1.dev10': [_release(10, '2026-02-01T00:00:00')],
        })

        oldest, newest = check_pypi_storage.oldest_and_newest_dev_upload(
            data, ['0.4.1.dev10', '0.4.1.dev9'])

        self.assertEqual('0.4.1.dev9', oldest)
        self.assertEqual('0.4.1.dev10', newest)

    def test_uses_the_earliest_upload_within_a_release(self):
        """A release's age is its first file, not whichever file sorts last."""
        data = _data({
            '0.4.1.dev1': [
                _release(10, '2026-03-01T00:00:00'),
                _release(10, '2026-01-01T00:00:00'),
            ],
            '0.4.1.dev2': [_release(10, '2026-02-01T00:00:00')],
        })

        oldest, newest = check_pypi_storage.oldest_and_newest_dev_upload(
            data, ['0.4.1.dev1', '0.4.1.dev2'])

        self.assertEqual('0.4.1.dev1', oldest)
        self.assertEqual('0.4.1.dev2', newest)

    def test_version_with_no_files_sorts_first(self):
        """An emptied version is reported as oldest, which is intended."""
        data = _data({
            '0.4.1.dev1': [],
            '0.4.1.dev2': [_release(10, '2026-02-01T00:00:00')],
        })

        oldest, newest = check_pypi_storage.oldest_and_newest_dev_upload(
            data, ['0.4.1.dev2', '0.4.1.dev1'])

        self.assertEqual('0.4.1.dev1', oldest)
        self.assertEqual('0.4.1.dev2', newest)

    def test_no_dev_versions(self):
        oldest, newest = check_pypi_storage.oldest_and_newest_dev_upload(
            _data({'0.4.0': [_release(10, '2026-01-01T00:00:00')]}), [])

        self.assertIsNone(oldest)
        self.assertIsNone(newest)


class ByteThresholdTestCase(testtools.TestCase):
    """The comparison is >=, so the boundary belongs in both directions."""

    def _ok_at(self, total_bytes):
        data = _data({
            '0.4.1.dev1': [_release(total_bytes, '2026-01-01T00:00:00')]})
        _, ok = check_pypi_storage.build_report(
            'kerbside-proxy', data, limit_bytes=1000, max_bytes_pct=50,
            max_dev_releases=300)
        return ok

    def test_exactly_at_the_threshold_is_crossed(self):
        self.assertFalse(self._ok_at(500))

    def test_one_byte_below_the_threshold_is_clear(self):
        self.assertTrue(self._ok_at(499))

    def test_above_the_threshold_is_crossed(self):
        self.assertFalse(self._ok_at(900))

    def test_report_names_the_byte_threshold(self):
        data = _data({'0.4.1.dev1': [_release(500, '2026-01-01T00:00:00')]})
        report, ok = check_pypi_storage.build_report(
            'kerbside-proxy', data, limit_bytes=1000, max_bytes_pct=50,
            max_dev_releases=300)

        self.assertFalse(ok)
        self.assertIn('THRESHOLD CROSSED:', report)
        self.assertIn('storage:', report)
        # The dev-count threshold is nowhere near crossed, so it must not
        # appear as a problem line.
        self.assertNotIn('dev release count is', report)


class DevCountThresholdTestCase(testtools.TestCase):
    """The dev-release count alarms independently of the byte total."""

    def _ok_with(self, dev_count):
        releases = {}
        for index in range(dev_count):
            releases['0.4.1.dev%d' % index] = [
                _release(1, '2026-01-01T00:00:%02d' % index)]
        _, ok = check_pypi_storage.build_report(
            'kerbside-proxy', _data(releases), limit_bytes=10 ** 9,
            max_bytes_pct=50, max_dev_releases=5)
        return ok

    def test_exactly_at_the_threshold_is_crossed(self):
        self.assertFalse(self._ok_with(5))

    def test_one_below_the_threshold_is_clear(self):
        self.assertTrue(self._ok_with(4))

    def test_final_releases_do_not_count_towards_the_dev_threshold(self):
        releases = {'0.4.%d' % index: [_release(1, '2026-01-01T00:00:00')]
                    for index in range(20)}
        report, ok = check_pypi_storage.build_report(
            'kerbside-proxy', _data(releases), limit_bytes=10 ** 9,
            max_bytes_pct=50, max_dev_releases=5)

        self.assertTrue(ok)
        self.assertIn('No dev releases found.', report)

    def test_report_names_the_dev_count_threshold(self):
        releases = {'0.4.1.dev%d' % index: [
            _release(1, '2026-01-01T00:00:%02d' % index)]
            for index in range(5)}
        report, ok = check_pypi_storage.build_report(
            'kerbside-proxy', _data(releases), limit_bytes=10 ** 9,
            max_bytes_pct=50, max_dev_releases=5)

        self.assertFalse(ok)
        self.assertIn('dev release count is 5, at or above the 5 threshold',
                      report)
        self.assertNotIn('storage:', report)


class BothThresholdsTestCase(testtools.TestCase):
    def test_both_crossed_reports_both(self):
        releases = {'0.4.1.dev%d' % index: [
            _release(400, '2026-01-01T00:00:%02d' % index)]
            for index in range(5)}
        report, ok = check_pypi_storage.build_report(
            'kerbside-proxy', _data(releases), limit_bytes=1000,
            max_bytes_pct=50, max_dev_releases=5)

        self.assertFalse(ok)
        self.assertIn('storage:', report)
        self.assertIn('dev release count is 5', report)

    def test_neither_crossed_says_so(self):
        report, ok = check_pypi_storage.build_report(
            'kerbside-proxy',
            _data({'0.4.1.dev1': [_release(1, '2026-01-01T00:00:00')]}),
            limit_bytes=10 ** 9, max_bytes_pct=50, max_dev_releases=300)

        self.assertTrue(ok)
        self.assertIn('OK: both thresholds are clear.', report)
        self.assertNotIn('THRESHOLD CROSSED', report)


class ParseProjectDataTestCase(testtools.TestCase):
    """Every parse failure must be EXIT_BROKEN, never exit 1."""

    def _assert_broken(self, body):
        exc = self.assertRaises(
            SystemExit, check_pypi_storage.parse_project_data, body)
        self.assertEqual(check_pypi_storage.EXIT_BROKEN, exc.code)

    def test_non_json_body(self):
        self._assert_broken(b'<html>503 Service Unavailable</html>')

    def test_body_without_a_releases_key(self):
        self._assert_broken(json.dumps({'info': {}}).encode('utf-8'))

    def test_body_that_is_not_an_object(self):
        self._assert_broken(json.dumps([1, 2, 3]).encode('utf-8'))

    def test_releases_that_is_not_an_object(self):
        """A PyPI schema change must be legible, not a traceback."""
        self._assert_broken(
            json.dumps({'releases': ['0.4.1.dev1']}).encode('utf-8'))

    def test_valid_body_is_returned(self):
        data = check_pypi_storage.parse_project_data(
            json.dumps(_data({'0.4.0': []})).encode('utf-8'))

        self.assertEqual({'0.4.0': []}, data['releases'])


class MainExitCodeTestCase(testtools.TestCase):
    """The three-way exit contract, exercised end to end through main().

    Exit 1 is what the workflow maps to "file a threshold-crossed issue",
    so it must be reachable only by a genuine crossing. Anything else
    that goes wrong has to be EXIT_BROKEN, or the workflow files an alarm
    carrying an empty report.
    """

    def _set_argv(self, argv):
        patcher = mock.patch.object(sys, 'argv', argv)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, body, argv_extra=None):
        handle, path = tempfile.mkstemp(suffix='.json')
        self.addCleanup(os.unlink, path)
        with os.fdopen(handle, 'w') as fd:
            fd.write(body)

        argv = ['check-pypi-storage.py', '--input-file', path]
        argv.extend(argv_extra or [])
        self._set_argv(argv)

        try:
            return check_pypi_storage.main()
        except SystemExit as exc:
            return exc.code

    def test_clear_exits_zero(self):
        body = json.dumps(_data({
            '0.4.1.dev1': [_release(1, '2026-01-01T00:00:00')]}))

        self.assertEqual(0, self._run(body))

    def test_genuine_crossing_exits_one(self):
        body = json.dumps(_data({
            '0.4.1.dev1': [_release(600, '2026-01-01T00:00:00')]}))

        self.assertEqual(
            1, self._run(body, ['--limit-bytes', '1000',
                                '--max-bytes-pct', '50']))

    def test_unparseable_body_exits_broken(self):
        self.assertEqual(
            check_pypi_storage.EXIT_BROKEN, self._run('not json at all'))

    def test_missing_releases_key_exits_broken(self):
        self.assertEqual(
            check_pypi_storage.EXIT_BROKEN, self._run(json.dumps({})))

    def test_malformed_releases_shape_exits_broken(self):
        """Regression: this used to reach the interpreter and exit 1."""
        body = json.dumps({'releases': ['0.4.1.dev1']})

        self.assertEqual(check_pypi_storage.EXIT_BROKEN, self._run(body))

    def test_null_file_size_exits_broken(self):
        """Regression: a null size raised TypeError and so exited 1.

        There is no fail() call for this; it is caught by main()'s
        structural guard, which is the point -- an unanticipated schema
        surprise must not masquerade as a threshold crossing.
        """
        body = json.dumps(_data({
            '0.4.1.dev1': [{'size': None,
                            'upload_time': '2026-01-01T00:00:00'}]}))

        self.assertEqual(check_pypi_storage.EXIT_BROKEN, self._run(body))

    def test_unreadable_input_file_exits_broken(self):
        self._set_argv(
            ['check-pypi-storage.py', '--input-file', '/nonexistent/x.json'])

        exc = self.assertRaises(SystemExit, check_pypi_storage.main)
        self.assertEqual(check_pypi_storage.EXIT_BROKEN, exc.code)
