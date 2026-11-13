import importlib.util
import io
import json
import os
import shutil
import tempfile
from pathlib import Path

import testtools


# tools/quic-bench/summarise.py turns a work directory of per-repeat JSON
# into the tables a transport verdict is quoted from, and every figure in
# them is arithmetic no other code repeats: a median taken over the wrong
# set of repeats, or a spread taken over fewer repeats than ran, is a
# plausible-looking number rather than a failure. The run data those
# tables were published from no longer exists, so these fixtures are the
# only remaining check on that arithmetic. Loaded by path because the
# script lives outside the importable package and its directory name
# contains a hyphen, as test_check_backend_tls_claims.py does.
_SUMMARISE_PATH = (
    Path(__file__).resolve().parents[3] / 'tools' / 'quic-bench' / 'summarise.py')
_spec = importlib.util.spec_from_file_location('quic_bench_summarise', _SUMMARISE_PATH)
summarise = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(summarise)


def _run(p50_ms=1.0, p95_ms=2.0, p99_ms=3.0, samples=100, timeouts=0, mbit_per_sec=10.0,
         connect_ms=5.0, gso=None, quic_cc=None, bytes_per_slot=None, bytes_per_slot_samples=0):
    """One repeat in the shape read_run() returns it."""
    return {
        'p50_ms': p50_ms,
        'p95_ms': p95_ms,
        'p99_ms': p99_ms,
        'samples': samples,
        'timeouts': timeouts,
        'mbit_per_sec': mbit_per_sec,
        'connect_ms': connect_ms,
        'gso': gso,
        'quic_cc': quic_cc,
        'bytes_per_slot': bytes_per_slot,
        'bytes_per_slot_samples': bytes_per_slot_samples,
    }


# Three repeats whose every column has a median distinct from its own mean
# and from its own extremes, so that each figure below is pinned to one
# calculation. p50 [4, 6, 9] medians to 6.0 against a mean of 6.33; p95
# [10, 12, 30] to 12.0 against 17.33; Mbit [80, 100, 95] to 95.0 against
# 91.67, with min and max two different repeats.
MEASURED = [
    _run(p50_ms=4.0, p95_ms=10.0, p99_ms=20.0, samples=100, timeouts=2, mbit_per_sec=80.0,
         connect_ms=5.0, bytes_per_slot=1200.0, bytes_per_slot_samples=4),
    _run(p50_ms=6.0, p95_ms=12.0, p99_ms=25.0, samples=120, timeouts=0, mbit_per_sec=100.0,
         connect_ms=7.0),
    _run(p50_ms=9.0, p95_ms=30.0, p99_ms=50.0, samples=140, timeouts=1, mbit_per_sec=95.0,
         connect_ms=9.0, bytes_per_slot=1400.0, bytes_per_slot_samples=6),
]

# A repeat that ran but produced no steady-state sample: the bench writes
# null percentiles and a zero throughput, which is exactly the shape that
# must not reach a median. Its five timeouts must still be counted.
UNMEASURED = _run(p50_ms=None, p95_ms=None, p99_ms=None, samples=0, timeouts=5,
                  mbit_per_sec=0.0, connect_ms=7.0)

_RESULT = {
    'interactive': {'p50_us': 1500, 'p95_us': 2500, 'p99_us': 4100, 'samples_steady': 980,
                    'timeouts': 3},
    'bulk': {'mbit_per_sec': 9.37},
    'connect_ms': 12.5,
    'gso': {'segments_available': 1, 'segments_used': 1},
    'quic_cc': 'cubic',
}


class AggregateTestCase(testtools.TestCase):
    def test_every_column_of_three_good_repeats(self):
        self.assertEqual(
            {
                'repeats': 3,
                'unmeasured_repeats': 0,
                'absent_repeats': 0,
                'p50_ms': 6.0,
                'p95_ms': 12.0,
                'p99_ms': 25.0,
                'p95_min_ms': 10.0,
                'p95_max_ms': 30.0,
                'p95_spread_ms': 20.0,
                'mbit_per_sec': 95.0,
                'mbit_min': 80.0,
                'mbit_max': 100.0,
                'connect_ms': 7.0,
                'samples': 120,
                'timeouts': 3,
                'bytes_per_slot': 1300.0,
                'gso': None,
                'quic_cc': None,
            },
            summarise.aggregate(MEASURED, 3))

    def test_unmeasured_repeat_is_excluded_but_its_timeouts_are_not(self):
        # The excluded repeat's zero throughput would pull the median from
        # 87.5 to 80.0 and the minimum from 80.0 to 0.0, and its null
        # percentiles have no median at all. Its timeouts belong to the
        # cell regardless: a repeat that timed out its way to no samples is
        # what that count is for.
        agg = summarise.aggregate([MEASURED[0], UNMEASURED, MEASURED[2]], 3)
        self.assertEqual(2, agg['repeats'])
        self.assertEqual(1, agg['unmeasured_repeats'])
        self.assertEqual(0, agg['absent_repeats'])
        self.assertEqual(6.5, agg['p50_ms'])
        self.assertEqual(20.0, agg['p95_ms'])
        self.assertEqual(35.0, agg['p99_ms'])
        self.assertEqual(20.0, agg['p95_spread_ms'])
        self.assertEqual(87.5, agg['mbit_per_sec'])
        self.assertEqual(80.0, agg['mbit_min'])
        self.assertEqual(95.0, agg['mbit_max'])
        self.assertEqual(120, agg['samples'])
        self.assertEqual(8, agg['timeouts'])

    def test_repeats_that_left_no_file_are_counted_against_the_attempt(self):
        # Five repeats ran and two left nothing behind. Those two cannot be
        # excluded on their merits, so the row must say they are missing
        # rather than present a three-repeat spread as a five-repeat one.
        agg = summarise.aggregate(MEASURED, 5)
        self.assertEqual(3, agg['repeats'])
        self.assertEqual(0, agg['unmeasured_repeats'])
        self.assertEqual(2, agg['absent_repeats'])
        self.assertEqual(20.0, agg['p95_spread_ms'])

    def test_a_queue_sample_no_repeat_produced_is_none_not_zero(self):
        agg = summarise.aggregate([MEASURED[1]], 1)
        self.assertIsNone(agg['bytes_per_slot'])

    def test_no_repeats_at_all(self):
        self.assertIsNone(summarise.aggregate([], 3))

    def test_no_measured_repeat(self):
        self.assertIsNone(summarise.aggregate([UNMEASURED, UNMEASURED], 2))

    def test_offload_and_controller_come_from_the_first_repeat_that_has_them(self):
        runs = [
            _run(gso=None, quic_cc=None),
            _run(gso={'segments_available': 2, 'segments_used': 1}, quic_cc='cubic'),
            _run(gso={'segments_available': 9, 'segments_used': 9}, quic_cc='bbr'),
        ]
        agg = summarise.aggregate(runs, 3)
        self.assertEqual({'segments_available': 2, 'segments_used': 1}, agg['gso'])
        self.assertEqual('cubic', agg['quic_cc'])


class ReadRunTestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.casedir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.casedir)

    def write_result(self, arm='quic', **overrides):
        result = dict(_RESULT, **overrides)
        with open(os.path.join(self.casedir, f'{arm}.json'), 'w') as handle:
            json.dump(result, handle)

    def write_backlog(self, arm, lines):
        with open(os.path.join(self.casedir, f'{arm}-backlog.jsonl'), 'w') as handle:
            handle.write(''.join(f'{line}\n' for line in lines))

    def test_a_repeat_that_left_no_results_file(self):
        self.assertIsNone(summarise.read_run(self.casedir, 'quic'))

    def test_microseconds_become_milliseconds(self):
        self.write_result()
        run = summarise.read_run(self.casedir, 'quic')
        self.assertEqual(1.5, run['p50_ms'])
        self.assertEqual(2.5, run['p95_ms'])
        self.assertEqual(4.1, run['p99_ms'])
        self.assertEqual(980, run['samples'])
        self.assertEqual(3, run['timeouts'])
        self.assertEqual(9.37, run['mbit_per_sec'])
        self.assertEqual(12.5, run['connect_ms'])
        self.assertEqual('cubic', run['quic_cc'])
        self.assertIsNone(run['bytes_per_slot'])
        self.assertEqual(0, run['bytes_per_slot_samples'])

    def test_a_percentile_with_no_samples_stays_missing(self):
        self.write_result(interactive={'p50_us': 1500, 'p95_us': None, 'p99_us': None,
                                       'samples_steady': 0, 'timeouts': 11})
        run = summarise.read_run(self.casedir, 'quic')
        self.assertEqual(1.5, run['p50_ms'])
        self.assertIsNone(run['p95_ms'])
        self.assertIsNone(run['p99_ms'])
        self.assertEqual(11, run['timeouts'])

    def test_bytes_per_slot_divides_backlog_by_packets_over_deep_queues_only(self):
        # 15000 bytes over 10 packets in the two deep samples. The shallow
        # sample is an ack-sized 60 bytes in one slot: counting it would
        # report 1369.1 over 11 slots, and dividing by samples rather than
        # slots would report 7500.
        self.write_result(arm='tcp')
        self.write_backlog('tcp', [
            '12.0 [{"qlen": 1, "backlog": 60}]',
            '12.5 [{"qlen": 4, "backlog": 6000}]',
            'not json at all',
            '13.0 [{"qlen": 6, "backlog": 9000}]',
            '13.5 []',
        ])
        run = summarise.read_run(self.casedir, 'tcp')
        self.assertEqual(1500.0, run['bytes_per_slot'])
        self.assertEqual(2, run['bytes_per_slot_samples'])

    def test_a_queue_that_never_filled_measures_nothing(self):
        self.write_result(arm='tcp')
        self.write_backlog('tcp', ['12.0 [{"qlen": 1, "backlog": 60}]'])
        run = summarise.read_run(self.casedir, 'tcp')
        self.assertIsNone(run['bytes_per_slot'])


class CollectTestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.workdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.workdir)

    def write_repeat(self, cell, rep, arms):
        casedir = os.path.join(self.workdir, cell, rep)
        os.makedirs(casedir)
        for arm in arms:
            with open(os.path.join(casedir, f'{arm}.json'), 'w') as handle:
                json.dump(_RESULT, handle)

    def write_host_facts(self, line='repeats: 5 duration: 45s warmup: 5s'):
        with open(os.path.join(self.workdir, 'host.txt'), 'w') as handle:
            handle.write(f'kernel: 6.12.0\nprofiles: 20:50\n{line}\nchannels: 4\n')

    def test_a_repeat_whose_file_never_arrived_is_still_counted(self):
        # The second repeat's QUIC arm died before writing its result, as a
        # kill or a full disk leaves it. read_run() returns nothing for it,
        # so only the attempt count carries the fact that it ran.
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep1', ('tcp', 'quic'))
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep2', ('tcp',))
        with open(os.path.join(self.workdir, '20ms-50mbit-0pct-cubic', 'notes.txt'), 'w') as handle:
            handle.write('not a repeat\n')
        os.makedirs(os.path.join(self.workdir, 'logs'))

        cells = summarise.collect(self.workdir)
        self.assertEqual(['20ms-50mbit-0pct-cubic'], list(cells))
        cell = cells['20ms-50mbit-0pct-cubic']
        self.assertEqual({'tcp': 2, 'quic': 2}, cell['attempted'])
        self.assertEqual(2, len(cell['runs']['tcp']))
        self.assertEqual(1, len(cell['runs']['quic']))

    def test_a_directory_in_a_cell_that_is_not_a_repeat_is_not_counted_as_one(self):
        # Anything but the harness's own rep<N> directories -- somewhere to
        # put logs or a capture, an editor's scratch directory -- is not a
        # repeat, and counting one would report a run that lost nothing as
        # having lost data.
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep1', ('tcp', 'quic'))
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep2', ('tcp', 'quic'))
        os.makedirs(os.path.join(self.workdir, '20ms-50mbit-0pct-cubic', 'logs'))
        os.makedirs(os.path.join(self.workdir, '20ms-50mbit-0pct-cubic', '.rep3.swp'))
        os.makedirs(os.path.join(self.workdir, '20ms-50mbit-0pct-cubic', 'rep2.orig'))

        cells = summarise.collect(self.workdir)
        cell = cells['20ms-50mbit-0pct-cubic']
        self.assertEqual({'tcp': 2, 'quic': 2}, cell['attempted'])
        self.assertEqual(2, cell['repeat_dirs'])
        summary = summarise.report(cells, [], headline_cc='cubic', out=io.StringIO())
        self.assertEqual(0, summary['cells']['20ms-50mbit-0pct-cubic']['quic']['absent_repeats'])
        self.assertEqual([], [line for line in summary['warnings'] if 'repeats' in line])

    def test_the_report_warns_about_a_repeat_whose_file_never_arrived(self):
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep1', ('tcp', 'quic'))
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep2', ('tcp',))
        summary = summarise.report(summarise.collect(self.workdir), [], headline_cc='cubic',
                                   out=io.StringIO())
        self.assertEqual(1, summary['cells']['20ms-50mbit-0pct-cubic']['quic']['absent_repeats'])
        self.assertIn(
            '20ms-50mbit-0pct-cubic quic: 1 of 2 repeats left no results file, so nothing from '
            'them reaches the medians or the spread',
            summary['warnings'])

    def test_a_repeat_that_never_got_a_directory_is_counted_from_host_txt(self):
        # A run killed part way through a cell leaves no directory at all for
        # the repeats it never reached, so the directories on their own
        # present a two-repeat spread as the five-repeat one asked for.
        self.write_host_facts()
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep1', ('tcp', 'quic'))
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep2', ('tcp', 'quic'))

        cell = summarise.collect(self.workdir)['20ms-50mbit-0pct-cubic']
        self.assertEqual(5, cell['requested_repeats'])
        self.assertEqual(2, cell['repeat_dirs'])
        self.assertEqual({'tcp': 5, 'quic': 5}, cell['attempted'])

    def test_more_directories_than_host_txt_asked_for_are_all_counted(self):
        # The larger of the two records wins in both directions: a work
        # directory holding more repeats than host.txt asked for has them.
        self.write_host_facts('repeats: 1 duration: 45s warmup: 5s')
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep1', ('tcp', 'quic'))
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep2', ('tcp', 'quic'))

        cell = summarise.collect(self.workdir)['20ms-50mbit-0pct-cubic']
        self.assertEqual({'tcp': 2, 'quic': 2}, cell['attempted'])

    def test_a_work_directory_with_no_host_txt_counts_the_directories(self):
        # The hand-assembled case: nothing records what was asked for, which
        # is not a reason to refuse to summarise what is there.
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep1', ('tcp', 'quic'))
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep2', ('tcp', 'quic'))

        cell = summarise.collect(self.workdir)['20ms-50mbit-0pct-cubic']
        self.assertIsNone(cell['requested_repeats'])
        self.assertEqual({'tcp': 2, 'quic': 2}, cell['attempted'])
        summary = summarise.report({'20ms-50mbit-0pct-cubic': cell}, [], headline_cc='cubic',
                                   out=io.StringIO())
        self.assertEqual([], [line for line in summary['warnings'] if 'repeats' in line])

    def test_a_host_txt_with_no_repeat_count_to_read_counts_the_directories(self):
        for line in ('repeats: many duration: 45s', 'repeats:', 'repeat: 5'):
            self.write_host_facts(line)
            self.assertIsNone(summarise.read_requested_repeats(self.workdir))

    def test_the_report_warns_when_a_cell_was_cut_short_of_what_was_asked_for(self):
        self.write_host_facts()
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep1', ('tcp', 'quic'))
        self.write_repeat('20ms-50mbit-0pct-cubic', 'rep2', ('tcp', 'quic'))
        summary = summarise.report(summarise.collect(self.workdir), [], headline_cc='cubic',
                                   out=io.StringIO())
        self.assertEqual(3, summary['cells']['20ms-50mbit-0pct-cubic']['quic']['absent_repeats'])
        self.assertIn(
            '20ms-50mbit-0pct-cubic: the harness was asked for 5 repeats and 2 got as far as a '
            'directory, so this cell was cut short and every figure in it is taken over fewer '
            'repeats than were asked for',
            summary['warnings'])


def _cell(cc, runs, attempted=None, requested_repeats=None):
    attempted = attempted if attempted is not None else len(runs)
    return {
        'fields': {'rtt': '20', 'rate': '50', 'loss': '0', 'cc': cc},
        'runs': {arm: list(runs) for arm in summarise.ARMS},
        'attempted': {arm: attempted for arm in summarise.ARMS},
        'repeat_dirs': attempted,
        'requested_repeats': requested_repeats,
    }


class HeadlineControllerTestCase(testtools.TestCase):
    def test_the_controller_the_caller_named(self):
        self.assertEqual('cubic', summarise.resolve_headline_cc('cubic', ['bbr', 'cubic']))

    def test_one_controller_in_the_matrix_needs_no_caller(self):
        self.assertEqual('bbr', summarise.resolve_headline_cc(None, ['bbr']))

    def test_several_controllers_and_nothing_names_the_gate_is_an_error(self):
        # bbr sorts before cubic, so a first-alphabetically default here
        # would label the sensitivity arm as the gate and the gate as a
        # sensitivity run.
        error = self.assertRaises(
            summarise.AmbiguousHeadlineCc, summarise.resolve_headline_cc, None, ['bbr', 'cubic'])
        self.assertIn('bbr, cubic', str(error))
        self.assertIn('--headline-cc', str(error))

    def test_a_controller_the_matrix_does_not_have_is_an_error(self):
        self.assertRaises(
            summarise.AmbiguousHeadlineCc, summarise.resolve_headline_cc, 'reno',
            ['bbr', 'cubic'])

    def test_the_controller_cells_txt_recorded_is_used_when_the_caller_named_none(self):
        self.assertEqual(
            'cubic', summarise.resolve_headline_cc(None, ['bbr', 'cubic'], detected='cubic'))

    def test_the_caller_outranks_the_controller_cells_txt_recorded(self):
        self.assertEqual(
            'bbr', summarise.resolve_headline_cc('bbr', ['bbr', 'cubic'], detected='cubic'))

    def test_a_detected_controller_the_matrix_does_not_have_blames_cells_txt(self):
        # An interrupted run lands here: cells.txt is appended before the
        # repeat directory is made, so it can name a controller no surviving
        # cell ran. The caller supplied nothing, so nothing may say they did.
        error = self.assertRaises(
            summarise.AmbiguousHeadlineCc, summarise.resolve_headline_cc, None, ['bbr', 'reno'],
            'cubic')
        self.assertIn('cells.txt', str(error))
        self.assertIn('cubic', str(error))
        self.assertIn('bbr', str(error))
        self.assertIn('--headline-cc', str(error))
        self.assertNotIn('asked for', str(error))

    def test_a_detected_controller_does_not_make_the_only_surviving_one_the_gate(self):
        # One controller in the matrix settles nothing here: cells.txt is the
        # only record of which arm the gate was, and it says this is not it.
        self.assertRaises(
            summarise.AmbiguousHeadlineCc, summarise.resolve_headline_cc, None, ['bbr'], 'cubic')

    def test_a_caller_the_matrix_does_not_have_is_still_blamed_for_their_own_value(self):
        error = self.assertRaises(
            summarise.AmbiguousHeadlineCc, summarise.resolve_headline_cc, 'reno', ['cubic'],
            'cubic')
        self.assertIn("asked for 'reno'", str(error))
        self.assertNotIn('cells.txt', str(error))

    def test_a_requested_controller_is_not_silently_replaced_by_the_only_one(self):
        # One controller in the matrix is unambiguous only when the caller
        # named none. Having asked for another, the caller gets an error
        # rather than a report about an arm they did not ask about.
        error = self.assertRaises(
            summarise.AmbiguousHeadlineCc, summarise.resolve_headline_cc, 'bbr', ['cubic'])
        self.assertIn('bbr', str(error))
        self.assertIn('cubic', str(error))

    def test_the_report_scopes_rows_by_the_controller_it_was_given(self):
        cells = {'20ms-50mbit-0pct-bbr': _cell('bbr', MEASURED),
                 '20ms-50mbit-0pct-cubic': _cell('cubic', MEASURED)}
        summary = summarise.report(cells, [], headline_cc='cubic', out=io.StringIO())
        self.assertEqual('gate', summary['gate']['20ms-50mbit-0pct-cubic']['scope'])
        self.assertEqual('sensitivity', summary['gate']['20ms-50mbit-0pct-bbr']['scope'])

    def test_without_a_controller_no_row_is_the_gate(self):
        cells = {'20ms-50mbit-0pct-bbr': _cell('bbr', MEASURED),
                 '20ms-50mbit-0pct-cubic': _cell('cubic', MEASURED)}
        out = io.StringIO()
        summary = summarise.report(cells, [], headline_cc=None, out=out)
        self.assertIsNone(summary['headline_cc'])
        self.assertEqual(['sensitivity', 'sensitivity'],
                         [row['scope'] for row in summary['gate'].values()])
        self.assertNotIn('The gate is defined against', out.getvalue())
