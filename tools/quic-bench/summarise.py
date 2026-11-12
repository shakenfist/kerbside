#!/usr/bin/env python3
"""Summarise a run-bench.sh work directory.

Reads every per-run results file the harness wrote and prints, per cell:

  * the interactive round trip's p50, p95 and p99, as the median of each
    repeat's own percentile, with the run-to-run spread of the p95 -- the
    difference between the highest and the lowest repeat;
  * the saturating channel's throughput, likewise;
  * the queue-accounting check: the mean bytes per netem queue slot, sampled
    from the server-side egress qdisc while the run was in flight.

The spread matters as much as the middle. A difference between the two arms
that is smaller than the spread of either is a difference this bench cannot
resolve, and saying so is a result.

Usage: summarise.py WORKDIR [--json SUMMARY.json]
"""

import argparse
import json
import os
import re
import statistics
import sys


CELL_RE = re.compile(r'^(?P<rtt>\d+)ms-(?P<rate>\d+)mbit-(?P<loss>[\d.]+)pct-(?P<cc>\w+)$')
ARMS = ('tcp', 'quic')

# A netem slot holds one packet. Below this many packets in the queue the
# bytes-per-slot ratio is dominated by whichever small ack happened to be in
# flight, so those samples say nothing about the sender's write size.
MIN_QUEUE_PACKETS = 2


class AmbiguousHeadlineCc(Exception):
    """The matrix spans several controllers and nothing names the gate's."""


def backlog_bytes_per_slot(path):
    """Mean bytes per occupied queue slot over a run's qdisc samples."""
    if not os.path.exists(path):
        return None, 0
    total_bytes = total_packets = samples = 0
    with open(path) as handle:
        for line in handle:
            _, _, payload = line.partition(' ')
            try:
                qdisc = json.loads(payload)[0]
            except (ValueError, IndexError, KeyError):
                continue
            packets = qdisc.get('qlen', 0)
            if packets >= MIN_QUEUE_PACKETS:
                total_bytes += qdisc.get('backlog', 0)
                total_packets += packets
                samples += 1
    if not total_packets:
        return None, samples
    return total_bytes / total_packets, samples


def us_to_ms(value):
    """Microseconds to milliseconds, passing a missing measurement through.

    The bench writes null rather than zero for a percentile it had no samples
    for, so that a failed cell cannot be read as a fast one.
    """
    return None if value is None else value / 1000.0


def read_run(casedir, arm):
    """One repeat of one arm, or None if the harness did not get a result."""
    path = os.path.join(casedir, f'{arm}.json')
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        data = json.load(handle)
    interactive = data['interactive']
    ratio, ratio_samples = backlog_bytes_per_slot(os.path.join(casedir, f'{arm}-backlog.jsonl'))
    return {
        'p50_ms': us_to_ms(interactive['p50_us']),
        'p95_ms': us_to_ms(interactive['p95_us']),
        'p99_ms': us_to_ms(interactive['p99_us']),
        'samples': interactive['samples_steady'],
        'timeouts': interactive['timeouts'],
        'mbit_per_sec': data['bulk']['mbit_per_sec'],
        'connect_ms': data['connect_ms'],
        'gso': data.get('gso'),
        'quic_cc': data.get('quic_cc'),
        'bytes_per_slot': ratio,
        'bytes_per_slot_samples': ratio_samples,
    }


def collect_gso_control(workdir):
    """The deliberately-wrong runs, if the harness made any.

    A check that can only ever pass proves nothing, so the harness also runs
    the QUIC arm once with segmentation offload left on. Its queue should hold
    many datagrams per slot where every measured run holds one.
    """
    controls = []
    for name in sorted(os.listdir(workdir)):
        casedir = os.path.join(workdir, name)
        if not name.startswith('gso-control') or not os.path.isdir(casedir):
            continue
        run = read_run(casedir, 'quic')
        if run is not None:
            controls.append((name, run))
    return controls


def collect(workdir):
    """Walk the work directory into {cell: {fields, runs, attempted}}."""
    cells = {}
    for name in sorted(os.listdir(workdir)):
        match = CELL_RE.match(name)
        if not match:
            continue
        celldir = os.path.join(workdir, name)
        if not os.path.isdir(celldir):
            continue
        runs = {arm: [] for arm in ARMS}
        # How many repeats each arm was asked for, counted as the directories
        # are walked. A repeat the harness lost -- a crash, a kill, a full
        # disk -- leaves no results file and so nothing in runs, and the only
        # other record of it is this count: without it such a repeat narrows
        # the spread the gate's threshold is taken from and says nothing.
        attempted = {arm: 0 for arm in ARMS}
        for rep in sorted(os.listdir(celldir)):
            casedir = os.path.join(celldir, rep)
            if not os.path.isdir(casedir):
                continue
            for arm in ARMS:
                attempted[arm] += 1
                run = read_run(casedir, arm)
                if run is not None:
                    runs[arm].append(run)
        cells[name] = {'fields': match.groupdict(), 'runs': runs, 'attempted': attempted}
    return cells


def aggregate(runs, attempted):
    """Median and spread across repeats for one arm of one cell.

    `runs` is the repeats that produced a results file and `attempted` how
    many were walked, so their difference is the repeats whose file never
    arrived. Those cannot be excluded on their merits the way a repeat with
    no steady-state samples can, since nothing about them is known, so they
    are counted and reported rather than passed over.
    """
    if not runs:
        return None
    # A repeat that produced no steady-state samples has no percentile to
    # take a median of. Those repeats are counted and excluded rather than
    # contributing a zero, which would drag every figure in the cell down.
    measured = [run for run in runs if run['p95_ms'] is not None]
    unmeasured = len(runs) - len(measured)
    if not measured:
        return None
    p95 = [run['p95_ms'] for run in measured]
    slots = [run['bytes_per_slot'] for run in runs if run['bytes_per_slot'] is not None]
    return {
        'repeats': len(measured),
        'unmeasured_repeats': unmeasured,
        'absent_repeats': attempted - len(runs),
        'p50_ms': statistics.median(run['p50_ms'] for run in measured),
        'p95_ms': statistics.median(p95),
        'p99_ms': statistics.median(run['p99_ms'] for run in measured),
        'p95_min_ms': min(p95),
        'p95_max_ms': max(p95),
        'p95_spread_ms': max(p95) - min(p95),
        # Throughput, connect time and sample counts come from the measured
        # repeats too: a repeat that produced no samples produced no usable
        # figure of any kind, and averaging its zeros in would understate
        # every column in the row.
        'mbit_per_sec': statistics.median(run['mbit_per_sec'] for run in measured),
        'mbit_min': min(run['mbit_per_sec'] for run in measured),
        'mbit_max': max(run['mbit_per_sec'] for run in measured),
        'connect_ms': statistics.median(run['connect_ms'] for run in measured),
        'samples': statistics.median(run['samples'] for run in measured),
        # Timeouts are counted over every repeat, including the excluded
        # ones: a repeat that timed out its way to no samples is exactly what
        # this count is for.
        'timeouts': sum(run['timeouts'] for run in runs),
        # None, not zero, when no run produced a usable queue sample: fmt()
        # prints '--' for a missing value and 0.0 would look like a short
        # datagram, which is the opposite of what this check is for.
        'bytes_per_slot': statistics.median(slots) if slots else None,
        'gso': next((run['gso'] for run in runs if run['gso']), None),
        'quic_cc': next((run['quic_cc'] for run in runs if run['quic_cc']), None),
    }


def fmt(value, places=1):
    return '--' if value is None else f'{value:.{places}f}'


def detect_headline_cc(workdir):
    """The controller the harness ran first, which is the gate's.

    run-bench.sh appends each cell to cells.txt as it starts it, in matrix
    order, so the first line names the headline arm. Without that file -- a
    hand-assembled work directory -- the caller has to say.
    """
    path = os.path.join(workdir, 'cells.txt')
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        for line in handle:
            match = CELL_RE.match(line.strip())
            if match:
                return match.group('cc')
    return None


def controllers(cells):
    """The congestion controllers the matrix covers, sorted."""
    return sorted({cell['fields']['cc'] for cell in cells.values()})


def resolve_headline_cc(requested, ccs):
    """The controller the gate's rows are, or an error rather than a guess.

    Reading a sensitivity arm as the gate inverts the scope of every row in
    the report, and the controllers sort in no meaningful order -- `bbr`
    before `cubic` -- so a first-alphabetically default is as likely to name
    the sensitivity arm as the gate. A matrix on one controller is the only
    case with nothing to choose; anything else the caller has to say. A
    controller the caller asked for and the matrix does not have is an error
    too, rather than the one controller it does have: the answer would be
    about an arm the caller did not ask about.
    """
    if requested in ccs:
        return requested
    if requested is not None:
        raise AmbiguousHeadlineCc(
            f"asked for '{requested}', which no cell under this directory ran; its controllers "
            f"are {', '.join(ccs) or 'none at all'}")
    if len(ccs) == 1:
        return ccs[0]
    raise AmbiguousHeadlineCc(
        f"cells on {', '.join(ccs) or 'no controller at all'} and nothing names the controller "
        'the harness ran first, so which rows are the gate and which are sensitivity runs is '
        'unknown; pass --headline-cc')


def report(cells, controls, headline_cc=None, out=sys.stdout):
    summary = {}
    warnings = []
    # The gate is defined against one controller on both sides. Any other arm
    # is a labelled sensitivity run, so its rows must not be quotable as the
    # gate's verdict. Which controller that is has already been settled by
    # resolve_headline_cc(); nothing here may fall back to a guess.
    ccs = controllers(cells)

    for cc in ccs:
        print(f'\n## Congestion controller: {cc}\n', file=out)
        print('| profile | loss | arm | p50 ms | p95 ms | p99 ms | p95 spread ms | p95 range ms | '
              'Mbit/s | samples/run | timeouts |', file=out)
        print('|---|---|---|---|---|---|---|---|---|---|---|', file=out)
        for name, cell in cells.items():
            fields = cell['fields']
            if fields['cc'] != cc:
                continue
            profile = f"{fields['rtt']} ms / {fields['rate']} Mbit"
            for arm in ARMS:
                runs, attempted = cell['runs'][arm], cell['attempted'][arm]
                agg = aggregate(runs, attempted)
                summary.setdefault(name, {})[arm] = agg
                absent = attempted - len(runs)
                if absent:
                    warnings.append(
                        f'{name} {arm}: {absent} of {attempted} repeats left no results file, so '
                        'nothing from them reaches the medians or the spread')
                if agg is None:
                    print(f"| {profile} | {fields['loss']}% | {arm} | missing ||||||||", file=out)
                    warnings.append(f'{name} {arm}: no repeat produced a measurement')
                    continue
                flag = '' if not agg['timeouts'] else f" **{agg['timeouts']}**"
                print(
                    f"| {profile} | {fields['loss']}% | {arm} | {fmt(agg['p50_ms'])} | "
                    f"{fmt(agg['p95_ms'])} | {fmt(agg['p99_ms'])} | {fmt(agg['p95_spread_ms'])} | "
                    f"{fmt(agg['p95_min_ms'])}-{fmt(agg['p95_max_ms'])} | "
                    f"{fmt(agg['mbit_per_sec'], 2)} | {int(agg['samples'])} |"
                    f"{flag or ' 0'} |",
                    file=out,
                )
                if agg['timeouts']:
                    warnings.append(
                        f"{name} {arm}: {agg['timeouts']} interactive exchange(s) timed out, so "
                        'that many samples are censored floors rather than measurements')
                if agg['unmeasured_repeats']:
                    warnings.append(
                        f"{name} {arm}: {agg['unmeasured_repeats']} of "
                        f"{agg['repeats'] + agg['unmeasured_repeats']} repeats produced no "
                        'steady-state samples and are excluded')

    print('\n## Queue accounting (bytes per netem slot, server egress)\n', file=out)
    print('| cell | arm | bytes/slot | segments available | segments used |', file=out)
    print('|---|---|---|---|---|', file=out)
    for name, cell in cells.items():
        for arm in ARMS:
            agg = summary.get(name, {}).get(arm)
            if agg is None:
                continue
            gso = agg['gso'] or {}
            print(
                f"| {name} | {arm} | {fmt(agg['bytes_per_slot'])} | "
                f"{gso.get('segments_available', '--')} | {gso.get('segments_used', '--')} |",
                file=out,
            )

    if controls:
        print('\n## Queue accounting, positive control (segmentation offload left on)\n', file=out)
        print('| cell | bytes/slot | segments available | segments used | p95 ms | Mbit/s |', file=out)
        print('|---|---|---|---|---|---|', file=out)
        for name, run in controls:
            gso = run['gso'] or {}
            print(
                f"| {name} | {fmt(run['bytes_per_slot'])} | {gso.get('segments_available', '--')} | "
                f"{gso.get('segments_used', '--')} | {fmt(run['p95_ms'])} | {fmt(run['mbit_per_sec'], 2)} |",
                file=out,
            )

    print('\n## Gate: quic p95 against tcp p95\n', file=out)
    print('The threshold is the bench\'s own run-to-run spread, taken as the wider of the two '
          'arms\' p95 spreads in that cell.\n', file=out)
    if headline_cc is not None:
        print(f'The gate is defined against `{headline_cc}` on both sides. Cells on another '
              'controller are sensitivity runs: their rows are marked as such and are not the '
              "gate's verdict.\n", file=out)
    print('| cell | scope | tcp p95 ms | quic p95 ms | delta ms | threshold ms | verdict |',
          file=out)
    print('|---|---|---|---|---|---|---|', file=out)
    gate = {}
    for name, arms in summary.items():
        tcp, quic = arms.get('tcp'), arms.get('quic')
        if not tcp or not quic:
            continue
        cc = cells[name]['fields']['cc']
        scope = 'gate' if cc == headline_cc else 'sensitivity'
        delta = quic['p95_ms'] - tcp['p95_ms']
        threshold = max(tcp['p95_spread_ms'], quic['p95_spread_ms'])
        if delta > threshold:
            verdict = 'quic worse beyond spread'
        elif -delta > threshold:
            verdict = 'quic better beyond spread'
        else:
            verdict = 'tie within spread'
        gate[name] = {'delta_ms': delta, 'threshold_ms': threshold, 'verdict': verdict,
                      'scope': scope}
        print(
            f'| {name} | {scope} | {fmt(tcp["p95_ms"])} | {fmt(quic["p95_ms"])} | {delta:+.1f} | '
            f'{fmt(threshold)} | {verdict} |',
            file=out,
        )

    if warnings:
        print('\n## Warnings\n', file=out)
        for line in warnings:
            print(f'- {line}', file=out)
    else:
        print('\n## Warnings\n\nNone: every cell measured every repeat, and no interactive '
              'exchange timed out.', file=out)

    return {'cells': summary, 'gate': gate, 'headline_cc': headline_cc, 'warnings': warnings,
            'gso_control': {name: run for name, run in controls}}


def main():
    parser = argparse.ArgumentParser(description='Summarise a quic-bench work directory.')
    parser.add_argument('workdir')
    parser.add_argument('--json', dest='json_out', help='also write the summary as JSON')
    parser.add_argument('--headline-cc', default=None,
                        help='the congestion controller the gate is defined against; defaults to '
                             'the first cell cells.txt records, and is required when that file is '
                             'absent and the matrix spans more than one controller')
    args = parser.parse_args()

    cells = collect(args.workdir)
    if not cells:
        print(f'No cells found under {args.workdir}', file=sys.stderr)
        return 1
    try:
        headline_cc = resolve_headline_cc(args.headline_cc or detect_headline_cc(args.workdir),
                                          controllers(cells))
    except AmbiguousHeadlineCc as exc:
        print(f'{args.workdir}: {exc}', file=sys.stderr)
        return 1
    summary = report(cells, collect_gso_control(args.workdir), headline_cc=headline_cc)
    if args.json_out:
        with open(args.json_out, 'w') as handle:
            json.dump(summary, handle, indent=1, sort_keys=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
