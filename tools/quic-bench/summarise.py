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
        'p50_ms': interactive['p50_us'] / 1000.0,
        'p95_ms': interactive['p95_us'] / 1000.0,
        'p99_ms': interactive['p99_us'] / 1000.0,
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
    """Walk the work directory into {cell: {arm: [run, ...]}}."""
    cells = {}
    for name in sorted(os.listdir(workdir)):
        match = CELL_RE.match(name)
        if not match:
            continue
        celldir = os.path.join(workdir, name)
        if not os.path.isdir(celldir):
            continue
        runs = {arm: [] for arm in ARMS}
        for rep in sorted(os.listdir(celldir)):
            casedir = os.path.join(celldir, rep)
            if not os.path.isdir(casedir):
                continue
            for arm in ARMS:
                run = read_run(casedir, arm)
                if run is not None:
                    runs[arm].append(run)
        cells[name] = {'fields': match.groupdict(), 'runs': runs}
    return cells


def aggregate(runs):
    """Median and spread across repeats for one arm of one cell."""
    if not runs:
        return None
    p95 = [run['p95_ms'] for run in runs]
    return {
        'repeats': len(runs),
        'p50_ms': statistics.median(run['p50_ms'] for run in runs),
        'p95_ms': statistics.median(p95),
        'p99_ms': statistics.median(run['p99_ms'] for run in runs),
        'p95_min_ms': min(p95),
        'p95_max_ms': max(p95),
        'p95_spread_ms': max(p95) - min(p95),
        'mbit_per_sec': statistics.median(run['mbit_per_sec'] for run in runs),
        'mbit_min': min(run['mbit_per_sec'] for run in runs),
        'mbit_max': max(run['mbit_per_sec'] for run in runs),
        'connect_ms': statistics.median(run['connect_ms'] for run in runs),
        'samples': statistics.median(run['samples'] for run in runs),
        'timeouts': sum(run['timeouts'] for run in runs),
        'bytes_per_slot': statistics.median(
            [run['bytes_per_slot'] for run in runs if run['bytes_per_slot'] is not None] or [0]
        ),
        'gso': next((run['gso'] for run in runs if run['gso']), None),
        'quic_cc': next((run['quic_cc'] for run in runs if run['quic_cc']), None),
    }


def fmt(value, places=1):
    return '--' if value is None else f'{value:.{places}f}'


def report(cells, controls, out=sys.stdout):
    summary = {}
    ccs = sorted({cell['fields']['cc'] for cell in cells.values()})

    for cc in ccs:
        print(f'\n## Congestion controller: {cc}\n', file=out)
        print('| profile | loss | arm | p50 ms | p95 ms | p99 ms | p95 spread ms | p95 range ms | '
              'Mbit/s | samples/run |', file=out)
        print('|---|---|---|---|---|---|---|---|---|---|', file=out)
        for name, cell in cells.items():
            fields = cell['fields']
            if fields['cc'] != cc:
                continue
            profile = f"{fields['rtt']} ms / {fields['rate']} Mbit"
            for arm in ARMS:
                agg = aggregate(cell['runs'][arm])
                summary.setdefault(name, {})[arm] = agg
                if agg is None:
                    print(f"| {profile} | {fields['loss']}% | {arm} | missing |||||||", file=out)
                    continue
                print(
                    f"| {profile} | {fields['loss']}% | {arm} | {fmt(agg['p50_ms'])} | "
                    f"{fmt(agg['p95_ms'])} | {fmt(agg['p99_ms'])} | {fmt(agg['p95_spread_ms'])} | "
                    f"{fmt(agg['p95_min_ms'])}-{fmt(agg['p95_max_ms'])} | "
                    f"{fmt(agg['mbit_per_sec'], 2)} | {int(agg['samples'])} |",
                    file=out,
                )

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
    print('| cell | tcp p95 ms | quic p95 ms | delta ms | threshold ms | verdict |', file=out)
    print('|---|---|---|---|---|---|', file=out)
    gate = {}
    for name, arms in summary.items():
        tcp, quic = arms.get('tcp'), arms.get('quic')
        if not tcp or not quic:
            continue
        delta = quic['p95_ms'] - tcp['p95_ms']
        threshold = max(tcp['p95_spread_ms'], quic['p95_spread_ms'])
        if delta > threshold:
            verdict = 'quic worse beyond spread'
        elif -delta > threshold:
            verdict = 'quic better beyond spread'
        else:
            verdict = 'tie within spread'
        gate[name] = {'delta_ms': delta, 'threshold_ms': threshold, 'verdict': verdict}
        print(
            f'| {name} | {fmt(tcp["p95_ms"])} | {fmt(quic["p95_ms"])} | {delta:+.1f} | '
            f'{fmt(threshold)} | {verdict} |',
            file=out,
        )

    return {'cells': summary, 'gate': gate,
            'gso_control': {name: run for name, run in controls}}


def main():
    parser = argparse.ArgumentParser(description='Summarise a quic-bench work directory.')
    parser.add_argument('workdir')
    parser.add_argument('--json', dest='json_out', help='also write the summary as JSON')
    args = parser.parse_args()

    cells = collect(args.workdir)
    if not cells:
        print(f'No cells found under {args.workdir}', file=sys.stderr)
        return 1
    summary = report(cells, collect_gso_control(args.workdir))
    if args.json_out:
        with open(args.json_out, 'w') as handle:
            json.dump(summary, handle, indent=1, sort_keys=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
