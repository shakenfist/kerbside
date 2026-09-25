#!/usr/bin/env python3
"""Summarise a run-matrix.sh results directory as markdown tables.

Usage: summarise.py WORKDIR

For each case (profile/activity/config), pools the latency samples from
every good repeat and reports p50/p95/max, the sample and timeout
counts, and how many repeats were good, lost to a qemu exit (a
`qemu-died` marker from run-matrix.sh) or failed (a `setup-failed`
marker, or files that cannot be read). Only good repeats are pooled.

It reports the display channel's delivered throughput twice: from the
client-leg socket's `bytes_acked` in the `ss` snapshots, and from the
proxy's own `/metrics` relay counter, which should agree. From the `ss`
snapshots taken during the measurement window it reports, for the
proxy's client-leg display socket, the median and 95th percentile
Send-Q (bytes written but not yet acknowledged: in flight plus not yet
sent), its median smoothed RTT and congestion window. For the proxy's
backend-leg display socket it reports the median and maximum Recv-Q
(payload bytes spice-server sent that the proxy has not yet read) and,
separately, the maximum kernel memory charged to that receive queue
(`skmem` `r`, which adds per-skb overhead to the payload) against the
receive buffer size. Last is spice-server's own Send-Q on that
connection.
"""

# audit-allow-print: this is a reporting CLI -- its markdown tables on
# stdout are the output (see run-matrix.sh).

import collections
import json
import os
import re
import statistics
import sys


def pct(values, p):
    if not values:
        return float('nan')
    values = sorted(values)
    k = (len(values) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def parse_ss(path, t0, t1):
    """Return {sock_key: [snapshot dicts]} for snapshots within [t0, t1]."""
    socks = collections.defaultdict(list)
    ts = None
    head = None
    with open(path) as f:
        for line in f:
            if line.startswith('@ '):
                ts = float(line.split()[1])
                continue
            if ts is None or ts < t0 or ts > t1:
                continue
            if not line.startswith('\t') and not line.startswith(' '):
                parts = line.split()
                if len(parts) >= 4:
                    head = (int(parts[0]), int(parts[1]), parts[2], parts[3])
                continue
            if head is None:
                continue
            info = {'ts': ts, 'recvq': head[0], 'sendq': head[1]}
            for key in ('bytes_acked', 'bytes_received', 'cwnd'):
                m = re.search(r'\b%s:(\d+)' % key, line)
                info[key] = int(m.group(1)) if m else 0
            m = re.search(r'\brtt:([\d.]+)/', line)
            info['rtt'] = float(m.group(1)) if m else 0.0
            m = re.search(r'skmem:\(r(\d+),rb(\d+),t\d+,tb(\d+),f\d+,w(\d+)',
                          line)
            if m:
                info.update(rmem=int(m.group(1)), rcvbuf=int(m.group(2)),
                            sndbuf=int(m.group(3)), wqueued=int(m.group(4)))
            socks[(head[2], head[3])].append(info)
            head = None
    return socks


def metric(path, direction):
    """Return the relay counter from a /metrics scrape, or None if unknown.

    A labelled counter has no series until its first increment, so a
    successful scrape without one means zero bytes (the usual state at t0,
    before the display channel has relayed a frame). run-matrix.sh also
    tolerates a failed scrape, which leaves an empty file: that is unknown,
    not zero, so it returns None.
    """
    scraped = False
    try:
        with open(path) as f:
            for line in f:
                if line.startswith('kerbside_proxy_'):
                    scraped = True
                if (line.startswith('kerbside_proxy_bytes_relayed_total{')
                        and direction in line):
                    return int(line.split()[-1])
    except OSError:
        pass
    return 0 if scraped else None


def case_stats(rep_dirs):
    lat, timeouts, tput, sendq, rtt, cwnd, rmem, rcvbuf = (
        [], 0, [], [], [], [], [], [])
    qsendq = []
    recvq = []
    relayed = []
    good = died = failed = 0
    for d in rep_dirs:
        if os.path.exists(os.path.join(d, 'setup-failed')):
            failed += 1
            continue
        if os.path.exists(os.path.join(d, 'qemu-died')):
            died += 1
            continue
        try:
            with open(os.path.join(d, 'keydraw.csv')) as f:
                lat += [float(x) for x in f if x.strip()]
            with open(os.path.join(d, 'keydraw.json')) as f:
                timeouts += json.load(f)['timeouts']
            t0 = float(open(os.path.join(d, 't0')).read())
            t1 = float(open(os.path.join(d, 't1')).read())
        except (OSError, ValueError, KeyError):
            failed += 1
            continue
        good += 1
        m0 = metric(os.path.join(d, 'metrics-0.txt'), 'server_to_client')
        m1 = metric(os.path.join(d, 'metrics-1.txt'), 'server_to_client')
        if m0 is not None and m1 is not None:
            relayed.append((m1 - m0) * 8 / (t1 - t0) / 1e6)
        socks = parse_ss(os.path.join(d, 'ss.txt'), t0, t1)
        client = {k: v for k, v in socks.items() if k[0].endswith(':5900')}
        backend = {k: v for k, v in socks.items() if k[1].endswith(':5910')}
        qemu = {k: v for k, v in socks.items() if k[0].endswith(':5910')}
        if client:
            disp = max(client.values(), key=lambda s: s[-1]['bytes_acked'])
            if len(disp) > 1:
                tput.append((disp[-1]['bytes_acked'] - disp[0]['bytes_acked'])
                            * 8 / (disp[-1]['ts'] - disp[0]['ts']) / 1e6)
            sendq += [s['sendq'] for s in disp]
            rtt += [s['rtt'] for s in disp]
            cwnd += [s['cwnd'] for s in disp]
        if backend:
            bdisp = max(backend.values(),
                        key=lambda s: s[-1]['bytes_received'])
            recvq += [s['recvq'] for s in bdisp]
            rmem += [s.get('rmem', 0) for s in bdisp]
            rcvbuf += [s.get('rcvbuf', 0) for s in bdisp]
        if qemu:
            qdisp = max(qemu.values(), key=lambda s: s[-1]['bytes_acked'])
            qsendq += [s['sendq'] for s in qdisp]
    return {
        'n': len(lat), 'timeouts': timeouts,
        'good': good, 'died': died, 'failed': failed,
        'p50': pct(lat, 50) * 1000, 'p95': pct(lat, 95) * 1000,
        'max': max(lat) * 1000 if lat else float('nan'),
        'tput': statistics.mean(tput) if tput else float('nan'),
        'relayed': statistics.mean(relayed) if relayed else float('nan'),
        'sendq50': pct(sendq, 50) / 1024, 'sendq95': pct(sendq, 95) / 1024,
        'rtt50': pct(rtt, 50), 'cwnd50': pct(cwnd, 50),
        'recvq50': pct(recvq, 50) / 1024,
        'recvqmax': max(recvq) / 1024 if recvq else float('nan'),
        'rmemmax': max(rmem) / 1024 if rmem else float('nan'),
        'rcvbuf': max(rcvbuf) / 1024 if rcvbuf else float('nan'),
        'qsendq50': pct(qsendq, 50) / 1024, 'qsendq95': pct(qsendq, 95) / 1024,
    }


def main():
    root = sys.argv[1]
    lost = 0
    print('| Link | Activity | Proxy | Repeats good (died, failed) | '
          'n (timeouts) | p50 ms | p95 ms | max ms | '
          'Display Mbit/s ss / metrics | Client Send-Q p50/p95 KiB | '
          'Client sRTT ms | cwnd | Backend Recv-Q p50/max KiB | '
          'Backend skmem max KiB (rcvbuf) | qemu Send-Q p50/p95 KiB |')
    print('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    for profile in sorted(os.listdir(root)):
        pdir = os.path.join(root, profile)
        if not os.path.isdir(pdir) or profile == 'tls':
            continue
        for activity in sorted(os.listdir(pdir)):
            adir = os.path.join(pdir, activity)
            configs = collections.defaultdict(list)
            for rep in os.listdir(adir):
                configs[rep.rsplit('-r', 1)[0]].append(rep)
            for config in sorted(configs):
                stats = case_stats(
                    [os.path.join(adir, r) for r in sorted(configs[config])])
                lost += stats['died'] + stats['failed']
                print(f'| {profile} | {activity} | {config} | '
                      f'{stats["good"]} ({stats["died"]}, '
                      f'{stats["failed"]}) | '
                      f'{stats["n"]} ({stats["timeouts"]}) | '
                      f'{stats["p50"]:.0f} | {stats["p95"]:.0f} | '
                      f'{stats["max"]:.0f} | {stats["tput"]:.1f} / '
                      f'{stats["relayed"]:.1f} | '
                      f'{stats["sendq50"]:.0f}/{stats["sendq95"]:.0f} | '
                      f'{stats["rtt50"]:.0f} | {stats["cwnd50"]:.0f} | '
                      f'{stats["recvq50"]:.0f}/{stats["recvqmax"]:.0f} | '
                      f'{stats["rmemmax"]:.0f} ({stats["rcvbuf"]:.0f}) | '
                      f'{stats["qsendq50"]:.0f}/{stats["qsendq95"]:.0f} |')
    if lost:
        print(f'WARNING: {lost} repeat(s) were lost to a qemu exit or a '
              f'setup failure and are excluded; see the Repeats column',
              file=sys.stderr)


if __name__ == '__main__':
    main()
