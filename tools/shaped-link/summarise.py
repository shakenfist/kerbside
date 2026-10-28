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

A second table reports spice-server's ACK window on the display channel,
from the proxy's `kerbside_proxy_ack_window_*` counters, which run-matrix.sh
samples into ackwin.txt alongside ss. Its deltas are taken over the key-press
window alone (the last `elapsed_s` seconds before t1), not the warm-up. It
gives the window spice-server set (20, or 40 if its start-up bandwidth test
judged the link slow), the display messages relayed per second, their mean
size, the client leg's median sRTT, the messages delivered per sRTT against
the 2W+1 that the window allows in flight, the message rate the window would
allow if it were the only limit, how often per second the channel
reached the block threshold, and the share of the window it spent there. The
proxy counts a message when it has read it, after spice-server sent it, so
that share is a lower bound whenever the backend leg holds a backlog. The
last column is the median in-flight count, first as the proxy sees it and
then with that backlog added: the proxy's backend Recv-Q plus
spice-server's Send-Q from the nearest ss snapshot, in mean-sized messages,
which spice-server has counted against the window and the proxy has not yet
read. The second figure is an estimate of spice-server's own count.

The window's ceiling follows from the client acknowledging every W messages:
two batches of W circulate, and each takes a round trip plus the time to
serialise W messages on the link, so at most 2W / (sRTT + W * size / rate)
messages a second get through.

A third table reports what each case cost the host, from the proxy's and
qemu's CPU time and RSS that run-matrix.sh samples into proc.txt: CPU in
cores used over the key-press window (CPU seconds per second), the mean RSS
over that window, and the peak RSS over the whole case, which includes the
quality capture when there was one. Cores and mean RSS are averaged over the
good repeats; the peak is the largest of them. The last column is the peak
of a transcoded display channel's pixmap cache, from the line the proxy logs
when the channel ends ("-" for a relayed case).

A fourth table, printed when run-matrix.sh ran with QUALITY=1 and
quality.sh has scored the screenshots, reports image quality from each
repeat's quality.json: how many repeats' backgrounds matched the reference
exactly while the activity ran (and the most pixels that differed in any),
the mean and lowest SSIM and the lowest PSNR of the frozen frame, and how
many repeats' displays settled before frozen.png was taken. A repeat whose
activity froze before its last key press (a `froze-early` marker) is counted
as failed in every table, since its latency samples did not all see the
activity; one whose ryll surface mirror lagged (`mirror-lagged`) is counted
in the quality table's last column, since its screenshots may be wrong.
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


def parse_ackwin(path):
    """Return [(ts, {series: value})] from an ackwin.txt sampling file."""
    samples = []
    try:
        with open(path) as f:
            for line in f:
                if line.startswith('@ '):
                    samples.append((float(line.split()[1]), {}))
                elif samples and line.startswith('kerbside_proxy_ack_window_'):
                    series, value = line.rsplit(None, 1)
                    samples[-1][1][series] = float(value)
    except OSError:
        pass
    return samples


def ack_series(sample, name, channel='display'):
    """Sum the series of counter `name` on `channel` in one sample."""
    total = 0.0
    for series, value in sample.items():
        if (series.startswith('kerbside_proxy_ack_window_%s{' % name)
                and 'channel="%s"' % channel in series):
            total += value
    return total


def ack_windows(sample, channel='display'):
    """Return the window label values SET_ACK has used on `channel`."""
    found = set()
    for series in sample:
        if (series.startswith('kerbside_proxy_ack_window_set_total{')
                and 'channel="%s"' % channel in series):
            m = re.search(r'window="([^"]+)"', series)
            if m:
                found.add(m.group(1))
    return found


def nearest(series, ts):
    """Return the value in [(ts, value)] sampled nearest to `ts`, or 0."""
    if not series:
        return 0
    return min(series, key=lambda x: abs(x[0] - ts))[1]


def ack_stats(rep_dirs, rate_mbit):
    """ACK-window figures for one case, averaged over its good repeats.

    Each run-matrix.sh case starts its own proxy with one display channel,
    so the display counters belong to that one channel, and its in-flight
    count at each sample is messages less window times credited ACKs.
    """
    rows = []
    windows = set()
    for d in rep_dirs:
        if bad_repeat(d) or os.path.exists(os.path.join(d, 'qemu-died')):
            continue
        try:
            with open(os.path.join(d, 't1')) as f:
                t1 = float(f.read())
            with open(os.path.join(d, 'keydraw.json')) as f:
                ta = t1 - json.load(f)['elapsed_s']
        except (OSError, ValueError, KeyError):
            continue
        samples = [x for x in parse_ackwin(os.path.join(d, 'ackwin.txt'))
                   if ta <= x[0] <= t1]
        if len(samples) < 2:
            continue
        (s0, a), (s1, b) = samples[0], samples[-1]
        dt = s1 - s0
        rep_windows = ack_windows(b)
        windows |= rep_windows
        window = int(next(iter(rep_windows))) if (
            len(rep_windows) == 1 and next(iter(rep_windows)).isdigit()) else None
        msgs = ack_series(b, 'messages_total') - ack_series(a, 'messages_total')
        stalls = ack_series(b, 'stalls_total') - ack_series(a, 'stalls_total')
        stalled = (ack_series(b, 'stalled_seconds_total')
                   - ack_series(a, 'stalled_seconds_total'))
        socks = parse_ss(os.path.join(d, 'ss.txt'), s0, s1)
        client = {k: v for k, v in socks.items() if k[0].endswith(':5900')}
        size = rtt = float('nan')
        if client:
            disp = max(client.values(), key=lambda x: x[-1]['bytes_acked'])
            if len(disp) > 1 and msgs:
                size = (disp[-1]['bytes_acked'] - disp[0]['bytes_acked']) / msgs
            rtt = pct([x['rtt'] for x in disp], 50)
        # Bytes spice-server has sent that the proxy has not yet read: the
        # proxy's backend Recv-Q plus spice-server's own Send-Q.
        backend = {k: v for k, v in socks.items() if k[1].endswith(':5910')}
        qemu = {k: v for k, v in socks.items() if k[0].endswith(':5910')}
        brecv, qsend = [], []
        if backend:
            bdisp = max(backend.values(), key=lambda x: x[-1]['bytes_received'])
            brecv = [(x['ts'], x['recvq']) for x in bdisp]
        if qemu:
            qdisp = max(qemu.values(), key=lambda x: x[-1]['bytes_acked'])
            qsend = [(x['ts'], x['sendq']) for x in qdisp]
        relay, total = [], []
        if window and size > 0:
            for ts, sample in samples:
                seen = (ack_series(sample, 'messages_total')
                        - window * ack_series(sample, 'acks_total'))
                unseen = (nearest(brecv, ts) + nearest(qsend, ts)) / size
                relay.append(seen)
                total.append(seen + unseen)
        rows.append({'rate': msgs / dt, 'stalls': stalls / dt,
                     'stalled': stalled / dt, 'size': size, 'rtt': rtt,
                     'relay50': pct(relay, 50), 'total50': pct(total, 50)})
    if not rows:
        return None

    def mean(key):
        return statistics.mean(r[key] for r in rows)

    out = {k: mean(k) for k in rows[0]}
    out['good'] = len(rows)
    out['windows'] = ','.join(sorted(windows)) or '-'
    numeric = [int(w) for w in windows if w.isdigit()]
    out['limit'] = 2 * numeric[0] + 1 if len(numeric) == 1 else float('nan')
    out['per_rtt'] = out['rate'] * out['rtt'] / 1000
    out['ceiling'] = float('nan')
    if len(numeric) == 1:
        serialise = numeric[0] * out['size'] * 8 / (rate_mbit * 1e6) if rate_mbit else 0
        out['ceiling'] = 2 * numeric[0] / (out['rtt'] / 1000 + serialise)
    return out


def bad_repeat(d):
    """Whether repeat directory `d` failed its setup, or froze too early."""
    return (os.path.exists(os.path.join(d, 'setup-failed'))
            or os.path.exists(os.path.join(d, 'froze-early')))


def keypress_window(d):
    """Return (start, end) of a repeat's key presses, or None."""
    try:
        with open(os.path.join(d, 't1')) as f:
            t1 = float(f.read())
        with open(os.path.join(d, 'keydraw.json')) as f:
            return t1 - json.load(f)['elapsed_s'], t1
    except (OSError, ValueError, KeyError):
        return None


def parse_proc(path):
    """Return (clk_tck, {name: [(ts, cpu_ticks, rss_kib)]}) from proc.txt."""
    clk_tck = 100
    series = collections.defaultdict(list)
    ts = None
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if line.startswith('# clk_tck') and len(parts) == 3:
                    clk_tck = int(parts[2])
                elif line.startswith('@ '):
                    ts = float(parts[1])
                elif ts is not None and len(parts) == 4:
                    series[parts[0]].append((ts, int(parts[1]) + int(parts[2]), int(parts[3])))
    except (OSError, ValueError):
        pass
    return clk_tck, series


PIXMAP_RE = re.compile(r'pixmap_cache_peak_bytes=(\d+)')


def pixmap_peak(path):
    """The largest pixmap cache peak a proxy log reports, or None."""
    peak = None
    try:
        with open(path, errors='replace') as f:
            for line in f:
                m = PIXMAP_RE.search(line)
                if m:
                    peak = max(peak or 0, int(m.group(1)))
    except OSError:
        pass
    return peak


def host_stats(rep_dirs):
    """CPU and memory for one case, over its good repeats, or None."""
    rows = []
    for d in rep_dirs:
        if bad_repeat(d) or os.path.exists(os.path.join(d, 'qemu-died')):
            continue
        window = keypress_window(d)
        clk_tck, series = parse_proc(os.path.join(d, 'proc.txt'))
        if window is None or not series:
            continue
        row = {'pixmap': pixmap_peak(os.path.join(d, 'proxy.log'))}
        for name in ('proxy', 'qemu'):
            samples = series.get(name, [])
            inside = [x for x in samples if window[0] <= x[0] <= window[1]]
            row[name + '_cores'] = float('nan')
            row[name + '_rss_mean'] = float('nan')
            row[name + '_rss_peak'] = max((x[2] for x in samples), default=float('nan'))
            if len(inside) >= 2:
                (t0, c0, _), (t1, c1, _) = inside[0], inside[-1]
                row[name + '_cores'] = (c1 - c0) / clk_tck / (t1 - t0)
                row[name + '_rss_mean'] = statistics.mean(x[2] for x in inside)
        rows.append(row)
    if not rows:
        return None
    out = {'good': len(rows)}
    for key in rows[0]:
        if key == 'pixmap':
            peaks = [r['pixmap'] for r in rows if r['pixmap'] is not None]
            out[key] = max(peaks) if peaks else None
        elif key.endswith('_peak'):
            out[key] = max(r[key] for r in rows)
        else:
            out[key] = statistics.mean(r[key] for r in rows)
    return out


def quality_stats(rep_dirs):
    """Image quality for one case, from its repeats' quality.json, or None."""
    rows = []
    lagged = 0
    for d in rep_dirs:
        if bad_repeat(d) or os.path.exists(os.path.join(d, 'qemu-died')):
            continue
        try:
            with open(os.path.join(d, 'quality.json')) as f:
                q = json.load(f)
        except (OSError, ValueError):
            continue
        try:
            with open(os.path.join(d, 'screenshots.json')) as f:
                q['settled'] = json.load(f).get('settled', False)
        except (OSError, ValueError):
            q['settled'] = False
        if os.path.exists(os.path.join(d, 'mirror-lagged')):
            lagged += 1
        rows.append(q)
    if not rows:
        return None

    def num(v):
        return float('inf') if v == 'inf' else float('nan') if v is None else float(v)

    mids = [r['mid_background'] for r in rows if 'differing_pixels' in r.get('mid_background', {})]
    frozen = [r['frozen'] for r in rows if 'ssim' in r.get('frozen', {})]
    ssims = [num(f['ssim']) for f in frozen]
    return {
        'n': len(rows), 'lagged': lagged,
        'mid_n': len(mids),
        'mid_exact': sum(1 for m in mids if m['exact']),
        'mid_diff': max((m['differing_pixels'] for m in mids), default=float('nan')),
        'ssim_mean': statistics.mean(ssims) if ssims else float('nan'),
        'ssim_min': min(ssims) if ssims else float('nan'),
        'psnr_min': min((num(f['psnr_db']) for f in frozen), default=float('nan')),
        'settled': sum(1 for r in rows if r['settled']),
    }


def case_stats(rep_dirs):
    lat, timeouts, tput, sendq, rtt, cwnd, rmem, rcvbuf = (
        [], 0, [], [], [], [], [], [])
    qsendq = []
    recvq = []
    relayed = []
    good = died = failed = 0
    for d in rep_dirs:
        if bad_repeat(d):
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
            with open(os.path.join(d, 't0')) as f:
                t0 = float(f.read())
            with open(os.path.join(d, 't1')) as f:
                t1 = float(f.read())
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


def cases(root):
    """Yield (profile, activity, config, [repeat dirs]) for every case."""
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
                yield profile, activity, config, [os.path.join(adir, r) for r in sorted(configs[config])]


def main():
    root = sys.argv[1]
    lost = 0
    print('| Link | Activity | Proxy | Repeats good (died, failed) | '
          'n (timeouts) | p50 ms | p95 ms | max ms | '
          'Display Mbit/s ss / metrics | Client Send-Q p50/p95 KiB | '
          'Client sRTT ms | cwnd | Backend Recv-Q p50/max KiB | '
          'Backend skmem max KiB (rcvbuf) | qemu Send-Q p50/p95 KiB |')
    print('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    for profile, activity, config, rep_dirs in cases(root):
        stats = case_stats(rep_dirs)
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
    ack_rows = []
    for profile, activity, config, rep_dirs in cases(root):
        m = re.search(r'-(\d+)mbit$', profile)
        stats = ack_stats(rep_dirs, int(m.group(1)) if m else 0)
        if stats:
            ack_rows.append((profile, activity, config, stats))
    if ack_rows:
        print()
        print('| Link | Activity | Proxy | Repeats | Window | Display msgs/s | '
              'Mean msg KiB | Client sRTT ms | Msgs per sRTT | 2W+1 | Window ceiling msgs/s | '
              'Stalls/s | Time at threshold | In flight p50: proxy / with backlog |')
        print('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
        for profile, activity, config, a in ack_rows:
            print(f'| {profile} | {activity} | {config} | {a["good"]} | '
                  f'{a["windows"]} | {a["rate"]:.0f} | '
                  f'{a["size"] / 1024:.1f} | {a["rtt"]:.0f} | '
                  f'{a["per_rtt"]:.0f} | {a["limit"]:.0f} | {a["ceiling"]:.0f} | '
                  f'{a["stalls"]:.1f} | {a["stalled"] * 100:.0f}% | '
                  f'{a["relay50"]:.0f} / {a["total50"]:.0f} |')
    host_rows, quality_rows = [], []
    for profile, activity, config, rep_dirs in cases(root):
        stats = host_stats(rep_dirs)
        if stats:
            host_rows.append((profile, activity, config, stats))
        stats = quality_stats(rep_dirs)
        if stats:
            quality_rows.append((profile, activity, config, stats))
    if host_rows:
        print()
        print('| Link | Activity | Proxy | Repeats | Proxy cores | Proxy RSS mean / peak MiB | '
              'qemu cores | qemu RSS mean / peak MiB | Pixmap cache peak MiB |')
        print('|---|---|---|---|---|---|---|---|---|')
        for profile, activity, config, h in host_rows:
            pixmap = '-' if h['pixmap'] is None else f'{h["pixmap"] / 1048576:.1f}'
            print(f'| {profile} | {activity} | {config} | {h["good"]} | '
                  f'{h["proxy_cores"]:.3f} | '
                  f'{h["proxy_rss_mean"] / 1024:.0f} / {h["proxy_rss_peak"] / 1024:.0f} | '
                  f'{h["qemu_cores"]:.3f} | '
                  f'{h["qemu_rss_mean"] / 1024:.0f} / {h["qemu_rss_peak"] / 1024:.0f} | {pixmap} |')
    if quality_rows:
        print()
        print('| Link | Activity | Proxy | Repeats | Background exact while animating (most px differing) | '
              'Frozen SSIM mean / min | Frozen PSNR min dB | Settled (mirror lagged) |')
        print('|---|---|---|---|---|---|---|---|')
        for profile, activity, config, q in quality_rows:
            print(f'| {profile} | {activity} | {config} | {q["n"]} | '
                  f'{q["mid_exact"]} of {q["mid_n"]} ({q["mid_diff"]}) | '
                  f'{q["ssim_mean"]:.4f} / {q["ssim_min"]:.4f} | {q["psnr_min"]:.1f} | '
                  f'{q["settled"]} of {q["n"]} ({q["lagged"]}) |')
    if lost:
        print(f'WARNING: {lost} repeat(s) were lost to a qemu exit or a '
              f'setup failure and are excluded; see the Repeats column',
              file=sys.stderr)


if __name__ == '__main__':
    main()
