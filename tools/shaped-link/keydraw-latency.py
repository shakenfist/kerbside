#!/usr/bin/env python3
"""Measure keypress-to-draw latency of the keydraw guest's key box.

Drives ryll's control socket like loadtests/latency/orchestrator.py, but
pairs each key press with the first `surface_drawn` event whose rect
intersects the guest's key box, rather than with the first draw of any
kind. With screen activity running, the first draw after a key press is
almost always an activity frame, so the unfiltered metric measures the
activity's frame interval rather than the key's latency.

The `rect` field of `surface_drawn` is not in the ryll control socket
protocol (v1.2); it comes from ryll-surface-drawn-rect.patch, which
build-ryll.sh applies. This script refuses to run without it: an
unmeasured probe press after warmup must produce a key-box draw.

One key press is outstanding at a time: press, wait for its draw (or
time out), then pause a random interval so presses do not phase-lock
with qemu's 30 ms display refresh timer.

Outputs, under --output-prefix:
  <prefix>.csv   one latency per line, in seconds (the loadtest format)
  <prefix>.json  counts, timeouts, dropped events, draw event totals
"""

# audit-allow-print: this is a measurement CLI -- run-matrix.sh captures
# its progress lines and JSON summary on stdout into keydraw.log.

import argparse
import json
import random
import socket
import sys
import threading
import time


def _parse_args():
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--socket', required=True, help='ryll control socket')
    p.add_argument('--output-prefix', required=True)
    p.add_argument('--samples', type=int, default=60)
    p.add_argument('--box', default='16,16,112,112',
                   help='key box as left,top,right,bottom')
    p.add_argument('--interval-min', type=float, default=0.4)
    p.add_argument('--interval-max', type=float, default=1.2)
    p.add_argument('--timeout', type=float, default=15.0,
                   help='seconds to wait for one key draw')
    p.add_argument('--warmup', type=float, default=5.0,
                   help='seconds of activity before the first press')
    p.add_argument('--scancode', type=lambda s: int(s, 0), default=0x39)
    return p.parse_args()


class Client:
    def __init__(self, path, box):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.rfile = self.sock.makefile('rb', buffering=1 << 20)
        self.box = box
        self.next_id = 0
        self.send_lock = threading.Lock()
        self.cond = threading.Condition()
        self.box_draws = []          # wallclock_us of key-box draws
        self.draw_events = 0
        self.draw_pixels = 0
        self.dropped = 0
        self.missing_rect = 0
        self.eof = False

    def send(self, method, params):
        with self.send_lock:
            self.next_id += 1
            line = json.dumps({'id': self.next_id, 'method': method,
                               'params': params}) + '\n'
            self.sock.sendall(line.encode())
            return self.next_id

    def request(self, method, params):
        req = self.send(method, params)
        while True:
            msg = json.loads(self.rfile.readline())
            if msg.get('id') == req:
                return msg

    def _intersects(self, r):
        bl, bt, br, bb = self.box
        return r[0] < br and r[2] > bl and r[1] < bb and r[3] > bt

    def reader(self):
        for raw in self.rfile:
            msg = json.loads(raw)
            ev = msg.get('event')
            if ev == 'surface_drawn':
                data = msg['data']
                rect = data.get('rect')
                if rect is None:
                    self.missing_rect += 1
                    continue
                self.draw_events += 1
                self.draw_pixels += (rect[2] - rect[0]) * (rect[3] - rect[1])
                if data.get('surface_id') == 0 and self._intersects(rect):
                    with self.cond:
                        self.box_draws.append(data['wallclock_us'])
                        self.cond.notify_all()
            elif ev == 'dropped':
                self.dropped += msg.get('data', {}).get('count', 1)
        with self.cond:
            self.eof = True
            self.cond.notify_all()

    def wait_box_draw_after(self, t_us, timeout):
        deadline = time.monotonic() + timeout
        with self.cond:
            while True:
                for ts in self.box_draws:
                    if ts >= t_us:
                        return ts
                left = deadline - time.monotonic()
                if left <= 0 or self.eof:
                    return None
                self.cond.wait(left)


def press(c, scancode):
    """Press and release a key; return the press time in microseconds."""
    press_us = int(time.time() * 1_000_000)
    c.send('send_key', {'scancode': scancode, 'state': 'down'})
    time.sleep(0.05)
    c.send('send_key', {'scancode': scancode, 'state': 'up'})
    return press_us


def main():
    args = _parse_args()
    box = tuple(int(v) for v in args.box.split(','))
    c = Client(args.socket, box)

    resp = c.request('hello', {'client_name': 'kerbside-shaped-link',
                               'protocol_version': '1.1'})
    if not resp.get('ok'):
        sys.exit(f'hello failed: {resp}')
    resp = c.request('subscribe', {'events': ['surface_drawn', 'dropped']})
    if 'surface_drawn' not in resp.get('result', {}).get('subscribed', []):
        sys.exit(f'surface_drawn subscription refused: {resp}')
    threading.Thread(target=c.reader, daemon=True).start()

    time.sleep(args.warmup)
    # Probe with one unmeasured press: its key-box draw is the only event
    # guaranteed to arrive whatever the activity, so it is what proves the
    # rect patch is present (an idle guest draws nothing during warmup).
    probe_us = press(c, args.scancode)
    if c.wait_box_draw_after(probe_us, args.timeout) is None:
        if c.missing_rect:
            sys.exit('surface_drawn has no rect field: ryll lacks '
                     'ryll-surface-drawn-rect.patch (see build-ryll.sh)')
        sys.exit(f'the probe key press drew nothing in the key box within '
                 f'{args.timeout:.0f}s; is the keydraw guest running?')
    time.sleep(random.uniform(args.interval_min, args.interval_max))

    samples = []
    timeouts = 0
    ev0, px0 = c.draw_events, c.draw_pixels
    t_start = time.monotonic()
    while len(samples) < args.samples and not c.eof:
        with c.cond:
            c.box_draws.clear()
        press_us = press(c, args.scancode)
        drawn = c.wait_box_draw_after(press_us, args.timeout)
        if drawn is None:
            timeouts += 1
            print(f'[keydraw] press {len(samples) + timeouts}: timeout',
                  file=sys.stderr)
            if timeouts > max(5, args.samples // 4):
                break
            # Let a late draw land before the next press can claim it.
            time.sleep(args.timeout)
        else:
            samples.append((drawn - press_us) / 1e6)
        time.sleep(random.uniform(args.interval_min, args.interval_max))
    elapsed = time.monotonic() - t_start

    with open(args.output_prefix + '.csv', 'w') as f:
        for s in samples:
            f.write(f'{s:.6f}\n')
    summary = {
        'samples': len(samples),
        'timeouts': timeouts,
        'dropped_events': c.dropped,
        'draw_events': c.draw_events - ev0,
        'draw_megapixels': (c.draw_pixels - px0) / 1e6,
        'elapsed_s': elapsed,
    }
    with open(args.output_prefix + '.json', 'w') as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
