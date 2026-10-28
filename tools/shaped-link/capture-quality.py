#!/usr/bin/env python3
"""Take the shaped-link rig's quality screenshots through ryll's control socket.

run-matrix.sh runs this with QUALITY=1, after keydraw-latency.py has taken
every latency sample, so the latency samples see the activity running and
only these screenshots see it frozen:

1. mid.png, at once, while the activity is still running. Only its static
   background is compared with the reference.
2. Press F12, which makes the keydraw guest draw its final frame (kd.frames)
   and stop. With --wait-frozen, wait for the guest's KEYDRAW FROZEN line on
   the serial console.
3. Wait --settle-min seconds, which must be longer than the transcoder's
   lossless delay, then take a screenshot every --stable seconds until two
   in a row are identical and the proxy's client-leg sockets have nothing
   unacknowledged at both, or --settle-max seconds have passed since the
   freeze. The last one is frozen.png.

ryll's `screenshot` verb returns a lossless PNG of the surface the client
holds. Timings and whether the display settled go to screenshots.json.
quality.py scores the PNGs.
"""

# audit-allow-print: this is a measurement CLI -- run-matrix.sh captures its
# progress lines on stdout into quality-capture.log.

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import time


def _parse_args():
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--socket', required=True, help='ryll control socket')
    p.add_argument('--out-dir', required=True)
    p.add_argument('--serial', required=True, help="the guest's serial log")
    p.add_argument('--wait-frozen', action='store_true',
                   help='wait for the guest to report its activity frozen')
    p.add_argument('--frozen-timeout', type=float, default=30.0)
    p.add_argument('--settle-min', type=float, default=2.0)
    p.add_argument('--settle-max', type=float, default=60.0)
    p.add_argument('--stable', type=float, default=1.0)
    p.add_argument('--client-port', type=int, default=5900,
                   help="the proxy's client-facing port, whose Send-Q must drain")
    p.add_argument('--freeze-scancode', type=lambda s: int(s, 0), default=0x58,
                   help='the scancode that freezes the activity (F12)')
    return p.parse_args()


class Control:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.rfile = self.sock.makefile('rb', buffering=1 << 20)
        self.next_id = 0

    def request(self, method, params):
        self.next_id += 1
        line = json.dumps({'id': self.next_id, 'method': method, 'params': params}) + '\n'
        self.sock.sendall(line.encode())
        while True:
            raw = self.rfile.readline()
            if not raw:
                raise RuntimeError('the control socket closed')
            msg = json.loads(raw)
            if msg.get('id') == self.next_id:
                return msg

    def screenshot(self):
        resp = self.request('screenshot', {'format': 'png'})
        if not resp.get('ok'):
            raise RuntimeError(f'screenshot failed: {resp}')
        return base64.b64decode(resp['result']['data_base64'])

    def press(self, scancode):
        self.request('send_key', {'scancode': scancode, 'state': 'down'})
        time.sleep(0.05)
        self.request('send_key', {'scancode': scancode, 'state': 'up'})


def serial_has(path, text):
    try:
        with open(path, errors='replace') as f:
            return text in f.read()
    except OSError:
        return False


def client_sendq(port):
    """Bytes the proxy has written to its clients that are not yet acknowledged."""
    out = subprocess.run(['ss', '-tnH', 'state', 'established', f'( sport = :{port} )'],
                         capture_output=True, text=True, check=False).stdout
    total = 0
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            total += int(parts[1])
    return total


def main():
    args = _parse_args()
    c = Control(args.socket)
    resp = c.request('hello', {'client_name': 'kerbside-shaped-link-quality',
                               'protocol_version': '1.1'})
    if not resp.get('ok'):
        sys.exit(f'hello failed: {resp}')
    record = {}

    record['mid_ts'] = time.time()
    with open(os.path.join(args.out_dir, 'mid.png'), 'wb') as f:
        f.write(c.screenshot())

    record['freeze_key_ts'] = time.time()
    c.press(args.freeze_scancode)
    frozen_at = time.time()
    if args.wait_frozen:
        deadline = time.monotonic() + args.frozen_timeout
        while not serial_has(args.serial, 'KEYDRAW FROZEN'):
            if time.monotonic() > deadline:
                sys.exit(f'the guest did not report its activity frozen within {args.frozen_timeout:.0f}s')
            time.sleep(0.1)
        frozen_at = time.time()
        record['frozen_ts'] = frozen_at

    time.sleep(args.settle_min)
    prev, prev_q = None, None
    settled = False
    while True:
        shot = c.screenshot()
        sendq = client_sendq(args.client_port)
        if shot == prev and sendq == 0 and prev_q == 0:
            settled = True
            break
        if time.time() - frozen_at > args.settle_max:
            break
        prev, prev_q = shot, sendq
        time.sleep(args.stable)
    record['frozen_shot_ts'] = time.time()
    record['settled'] = settled
    record['settle_s'] = record['frozen_shot_ts'] - frozen_at
    with open(os.path.join(args.out_dir, 'frozen.png'), 'wb') as f:
        f.write(shot)
    with open(os.path.join(args.out_dir, 'screenshots.json'), 'w') as f:
        json.dump(record, f, indent=2)
    print(json.dumps(record))
    if not settled:
        print(f'the display had not settled {args.settle_max:.0f}s after the freeze', file=sys.stderr)


if __name__ == '__main__':
    main()
