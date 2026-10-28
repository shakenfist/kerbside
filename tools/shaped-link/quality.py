#!/usr/bin/env python3
"""Score the shaped-link rig's screenshots against a lossless reference.

Usage:
  quality.py cases --reference REF.png PATH...
  quality.py pair --reference REF.png IMAGE.png [--exclude L,T,R,B]...

It needs numpy and Pillow, so run it through quality.sh, which keeps them
in a venv of their own. summarise.py, which has to run anywhere, only reads
what this writes.

`cases` walks each PATH (a run-matrix.sh WORKDIR, or one case directory)
for case directories holding the screenshots run-matrix.sh takes with
QUALITY=1, and writes quality.json into each. Two comparisons are made,
both against REF.png, which should be the frozen.png of an unshaped,
relayed case with streaming off, whose draws are all lossless:

- mid.png, taken while the activity runs, is compared over the static
  background only: everything outside the activity rectangle. The
  background never changes, so it should match the reference exactly;
  anything less means lossy compression, or a lossy draw that covered
  more than the activity, has spread onto the text.
- frozen.png, taken after the activity has frozen and the display has
  settled, is compared over the whole frame, by SSIM and PSNR. A
  transcoder that refreshes lossy areas losslessly should converge on the
  reference exactly; a relay that sent JPEG keeps it.

The guest's key box is left out of every comparison, because its colour
depends on how many key presses reached the guest. The box and the
activity rectangle are read from the guest's KEYDRAW START line in the
case's serial.log.

SSIM is Wang et al.'s (2004) on luma (BT.601), with an 11x11 Gaussian
window of sigma 1.5, K1 0.01 and K2 0.03, over windows that lie wholly
inside the frame and touch no excluded pixel. PSNR is over the R, G and B
of the included pixels; identical images have an infinite PSNR, written
to JSON as the string "inf".

`pair` prints the whole-frame comparison of two PNGs as JSON.
"""

# audit-allow-print: this is a measurement CLI -- its JSON on stdout is the
# output (see quality.sh and run-matrix.sh).

import argparse
import json
import math
import os
import re
import sys

import numpy as np
from PIL import Image


WINDOW = 11
SIGMA = 1.5
K1 = 0.01
K2 = 0.03
PEAK = 255.0
START_RE = re.compile(r'KEYDRAW START (\d+)x(\d+) box (\d+)x(\d+)@(\d+),(\d+) '
                      r'activity (\d+)x(\d+)@(\d+),(\d+)')


def load(path):
    """Return a PNG as an H x W x 3 uint8 array."""
    with Image.open(path) as img:
        return np.asarray(img.convert('RGB'), dtype=np.uint8)


def luma(rgb):
    """BT.601 luma of an RGB array, as float64."""
    rgb = rgb.astype(np.float64)
    return 0.299 * rgb[..., 0] + 0.587 * rgb[..., 1] + 0.114 * rgb[..., 2]


def gaussian_kernel(size=WINDOW, sigma=SIGMA):
    x = np.arange(size, dtype=np.float64) - (size - 1) / 2
    k = np.exp(-x ** 2 / (2 * sigma ** 2))
    return k / k.sum()


def filter_valid(img, kernel):
    """Separable correlation of a 2-D array with `kernel`, 'valid' mode.

    The output is smaller than the input by len(kernel) - 1 in each
    dimension: each value is a window lying wholly inside the image.
    """
    n = len(kernel)
    h, w = img.shape
    rows = sum(kernel[i] * img[i:h - n + 1 + i, :] for i in range(n))
    return sum(kernel[i] * rows[:, i:w - n + 1 + i] for i in range(n))


def mask_of(shape, excludes):
    """A boolean H x W array, True for the pixels to compare."""
    mask = np.ones(shape[:2], dtype=bool)
    for left, top, right, bottom in excludes:
        mask[max(top, 0):max(bottom, 0), max(left, 0):max(right, 0)] = False
    return mask


def ssim(a, b, mask=None):
    """Mean SSIM of two RGB arrays over the windows `mask` wholly includes.

    Returns None when no window qualifies.
    """
    x, y = luma(a), luma(b)
    if min(x.shape) < WINDOW:
        return None
    k = gaussian_kernel()
    mu_x, mu_y = filter_valid(x, k), filter_valid(y, k)
    var_x = filter_valid(x * x, k) - mu_x * mu_x
    var_y = filter_valid(y * y, k) - mu_y * mu_y
    cov = filter_valid(x * y, k) - mu_x * mu_y
    c1, c2 = (K1 * PEAK) ** 2, (K2 * PEAK) ** 2
    smap = (((2 * mu_x * mu_y + c1) * (2 * cov + c2))
            / ((mu_x * mu_x + mu_y * mu_y + c1) * (var_x + var_y + c2)))
    if mask is not None:
        # A window counts only if it contains no excluded pixel.
        excluded = filter_valid((~mask).astype(np.float64), np.ones(WINDOW))
        smap = smap[excluded == 0]
    if smap.size == 0:
        return None
    return float(smap.mean())


def psnr(a, b, mask=None):
    """PSNR in dB of two RGB arrays over the pixels `mask` includes."""
    diff = a.astype(np.float64) - b.astype(np.float64)
    if mask is not None:
        diff = diff[mask]
    if diff.size == 0:
        return None
    mse = float(np.mean(diff * diff))
    if mse == 0:
        return math.inf
    return 10 * math.log10(PEAK * PEAK / mse)


def compare(reference, image, excludes=(), with_ssim=True):
    """Compare two RGB arrays over everything outside `excludes`."""
    if reference.shape != image.shape:
        return {'error': f'size {image.shape[1]}x{image.shape[0]} does not match the reference '
                         f'{reference.shape[1]}x{reference.shape[0]}'}
    mask = mask_of(reference.shape, excludes)
    differs = np.any(reference != image, axis=2) & mask
    out = {
        'pixels': int(mask.sum()),
        'differing_pixels': int(differs.sum()),
        'exact': not bool(differs.any()),
        'psnr_db': psnr(reference, image, mask),
    }
    if with_ssim:
        out['ssim'] = ssim(reference, image, mask)
    return out


def regions(serial_path):
    """Return (key box, activity rectangle) as (L, T, R, B), from serial.log."""
    with open(serial_path, errors='replace') as f:
        for line in f:
            m = START_RE.search(line)
            if m:
                bw, bh, bx, by, aw, ah, ax, ay = (int(v) for v in m.groups()[2:])
                return (bx, by, bx + bw, by + bh), (ax, ay, ax + aw, ay + ah)
    raise ValueError(f'no KEYDRAW START line in {serial_path}')


def score_case(case_dir, reference):
    """Score one case directory's screenshots; return the quality.json dict."""
    box, activity = regions(os.path.join(case_dir, 'serial.log'))
    out = {'key_box': list(box), 'activity': list(activity)}
    mid = os.path.join(case_dir, 'mid.png')
    if os.path.exists(mid):
        out['mid_background'] = compare(reference, load(mid), [box, activity], with_ssim=False)
    frozen = os.path.join(case_dir, 'frozen.png')
    if os.path.exists(frozen):
        image = load(frozen)
        out['frozen'] = compare(reference, image, [box])
        out['frozen_background'] = compare(reference, image, [box, activity], with_ssim=False)
    return out


def case_dirs(paths):
    for path in paths:
        for root, _, files in os.walk(path):
            if 'serial.log' in files and ('mid.png' in files or 'frozen.png' in files):
                yield root


def to_json(value):
    """JSON text for `value`, with infinite floats as the string "inf"."""
    def fix(v):
        if isinstance(v, float) and math.isinf(v):
            return 'inf'
        if isinstance(v, dict):
            return {k: fix(x) for k, x in v.items()}
        if isinstance(v, list):
            return [fix(x) for x in v]
        return v
    return json.dumps(fix(value), indent=2, sort_keys=True)


def rect(text):
    parts = [int(v) for v in text.split(',')]
    if len(parts) != 4:
        raise argparse.ArgumentTypeError('expected L,T,R,B')
    return tuple(parts)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = p.add_subparsers(dest='command', required=True)
    pc = sub.add_parser('cases', help='score every case under the given paths')
    pc.add_argument('--reference', required=True, help='the reference PNG')
    pc.add_argument('paths', nargs='+')
    pp = sub.add_parser('pair', help='compare two PNGs')
    pp.add_argument('--reference', required=True)
    pp.add_argument('image')
    pp.add_argument('--exclude', type=rect, action='append', default=[],
                    help='a rectangle L,T,R,B to leave out; may be repeated')
    args = p.parse_args(argv)

    reference = load(args.reference)
    if args.command == 'pair':
        print(to_json(compare(reference, load(args.image), args.exclude)))
        return 0
    failed = 0
    for case in sorted(case_dirs(args.paths)):
        try:
            result = score_case(case, reference)
        except (OSError, ValueError) as e:
            print(f'{case}: {e}', file=sys.stderr)
            failed += 1
            continue
        result['reference'] = os.path.abspath(args.reference)
        with open(os.path.join(case, 'quality.json'), 'w') as f:
            f.write(to_json(result) + '\n')
        frozen = result.get('frozen', {})
        print(f'{case}: frozen ssim {frozen.get("ssim")} psnr {frozen.get("psnr_db")}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
