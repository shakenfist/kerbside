"""Tests for quality.py. Run with `quality.sh test`, which supplies numpy and Pillow."""

import math
import os
import sys
import tempfile
import unittest

import numpy as np
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import quality  # noqa: E402


def textured(h=64, w=80, seed=7):
    """A deterministic image with texture everywhere, like the guest's text."""
    rng = np.random.default_rng(seed)
    return rng.integers(0, 256, size=(h, w, 3), dtype=np.uint8)


def ssim_by_loops(a, b):
    """SSIM computed window by window, to check the vectorised version."""
    x, y = quality.luma(a), quality.luma(b)
    k = quality.gaussian_kernel()
    w2 = np.outer(k, k)
    n = quality.WINDOW
    c1, c2 = (quality.K1 * 255) ** 2, (quality.K2 * 255) ** 2
    values = []
    for top in range(x.shape[0] - n + 1):
        for left in range(x.shape[1] - n + 1):
            wx, wy = x[top:top + n, left:left + n], y[top:top + n, left:left + n]
            mx, my = (w2 * wx).sum(), (w2 * wy).sum()
            vx = (w2 * (wx - mx) ** 2).sum()
            vy = (w2 * (wy - my) ** 2).sum()
            cov = (w2 * (wx - mx) * (wy - my)).sum()
            values.append(((2 * mx * my + c1) * (2 * cov + c2))
                          / ((mx * mx + my * my + c1) * (vx + vy + c2)))
    return float(np.mean(values))


class QualityTest(unittest.TestCase):
    def test_identical_images_score_perfectly(self):
        a = textured()
        result = quality.compare(a, a.copy())
        self.assertEqual(result['ssim'], 1.0)
        self.assertTrue(math.isinf(result['psnr_db']))
        self.assertTrue(result['exact'])
        self.assertEqual(result['differing_pixels'], 0)

    def test_a_known_perturbation_scores_lower(self):
        a = textured()
        b = a.astype(np.int16)
        # Brighten a 10x20 block by 10 in every channel, staying in range.
        b[20:30, 30:50] = np.clip(b[20:30, 30:50] + 10, 0, 255)
        b = b.astype(np.uint8)
        diff = b.astype(np.float64) - a
        expected_psnr = 10 * math.log10(255 ** 2 / np.mean(diff ** 2))

        result = quality.compare(a, b)
        self.assertFalse(result['exact'])
        self.assertEqual(result['differing_pixels'], int(np.any(a != b, axis=2).sum()))
        self.assertAlmostEqual(result['psnr_db'], expected_psnr, places=9)
        self.assertLess(result['ssim'], 1.0)
        self.assertAlmostEqual(result['ssim'], ssim_by_loops(a, b), places=9)

    def test_a_perturbation_inside_an_exclusion_is_ignored(self):
        a = textured()
        b = a.copy()
        b[20:30, 30:50] = 0
        result = quality.compare(a, b, [(30, 20, 50, 30)])
        self.assertTrue(result['exact'])
        self.assertEqual(result['ssim'], 1.0)
        self.assertTrue(math.isinf(result['psnr_db']))
        self.assertEqual(result['pixels'], 64 * 80 - 10 * 20)

    def test_mismatched_sizes_are_an_error(self):
        result = quality.compare(textured(), textured(h=60))
        self.assertIn('error', result)

    def test_a_case_is_scored_from_its_files(self):
        ref = textured(h=100, w=120)
        frozen = ref.copy()
        frozen[0:10, 0:10] = 0                  # the key box: ignored
        mid = ref.copy()
        mid[50:90, 60:110] = 255 - mid[50:90, 60:110]   # the activity: ignored
        mid[95, 5] = 0                          # the background: counted
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'serial.log'), 'w') as f:
                f.write('boot noise\nKEYDRAW START 120x100 box 10x10@0,0 '
                        'activity 50x40@60,50 fps=30 noise=3 delay=0 frames=9\n')
            Image.fromarray(frozen).save(os.path.join(d, 'frozen.png'))
            Image.fromarray(mid).save(os.path.join(d, 'mid.png'))
            result = quality.score_case(d, ref)
        self.assertEqual(result['key_box'], [0, 0, 10, 10])
        self.assertEqual(result['activity'], [60, 50, 110, 90])
        self.assertTrue(result['frozen']['exact'])
        self.assertEqual(result['frozen']['ssim'], 1.0)
        self.assertEqual(result['mid_background']['differing_pixels'], 1)
        self.assertFalse(result['mid_background']['exact'])

    def test_infinity_is_written_as_a_string(self):
        self.assertIn('"inf"', quality.to_json({'psnr_db': math.inf}))


if __name__ == '__main__':
    unittest.main()
