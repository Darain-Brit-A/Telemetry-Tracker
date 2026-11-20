"""B16: the validation report must not print a zero latency when nothing was measured."""
import unittest

from helpers import ROOT  # noqa: F401
from tools.verify import render_ack_text


class RenderAckText(unittest.TestCase):
    def test_no_samples_says_not_measured(self):
        self.assertEqual(render_ack_text({"n": 0}), "browser render-ack not measured (no browser open)")

    def test_samples_are_reported(self):
        self.assertEqual(render_ack_text({"n": 8, "p95": 4490}), "browser render-ack p95 4.49s (n=8)")


if __name__ == "__main__":
    unittest.main()
