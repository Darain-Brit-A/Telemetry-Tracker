"""Two-machine deployment: the SaaS certificate names, the address collectors are given, and portable
collector configs (certificate paths relative to the config folder)."""
import os
import unittest

from helpers import ROOT, make_app  # noqa: F401
import collector.collector as colmod
from setup_env import server_san


class TwoMachines(unittest.TestCase):
    def test_certificate_names(self):
        self.assertEqual(server_san(), "DNS:localhost,IP:127.0.0.1")
        self.assertEqual(server_san("192.168.1.20"), "DNS:localhost,IP:127.0.0.1,IP:192.168.1.20")
        self.assertEqual(server_san("saas-laptop.local"), "DNS:localhost,IP:127.0.0.1,DNS:saas-laptop.local")
        self.assertEqual(server_san("127.0.0.1"), server_san())

    def test_discovery_hands_out_the_public_host(self):
        app = make_app(self)
        self.assertTrue(app.ingest_url("eu-west").endswith("://127.0.0.1:%d/r/eu-west" % app.ingest_port))
        app.public_host = "192.168.1.20"
        self.assertIn("://192.168.1.20:", app.ingest_url("eu-west"))
        app.public_host = "fd00::20"
        self.assertIn("://[fd00::20]:", app.ingest_url("eu-west"))

    def test_collector_cert_paths_are_relative_to_config(self):
        self.assertEqual(colmod.config_path("certs/ca.crt"), os.path.join(colmod.CONFIG_DIR, "certs/ca.crt"))
        absolute = os.path.abspath(os.sep + os.path.join("x", "ca.crt"))
        self.assertEqual(colmod.config_path(absolute), absolute)
        self.assertIsNone(colmod.config_path(None))


if __name__ == "__main__":
    unittest.main()
