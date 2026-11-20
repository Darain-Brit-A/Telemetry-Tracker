"""Live air-quality feed (tools/openaq_poller.py): reading selection, unit conversion and the CPCB
categories the engine names, tested on canned OpenAQ responses (no network)."""
import unittest

from helpers import ROOT  # noqa: F401
from common.policy import load_policy
from common.util import parse_iso
from saas.aiops import AIR, METRIC_META, cpcb_category
from tools.openaq_poller import Poller, pick_latest, to_ugm3

NOW = parse_iso("2026-11-20T19:00:00Z")
SENSORS = {1: ("pm25", "µg/m³"), 2: ("pm10", "µg/m³"), 3: ("no2", "ppb"), 4: ("pm25", "µg/m³"),
           5: ("co", "ppb"), 6: ("so2", "furlongs")}


def reading(sensor, value, when):
    return {"sensorsId": sensor, "value": value, "datetime": {"utc": when}}


class PickLatest(unittest.TestCase):
    def test_newest_recent_reading_per_metric_in_ugm3(self):
        got = pick_latest([
            reading(1, 91.0, "2026-11-20T17:30:00Z"),
            reading(4, 55.0, "2022-10-31T02:00:00Z"),       # a second, long-dead PM2.5 sensor
            reading(2, 228.0, "2026-11-20T17:30:00Z"),
            reading(3, 37.3, "2026-11-20T17:30:00Z"),       # ppb -> ug/m3
            reading(5, 1.08, "2026-11-20T17:30:00Z"),       # CO is not tracked
        ], SENSORS, NOW, max_age_h=3)
        self.assertEqual(got["pm25_ugm3"], (91.0, parse_iso("2026-11-20T17:30:00Z")))
        self.assertEqual(got["pm10_ugm3"][0], 228.0)
        self.assertAlmostEqual(got["no2_ugm3"][0], 70.2, places=1)
        self.assertEqual(set(got), {"pm25_ugm3", "pm10_ugm3", "no2_ugm3"})

    def test_stale_negative_and_unknown_dropped(self):
        got = pick_latest([
            reading(1, 40.0, "2026-11-20T14:00:00Z"),       # 5 h old
            reading(2, -1.0, "2026-11-20T18:30:00Z"),       # invalid
            reading(99, 10.0, "2026-11-20T18:30:00Z"),      # sensor not in the location's list
        ], SENSORS, NOW, max_age_h=3)
        self.assertEqual(got, {})

    def test_units(self):
        self.assertEqual(to_ugm3("pm25", 12.0, "µg/m³"), 12.0)
        self.assertEqual(to_ugm3("pm25", 12.0, "ug/m3"), 12.0)
        self.assertAlmostEqual(to_ugm3("no2", 1.0, "ppm"), 1881.6, places=1)
        self.assertIsNone(to_ugm3("so2", 5.0, "furlongs"))
        self.assertIsNone(to_ugm3("pm25", 5.0, "ppb"))           # no molar conversion for particles


class Events(unittest.TestCase):
    def test_events_carry_values_and_age(self):
        cfg = {"openaq_locations": {"silk-board": 6975}, "ui_port": 0,
               "hosts": {"silk-board": {"role": "air-monitor", "service": "Silk Board"}}}
        p = Poller(cfg, "k")
        measured = parse_iso("2026-11-20T17:30:00Z")
        p.readings = {"silk-board": {"pm25_ugm3": (91.0, measured), "pm10_ugm3": (228.0, measured)}}
        [ev] = p.events()
        self.assertEqual((ev["type"], ev["host"], ev["service"], ev["role"]), ("metric", "silk-board", "Silk Board", "air-monitor"))
        self.assertEqual(ev["metrics"]["pm25_ugm3"], 91.0)
        self.assertGreater(ev["metrics"]["aq_age_min"], 0)


class EngineAndPolicy(unittest.TestCase):
    def test_cpcb_categories(self):
        self.assertEqual(cpcb_category("pm25_ugm3", 25), "Good")
        self.assertEqual(cpcb_category("pm25_ugm3", 91), "Poor")
        self.assertEqual(cpcb_category("pm25_ugm3", 139), "Very Poor")
        self.assertEqual(cpcb_category("pm10_ugm3", 500), "Severe")
        self.assertIsNone(cpcb_category("cpu_pct", 50))

    def test_air_metrics_allowed_and_detected(self):
        names = set(load_policy()["metric_names"])
        self.assertTrue({"pm25_ugm3", "pm10_ugm3", "no2_ugm3", "aq_age_min"} <= names)
        self.assertTrue(AIR <= set(METRIC_META))


if __name__ == "__main__":
    unittest.main()
