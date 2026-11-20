"""Live air-quality feed (tools/openaq_poller.py): live-sensor selection, hourly history, unit conversion,
events at real measurement times, and the CPCB categories the engine names. Canned OpenAQ responses only
(no network)."""
import unittest

from helpers import ROOT, make_app  # noqa: F401
from common.policy import load_policy
from common.util import now_ms, parse_iso
from saas.aiops import AIR, METRIC_META, cpcb_category
from tools.openaq_poller import active_sensors, hourly_points, to_events, to_ugm3

NOW = parse_iso("2026-11-20T19:00:00Z")
SENSORS = {1: ("pm25", "µg/m³"), 2: ("pm10", "µg/m³"), 3: ("no2", "ppb"), 4: ("pm25", "µg/m³"),
           5: ("co", "ppb"), 6: ("so2", "furlongs")}


def reading(sensor, value, when):
    return {"sensorsId": sensor, "value": value, "datetime": {"utc": when}}


class Selection(unittest.TestCase):
    def test_live_sensor_per_pollutant_in_ugm3(self):
        got = active_sensors([
            reading(1, 91.0, "2026-11-20T17:30:00Z"),
            reading(4, 55.0, "2022-10-31T02:00:00Z"),       # a second, long-dead PM2.5 sensor
            reading(2, 228.0, "2026-11-20T17:30:00Z"),
            reading(3, 37.3, "2026-11-20T17:30:00Z"),       # ppb -> ug/m3
            reading(5, 1.08, "2026-11-20T17:30:00Z"),       # CO is not tracked
        ], SENSORS, NOW, max_age_h=24)
        self.assertEqual(got["pm25_ugm3"], (1, 91.0, parse_iso("2026-11-20T17:30:00Z")))
        self.assertEqual(got["pm10_ugm3"][:2], (2, 228.0))
        self.assertEqual(got["no2_ugm3"][0], 3)
        self.assertAlmostEqual(got["no2_ugm3"][1], 70.2, places=1)
        self.assertEqual(set(got), {"pm25_ugm3", "pm10_ugm3", "no2_ugm3"})

    def test_stale_negative_and_unknown_dropped(self):
        got = active_sensors([
            reading(1, 40.0, "2026-11-20T10:00:00Z"),       # 9 h old
            reading(2, -1.0, "2026-11-20T18:30:00Z"),       # invalid
            reading(99, 10.0, "2026-11-20T18:30:00Z"),      # sensor not in the location's list
        ], SENSORS, NOW, max_age_h=6)
        self.assertEqual(got, {})

    def test_units(self):
        self.assertEqual(to_ugm3("pm25", 12.0, "µg/m³"), 12.0)
        self.assertEqual(to_ugm3("pm25", 12.0, "ug/m3"), 12.0)
        self.assertAlmostEqual(to_ugm3("no2", 1.0, "ppm"), 1881.6, places=1)
        self.assertIsNone(to_ugm3("so2", 5.0, "furlongs"))
        self.assertIsNone(to_ugm3("pm25", 5.0, "ppb"))           # no molar conversion for particles


class History(unittest.TestCase):
    def test_hourly_points_at_end_of_hour_sorted(self):
        res = [{"value": 80.0, "period": {"datetimeTo": {"utc": "2026-11-20T17:30:00Z"}}},
               {"value": 70.0, "period": {"datetimeTo": {"utc": "2026-11-20T16:30:00Z"}}},
               {"value": -5, "period": {"datetimeTo": {"utc": "2026-11-20T15:30:00Z"}}},
               {"value": 60.0, "period": {}}]
        self.assertEqual(hourly_points(res, "pm25", "µg/m³"),
                         [(parse_iso("2026-11-20T16:30:00Z"), 70.0), (parse_iso("2026-11-20T17:30:00Z"), 80.0)])

    def test_events_one_per_measurement_time_in_order(self):
        t1, t2 = parse_iso("2026-11-20T16:30:00Z"), parse_iso("2026-11-20T17:30:00Z")
        evs = to_events("silk-board", {"role": "air-monitor", "service": "Silk Board"},
                        {"pm25_ugm3": [(t2, 91.0), (t1, 80.0)], "pm10_ugm3": [(t2, 228.0)]})
        self.assertEqual([e["ts"] for e in evs], ["2026-11-20T16:30:00.000Z", "2026-11-20T17:30:00.000Z"])
        self.assertEqual(evs[1]["metrics"], {"pm25_ugm3": 91.0, "pm10_ugm3": 228.0})
        self.assertEqual((evs[0]["type"], evs[0]["service"], evs[0]["role"]), ("metric", "Silk Board", "air-monitor"))


class EngineAndPolicy(unittest.TestCase):
    def test_cpcb_categories(self):
        self.assertEqual(cpcb_category("pm25_ugm3", 25), "Good")
        self.assertEqual(cpcb_category("pm25_ugm3", 91), "Poor")
        self.assertEqual(cpcb_category("pm25_ugm3", 139), "Very Poor")
        self.assertEqual(cpcb_category("pm10_ugm3", 500), "Severe")
        self.assertIsNone(cpcb_category("cpu_pct", 50))

    def test_air_metrics_allowed_and_detected(self):
        names = set(load_policy()["metric_names"])
        self.assertTrue({"pm25_ugm3", "pm10_ugm3", "no2_ugm3"} <= names)
        self.assertTrue(AIR <= set(METRIC_META))

    def test_history_trains_baseline_but_never_alerts(self):
        app = make_app(self)
        app.reg["tenants"]["acme"]["history_after_s"] = 10800
        eng, now = app.engine, now_ms()
        start = now - 4 * 86_400_000
        for i in range(90):                                   # 90 hourly readings, ending 6 h ago
            v = 40 + (i % 5) + (300 if i in (40, 41, 42, 43) else 0)       # a big spike 2.5 days ago
            eng.on_point("acme", "mon", "pm25_ugm3", start + i * 3_600_000, v)
        st = app.stores.for_tenant("acme")
        self.assertEqual(st.rows("SELECT id FROM alerts WHERE tenant_id='acme'"), [])     # history: no alerts
        s = eng.series[("acme", "mon", "pm25_ugm3")]
        self.assertIsNotNone(s.learned)                                                  # but a baseline
        self.assertLess(s.learned[0], 60)
        for k in range(4):                                    # a recent spike does alert
            eng.on_point("acme", "mon", "pm25_ugm3", now - (4 - k) * 900_000, 200)
        self.assertTrue(st.rows("SELECT id FROM alerts WHERE tenant_id='acme' AND signal='pm25_ugm3'"))


if __name__ == "__main__":
    unittest.main()
