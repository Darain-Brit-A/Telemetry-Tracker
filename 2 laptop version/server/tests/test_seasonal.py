"""ML feature 3: seasonal baseline. A compressed day (48 s, 2 one-second windows per "hour") with a daily
peak in hours 17-21. Once 3 days of history exist, the peak must not alert, while the same level at a
quiet hour must."""
import json
import unittest

from helpers import Feeder, make_app, normal
from common.util import now_ms

DAY_MS = 48_000
HOUR_W = 2                      # windows per hour
PEAK = range(17 * HOUR_W, 21 * HOUR_W)


def app_with(test, min_days):
    app = make_app(test)
    app.reg["tenants"]["acme"]["seasonal"] = {"day_ms": DAY_MS, "min_days": min_days}
    return app


def run(test, min_days, days=4, night_spike=False):
    """Feed `days` compressed days; return the cpu alerts with the day index they started on."""
    app = app_with(test, min_days)
    f = Feeder(app, "col-a1")
    t0 = (now_ms() - (days + 1) * DAY_MS) // DAY_MS * DAY_MS
    w_per_day = DAY_MS // 1000
    for d in range(days):
        for w in range(w_per_day):
            cpu = normal(d * w_per_day + w, 32, 1.5)
            if w in PEAK:
                cpu += 28                                       # the normal evening peak, every day
            if night_spike and d == days - 1 and 12 * HOUR_W <= w < 16 * HOUR_W:   # quiet hours, after warm-up
                cpu += 28                                       # same level at a quiet hour: a real anomaly
            f.send(t0 + (d * w_per_day + w) * 1000, {"s-db1": {"cpu_pct": cpu}})
    rows = app.stores.for_tenant("acme").rows("SELECT first_event_ms, detail, title FROM alerts WHERE signal='cpu_pct'")
    return [dict(r, day=(r["first_event_ms"] - t0) // DAY_MS) for r in rows]


class SeasonalBaseline(unittest.TestCase):
    def test_daily_peak_does_not_alert_after_learning(self):
        alerts = run(self, min_days=3)
        self.assertEqual([a for a in alerts if a["day"] >= 3], [])

    def test_without_seasonal_the_daily_peak_alerts(self):
        alerts = run(self, min_days=99)                     # profile never ready = today's behaviour
        self.assertTrue([a for a in alerts if a["day"] >= 3], "the recent baseline should flag the peak")

    def test_night_spike_still_detected_and_explained(self):
        alerts = [a for a in run(self, min_days=3, night_spike=True) if a["day"] >= 3]
        self.assertEqual(len(alerts), 1)
        detail = json.loads(alerts[0]["detail"])
        self.assertEqual(detail["baseline_kind"], "seasonal")
        self.assertIn("expected for this hour", alerts[0]["title"])

    def test_identical_to_today_before_enough_history(self):
        early = lambda alerts: sorted(a["first_event_ms"] for a in alerts if a["day"] < 3)  # noqa: E731
        self.assertEqual(early(run(self, min_days=3)), early(run(self, min_days=99)))


if __name__ == "__main__":
    unittest.main()
