"""B20: offset-less timestamps must be read in the site's timezone even where Python has no timezone
database (stock Windows without the `tzdata` package), and an unknown zone must warn, not silently use UTC."""
import contextlib
import io
import sys
import unittest
from datetime import datetime, timedelta, timezone

from helpers import ROOT  # noqa: F401
import common.util as util


@contextlib.contextmanager
def no_zoneinfo():
    """Make `from zoneinfo import ZoneInfo` fail, as on a Python without a timezone database."""
    saved = sys.modules.get("zoneinfo")
    sys.modules["zoneinfo"] = None
    util._zone.cache_clear()
    try:
        yield
    finally:
        if saved is None:
            sys.modules.pop("zoneinfo", None)
        else:
            sys.modules["zoneinfo"] = saved
        util._zone.cache_clear()


def zoneinfo_or_none(name):
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        return None


class BuiltinZones(unittest.TestCase):
    def test_kolkata_without_tz_database(self):
        with no_zoneinfo():
            self.assertEqual(util.parse_iso("2026-11-20T14:30:00", "Asia/Kolkata"),
                             util.parse_iso("2026-11-20T09:00:00Z"))

    def test_daylight_saving_without_tz_database(self):
        with no_zoneinfo():
            # New York: EST in January (UTC-5), EDT in July (UTC-4)
            self.assertEqual(util.parse_iso("2026-01-15T12:00:00", "America/New_York"),
                             util.parse_iso("2026-01-15T17:00:00Z"))
            self.assertEqual(util.parse_iso("2026-07-15T12:00:00", "America/New_York"),
                             util.parse_iso("2026-07-15T16:00:00Z"))
            # Berlin: CET in December (UTC+1), CEST in August (UTC+2)
            self.assertEqual(util.parse_iso("2026-12-01T12:00:00", "Europe/Berlin"),
                             util.parse_iso("2026-12-01T11:00:00Z"))
            self.assertEqual(util.parse_iso("2026-08-01T12:00:00", "Europe/Berlin"),
                             util.parse_iso("2026-08-01T10:00:00Z"))

    def test_unknown_zone_warns_once(self):
        with no_zoneinfo():
            util._ZONE_WARNED.discard("Mars/Olympus_Mons")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                a = util.parse_iso("2026-11-20T10:00:00", "Mars/Olympus_Mons")
                util._zone.cache_clear()
                util.parse_iso("2026-11-20T10:00:00", "Mars/Olympus_Mons")
            self.assertEqual(a, util.parse_iso("2026-11-20T10:00:00Z"))
            self.assertEqual(err.getvalue().count("Mars/Olympus_Mons"), 1)

    def test_builtin_table_matches_tz_database_hour_by_hour(self):
        """Every built-in zone agrees with the real timezone database for every hour of 2025-2027
        (skipped where no database is installed, e.g. Windows CI)."""
        if zoneinfo_or_none("Europe/Berlin") is None:
            self.skipTest("no timezone database on this machine")
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        for name in util._BUILTIN_ZONES:
            ref, mine = zoneinfo_or_none(name), util.builtin_zone(name)
            if ref is None:
                continue
            for h in range(0, 3 * 366 * 24):
                u = start + timedelta(hours=h)
                local = u.astimezone(ref).replace(tzinfo=None)
                # the repeated hour when clocks go back is ambiguous in wall-clock time; skip it
                if ref.utcoffset(local.replace(fold=0)) != ref.utcoffset(local.replace(fold=1)):
                    continue
                self.assertEqual(mine.utcoffset(local), ref.utcoffset(local), f"{name} at {local}")


if __name__ == "__main__":
    unittest.main()
