import time
from datetime import datetime, timedelta, timezone


class RealClock:
    def monotonic(self):
        return time.monotonic()

    def sleep(self, s):
        if s > 0:
            time.sleep(s)

    def now_iso(self):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def iso_after(self, seconds):
        return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeClock:
    """Deterministic clock for fixtures: sleeping only advances virtual time."""

    def __init__(self, start="2026-10-28T10:00:00Z"):
        self._t0 = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        self.t = 0.0

    def monotonic(self):
        return self.t

    def sleep(self, s):
        if s > 0:
            self.t += s

    def now_iso(self):
        return (self._t0 + timedelta(seconds=int(self.t))).strftime("%Y-%m-%dT%H:%M:%SZ")

    def iso_after(self, seconds):
        return (self._t0 + timedelta(seconds=int(self.t + seconds))).strftime("%Y-%m-%dT%H:%M:%SZ")
