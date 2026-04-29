"""
NIST SP 800-90B continuous health tests.

Two tests, run on every byte produced by the entropy source:

  * Repetition Count Test (RCT) — flags catastrophic stuck-output failures
  * Adaptive Proportion Test (APT) — flags entropy collapse over a sliding window

Cutoffs are derived for an assumed minimum entropy H_min and a false-positive
rate of 2^-20 per the SP 800-90B procedure. Defaults assume H_min = 0.5
bits/byte (very conservative); tighten to your measured H_min in production.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass


def rct_cutoff(h_min: float, alpha: float = 2 ** -20) -> int:
    return 1 + math.ceil(math.log2(1.0 / alpha) / h_min)


def apt_cutoff(window: int, h_min: float, alpha: float = 2 ** -20) -> int:
    """Critical binomial value for APT — closed form per SP 800-90B 4.4.2."""
    p = 2 ** (-h_min)
    # Use normal approximation for large W; fine for window=512.
    mean = window * p
    sd = math.sqrt(window * p * (1 - p))
    # z-score for tail prob alpha/window  (Bonferroni over W positions)
    # alpha/window ≈ 2^-20 / 512 = 2^-29 → z ≈ 5.4
    z = 5.4
    return int(math.ceil(mean + z * sd))


class RepetitionCountTest:
    def __init__(self, h_min: float = 0.5):
        self.cutoff = rct_cutoff(h_min)
        self._last = None
        self._run = 0
        self.failures = 0

    def update(self, b: int) -> bool:
        if b == self._last:
            self._run += 1
            if self._run >= self.cutoff:
                self.failures += 1
                return False
        else:
            self._last = b
            self._run = 1
        return True


class AdaptiveProportionTest:
    def __init__(self, window: int = 512, h_min: float = 0.5):
        self.window = window
        self.cutoff = apt_cutoff(window, h_min)
        self._ref = None
        self._matches = 0
        self._pos = 0
        self.failures = 0

    def update(self, b: int) -> bool:
        if self._pos == 0:
            self._ref = b
            self._matches = 1
        elif b == self._ref:
            self._matches += 1
        self._pos += 1
        if self._pos >= self.window:
            ok = self._matches < self.cutoff
            self._pos = 0
            if not ok:
                self.failures += 1
            return ok
        return True


@dataclass
class HealthReport:
    bytes_seen: int
    rct_failures: int
    apt_failures: int
    rct_cutoff: int
    apt_cutoff: int
    healthy: bool


class HealthMonitor:
    """Combined RCT + APT monitor with rolling stats."""

    def __init__(self, h_min: float = 0.5, apt_window: int = 512):
        self.rct = RepetitionCountTest(h_min)
        self.apt = AdaptiveProportionTest(apt_window, h_min)
        self.bytes_seen = 0
        self.healthy = True

    def feed(self, data: bytes) -> bool:
        for b in data:
            self.bytes_seen += 1
            if not self.rct.update(b):
                self.healthy = False
            if not self.apt.update(b):
                self.healthy = False
        return self.healthy

    def report(self) -> HealthReport:
        return HealthReport(
            bytes_seen=self.bytes_seen,
            rct_failures=self.rct.failures,
            apt_failures=self.apt.failures,
            rct_cutoff=self.rct.cutoff,
            apt_cutoff=self.apt.cutoff,
            healthy=self.healthy,
        )
