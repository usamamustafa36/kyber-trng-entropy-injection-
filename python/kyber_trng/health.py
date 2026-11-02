"""NIST SP 800-90B continuous health tests.

Implements the two startup-and-continuous tests required by SP 800-90B
§4.4 for entropy sources:

* :class:`RepetitionCountTest` (§4.4.1) — fails when the same byte is
  produced ``C_RCT`` times in a row.
* :class:`AdaptiveProportionTest` (§4.4.2) — over a sliding window of
  ``W`` bytes, fails when any single byte's count exceeds ``C_APT``.

Cutoffs are derived from a target false-positive rate ``α`` and assumed
min-entropy ``H`` per byte.  Defaults: α = 2⁻²⁰, H = 0.5 bits/byte,
W = 512.  Under these defaults ``C_RCT = 41`` (per the closed-form
formula in §4.4.1) and ``C_APT`` is the smallest integer ``c`` with
``Pr[Binomial(W, 2^-H) ≥ c] ≤ α``.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


def rct_cutoff(h_min: float, alpha: float) -> int:
    r"""Closed-form RCT cutoff per SP 800-90B §4.4.1.

    :math:`C = 1 + \lceil -\log_2(\alpha) / H \rceil`.
    """
    if h_min <= 0:
        raise ValueError("h_min must be positive")
    if not (0 < alpha < 1):
        raise ValueError("alpha must lie in (0, 1)")
    return 1 + math.ceil(-math.log2(alpha) / h_min)


def apt_cutoff(h_min: float, alpha: float, window: int = 512) -> int:
    """Smallest c with Pr[Binomial(W, 2^-H) ≥ c] ≤ α.

    Computed by upper-tail evaluation; falls back to a normal
    approximation if scipy is unavailable.
    """
    p = 2.0 ** (-h_min)
    try:
        from scipy.stats import binom

        # ppf gives the smallest c with CDF(c) ≥ 1-α, i.e. tail ≤ α.
        return int(binom.ppf(1 - alpha, window, p))
    except ImportError:  # pragma: no cover
        mu = window * p
        sigma = math.sqrt(window * p * (1 - p))
        # 4.75σ ≈ tail of 1e-6 ≈ 2⁻²⁰.
        return min(window, int(math.ceil(mu + 4.75 * sigma)))


@dataclass
class HealthReport:
    """Snapshot of the health-monitor state."""

    ok: bool
    rct_failed: bool
    apt_failed: bool
    bytes_seen: int
    rct_run_length: int
    rct_run_value: Optional[int]
    apt_window: int
    apt_max_count: int
    apt_max_value: Optional[int]
    rct_cutoff: int
    apt_cutoff: int

    @property
    def reason(self) -> Optional[str]:
        if self.ok:
            return None
        bits = []
        if self.rct_failed:
            bits.append(f"RCT: byte 0x{self.rct_run_value:02x} repeated "
                        f"{self.rct_run_length}× (cutoff {self.rct_cutoff})")
        if self.apt_failed:
            bits.append(f"APT: byte 0x{self.apt_max_value:02x} count "
                        f"{self.apt_max_count}/{self.apt_window} "
                        f"(cutoff {self.apt_cutoff})")
        return "; ".join(bits)


class RepetitionCountTest:
    """SP 800-90B §4.4.1 RCT — fail on long runs of a single byte."""

    def __init__(self, h_min: float = 0.5, alpha: float = 2 ** -20):
        self.cutoff = rct_cutoff(h_min, alpha)
        self.run_value: Optional[int] = None
        self.run_length: int = 0
        self.failed: bool = False

    def update(self, b: int) -> None:
        if b == self.run_value:
            self.run_length += 1
        else:
            self.run_value = b
            self.run_length = 1
        if self.run_length >= self.cutoff:
            self.failed = True


class AdaptiveProportionTest:
    """SP 800-90B §4.4.2 APT — fail on any byte's frequency exceeding cutoff."""

    def __init__(self, h_min: float = 0.5, alpha: float = 2 ** -20, window: int = 512):
        self.window = int(window)
        self.cutoff = apt_cutoff(h_min, alpha, self.window)
        self._buf: deque[int] = deque(maxlen=self.window)
        self._counts = [0] * 256
        self.failed: bool = False
        self.max_count: int = 0
        self.max_value: Optional[int] = None

    def update(self, b: int) -> None:
        if len(self._buf) == self.window:
            self._counts[self._buf[0]] -= 1
        self._buf.append(b)
        self._counts[b] += 1
        if self._counts[b] > self.max_count:
            self.max_count = self._counts[b]
            self.max_value = b
        # Only check failures once the window is full, per spec.
        if len(self._buf) == self.window and self._counts[b] >= self.cutoff:
            self.failed = True


class HealthMonitor:
    """Composes RCT and APT into a single fail-closed monitor.

    Once :pyattr:`failed` is set, the monitor stays failed (per
    SP 800-90B §4.5).  Recovery requires constructing a fresh instance.
    """

    def __init__(self, h_min: float = 0.5, alpha: float = 2 ** -20, apt_window: int = 512):
        self.h_min = h_min
        self.alpha = alpha
        self.rct = RepetitionCountTest(h_min, alpha)
        self.apt = AdaptiveProportionTest(h_min, alpha, apt_window)
        self.bytes_seen: int = 0
        self.failed: bool = False

    def update(self, data: bytes) -> HealthReport:
        if not self.failed:
            for b in data:
                self.rct.update(b)
                self.apt.update(b)
                self.bytes_seen += 1
                if self.rct.failed or self.apt.failed:
                    self.failed = True
                    break
            else:
                self.bytes_seen += 0  # all bytes consumed without failure
        return self.report()

    def report(self) -> HealthReport:
        return HealthReport(
            ok=not self.failed,
            rct_failed=self.rct.failed,
            apt_failed=self.apt.failed,
            bytes_seen=self.bytes_seen,
            rct_run_length=self.rct.run_length,
            rct_run_value=self.rct.run_value,
            apt_window=self.apt.window,
            apt_max_count=self.apt.max_count,
            apt_max_value=self.apt.max_value,
            rct_cutoff=self.rct.cutoff,
            apt_cutoff=self.apt.cutoff,
        )
