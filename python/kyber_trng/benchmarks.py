"""Latency and throughput benchmarks for ML-KEM under different sources."""

from __future__ import annotations

import math
import os
import statistics
import time
from dataclasses import dataclass
from typing import Callable, List, Optional

from .source import TRNGSource, SimulatedTRNGSource
from .hybrid import HybridDRBG
from .kyber_shim import kyber, set_entropy_source, get_entropy_source


@dataclass
class LatencyStats:
    label: str
    op: str
    n: int
    mean_ms: float
    median_ms: float
    stdev_ms: float
    ci95_ms: float
    min_ms: float
    max_ms: float


def _t95(n: int) -> float:
    """Crude 95% t-multiplier; good enough for n in [10, 1000]."""
    if n <= 1:
        return float("nan")
    table = {2: 12.71, 5: 2.78, 10: 2.26, 20: 2.09, 30: 2.04, 50: 2.01, 100: 1.98}
    keys = sorted(table)
    for k in keys:
        if n <= k:
            return table[k]
    return 1.96


def measure(label: str, op: str, fn: Callable[[], None], n: int) -> LatencyStats:
    samples = []
    # one warm-up
    fn()
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    mean = statistics.mean(samples)
    median = statistics.median(samples)
    stdev = statistics.stdev(samples) if len(samples) > 1 else 0.0
    ci = _t95(n) * stdev / math.sqrt(n) if n > 1 else 0.0
    return LatencyStats(label, op, n, mean, median, stdev, ci,
                        min(samples), max(samples))


# --- Drivers ---------------------------------------------------------------

class _OSUrandomSource(TRNGSource):
    name = "os_urandom"
    def read(self, n: int) -> bytes:
        return os.urandom(n)


def benchmark_all(n_runs: int = 100, level: int = 1024) -> List[LatencyStats]:
    """Benchmark KeyGen, Encaps, Decaps under three entropy sources.

    Returns 9 :class:`LatencyStats` records.  Decaps does not consume
    fresh entropy, but is included to confirm the source-switch overhead
    is bounded.
    """
    facade = getattr(kyber, f"l{level}")
    sources = [
        ("os_urandom", _OSUrandomSource()),
        ("simulated_trng", SimulatedTRNGSource()),
        ("hybrid_trng_drbg", HybridDRBG(SimulatedTRNGSource())),
    ]
    saved = get_entropy_source()
    results: List[LatencyStats] = []
    try:
        for label, src in sources:
            set_entropy_source(src)
            # Pre-generate a key for encaps/decaps so the cost is isolated.
            ek, dk = facade.keygen()
            _, ct = facade.encaps(ek)

            results.append(measure(label, "keygen",
                                   lambda f=facade: f.keygen(), n_runs))
            results.append(measure(label, "encaps",
                                   lambda f=facade, k=ek: f.encaps(k), n_runs))
            results.append(measure(label, "decaps",
                                   lambda f=facade, d=dk, c=ct: f.decaps(d, c), n_runs))
    finally:
        set_entropy_source(saved)
    return results


def format_latency_table(rows: List[LatencyStats]) -> str:
    """Pretty-print a list of LatencyStats as a fixed-width table."""
    headers = ["source", "op", "n", "mean(ms)", "±95%CI", "median", "stdev", "min", "max"]
    fmt_row = "{:<18}{:<10}{:>5}{:>10}{:>10}{:>10}{:>10}{:>10}{:>10}"
    lines = [fmt_row.format(*headers)]
    lines.append("-" * len(lines[0]))
    for r in rows:
        lines.append(fmt_row.format(
            r.label, r.op, r.n,
            f"{r.mean_ms:.3f}", f"{r.ci95_ms:.3f}",
            f"{r.median_ms:.3f}", f"{r.stdev_ms:.3f}",
            f"{r.min_ms:.3f}", f"{r.max_ms:.3f}",
        ))
    return "\n".join(lines)
