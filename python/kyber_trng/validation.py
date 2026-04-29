"""
Statistical validation of the entropy stream.

Implements the most diagnostic of the NIST SP 800-22r1a tests in pure Python
(monobit, block frequency, runs, longest run, cumulative sums) and shells out
to external tools when available (`ent`, `dieharder`). Standalone enough to
run in CI without external dependencies; richer when ent/dieharder are
present.

Usage:

    from kyber_trng.validation import StatisticalSuite
    from kyber_trng.source import SerialTRNGSource

    src = SerialTRNGSource("/dev/ttyACM0")
    sample = src.read(1_048_576)   # 1 MiB
    report = StatisticalSuite().run_all(sample)
    print(report)
"""

from __future__ import annotations

import math
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Dict, Optional

try:
    from scipy.special import erfc, gammaincc  # type: ignore
    _HAVE_SCIPY = True
except ImportError:
    _HAVE_SCIPY = False
    def erfc(x):  # fallback — Abramowitz & Stegun 7.1.26
        t = 1.0 / (1.0 + 0.3275911 * abs(x))
        a = (0.254829592, -0.284496736, 1.421413741, -1.453152027, 1.061405429)
        e = 1 - t * sum(a[i] * t**i for i in range(5)) * math.exp(-x * x)
        return 1 - e if x >= 0 else 1 + e
    def gammaincc(a, x):  # crude — adequate for the regime we use
        return math.exp(-x) * sum(x**k / math.factorial(k + a - 1) for k in range(20))


@dataclass
class TestResult:
    name: str
    p_value: float
    passed: bool
    detail: str = ""


@dataclass
class SuiteReport:
    n_bytes: int
    results: list = field(default_factory=list)
    external: Dict[str, str] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    def __str__(self) -> str:
        lines = [f"=== Statistical Validation Report ({self.n_bytes:,} bytes) ==="]
        for r in self.results:
            mark = "PASS" if r.passed else "FAIL"
            lines.append(f"  [{mark}] {r.name:30s}  p = {r.p_value:.4f}  {r.detail}")
        for k, v in self.external.items():
            lines.append(f"  [external: {k}]")
            lines.append(v.rstrip())
        lines.append("=" * 60)
        lines.append(f"OVERALL: {'PASS' if self.passed else 'FAIL'}")
        return "\n".join(lines)


def _bits(data: bytes):
    for b in data:
        for i in range(7, -1, -1):
            yield (b >> i) & 1


def monobit(data: bytes, alpha: float = 0.01) -> TestResult:
    n = len(data) * 8
    s = sum(1 if b else -1 for b in _bits(data))
    s_obs = abs(s) / math.sqrt(n)
    p = erfc(s_obs / math.sqrt(2))
    return TestResult("monobit (frequency)", p, p >= alpha,
                      f"|S|/sqrt(n) = {s_obs:.3f}")


def block_frequency(data: bytes, M: int = 128, alpha: float = 0.01) -> TestResult:
    bits = list(_bits(data))
    N = len(bits) // M
    if N == 0:
        return TestResult("block frequency", 1.0, True, "n too small")
    chi2 = 0.0
    for i in range(N):
        block = bits[i * M:(i + 1) * M]
        pi = sum(block) / M
        chi2 += (pi - 0.5) ** 2
    chi2 *= 4 * M
    p = float(gammaincc(N / 2, chi2 / 2))
    return TestResult("block frequency", p, p >= alpha, f"chi2 = {chi2:.2f}, N = {N}")


def runs_test(data: bytes, alpha: float = 0.01) -> TestResult:
    bits = list(_bits(data))
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return TestResult("runs", 0.0, False, "monobit prereq failed")
    V = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    num = abs(V - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p = erfc(num / den)
    return TestResult("runs", p, p >= alpha, f"V = {V}")


def longest_run_block(data: bytes, alpha: float = 0.01) -> TestResult:
    """Longest run of ones in 8-bit blocks (M=8 variant for n>=128)."""
    bits = list(_bits(data))
    n_bits = len(bits)
    if n_bits < 128:
        return TestResult("longest run", 1.0, True, "n too small for M=8")
    M = 8
    N = n_bits // M
    classes = [0, 0, 0, 0]   # <=1, =2, =3, >=4
    for i in range(N):
        block = bits[i * M:(i + 1) * M]
        longest = cur = 0
        for b in block:
            cur = cur + 1 if b else 0
            longest = max(longest, cur)
        if longest <= 1: classes[0] += 1
        elif longest == 2: classes[1] += 1
        elif longest == 3: classes[2] += 1
        else: classes[3] += 1
    pi = (0.2148, 0.3672, 0.2305, 0.1875)
    chi2 = sum((classes[i] - N * pi[i]) ** 2 / (N * pi[i]) for i in range(4))
    p = float(gammaincc(3 / 2, chi2 / 2))
    return TestResult("longest run of ones", p, p >= alpha, f"chi2 = {chi2:.2f}")


def cumulative_sums(data: bytes, alpha: float = 0.01) -> TestResult:
    bits = [1 if b else -1 for b in _bits(data)]
    n = len(bits)
    s = 0; max_abs = 0
    for b in bits:
        s += b
        max_abs = max(max_abs, abs(s))
    z = max_abs
    # Approximate p-value (forward direction) per SP 800-22 §2.13
    if _HAVE_SCIPY:
        from scipy.stats import norm  # type: ignore
        p = 1.0
        k_max = int((n / z - 1) // 4)
        for k in range(-k_max, k_max + 1):
            p -= norm.cdf(((4 * k + 1) * z) / math.sqrt(n)) - norm.cdf(((4 * k - 1) * z) / math.sqrt(n))
        p = max(0.0, min(1.0, p))
    else:
        # Crude bound — replace with scipy in production
        p = math.exp(-z * z / (2 * n))
    return TestResult("cumulative sums (max)", p, p >= alpha, f"z = {z}")


def shannon_entropy_bits_per_byte(data: bytes) -> float:
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def chi_square_uniform(data: bytes) -> float:
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    expected = len(data) / 256
    return sum((c - expected) ** 2 / expected for c in counts)


class StatisticalSuite:
    def run_all(self, data: bytes) -> SuiteReport:
        report = SuiteReport(n_bytes=len(data))
        report.results.extend([
            monobit(data),
            block_frequency(data),
            runs_test(data),
            longest_run_block(data),
            cumulative_sums(data),
        ])
        h = shannon_entropy_bits_per_byte(data)
        chi = chi_square_uniform(data)
        report.results.append(TestResult(
            "shannon entropy", 1.0 if h >= 7.5 else 0.0, h >= 7.5,
            f"H = {h:.4f} bits/byte (target ≥ 7.5)",
        ))
        report.results.append(TestResult(
            "chi-square uniform", 1.0 if 200 < chi < 320 else 0.0,
            200 < chi < 320,
            f"chi2 = {chi:.2f} (expected ~255 ± 23 for uniform)",
        ))

        # External tools (optional)
        if shutil.which("ent"):
            with tempfile.NamedTemporaryFile() as fh:
                fh.write(data); fh.flush()
                out = subprocess.run(["ent", fh.name], capture_output=True, text=True, timeout=30)
                report.external["ent"] = out.stdout
        if shutil.which("dieharder") and len(data) >= 1024 * 1024:
            with tempfile.NamedTemporaryFile() as fh:
                fh.write(data); fh.flush()
                # Run a quick subset; full battery takes hours
                out = subprocess.run(
                    ["dieharder", "-d", "0", "-g", "201", "-f", fh.name],
                    capture_output=True, text=True, timeout=300,
                )
                report.external["dieharder (test 0)"] = out.stdout

        return report
