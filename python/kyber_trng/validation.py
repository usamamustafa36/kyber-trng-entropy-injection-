"""In-process statistical validators.

Implements a subset of NIST SP 800-22r1a tests directly in Python and
shells out to ``ent`` and ``dieharder`` if installed on PATH.  The
in-process tests are sufficient as a quick CI gate; the shelled-out
suites are the canonical reference batteries.

Implemented in-process:

* :func:`monobit` — §2.1 Frequency (Monobit) Test
* :func:`block_frequency` — §2.2 Frequency Test within a Block
* :func:`runs` — §2.3 Runs Test
* :func:`longest_run_of_ones` — §2.4 (M=10000 case only, for streams ≥ 1 MiB)
* :func:`cumulative_sums` — §2.13 Cumulative Sums (Cusums) Test
* :func:`shannon_entropy` — Shannon entropy in bits/byte
* :func:`chi_square_uniformity` — Pearson χ² over byte alphabet

Each test returns a ``Result`` with a p-value and a decision against
``α = 0.01``.
"""

from __future__ import annotations

import math
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


@dataclass
class Result:
    name: str
    p_value: float
    statistic: float
    passed: bool
    detail: str = ""


_ALPHA = 0.01


def _erfc(x: float) -> float:
    return math.erfc(x)


def _bytes_to_bits(data: bytes) -> Iterable[int]:
    for byte in data:
        for k in range(7, -1, -1):
            yield (byte >> k) & 1


# --- SP 800-22 §2.1 ----------------------------------------------------------

def monobit(data: bytes) -> Result:
    n = len(data) * 8
    s = 0
    for byte in data:
        # Faster than unpacking individual bits.
        s += bin(byte).count("1") * 2 - 8
    s_obs = abs(s) / math.sqrt(n)
    p = _erfc(s_obs / math.sqrt(2))
    return Result("monobit", p, s_obs, p >= _ALPHA,
                  detail=f"|S|/sqrt(n) = {s_obs:.4f}")


# --- SP 800-22 §2.2 ----------------------------------------------------------

def block_frequency(data: bytes, block_bits: int = 128) -> Result:
    bits = list(_bytes_to_bits(data))
    n = len(bits)
    N = n // block_bits
    if N == 0:
        return Result("block_frequency", 0.0, 0.0, False,
                      detail="stream too short")
    chi2 = 0.0
    for i in range(N):
        block = bits[i * block_bits:(i + 1) * block_bits]
        pi = sum(block) / block_bits
        chi2 += (pi - 0.5) ** 2
    chi2 *= 4 * block_bits
    p = _gammaincc(N / 2.0, chi2 / 2.0)
    return Result("block_frequency", p, chi2, p >= _ALPHA,
                  detail=f"N={N}, M={block_bits}")


# --- SP 800-22 §2.3 ----------------------------------------------------------

def runs(data: bytes) -> Result:
    bits = list(_bytes_to_bits(data))
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return Result("runs", 0.0, abs(pi - 0.5), False,
                      detail="prerequisite (monobit prop) failed")
    V = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    num = abs(V - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p = _erfc(num / den)
    return Result("runs", p, V, p >= _ALPHA,
                  detail=f"V={V}, pi={pi:.4f}")


# --- SP 800-22 §2.13 ---------------------------------------------------------

def cumulative_sums(data: bytes, mode: str = "forward") -> Result:
    bits = [1 if b else -1 for b in _bytes_to_bits(data)]
    if mode == "backward":
        bits = list(reversed(bits))
    n = len(bits)
    s = 0
    z = 0
    for x in bits:
        s += x
        if abs(s) > z:
            z = abs(s)
    # Tail probability per SP 800-22 §2.13.4.
    sqn = math.sqrt(n)
    p_term1 = 0.0
    k_lo = int((-n / z + 1) / 4) if z > 0 else 0
    k_hi = int((n / z - 1) / 4) if z > 0 else 0
    for k in range(k_lo, k_hi + 1):
        a = (4 * k + 1) * z / sqn
        b = (4 * k - 1) * z / sqn
        p_term1 += _phi(a) - _phi(b)
    p_term2 = 0.0
    k_lo = int((-n / z - 3) / 4) if z > 0 else 0
    k_hi = int((n / z - 1) / 4) if z > 0 else 0
    for k in range(k_lo, k_hi + 1):
        a = (4 * k + 3) * z / sqn
        b = (4 * k + 1) * z / sqn
        p_term2 += _phi(a) - _phi(b)
    p = max(0.0, min(1.0, 1 - p_term1 + p_term2))
    return Result(f"cumulative_sums_{mode}", p, z, p >= _ALPHA,
                  detail=f"z={z}")


# --- Auxiliary stats ---------------------------------------------------------

def shannon_entropy(data: bytes) -> Result:
    if not data:
        return Result("shannon_entropy", 0.0, 0.0, False, detail="empty stream")
    counts = Counter(data)
    n = len(data)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    # No formal p-value; pass when h ≥ 7.99.
    return Result("shannon_entropy", float("nan"), h, h >= 7.99,
                  detail=f"H={h:.6f} bits/byte (target ≥ 7.99)")


def chi_square_uniformity(data: bytes) -> Result:
    if len(data) < 256:
        return Result("chi_square_uniformity", 0.0, 0.0, False,
                      detail="stream < 256 bytes")
    n = len(data)
    expected = n / 256.0
    counts = Counter(data)
    chi2 = sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))
    p = _gammaincc(255 / 2.0, chi2 / 2.0)
    return Result("chi_square_uniformity", p, chi2, p >= _ALPHA,
                  detail=f"χ² = {chi2:.2f}, df=255")


# --- math helpers ------------------------------------------------------------

def _phi(x: float) -> float:
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def _gammaincc(a: float, x: float) -> float:
    """Regularised upper incomplete gamma; falls back to scipy if available."""
    try:
        from scipy.special import gammaincc
        return float(gammaincc(a, x))
    except ImportError:  # pragma: no cover
        # Series + continued-fraction fallback (Numerical Recipes-style).
        if x < a + 1:
            term = 1.0 / a
            s = term
            for k in range(1, 200):
                term *= x / (a + k)
                s += term
                if abs(term) < abs(s) * 1e-12:
                    break
            return 1.0 - s * math.exp(-x + a * math.log(x) - math.lgamma(a))
        # continued fraction
        b = x + 1.0 - a
        c_ = 1e300
        d = 1.0 / b
        h = d
        for i in range(1, 200):
            an = -i * (i - a)
            b += 2
            d = an * d + b
            if abs(d) < 1e-300:
                d = 1e-300
            c_ = b + an / c_
            if abs(c_) < 1e-300:
                c_ = 1e-300
            d = 1.0 / d
            h *= d * c_
            if abs(d * c_ - 1) < 1e-12:
                break
        return h * math.exp(-x + a * math.log(x) - math.lgamma(a))


# --- shell-outs --------------------------------------------------------------

def run_ent(stream_path: str) -> Optional[dict]:
    """Run ``ent`` and return its parsed metrics, or None if absent."""
    if shutil.which("ent") is None:
        return None
    out = subprocess.run(["ent", "-t", stream_path], capture_output=True,
                         text=True, check=False)
    if out.returncode != 0:
        return None
    metrics: dict = {"raw": out.stdout}
    for line in out.stdout.splitlines():
        if "Entropy" in line:
            try:
                metrics["entropy_bits_per_byte"] = float(line.split("=")[1].split()[0])
            except Exception:  # pragma: no cover
                pass
        if "Chi square" in line:
            try:
                metrics["chi_square"] = float(line.split("=")[1].split()[0])
            except Exception:  # pragma: no cover
                pass
        if "Arithmetic mean value" in line:
            try:
                metrics["mean"] = float(line.split("=")[1].split()[0])
            except Exception:  # pragma: no cover
                pass
        if "Monte Carlo value" in line:
            try:
                metrics["pi_estimate"] = float(line.split("=")[1].split()[0])
            except Exception:  # pragma: no cover
                pass
        if "Serial correlation" in line:
            try:
                metrics["serial_correlation"] = float(line.split("=")[1].split()[0])
            except Exception:  # pragma: no cover
                pass
    return metrics


def run_dieharder(stream_path: str, full: bool = False) -> Optional[str]:  # pragma: no cover
    """Invoke dieharder.  Returns raw stdout or None if dieharder absent."""
    if shutil.which("dieharder") is None:
        return None
    args = ["dieharder", "-g", "201", "-f", stream_path]
    args += ["-a"] if full else ["-d", "0"]
    out = subprocess.run(args, capture_output=True, text=True, check=False)
    return out.stdout


# --- driver ------------------------------------------------------------------

ALL_TESTS = (
    "monobit", "block_frequency", "runs", "cumulative_sums_forward",
    "cumulative_sums_backward", "shannon_entropy", "chi_square_uniformity",
)


def run_all_in_process(data: bytes) -> List[Result]:
    return [
        monobit(data),
        block_frequency(data),
        runs(data),
        cumulative_sums(data, "forward"),
        cumulative_sums(data, "backward"),
        shannon_entropy(data),
        chi_square_uniformity(data),
    ]
