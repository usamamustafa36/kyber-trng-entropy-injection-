"""Tests for the SP 800-90B conditioning stage."""
import math
import pytest

from kyber_trng import ConditionedSource, SimulatedTRNGSource, TRNGSource


class _CountingSource(TRNGSource):
    """Records how many raw bytes the conditioner consumed."""
    name = "counting"

    def __init__(self):
        self.consumed = 0

    def read(self, n: int) -> bytes:
        self.consumed += n
        return bytes(range(256)) * (n // 256 + 1)


def test_output_length_exact():
    c = ConditionedSource(SimulatedTRNGSource())
    for n in (1, 32, 64, 255):
        assert len(c.read(n)) == n


def test_zero_and_negative():
    c = ConditionedSource(SimulatedTRNGSource())
    assert c.read(0) == b""
    with pytest.raises(ValueError):
        c.read(-1)


def test_compression_ratio_matches_h_min():
    """Input must carry 8n + margin bits of min-entropy at the stated h_min."""
    for h_min in (0.5, 1.0, 4.0, 8.0):
        src = _CountingSource()
        c = ConditionedSource(src, h_min=h_min, margin_bits=64)
        c.read(32)
        assert src.consumed == math.ceil((8 * 32 + 64) / h_min)


def test_default_is_conservative():
    """At the health-test h_min of 0.5, 32 bytes out costs 640 bytes in."""
    c = ConditionedSource(SimulatedTRNGSource())
    assert c.raw_bytes_required(32) == 640


def test_bias_is_removed():
    """A source stuck at one value still yields a uniform-looking output."""
    class _Stuck(TRNGSource):
        name = "stuck"
        def read(self, n: int) -> bytes:
            return b"\x00" * n

    out = ConditionedSource(_Stuck()).read(4096)
    counts = [0] * 256
    for b in out:
        counts[b] += 1
    # chi-square against uniform; a stuck source passed through XOR would fail
    exp = len(out) / 256
    chi2 = sum((c - exp) ** 2 / exp for c in counts)
    assert chi2 < 400, f"conditioned output not uniform: chi2={chi2}"


def test_rejects_bad_parameters():
    s = SimulatedTRNGSource()
    for bad in (0, -1, 9):
        with pytest.raises(ValueError):
            ConditionedSource(s, h_min=bad)
    with pytest.raises(ValueError):
        ConditionedSource(s, margin_bits=-1)
