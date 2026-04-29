"""
Unit tests for SP 800-90B health monitors and the hybrid DRBG.

Run: python -m pytest tests/
"""

import os
import pytest

from kyber_trng.health import HealthMonitor, RepetitionCountTest, AdaptiveProportionTest
from kyber_trng.source import SimulatedTRNGSource
from kyber_trng.hybrid import HybridDRBG
from kyber_trng.validation import StatisticalSuite


def test_rct_passes_random():
    rct = RepetitionCountTest(h_min=0.5)
    for b in os.urandom(10_000):
        assert rct.update(b)


def test_rct_flags_stuck_output():
    rct = RepetitionCountTest(h_min=0.5)
    failed = False
    for _ in range(rct.cutoff + 5):
        if not rct.update(0xAA):
            failed = True
            break
    assert failed, "RCT did not flag a stuck output"


def test_apt_passes_random():
    apt = AdaptiveProportionTest(window=512, h_min=0.5)
    for b in os.urandom(10_000):
        assert apt.update(b)


def test_health_monitor_combined():
    hm = HealthMonitor()
    assert hm.feed(os.urandom(8192))
    r = hm.report()
    assert r.healthy
    assert r.bytes_seen == 8192
    assert r.rct_failures == 0
    assert r.apt_failures == 0


def test_hybrid_drbg_outputs_correct_length():
    src = SimulatedTRNGSource()
    drbg = HybridDRBG(src, reseed_interval=4096)
    for n in (16, 32, 64, 1024, 4097):  # crosses reseed boundary
        out = drbg.read(n)
        assert len(out) == n


def test_hybrid_drbg_not_repeating():
    drbg = HybridDRBG(SimulatedTRNGSource())
    samples = [drbg.read(32) for _ in range(20)]
    assert len(set(samples)) == 20


def test_statistical_suite_random():
    """OS entropy must pass the in-Python NIST subset."""
    data = os.urandom(64 * 1024)
    report = StatisticalSuite().run_all(data)
    assert report.passed, f"OS entropy failed validation:\n{report}"


def test_statistical_suite_flags_constant():
    """All-zero stream MUST fail."""
    data = b"\x00" * (16 * 1024)
    report = StatisticalSuite().run_all(data)
    assert not report.passed
