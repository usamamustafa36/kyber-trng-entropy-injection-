"""Tests for SP 800-90B health monitor (RCT + APT)."""

import os

import pytest

from kyber_trng.health import (
    HealthMonitor, RepetitionCountTest, AdaptiveProportionTest,
    rct_cutoff, apt_cutoff,
)


def test_rct_cutoff_matches_thesis():
    # Thesis / paper §6: H=0.5, α=2⁻²⁰ → C_RCT=41.
    assert rct_cutoff(0.5, 2 ** -20) == 41


def test_rct_trips_on_constant_stream():
    rct = RepetitionCountTest(h_min=0.5, alpha=2 ** -20)
    for _ in range(rct.cutoff):
        rct.update(0)
    assert rct.failed


def test_rct_does_not_trip_on_alternating():
    rct = RepetitionCountTest(h_min=0.5, alpha=2 ** -20)
    for i in range(10000):
        rct.update(i & 1)
    assert not rct.failed


def test_apt_cutoff_for_h_one():
    # H=1 → p=0.5 → expected count W/2.  Cutoff should be > W/2.
    c = apt_cutoff(1.0, 2 ** -20, 512)
    assert c > 256
    assert c <= 512


def test_apt_trips_on_biased_stream():
    apt = AdaptiveProportionTest(h_min=0.5, alpha=2 ** -20, window=512)
    # Stream that's overwhelmingly 0x42.
    for _ in range(apt.window * 2):
        apt.update(0x42)
    assert apt.failed


def test_health_monitor_passes_on_random_stream():
    h = HealthMonitor()
    # 4 KiB of OS-level randomness.  Should never trip the cutoffs.
    h.update(os.urandom(4096))
    assert h.report().ok


def test_health_monitor_fails_closed():
    h = HealthMonitor()
    h.update(b"\x00" * 100)
    assert h.failed
    # Once failed, further "good" data does not recover.
    h.update(os.urandom(1024))
    assert h.failed


def test_apt_constant_byte_within_window_bounds():
    """An all-zero stream should fail APT once the window is full."""
    apt = AdaptiveProportionTest(h_min=0.5, alpha=2 ** -20, window=512)
    for _ in range(apt.window):
        apt.update(0)
    assert apt.failed
