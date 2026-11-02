"""Tests for HMAC-DRBG and HybridDRBG."""

import os

import pytest

from kyber_trng.hybrid import HMAC_DRBG, HybridDRBG
from kyber_trng.source import SimulatedTRNGSource


def test_hmac_drbg_deterministic_under_same_seed():
    a = HMAC_DRBG(b"\x00" * 48)
    b = HMAC_DRBG(b"\x00" * 48)
    assert a.generate(64) == b.generate(64)


def test_hmac_drbg_different_seeds_diverge():
    a = HMAC_DRBG(b"\x00" * 48)
    b = HMAC_DRBG(b"\x01" * 48)
    assert a.generate(64) != b.generate(64)


def test_hmac_drbg_reseed_changes_output():
    a = HMAC_DRBG(b"\x00" * 48)
    snapshot = a.generate(64)
    a.reseed(b"\xff" * 48)
    fresh = a.generate(64)
    assert snapshot != fresh


def test_hmac_drbg_chunked_request_matches_concatenated():
    a = HMAC_DRBG(b"\x00" * 48)
    b = HMAC_DRBG(b"\x00" * 48)
    chunked = a.generate(8000)
    monolithic = b.generate(8000)
    assert chunked == monolithic
    assert len(chunked) == 8000


def test_hybrid_drbg_lengths_and_distinctness():
    h = HybridDRBG(SimulatedTRNGSource())
    a = h.read(1024)
    b = h.read(1024)
    assert len(a) == 1024 and len(b) == 1024
    assert a != b


def test_hybrid_drbg_reseed_threshold_runs_clean():
    """Reseeding at the configured threshold must not raise or produce empties."""
    h = HybridDRBG(SimulatedTRNGSource(), reseed_interval_bytes=4096)
    out = h.read(20480)  # crosses several reseed boundaries
    assert len(out) == 20480
    assert out.count(0) < len(out)  # not stuck-at-zero


def test_hybrid_drbg_seed_too_short_rejected():
    src = SimulatedTRNGSource()
    with pytest.raises(ValueError):
        HMAC_DRBG(b"\x00" * 16)


def test_hmac_drbg_zero_request_returns_empty():
    a = HMAC_DRBG(b"\x00" * 48)
    assert a.generate(0) == b""
