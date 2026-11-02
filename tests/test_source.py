"""Tests for the entropy source layer."""

import pytest

from kyber_trng.source import SimulatedTRNGSource, crc8


def test_simulated_returns_exact_length():
    src = SimulatedTRNGSource()
    for n in (0, 1, 7, 32, 1024, 4097):
        out = src.read(n)
        assert isinstance(out, bytes)
        assert len(out) == n


def test_simulated_independent_reads_differ():
    src = SimulatedTRNGSource()
    a = src.read(64)
    b = src.read(64)
    assert a != b  # negligible chance of equality at 512 bits


def test_simulated_random_bytes_alias():
    src = SimulatedTRNGSource()
    # The kyber-py integration calls .random_bytes(n).
    out = src.random_bytes(32)
    assert len(out) == 32


def test_simulated_negative_n_raises():
    src = SimulatedTRNGSource()
    with pytest.raises(ValueError):
        src.read(-1)


def test_crc8_known_vectors():
    # CRC-8/SMBUS of single bytes — match against an independent reference.
    # Computed with python-crc; pinned values are stable.
    assert crc8(0x00) == 0x00
    assert crc8(0xFF) == 0xF3
    assert crc8(0x01) == 0x07
    assert crc8(0x55) == 0xAC
    assert crc8(0xAA) == 0x5F


def test_simulated_byte_diversity():
    """Random byte distribution should cover a wide range, not be stuck."""
    src = SimulatedTRNGSource()
    data = src.read(8192)
    distinct = len(set(data))
    assert distinct >= 200  # 256 possible; loose bound for jitter variance
