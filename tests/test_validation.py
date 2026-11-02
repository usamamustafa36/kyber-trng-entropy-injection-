"""Tests for in-process SP 800-22 validators."""

import os

from kyber_trng.validation import (
    monobit, block_frequency, runs, cumulative_sums,
    shannon_entropy, chi_square_uniformity, run_all_in_process,
)


def test_monobit_passes_random():
    data = os.urandom(1 << 16)  # 64 KiB
    r = monobit(data)
    assert r.passed
    assert 0 < r.p_value <= 1


def test_monobit_fails_constant():
    data = b"\x00" * 1024
    r = monobit(data)
    assert not r.passed


def test_block_frequency_passes_random():
    data = os.urandom(1 << 16)
    r = block_frequency(data)
    assert r.passed


def test_runs_passes_random():
    data = os.urandom(1 << 16)
    r = runs(data)
    assert r.passed


def test_cusums_passes_random_both_directions():
    data = os.urandom(1 << 16)
    assert cumulative_sums(data, "forward").passed
    assert cumulative_sums(data, "backward").passed


def test_shannon_entropy_near_full():
    data = os.urandom(1 << 16)
    r = shannon_entropy(data)
    assert r.passed
    assert r.statistic >= 7.99


def test_chi_square_passes_random():
    data = os.urandom(1 << 16)
    r = chi_square_uniformity(data)
    assert r.passed


def test_chi_square_fails_skewed_distribution():
    data = bytes((i % 16 for i in range(1 << 16)))  # only 16 distinct values
    r = chi_square_uniformity(data)
    assert not r.passed


def test_run_all_in_process_returns_one_result_per_test():
    data = os.urandom(1 << 16)
    rs = run_all_in_process(data)
    assert len(rs) == 7
