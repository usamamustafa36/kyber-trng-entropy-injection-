"""Tests for the kyber-py integration shim."""

import pytest

from kyber_trng.kyber_shim import (
    kyber, set_entropy_source, audit_log,
)
from kyber_trng.source import SimulatedTRNGSource
from kyber_trng.hybrid import HybridDRBG


def setup_function(_):
    set_entropy_source(SimulatedTRNGSource())
    audit_log.clear()


def test_keygen_encaps_decaps_round_trip_l1024():
    ek, dk = kyber.l1024.keygen()
    K, ct = kyber.l1024.encaps(ek)
    K2 = kyber.l1024.decaps(dk, ct)
    assert K == K2


def test_keygen_encaps_decaps_round_trip_l768():
    ek, dk = kyber.l768.keygen()
    K, ct = kyber.l768.encaps(ek)
    K2 = kyber.l768.decaps(dk, ct)
    assert K == K2


def test_no_source_installed_raises():
    set_entropy_source(None)
    with pytest.raises(RuntimeError):
        kyber.l1024.keygen()


def test_audit_log_records_operations():
    kyber.l1024.keygen()
    entries = audit_log.entries()
    assert len(entries) == 1
    assert entries[0].operation == "ml_kem_1024.keygen"
    assert entries[0].source == "simulated"
    assert entries[0].bytes_consumed >= 32  # keygen consumes ≥ 32 bytes


def test_audit_log_records_under_hybrid():
    set_entropy_source(HybridDRBG(SimulatedTRNGSource()))
    ek, dk = kyber.l1024.keygen()
    K, ct = kyber.l1024.encaps(ek)
    entries = audit_log.entries()
    sources = {e.source for e in entries}
    assert sources == {"hybrid"}
    ops = [e.operation for e in entries]
    assert ops == ["ml_kem_1024.keygen", "ml_kem_1024.encaps"]


def test_keygen_under_two_sources_yields_distinct_keys():
    set_entropy_source(SimulatedTRNGSource())
    ek1, _ = kyber.l1024.keygen()
    ek2, _ = kyber.l1024.keygen()
    assert ek1 != ek2
