"""
Kyber (ML-KEM) wrapper that injects TRNG entropy in place of os.urandom.

Compatible with the kyber-py library by Giacomo Pope (github.com/GiacomoPope/kyber-py).
The shim transparently patches os.urandom for the duration of each Kyber call,
sourcing bytes from the configured TRNGSource / HybridDRBG instead.

Usage:

    from kyber_trng import set_entropy_source, keygen, encaps, decaps
    from kyber_trng.source import SerialTRNGSource

    set_entropy_source(SerialTRNGSource("/dev/ttyACM0"))

    pk, sk = keygen()
    ct, ss_a = encaps(pk)
    ss_b = decaps(ct, sk)
    assert ss_a == ss_b
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from typing import Optional, Tuple, Union

from .source import TRNGSource
from .hybrid import HybridDRBG

_lock = threading.Lock()
_active_source: Optional[Union[TRNGSource, HybridDRBG]] = None
_audit_log: list = []
_audit_max = 1024


def set_entropy_source(source: Union[TRNGSource, HybridDRBG]) -> None:
    """Install the entropy source used by all subsequent Kyber operations."""
    global _active_source
    with _lock:
        _active_source = source


def get_entropy_source() -> Optional[Union[TRNGSource, HybridDRBG]]:
    return _active_source


def audit_log() -> list:
    """Recent (operation, n_bytes_consumed) tuples — for analysis & traceability."""
    return list(_audit_log)


@contextmanager
def _patched_urandom(label: str):
    """
    Monkey-patch os.urandom for the duration of a Kyber call.

    kyber-py and most reference implementations call os.urandom internally
    for keygen seeds (d, z) and encaps coins (m). Patching scoped to the
    call avoids global side effects.
    """
    if _active_source is None:
        raise RuntimeError(
            "No entropy source configured — call set_entropy_source() first."
        )

    original = os.urandom
    consumed = [0]

    def _patched(n: int) -> bytes:
        consumed[0] += n
        return _active_source.read(n)

    os.urandom = _patched  # type: ignore[assignment]
    try:
        yield
    finally:
        os.urandom = original
        if len(_audit_log) >= _audit_max:
            _audit_log.pop(0)
        _audit_log.append((label, consumed[0]))


def _import_kyber():
    """Import the upstream kyber-py library lazily so the package can be installed
    without it (e.g., for firmware-only or test-only workflows)."""
    try:
        from kyber_py.ml_kem import ML_KEM_1024  # type: ignore
        return ML_KEM_1024
    except ImportError as exc:
        raise ImportError(
            "kyber-py not installed. Install with: pip install kyber-py"
        ) from exc


def keygen() -> Tuple[bytes, bytes]:
    """ML-KEM-1024 key generation with TRNG-sourced entropy."""
    ml_kem = _import_kyber()
    with _patched_urandom("keygen"):
        ek, dk = ml_kem.keygen()
    return ek, dk


def encaps(public_key: bytes) -> Tuple[bytes, bytes]:
    """ML-KEM-1024 encapsulation. Returns (ciphertext, shared_secret)."""
    ml_kem = _import_kyber()
    with _patched_urandom("encaps"):
        ss, ct = ml_kem.encaps(public_key)
    return ct, ss


def decaps(ciphertext: bytes, secret_key: bytes) -> bytes:
    """ML-KEM-1024 decapsulation. Returns shared_secret.

    Decaps is deterministic — no entropy consumed — but we still log the call
    for completeness of the audit trail.
    """
    ml_kem = _import_kyber()
    with _patched_urandom("decaps"):
        ss = ml_kem.decaps(secret_key, ciphertext)
    return ss
