"""Integration shim between :mod:`kyber_trng` and ``kyber-py``.

``kyber-py``'s ``ML_KEM`` instances expose a ``random_bytes`` attribute
(default ``os.urandom``).  We replace that attribute on each call,
counting the bytes the call actually consumed via a small wrapper.

This is cleaner than the scoped ``os.urandom`` patch the original
specification described — it touches one well-documented public
attribute instead of monkey-patching a builtin.
"""

from __future__ import annotations

import os
import threading
import warnings
from contextlib import contextmanager
from typing import Iterator, Optional, Tuple

from .audit import AuditLog
from .source import TRNGSource


_lock = threading.RLock()
_active: Optional[TRNGSource] = None
audit_log = AuditLog()


def set_entropy_source(source: Optional[TRNGSource]) -> None:
    """Install ``source`` as the active entropy source.  ``None`` clears."""
    global _active
    with _lock:
        _active = source


def get_entropy_source() -> Optional[TRNGSource]:
    return _active


def _ml_kem_class(level: int):
    if level == 512:
        from kyber_py.ml_kem import ML_KEM_512 as cls
    elif level == 768:
        from kyber_py.ml_kem import ML_KEM_768 as cls
    elif level == 1024:
        from kyber_py.ml_kem import ML_KEM_1024 as cls
    else:
        raise ValueError(f"unknown ML-KEM level {level!r}; expected 512/768/1024")
    return cls


@contextmanager
def _bound_random_bytes(instance, source: TRNGSource, label: str) -> Iterator[None]:
    """Temporarily hook ``instance.random_bytes`` to ``source.read``.

    Records (operation, bytes_consumed) into the audit log on exit.
    """
    original = instance.random_bytes
    counter = [0]

    def _patched(n: int) -> bytes:
        counter[0] += n
        return source.read(n)

    instance.random_bytes = _patched
    try:
        yield
    finally:
        instance.random_bytes = original
        audit_log.record(label, source.name, counter[0])


class _KyberFacade:
    """Thin facade over ``kyber-py``'s ``ML_KEM`` classes.

    Supports ``keygen()``, ``encaps(ek)``, and ``decaps(dk, ct)`` for
    levels 512, 768, and 1024.  Use ``kyber.l1024`` / ``.l768`` / ``.l512``
    for the convenience accessors.
    """

    def __init__(self, level: int):
        self._level = level
        self._cls = _ml_kem_class(level)

    @property
    def level(self) -> int:
        return self._level

    def _require_source(self) -> TRNGSource:
        with _lock:
            if _active is None:
                raise RuntimeError(
                    "kyber_trng: no entropy source installed.  Call "
                    "set_entropy_source(SimulatedTRNGSource()) (or another "
                    "TRNGSource) before invoking keygen/encaps."
                )
            return _active

    def keygen(self) -> Tuple[bytes, bytes]:
        src = self._require_source()
        with _bound_random_bytes(self._cls, src, f"ml_kem_{self._level}.keygen"):
            return self._cls.keygen()

    def encaps(self, ek: bytes) -> Tuple[bytes, bytes]:
        src = self._require_source()
        with _bound_random_bytes(self._cls, src, f"ml_kem_{self._level}.encaps"):
            return self._cls.encaps(ek)

    def decaps(self, dk: bytes, ct: bytes) -> bytes:
        # decaps does not consume fresh entropy in ML-KEM, but we still
        # patch defensively in case of upstream changes.
        src = self._require_source()
        with _bound_random_bytes(self._cls, src, f"ml_kem_{self._level}.decaps"):
            return self._cls.decaps(dk, ct)


class _Kyber:
    """Namespace giving ``kyber.l1024.keygen()`` etc."""

    def __init__(self) -> None:
        self.l512 = _KyberFacade(512)
        self.l768 = _KyberFacade(768)
        self.l1024 = _KyberFacade(1024)


kyber = _Kyber()


@contextmanager
def kat_mode(seed: bytes) -> Iterator[None]:
    """Temporarily disable the TRNG and seed AES-CTR_DRBG from ``seed``.

    Use this only for KAT replay against published NIST vectors.
    Emits a ``UserWarning`` on entry — KAT mode is *not* a production
    operating mode.
    """
    if len(seed) < 48:
        raise ValueError("KAT seed must be ≥ 48 bytes (NIST KAT format)")
    warnings.warn(
        "kyber_trng.kat_mode active: TRNG bypassed for KAT replay.",
        UserWarning,
        stacklevel=2,
    )
    saved = get_entropy_source()
    set_entropy_source(None)
    # Seed each level.
    classes = [_ml_kem_class(l) for l in (512, 768, 1024)]
    saved_random = [c.random_bytes for c in classes]
    for c in classes:
        c.set_drbg_seed(seed)
    try:
        yield
    finally:
        for c, r in zip(classes, saved_random):
            c.random_bytes = r
        set_entropy_source(saved)
