"""
Hybrid TRNG ⊕ DRBG entropy mode.

Improvement over the baseline thesis design: instead of replacing AES-CTR_DRBG
*entirely* with the TRNG (which trades one single point of failure for
another), this module XORs the TRNG output with HKDF-DRBG output reseeded
from the TRNG. Properties:

  * If the TRNG fails (stuck output, low entropy): DRBG output preserves
    cryptographic strength as long as the TRNG seed at boot was good.
  * If the DRBG seed is leaked / state is captured: live TRNG injection means
    output remains unpredictable.
  * Both must be compromised simultaneously for the entropy stream to fail.

This is "defense in depth" applied to entropy — analogous to TLS hybrid
key exchange combining classical + post-quantum KEMs.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from .source import TRNGSource
from .health import HealthMonitor


class HybridDRBG:
    """
    HMAC-SHA256-based DRBG mixed with live TRNG bytes.

    Seed: TRNG bytes (>= 64 bytes recommended)
    Reseed interval: configurable; default 1 MiB of output

    Generate(n):
        drbg_bytes = HMAC-DRBG(K, V).expand(n)
        trng_bytes = trng.read(n)
        return drbg_bytes XOR trng_bytes
    """

    def __init__(
        self,
        trng: TRNGSource,
        reseed_interval: int = 1 << 20,
        seed_size: int = 64,
        health: Optional[HealthMonitor] = None,
    ):
        self._trng = trng
        self._reseed_interval = reseed_interval
        self._seed_size = seed_size
        self._health = health or HealthMonitor()
        self._bytes_since_reseed = 0
        self._K = b"\x00" * 32
        self._V = b"\x01" * 32
        self._reseed()

    def _hmac(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    def _reseed(self) -> None:
        seed = self._trng.read(self._seed_size)
        if not self._health.feed(seed):
            raise RuntimeError("TRNG failed health tests during reseed")
        self._K = self._hmac(self._K, self._V + b"\x00" + seed)
        self._V = self._hmac(self._K, self._V)
        self._K = self._hmac(self._K, self._V + b"\x01" + seed)
        self._V = self._hmac(self._K, self._V)
        self._bytes_since_reseed = 0

    def _drbg_generate(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            self._V = self._hmac(self._K, self._V)
            out.extend(self._V)
        self._K = self._hmac(self._K, self._V + b"\x00")
        self._V = self._hmac(self._K, self._V)
        return bytes(out[:n])

    def read(self, n: int) -> bytes:
        if self._bytes_since_reseed + n > self._reseed_interval:
            self._reseed()
        drbg = self._drbg_generate(n)
        live = self._trng.read(n)
        if not self._health.feed(live):
            raise RuntimeError("TRNG failed health tests during generate")
        self._bytes_since_reseed += n
        return bytes(a ^ b for a, b in zip(drbg, live))

    def close(self) -> None:
        self._trng.close()

    @property
    def health(self) -> HealthMonitor:
        return self._health
