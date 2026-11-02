"""HMAC-SHA256 DRBG and the hybrid TRNG ⊕ DRBG construction.

The DRBG follows NIST SP 800-90A §10.1.2 (HMAC_DRBG, SHA-256).  State is
``(K, V)`` with ``K`` the HMAC key and ``V`` the rolling value; both are
32 bytes.  ``Update`` and ``Generate`` follow the spec verbatim apart
from minor naming changes.

The :class:`HybridDRBG` wraps any :class:`TRNGSource` and an
``HMAC_DRBG`` instance.  On every ``read(n)`` it XORs ``DRBG.generate(n)``
with ``TRNG.read(n)``.  This delivers entropy *defense in depth*:

* compromise of the DRBG state alone yields a stream still XORed with
  live TRNG output;
* compromise of the TRNG alone yields a stream still XORed with DRBG
  output seeded from earlier (uncompromised) TRNG bytes.

The DRBG is reseeded every :pyattr:`reseed_interval_bytes` of generated
output (default 1 MiB) using fresh TRNG bytes.
"""

from __future__ import annotations

import hmac
import hashlib
from typing import Optional

from .source import TRNGSource


class HMAC_DRBG:
    """HMAC-SHA256 DRBG, NIST SP 800-90A §10.1.2."""

    OUTLEN = 32  # bytes
    MAX_BYTES_PER_REQUEST = 7500  # SP 800-90A Table 2 caps at 2^19 bits

    def __init__(self, seed: bytes, personalization: bytes = b""):
        if len(seed) < 32:
            raise ValueError("HMAC_DRBG seed must be ≥ 32 bytes")
        self.K = b"\x00" * self.OUTLEN
        self.V = b"\x01" * self.OUTLEN
        self._update(seed + personalization)
        self.reseed_counter = 1

    def _hmac(self, data: bytes) -> bytes:
        return hmac.new(self.K, data, hashlib.sha256).digest()

    def _update(self, provided_data: bytes = b"") -> None:
        self.K = hmac.new(self.K, self.V + b"\x00" + provided_data,
                          hashlib.sha256).digest()
        self.V = self._hmac(self.V)
        if provided_data:
            self.K = hmac.new(self.K, self.V + b"\x01" + provided_data,
                              hashlib.sha256).digest()
            self.V = self._hmac(self.V)

    def reseed(self, entropy: bytes, additional: bytes = b"") -> None:
        if len(entropy) < 32:
            raise ValueError("reseed entropy must be ≥ 32 bytes")
        self._update(entropy + additional)
        self.reseed_counter = 1

    def generate(self, n: int, additional: bytes = b"") -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return b""
        if n > self.MAX_BYTES_PER_REQUEST:
            # Spec-conforming chunking.
            out = bytearray()
            while n > 0:
                take = min(n, self.MAX_BYTES_PER_REQUEST)
                out.extend(self.generate(take, additional if not out else b""))
                n -= take
            return bytes(out)
        if additional:
            self._update(additional)
        out = bytearray()
        while len(out) < n:
            self.V = self._hmac(self.V)
            out.extend(self.V)
        self._update(additional)
        self.reseed_counter += 1
        return bytes(out[:n])


class HybridDRBG(TRNGSource):
    """Hybrid TRNG ⊕ HMAC-DRBG entropy source.

    Each output byte is ``DRBG.generate(1) XOR TRNG.read(1)``.  The DRBG
    is reseeded from the TRNG every ``reseed_interval_bytes`` bytes.
    """

    name = "hybrid"

    def __init__(
        self,
        trng: TRNGSource,
        seed_bytes: int = 64,
        reseed_interval_bytes: int = 1 << 20,
        personalization: bytes = b"kyber_trng.hybrid v1",
    ) -> None:
        self._trng = trng
        self._reseed_interval = int(reseed_interval_bytes)
        self._since_reseed = 0
        seed = trng.read(seed_bytes)
        self._drbg = HMAC_DRBG(seed, personalization)

    def read(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return b""
        out = bytearray(n)
        produced = 0
        while produced < n:
            if self._since_reseed >= self._reseed_interval:
                self._drbg.reseed(self._trng.read(64))
                self._since_reseed = 0
            take = min(n - produced, self._reseed_interval - self._since_reseed,
                       HMAC_DRBG.MAX_BYTES_PER_REQUEST)
            drbg_chunk = self._drbg.generate(take)
            trng_chunk = self._trng.read(take)
            for i in range(take):
                out[produced + i] = drbg_chunk[i] ^ trng_chunk[i]
            produced += take
            self._since_reseed += take
        return bytes(out)
