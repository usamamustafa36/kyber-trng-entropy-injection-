"""
kyber_trng — Hardware-entropy-injected Kyber (ML-KEM) wrapper.

Replaces the deterministic AES-CTR_DRBG / os.urandom entropy source inside
kyber-py with bytes pulled from a hardware TRNG (SAM3X8E ring-oscillator
firmware) — eliminating the deterministic single point of failure that affects
every standard Kyber deployment.

Improvement over the baseline thesis design:
  * Hybrid TRNG ⊕ DRBG mode (defense in depth)
  * NIST SP 800-90B continuous health tests on the host side as well as in firmware
  * Per-byte min-entropy estimation
  * Auditable byte-source log

Author: Usama Mustafa
License: MIT
"""

from .source import TRNGSource, SimulatedTRNGSource, SerialTRNGSource
from .hybrid import HybridDRBG
from .health import RepetitionCountTest, AdaptiveProportionTest, HealthMonitor
from .kyber_shim import keygen, encaps, decaps, set_entropy_source

__all__ = [
    "TRNGSource",
    "SimulatedTRNGSource",
    "SerialTRNGSource",
    "HybridDRBG",
    "RepetitionCountTest",
    "AdaptiveProportionTest",
    "HealthMonitor",
    "keygen",
    "encaps",
    "decaps",
    "set_entropy_source",
]

__version__ = "0.1.0"
