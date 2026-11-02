"""kyber_trng — entropy injection framework for ML-KEM.

This package separates the entropy *source* from the lattice-cryptographic
operations of ML-KEM.  Sources implement a uniform :class:`TRNGSource`
interface and may be:

* a hardware ring-oscillator TRNG accessed via USB CDC (production);
* a software simulator that mixes OS entropy with timing-jitter samples
  (development, CI, and the validation runs reported in this repository);
* a hybrid mode that XORs live source bytes with HMAC-DRBG output.

The package also implements the SP 800-90B RCT and APT continuous health
tests, an audit log, and a thin shim that wires the active source into
``kyber-py``'s ``ML_KEM`` instances by overriding their ``random_bytes``
attribute.
"""

from .source import (TRNGSource, SimulatedTRNGSource, SerialTRNGSource,
                     ConditionedSource, TRNGSourceError)
from .health import HealthMonitor, HealthReport, RepetitionCountTest, AdaptiveProportionTest
from .hybrid import HybridDRBG, HMAC_DRBG
from .kyber_shim import set_entropy_source, kyber, kat_mode, audit_log

__all__ = [
    "TRNGSource", "SimulatedTRNGSource", "SerialTRNGSource",
    "ConditionedSource", "TRNGSourceError",
    "HealthMonitor", "HealthReport", "RepetitionCountTest", "AdaptiveProportionTest",
    "HybridDRBG", "HMAC_DRBG",
    "set_entropy_source", "kyber", "kat_mode", "audit_log",
]

__version__ = "0.1.0"
