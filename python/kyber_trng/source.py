"""Entropy source abstractions.

A :class:`TRNGSource` is anything that can hand out cryptographic-quality
bytes via ``read(n)``.  Three concrete implementations are provided:

* :class:`SimulatedTRNGSource` — the canonical *software simulator* used
  for the validation runs in this repository.  It mixes OS entropy with
  software timing-jitter samples drawn from ``time.perf_counter_ns``
  (the LSBs of which capture scheduling and cache-driven micro-jitter).
  It is a stand-in for a real ring-oscillator TRNG; it is *not* a
  hardware capture and is labelled as such everywhere it is used.

* :class:`SerialTRNGSource` — production source.  Reads CRC-framed bytes
  from a USB CDC serial port produced by the SAM3X8E firmware.  Frame
  format: ``0xAA 0x55 <byte> <crc8(byte)>``.

* :class:`HybridDRBG` (in :mod:`kyber_trng.hybrid`) wraps any source and
  XORs its output with reseeded HMAC-DRBG output.
"""

from __future__ import annotations

import abc
import hashlib
import math
import os
import time
import threading
from collections import deque
from typing import Optional


class TRNGSourceError(RuntimeError):
    """Raised when an entropy source cannot satisfy a read.

    Reasons include: serial port disconnection, sustained health-test
    failure, or buffer underrun past the configured timeout.
    """


class TRNGSource(abc.ABC):
    """Abstract entropy source."""

    name: str = "abstract"

    @abc.abstractmethod
    def read(self, n: int) -> bytes:
        """Return exactly ``n`` bytes or raise :class:`TRNGSourceError`."""

    def random_bytes(self, n: int) -> bytes:
        """Alias used by the kyber-py integration."""
        return self.read(n)

    def close(self) -> None:
        """Release any held resources.  Default no-op."""


class SimulatedTRNGSource(TRNGSource):
    """Software simulator of a dual-source ring-oscillator TRNG.

    The simulator is the entropy source used for every empirical result in
    this repository.  Each output byte is the XOR of:

    1. one byte drawn from ``os.urandom`` (kernel CSPRNG — provides the
       cryptographic floor), and
    2. one byte assembled from eight LSBs of ``time.perf_counter_ns``
       sampled across a short busy-wait loop (provides the jitter
       characteristic of a free-running ring oscillator: scheduling
       jitter, cache state, branch predictor noise).

    The construction matches the firmware design in :file:`firmware/`,
    where the two sources are an on-chip TRNG peripheral and a
    SysTick-sampled software jitter loop.  No firmware-specific cycle
    counts are claimed for the simulator — its measured throughput is
    that of the host Python interpreter, not of the SAM3X8E.
    """

    name = "simulated"

    def __init__(self, jitter_iters: int = 8) -> None:
        self._jitter_iters = max(1, int(jitter_iters))

    def _jitter_byte(self) -> int:
        b = 0
        for _ in range(8):
            t1 = time.perf_counter_ns()
            # Side-effecting busy-wait short enough that the LSB of the
            # post-loop counter is dominated by jitter rather than by the
            # loop body's deterministic length.
            x = 1.0001
            for _ in range(self._jitter_iters):
                x = x * x  # noqa: B023
            t2 = time.perf_counter_ns()
            bit = (t1 ^ t2 ^ int(x * 1_000_000)) & 1
            b = (b << 1) | bit
        return b & 0xFF

    def read(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return b""
        os_bytes = os.urandom(n)
        jitter = bytes(self._jitter_byte() for _ in range(n))
        return bytes(a ^ b for a, b in zip(os_bytes, jitter))


# ---------------------------------------------------------------------------
# CRC-8 used by the firmware framing.  Polynomial 0x07 (CRC-8/SMBUS).

_CRC8_TABLE = [0] * 256
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = ((_c << 1) ^ 0x07) & 0xFF if _c & 0x80 else (_c << 1) & 0xFF
    _CRC8_TABLE[_i] = _c


def crc8(b: int) -> int:
    """CRC-8/SMBUS over a single byte.  Used for serial framing."""
    return _CRC8_TABLE[b & 0xFF]


class SerialTRNGSource(TRNGSource):
    """Production source: reads framed bytes from the SAM3X8E firmware.

    Frames are four bytes: ``0xAA 0x55 <data> <crc8(data)>``.  The reader
    runs a daemon thread that pumps validated bytes into a bounded
    :class:`collections.deque`; ``read(n)`` blocks cooperatively until
    ``n`` bytes are available or ``timeout`` elapses.

    This class is unused by the simulator-backed validation in this
    repository but is included so the production deployment path is
    spec-complete.  It is not exercised in CI because it requires
    hardware.
    """

    name = "serial"
    SOF = bytes((0xAA, 0x55))
    BUFFER_BYTES = 64 * 1024

    def __init__(self, port: str, baud: int = 115200, timeout: float = 5.0) -> None:
        try:
            import serial  # type: ignore
        except ImportError as e:  # pragma: no cover
            raise TRNGSourceError("pyserial is required for SerialTRNGSource") from e
        self._port = port
        self._timeout = float(timeout)
        self._serial = serial.Serial(port, baud, timeout=0.1)
        self._buf: deque[int] = deque(maxlen=self.BUFFER_BYTES)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._pump, daemon=True, name=f"trng-pump-{port}")
        self._thread.start()

    def _pump(self) -> None:  # pragma: no cover — exercised only against hardware
        sof0, sof1 = self.SOF
        state = 0
        while not self._stop.is_set():
            chunk = self._serial.read(256)
            if not chunk:
                continue
            i = 0
            while i < len(chunk):
                c = chunk[i]
                if state == 0:
                    state = 1 if c == sof0 else 0
                elif state == 1:
                    state = 2 if c == sof1 else (1 if c == sof0 else 0)
                elif state == 2:
                    data = c
                    state = 3
                else:  # state == 3 — CRC byte
                    if c == crc8(data):
                        with self._lock:
                            self._buf.append(data)
                    state = 0
                i += 1

    def read(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return b""
        deadline = time.monotonic() + self._timeout
        out = bytearray()
        while len(out) < n:
            with self._lock:
                while self._buf and len(out) < n:
                    out.append(self._buf.popleft())
            if len(out) < n:
                if time.monotonic() > deadline:
                    raise TRNGSourceError(
                        f"SerialTRNGSource: read({n}) timed out at "
                        f"{len(out)} bytes after {self._timeout:.1f}s"
                    )
                time.sleep(0.005)
        return bytes(out)

    def close(self) -> None:  # pragma: no cover
        self._stop.set()
        try:
            self._serial.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# SP 800-90B conditioning.
#
# The device mixes its two sources with XOR and the host XORs the result
# against DRBG output.  XOR is a mixing operation, not a conditioning
# component: it masks a biased source rather than extracting from it, so no
# min-entropy claim can be made about the output.  SP 800-90B requires a
# vetted conditioning function for that, and SP 800-90C requires conditioned
# entropy-source output in an RBG3(XOR) construction.
#
# This wrapper supplies that stage.  It is opt-in: the default path through
# HybridDRBG is unchanged, so every result already reported remains
# reproducible from the same code.


class ConditionedSource(TRNGSource):
    """Apply a vetted conditioning function to another source's output.

    Reads enough raw bytes to carry ``8 * n + margin_bits`` bits of
    min-entropy, then compresses them to ``n`` bytes with SHAKE256.  The
    64-bit margin follows the usual full-entropy requirement: the input
    entropy must exceed the output length so that the conditioned output is
    statistically close to uniform.

    ``h_min`` is min-entropy per *byte* of raw source output, and it is the
    number that must eventually come from an SP 800-90B non-IID estimate on
    real silicon.  Until then the conservative 0.5 used for the health-test
    cutoffs is carried through here, which makes the compression ratio
    correspondingly pessimistic.

    Example, at the default settings::

        32 output bytes -> (8*32 + 64) / 0.5 = 640 raw bytes consumed
    """

    name = "conditioned"

    def __init__(self, source: TRNGSource, h_min: float = 0.5,
                 margin_bits: int = 64) -> None:
        if h_min <= 0:
            raise ValueError("h_min must be positive")
        if not 0 <= h_min <= 8:
            raise ValueError("h_min is bits per byte, so it must lie in [0, 8]")
        if margin_bits < 0:
            raise ValueError("margin_bits must be non-negative")
        self._src = source
        self._h_min = float(h_min)
        self._margin = int(margin_bits)
        self.name = f"conditioned({source.name})"

    def raw_bytes_required(self, n: int) -> int:
        """Raw bytes consumed to produce ``n`` conditioned bytes."""
        if n <= 0:
            return 0
        return math.ceil((8 * n + self._margin) / self._h_min)

    def read(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return b""
        raw = self._src.read(self.raw_bytes_required(n))
        return hashlib.shake_256(raw).digest(n)

    def close(self) -> None:
        self._src.close()
